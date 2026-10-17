from __future__ import annotations
from urllib.parse import quote, urlsplit
import httpx
from ..model import Rejected, canonical, digest, decode_json, validate_result
from ..connector_capture import (ConnectorCapture, CapturePending, MAX_MATRIX_ROOMS,
                                 MAX_MATRIX_EVENTS, MAX_PAGE_RESULTS, MAX_REFERENCE_BYTES)


class MatrixAdapter:
    contract_version = "frank.integration.v1"
    provider_idempotent = True

    def __init__(
        self, integration_id, config, *, client, secret_resolver, environment="production",
        connector_capture=None
    ):
        if set(config) != {"homeserver", "account_id", "token_ref", "routes"}:
            raise Rejected("Malformed Matrix configuration")
        url = urlsplit(config["homeserver"])
        if (
            url.scheme not in {"http", "https"}
            or not url.hostname
            or url.username
            or url.password
            or url.query
            or url.fragment
            or url.path not in {"", "/"}
        ):
            raise Rejected("Invalid Matrix origin")
        if environment == "production" and url.scheme != "https":
            raise Rejected("Production Matrix requires TLS")
        if not isinstance(config["token_ref"], str) or not config["token_ref"].startswith(
            "secret:"
        ):
            raise Rejected("Matrix token must be a secret reference")
        if not isinstance(config["routes"], dict) or not config["routes"]:
            raise Rejected("Matrix routes must be explicit")
        for route in config["routes"].values():
            if (
                set(route) != {"room_id", "sender_id"}
                or not route["room_id"].startswith("!")
                or not route["sender_id"].startswith("@")
            ):
                raise Rejected("Invalid Matrix room/account route")
        self.integration_id, self.config, self.client, self.resolve = (
            integration_id,
            config,
            client,
            secret_resolver,
        )
        self.token = None
        self.ready = False
        self.connector_capture = connector_capture
        if connector_capture is not None:
            if type(connector_capture) is not ConnectorCapture:
                raise Rejected("Trusted connector capture required")
            connector_capture.bind("matrix", integration_id, config)
            if connector_capture.policy.route not in config["routes"]:
                raise Rejected("Capture route is not configured")
            self.config = decode_json(canonical(config))

    async def _call(self, method, path, *, missing_ok=False, **kwargs):
        try:
            response = await self.client.request(
                method,
                self.config["homeserver"].rstrip("/") + "/_matrix/client/v3" + path,
                headers={"Authorization": "Bearer " + self.token},
                follow_redirects=False,
                timeout=20,
                **kwargs,
            )
            if missing_ok and response.status_code == 404:
                return None
            if response.status_code >= 300:
                raise Rejected("Matrix request rejected")
            if len(response.content) > 1024 * 1024:
                raise Rejected("Matrix response exceeds bound")
            return decode_json(response.content)
        except (httpx.HTTPError, ValueError) as exc:
            if isinstance(exc, Rejected):
                raise
            raise Rejected("Matrix transport or response failure") from None

    async def connect(self):
        self.token = self.resolve(self.config["token_ref"])
        if not isinstance(self.token, str) or not self.token:
            raise Rejected("Matrix credential reference is unavailable")
        try:
            data = await self._call("GET", "/account/whoami")
            if data.get("user_id") != self.config["account_id"]:
                raise Rejected("Matrix credential belongs to another account")
            for room in sorted({route["room_id"] for route in self.config["routes"].values()}):
                encryption = await self._call(
                    "GET", f"/rooms/{quote(room, safe='')}/state/m.room.encryption", missing_ok=True
                )
                if encryption is not None:
                    raise Rejected("Encrypted Matrix rooms require a qualified crypto adapter")
        except Exception:
            self.token = None
            self.ready = False
            raise
        self.ready = True

    async def close(self):
        self.token = None
        self.ready = False

    async def capabilities(self):
        return frozenset({"send", "receive", "health", "cancel", "reconcile"})

    async def health(self):
        return {
            "integration_id": self.integration_id,
            "ready": self.ready,
            "code": "ready" if self.ready else "disconnected",
        }

    async def send(self, work):
        if not self.ready:
            raise Rejected("Matrix adapter is disconnected")
        route = self.config["routes"].get(work["route"])
        if not route:
            raise Rejected("Matrix work route is not configured")
        encryption = await self._call(
            "GET",
            f"/rooms/{quote(route['room_id'], safe='')}/state/m.room.encryption",
            missing_ok=True,
        )
        if encryption is not None:
            raise Rejected("Encrypted Matrix rooms require a qualified crypto adapter")
        body = {"msgtype": "m.text", "body": canonical(work).decode(), "org.zenith.frank.v1": work}
        data = await self._call(
            "PUT",
            f"/rooms/{quote(route['room_id'], safe='')}/send/m.room.message/{quote(work['effect_id'], safe='')}",
            json=body,
        )
        reference = data.get("event_id")
        if not isinstance(reference, str) or not reference:
            raise Rejected("Matrix send lacked acknowledgement")
        return {
            "schema": "frank.result.v1",
            "event_id": "ack-" + digest(reference)[:48],
            **{
                key: work[key]
                for key in ("binding", "actor_id", "integration_id", "route", "effect_id")
            },
            "provider_reference": reference,
            "outcome": "acknowledged",
            "outputs": {},
        }

    def normalize(self, room, event):
        if event.get("type") != "m.room.message":
            return None
        content = event.get("content") or {}
        result = content.get("org.zenith.frank.v1")
        if not isinstance(result, dict) or result.get("schema") != "frank.result.v1":
            return None
        route = self.config["routes"].get(result.get("route"))
        if (
            not route
            or route["room_id"] != room
            or route["sender_id"] != event.get("sender")
            or result.get("integration_id") != self.integration_id
        ):
            raise Rejected("Matrix result came from an unrelated room or account")
        if not isinstance(event.get("event_id"), str):
            raise Rejected("Matrix event has no stable identity")
        # Never let a body choose the delivery event identity or provider correlation.
        return {
            **result,
            "event_id": "event-" + digest(event["event_id"])[:48],
            "provider_reference": event["event_id"],
        }

    async def receive(self, cursor):
        if not self.ready:
            raise Rejected("Matrix adapter is disconnected")
        params = {"timeout": 0}
        if cursor:
            params["since"] = cursor
        data = await self._call("GET", "/sync", params=params)
        if self.connector_capture is not None:
            return await self._capture_page(data)
        result = []
        for room, body in (data.get("rooms", {}).get("join", {})).items():
            timeline = body.get("timeline") or {}
            if timeline.get("limited"):
                raise Rejected("Matrix replay gap requires reconciliation")
            for event in timeline.get("events") or []:
                normalized = self.normalize(room, event)
                if normalized:
                    result.append(normalized)
                if len(result) > 100:
                    raise Rejected("Matrix result page exceeds bound")
        next_cursor = data.get("next_batch")
        if not isinstance(next_cursor, str) or len(next_cursor) > 4096:
            raise Rejected("Matrix cursor is invalid")
        return result, next_cursor

    async def _capture_plain_room(self, room):
        encryption = await self._call(
            "GET", f"/rooms/{quote(room, safe='')}/state/m.room.encryption", missing_ok=True
        )
        if encryption is not None:
            raise Rejected("Encrypted Matrix rooms require a qualified crypto adapter")

    async def _capture_page(self, data):
        capture = self.connector_capture
        capture.bind("matrix", self.integration_id, self.config)
        # Validate every room/page before preparing or writing any eligible capture.
        data = decode_json(canonical(data))
        if type(data) is not dict or type(data.get("next_batch")) is not str or len(data["next_batch"].encode()) > MAX_REFERENCE_BYTES:
            raise Rejected("Matrix cursor is invalid")
        rooms = data.get("rooms", {})
        if type(rooms) is not dict or type(rooms.get("join", {})) is not dict:
            raise Rejected("Matrix room page is malformed")
        joined = rooms.get("join", {})
        if len(joined) > MAX_MATRIX_ROOMS:
            raise Rejected("Matrix room page exceeds bound")
        events = []
        for room, body in joined.items():
            if type(room) is not str or type(body) is not dict or type(body.get("timeline", {})) is not dict:
                raise Rejected("Matrix timeline is malformed")
            timeline = body.get("timeline", {})
            if type(timeline.get("limited", False)) is not bool or timeline.get("limited", False):
                raise Rejected("Matrix replay gap requires reconciliation")
            page = timeline.get("events", [])
            if type(page) is not list or any(type(event) is not dict for event in page):
                raise Rejected("Matrix events are malformed")
            if any(event.get("content") is not None and type(event["content"]) is not dict for event in page):
                raise Rejected("Matrix event content is malformed")
            events.extend((room, event) for event in page)
            if len(events) > MAX_MATRIX_EVENTS:
                raise Rejected("Matrix event page exceeds bound")
        normalized = []
        for room, event in events:
            result = self.normalize(room, event)
            if result is not None:
                normalized.append((room, event, decode_json(canonical(result))))
            if len(normalized) > MAX_PAGE_RESULTS:
                raise Rejected("Matrix result page exceeds bound")
        prepared, plain_rooms = [], set()
        for room, event, result in normalized:
            if capture.selected(result["route"]):
                item = capture.prepare_matrix(result, room=room, event=event, read_path="sync")
                if item is not None:
                    prepared.append(item)
                    plain_rooms.add(room)
        # All prepared records already freeze final result, work and provenance.
        for room in sorted(plain_rooms):
            await self._capture_plain_room(room)
        capture.bind("matrix", self.integration_id, self.config)
        if prepared:
            capture.commit(prepared)
            raise CapturePending("Unsigned Matrix capture retained; cursor withheld")
        return [result for _, _, result in normalized], data["next_batch"]

    async def cancel(self, work):
        # A send acknowledgement cannot prove a remote actor stopped. No false success.
        return False

    async def reconcile(self, work, provider_reference):
        capture = self.connector_capture
        if capture is not None and capture.selected(work["route"]):
            capture.bind("matrix", self.integration_id, self.config)
            work = decode_json(canonical(work))
            if capture.retained(work) is not None:
                raise CapturePending("Unsigned Matrix capture retained; issuer unavailable")
        if not provider_reference:
            return None
        route = self.config["routes"][work["route"]]
        event = await self._call(
            "GET",
            f"/rooms/{quote(route['room_id'], safe='')}/event/{quote(provider_reference, safe='')}",
        )
        result = self.normalize(route["room_id"], event)
        if capture is not None and capture.selected(work["route"]) and result is not None:
            validate_result(result, work)
            if event.get("event_id") != provider_reference:
                raise Rejected("Matrix event read returned another event")
            item = capture.prepare_matrix(result, room=route["room_id"], event=event, read_path="event")
            if item is not None:
                await self._capture_plain_room(route["room_id"])
                capture.bind("matrix", self.integration_id, self.config)
                capture.commit((item,))
                raise CapturePending("Unsigned Matrix capture retained; issuer unavailable")
        return result
