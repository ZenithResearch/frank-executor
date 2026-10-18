"""Public Runtime-client ports and explicit supplied-input dependencies.

No Runtime application/store imports, provider discovery, audio fabrication,
external status delivery or automatic fallback to synthetic fixture ports.
"""
from __future__ import annotations
import base64
import hashlib
import re
import time

from frank_executor.model import Binding, Rejected, canonical, decode_json, digest, identity
from process_runtime.compiler import validate_values
from .ports import ReviewFailure


class RuntimeArtifacts:
    effects_disabled = True  # Content-addressed local Runtime writes only.
    def __init__(self, gateway):
        self.gateway = gateway

    async def read(self, reference):
        if type(reference) is not dict or set(reference) != {"content_hash","byte_length","media_type"}:
            raise ReviewFailure("malformed_artifact")
        response = await self.gateway.query("artifact.get",{"content_hash":reference["content_hash"]})
        if response.get("artifact") != reference:
            raise ReviewFailure("artifact_integrity_mismatch")
        try:
            raw = base64.b64decode(response["content_base64"],validate=True)
        except (ValueError,TypeError,KeyError):
            raise ReviewFailure("artifact_integrity_mismatch") from None
        if (type(reference["byte_length"]) is not int or len(raw) != reference["byte_length"]
                or len(raw) > 1024*1024 or hashlib.sha256(raw).hexdigest() != reference["content_hash"]):
            raise ReviewFailure("artifact_integrity_mismatch")
        return raw

    async def write(self, content, media_type):
        if type(content) is not bytes or len(content) > 1024*1024:
            raise Rejected("Local Runtime artifact exceeds bound")
        reference = {"content_hash":hashlib.sha256(content).hexdigest(),"byte_length":len(content),"media_type":media_type}
        result = await self.gateway.execute("artifact.put",{"artifact":reference,"content_base64":base64.b64encode(content).decode()},None)
        if result.get("result",{}).get("artifact") != reference:
            raise ReviewFailure("artifact_write_integrity_mismatch")
        return reference


class RuntimeClaims:
    effects_disabled = True
    def __init__(self, gateway, journal, *, actor_id, integration_id, route):
        self.gateway, self.journal = gateway, journal
        self.actor_id,self.integration_id,self.route = map(identity,(actor_id,integration_id,route))

    async def check(self, work):
        # Snapshot all caller data before the first public-client await.
        work = decode_json(canonical(work))
        binding = Binding.read(work["binding"])
        if any(work.get(n) != getattr(self,n) for n in ("actor_id","integration_id","route")):
            raise Rejected("Claim outside selected producer route")
        with self.journal.connection() as db:
            rows = db.execute("SELECT * FROM deliveries WHERE json_extract(work,'$.integration_id')=? AND json_extract(work,'$.effect_id')=?",(self.integration_id,work["effect_id"])).fetchall()
            if (len(rows) != 1 or rows[0]["work"] != canonical(work).decode()
                    or rows[0]["digest"] != digest(work) or rows[0]["state"] not in {"unknown","acknowledged","succeeded","failed"}):
                raise Rejected("Exact dispatched Frank delivery required")
        data = await self.gateway.query("attempt.get",{n:getattr(binding,n) for n in ("run_id","step_id","attempt_id")})
        run = await self.gateway.query("run.get",{"run_id":binding.run_id})
        pin = data.get("pin")
        if (type(pin) is not dict or set(pin) != {"process_id","process_version","compilation_hash"}
                or run.get("pin") != pin or type(pin["compilation_hash"]) is not str
                or not re.fullmatch(r"[a-f0-9]{64}",pin["compilation_hash"])):
            raise Rejected("Current published process pin changed")
        identity(pin["process_id"]);identity(pin["process_version"])
        published = await self.gateway.query("version.get",{"process_version":pin["process_version"]})
        compiled = published.get("compiled")
        if (published.get("pin") != pin or type(compiled) is not dict
                or compiled.get("schema") != "process.compiled.v1" or compiled.get("process_id") != pin["process_id"]
                or digest(compiled) != pin["compilation_hash"] or type(compiled.get("steps")) is not list):
            raise Rejected("Actual published version does not match current execution pin")
        selected = [step for step in compiled["steps"] if type(step) is dict and step.get("step_id") == binding.step_id]
        if (len(selected) != 1 or type(selected[0].get("capabilities")) is not list
                or work["operation"] not in selected[0]["capabilities"]
                or selected[0].get("inputs") != data.get("input_types")
                or selected[0].get("outputs") != work["output_types"]):
            raise Rejected("Actual published step does not authorize selected review operation")
        try:
            validate_values(work["inputs"],selected[0]["inputs"])
        except Exception:
            raise Rejected("Actual published input contract does not authorize review work") from None
        now = time.time_ns()//1_000_000
        if (any(data.get(n) != v for n,v in binding.json().items()) or data.get("actor_id") != self.actor_id
                or data.get("state") != "active" or data.get("current") is not True
                or type(data.get("lease_expires_at_ms")) is not int or now >= data["lease_expires_at_ms"]
                or data.get("inputs") != work["inputs"] or data.get("input_digest") != digest(work["inputs"])
                or data.get("output_types") != work["output_types"] or run.get("run_id") != binding.run_id
                or run.get("state") not in {"pending","running","blocked"}
                or data.get("pin") != run.get("pin")):
            raise Rejected("Runtime reports changed, retired or expired review claim")
        return {"schema":"frank.local-review.claim-observation.v1","work_sha256":digest(work),
                "attempt":data,"run":run,"published_version":published,"observed_at_ms":now}


class RuntimeSnapshotSources:
    effects_disabled = True
    def __init__(self, artifacts, snapshots):
        # Source selection is owner composition data, not work/model paths/URLs.
        self.artifacts = artifacts
        self.snapshots = decode_json(canonical(snapshots))
        if type(self.snapshots) is not dict or len(self.snapshots) > 64:
            raise Rejected("Bounded selected source snapshots required")
        for subject, rows in self.snapshots.items():
            identity(subject)
            if type(rows) is not list or len(rows) > 128:
                raise Rejected("Selected snapshot capacity exceeded")
            for row in rows:
                if type(row) is not dict or set(row) != {"path","artifact"} or type(row["path"]) is not str or not 1 <= len(row["path"]) <= 4096:
                    raise Rejected("Selected logical source identity required")

    async def inspect(self, subject, selectors):
        if (type(selectors) is not list or len(selectors) > 128
                or any(type(s) is not str or len(s) > 4096 for s in selectors)):
            raise Rejected("Selector capacity exceeded")
        found = []
        for row in self.snapshots.get(subject,[]):
            raw = await self.artifacts.read(row["artifact"])
            try:
                text = raw.decode("utf-8")
            except UnicodeError:
                raise ReviewFailure("malformed_source_evidence") from None
            for number,line in enumerate(text.splitlines(),1):
                for selector in selectors:
                    parts = selector.split(".")
                    tag,classes = parts[0],parts[1:]
                    match = re.search(r'className="([^"]*)"',line)
                    if tag and re.search(r"<"+re.escape(tag)+r"\b",line) and (not classes or match and set(classes).issubset(match[1].split())):
                        found.append({"path":row["path"],"line":number,"selector":selector,
                                      "content_hash":hashlib.sha256(raw).hexdigest(),"text":line})
        canonical(found)
        return found

    async def resolve(self, subject, events):
        rows = []
        for selector in sorted({e["target"] for e in events if e["target"]}):
            refs = await self.inspect(subject,[selector])
            if len(refs) == 1:
                ref = refs[0]
                rows.append({"component":selector,"selectors":[selector],"aliases":[],
                    "source":f"{ref['path']}:{ref['line']}","spatial_hint":"","resolution_status":"resolved"})
        return rows


class SuppliedTranscript:
    """Explicit transcript evidence for a selected actual audio; never an STT claim."""
    effects_disabled = True
    def __init__(self, artifacts, *, audio_sha256, transcript_artifact):
        if type(audio_sha256) is not str or not re.fullmatch(r"[a-f0-9]{64}",audio_sha256):
            raise Rejected("Actual selected audio digest required")
        self.artifacts,self.audio_sha256 = artifacts,audio_sha256
        self.transcript_artifact = decode_json(canonical(transcript_artifact))

    async def transcribe(self, audio, reference):
        if type(audio) is not bytes or hashlib.sha256(audio).hexdigest() != self.audio_sha256 or reference.get("content_hash") != self.audio_sha256:
            raise Rejected("Supplied transcript belongs to another audio")
        value = decode_json(await self.artifacts.read(self.transcript_artifact))
        if (type(value) is not dict or set(value) != {"schema","audio_sha256","transcript","words","audio_offset_ms"}
                or value["schema"] != "frank.supplied-audio-transcript.v1" or value["audio_sha256"] != self.audio_sha256):
            raise Rejected("Explicit supplied transcript evidence required")
        return {n:value[n] for n in ("transcript","words","audio_offset_ms")} | {
            "provenance":{"kind":"supplied-transcript-for-audio","artifact":self.transcript_artifact,"audio_sha256":self.audio_sha256}}


class DurableSimulatedIntents:
    """Real durable local recording; external status/note operations stay simulated."""
    effects_disabled = True
    def __init__(self, journal):
        self.journal = journal
        with journal.connection() as db:
            db.execute("CREATE TABLE IF NOT EXISTS local_review_intents (identity TEXT PRIMARY KEY,body BLOB NOT NULL)")

    async def record(self, binding, operation, payload):
        Binding.read(binding)
        if operation not in {"review.status","vault.daily-note"}:
            raise Rejected("Unsupported simulated intent")
        body = canonical({"binding":binding,"operation":operation,"payload":payload,
                          "simulation":True,"external_send_count":0,"native_authority":False})
        key = digest({"binding":binding,"operation":operation})
        with self.journal.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            prior = db.execute("SELECT body FROM local_review_intents WHERE identity=?",(key,)).fetchone()
            if prior and bytes(prior[0]) != body:
                raise Rejected("Simulated intent changed")
            if not prior:
                if db.execute("SELECT count(*) FROM local_review_intents").fetchone()[0] >= 128:
                    raise Rejected("Simulated intent capacity exhausted")
                db.execute("INSERT INTO local_review_intents VALUES (?,?)",(key,body))
        return {"simulation":True,"recorded":True,"intent_digest":hashlib.sha256(body).hexdigest()}
