from __future__ import annotations
from .model import Actor, Rejected, identity


class Registry:
    """Core only knows the versioned plugin protocol and explicitly enabled IDs."""

    def __init__(self, configuration, factories):
        if (
            set(configuration) != {"schema", "integrations", "actors"}
            or configuration["schema"] != "frank.integrations.v1"
        ):
            raise Rejected("Unsupported integration configuration")
        self.adapters = {}
        self.actors = {}
        seen = set()
        if not isinstance(configuration["integrations"], list) or not isinstance(
            configuration["actors"], list
        ):
            raise Rejected("Integration and actor configuration must be arrays")
        for entry in configuration["integrations"]:
            if (
                set(entry) != {"id", "plugin", "enabled", "config"}
                or type(entry["enabled"]) is not bool
            ):
                raise Rejected("Malformed integration configuration")
            identifier = identity(entry["id"])
            if identifier in seen:
                raise Rejected("Duplicate integration identity")
            seen.add(identifier)
            if not entry["enabled"]:
                continue
            if identifier in self.adapters or entry["plugin"] not in factories:
                raise Rejected("Unknown or duplicate enabled integration")
            adapter = factories[entry["plugin"]](identifier, entry["config"])
            if (
                adapter.contract_version != "frank.integration.v1"
                or adapter.integration_id != identifier
            ):
                raise Rejected("Incompatible integration adapter")
            self.adapters[identifier] = adapter
        for raw in configuration["actors"]:
            if set(raw) != {"actor_id", "integration_id", "capabilities", "resources", "route"}:
                raise Rejected("Malformed actor configuration")
            for key in ("capabilities", "resources"):
                if (
                    not isinstance(raw[key], list)
                    or any(not isinstance(item, str) for item in raw[key])
                    or len(set(raw[key])) != len(raw[key])
                ):
                    raise Rejected("Actor declarations must be unique string arrays")
            actor = Actor(
                raw["actor_id"],
                raw["integration_id"],
                tuple(raw["capabilities"]),
                tuple(raw["resources"]),
                raw["route"],
            )
            if actor.actor_id in self.actors or actor.integration_id not in self.adapters:
                raise Rejected("Actor refers to missing or ambiguous integration")
            self.actors[actor.actor_id] = actor

    async def connect(self):
        opened = []
        try:
            for adapter in self.adapters.values():
                opened.append(adapter)
                await adapter.connect()
                if not {"send", "receive", "health", "cancel", "reconcile"}.issubset(
                    await adapter.capabilities()
                ):
                    raise Rejected("Integration lacks required protocol capabilities")
                if (await adapter.health()).get("ready") is not True:
                    raise Rejected("Integration is not ready")
        except Exception:
            for adapter in reversed(opened):
                try:
                    await adapter.close()
                except Exception:
                    pass
            raise

    async def close(self):
        for adapter in reversed(list(self.adapters.values())):
            await adapter.close()

    def match(self, capabilities, resources):
        explanations = {
            actor.actor_id: actor.missing(capabilities, resources) for actor in self.actors.values()
        }
        eligible = [
            self.actors[key]
            for key, missing in sorted(explanations.items())
            if not any(missing.values())
        ]
        return eligible, explanations

    def adapter(self, actor):
        return self.adapters[actor.integration_id]
