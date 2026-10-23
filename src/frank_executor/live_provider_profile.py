"""Closed production composition for one owner-selected Hermes provider."""
from __future__ import annotations

from dataclasses import dataclass
from importlib.resources import files
import json
from pathlib import Path
from urllib.parse import urlsplit

from .connector_capture import ConnectorCapture, ConnectorPolicy
from .connector_result_producer import ConnectorResultProducer
from .hermes_subprocess import HermesSubprocessFactory
from .model import Rejected, decode_json, digest, identity
from .native_results import FileReceiverPolicy, NativeResultVerifier, NativeSecSHelper
from .wallet_authority import WalletCallAuthority, _pinned_file


BRAND_CAPABILITIES = (
    "brand.intake.qualify",
    "brand.package.assemble",
    "brand.research.market",
    "brand.research.visual",
    "brand.review.roundtable",
    "brand.strategy.develop",
    "brand.system.develop",
)
BRAND_RESOURCES = ("brand.research", "brand.workspace")
MOCK_EXECUTION_LABEL = "ANIMA TRANSPORT TEST - MOCK OUTPUT - NOT BRAND WORK"


def closed(value, fields):
    if type(value) is not dict or set(value) != set(fields):
        raise Rejected("Unsupported live-provider profile shape")
    return value


def pin(value):
    if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise Rejected("Exact live-provider SHA256 required")
    return value


def path(value):
    result = Path(value)
    if type(value) is not str or not result.is_absolute() or ".." in result.parts:
        raise Rejected("Absolute live-provider path required")
    return result


def command(value, connector=False):
    fields = {"executable", "executable_sha256", "configuration", "configuration_sha256"}
    if connector:
        fields |= {"authority_configuration", "authority_configuration_sha256"}
    closed(value, fields)
    for name in ("executable_sha256", "configuration_sha256"):
        pin(value[name])
    for name in ("executable", "configuration"):
        path(value[name])
    if connector:
        path(value["authority_configuration"]); pin(value["authority_configuration_sha256"])
    return value


@dataclass(frozen=True)
class LiveProviderProfile:
    config_path: Path
    config_sha256: str
    master_bytes: bytes
    composition_bytes: bytes

    @property
    def master(self): return decode_json(self.master_bytes)

    @property
    def composition(self): return decode_json(self.composition_bytes)

    @property
    def actor(self): return self.composition["actor"]

    @property
    def execution(self):
        return self.composition.get("execution", {"mode": "production"})

    def current(self):
        master = self.master
        if (_pinned_file(self.config_path, self.config_sha256, 65536) != self.master_bytes
                or _pinned_file(path(master["composition"]["path"]),
                                master["composition"]["sha256"], 65536) != self.composition_bytes):
            raise Rejected("Live-provider composition changed")

    def native_sources(self):
        self.current(); master, actor = self.master, self.actor
        authority = WalletCallAuthority(**master["wallet"])
        helper = NativeSecSHelper(master["verifier"]["executable"], master["verifier"]["sha256"])
        verifier = NativeResultVerifier(helper, FileReceiverPolicy(master["verifier"]["policy"]))
        authority.check_available()
        verifier.require_native_sources(actor_binding=(actor["actor_id"], actor["integration_id"], actor["route"]))
        factory = HermesSubprocessFactory(**master["hermes"])
        return authority, verifier, factory


def load_profile(config_path, config_sha256):
    selected, expected = path(config_path), pin(config_sha256)
    raw = _pinned_file(selected, expected, 65536)
    master = closed(decode_json(raw), ("schema", "composition", "wallet", "result", "verifier", "hermes"))
    if master["schema"] != "frank.live-provider.config.v1":
        raise Rejected("Unsupported live-provider profile")
    closed(master["composition"], ("path", "sha256")); pin(master["composition"]["sha256"])
    body = _pinned_file(path(master["composition"]["path"]), master["composition"]["sha256"], 65536)
    value = decode_json(body)
    required = {"schema", "runtime_endpoint", "journal", "actor", "run_ids",
                "provider", "producer_artifact_sha256", "normalizer_sha256",
                "source_manifest_sha256"}
    keys = set(value) if type(value) is dict else set()
    if type(value) is not dict or (keys != required and keys != required | {"execution"}):
        raise Rejected("Unsupported live-provider profile shape")
    if value["schema"] != "frank.live-provider.composition.v1":
        raise Rejected("Unsupported live-provider composition")
    endpoint = urlsplit(value["runtime_endpoint"])
    if (endpoint.scheme != "http" or endpoint.hostname != "127.0.0.1" or endpoint.port is None
            or endpoint.username is not None or endpoint.password is not None
            or endpoint.query or endpoint.fragment or endpoint.path not in ("", "/")):
        raise Rejected("Live provider requires explicit numeric-loopback Runtime")
    journal = path(value["journal"])
    actor = closed(value["actor"], ("actor_id", "integration_id", "route", "capabilities", "resources"))
    for name in ("actor_id", "integration_id", "route"): identity(actor[name])
    if (actor["capabilities"] != list(BRAND_CAPABILITIES)
            or actor["resources"] != list(BRAND_RESOURCES)
            or actor["route"] != "local"):
        raise Rejected("First live provider is limited to the reviewed automated brand profile")
    if (type(value["run_ids"]) is not list or not 1 <= len(value["run_ids"]) <= 16
            or len(set(value["run_ids"])) != len(value["run_ids"])):
        raise Rejected("Finite live-provider runs required")
    for run in value["run_ids"]: identity(run)
    provider = closed(value["provider"], ("model", "toolsets", "routes", "max_iterations"))
    if provider != {"model":"openai-codex/gpt-5.6-sol", "toolsets":[], "routes":["local"], "max_iterations":4}:
        raise Rejected("Unsupported first live-provider selection")
    if "execution" in value:
        execution = closed(value["execution"], ("mode", "label"))
        if execution != {"mode": "mock", "label": MOCK_EXECUTION_LABEL}:
            raise Rejected("Unsupported live-provider execution binding")
    for name in ("producer_artifact_sha256", "normalizer_sha256", "source_manifest_sha256"):
        pin(value[name])
    command(master["wallet"]); command(master["result"], connector=True)
    verifier = closed(master["verifier"], ("executable", "sha256", "policy"))
    path(verifier["executable"]); pin(verifier["sha256"]); path(verifier["policy"])
    hermes = closed(master["hermes"], ("python", "python_sha256", "source_root", "run_agent_sha256",
                                               "hermes_home", "version", "timeout_seconds"))
    for name in ("python", "source_root", "hermes_home"): path(hermes[name])
    pin(hermes["python_sha256"]); pin(hermes["run_agent_sha256"])
    fixed = {selected, path(master["composition"]["path"]), path(verifier["executable"]),
             path(verifier["policy"]), path(master["wallet"]["executable"]), path(master["wallet"]["configuration"]),
             path(master["result"]["executable"]), path(master["result"]["configuration"]),
             path(master["result"]["authority_configuration"])}
    if journal in fixed:
        raise Rejected("Live-provider journal overlaps immutable inputs")
    profile = LiveProviderProfile(selected, expected, raw, body); profile.current(); return profile


def compose(profile):
    from process_runtime_client import RuntimeClient
    from frank_review_adapter.local_ports import RuntimeArtifacts, RuntimeClaims
    from .output_materializer import RuntimeOutputMaterializer
    from .provider_input import RuntimeInputHydrator
    from .executor import Executor
    from .integrations.hermes import HermesAdapter
    from .journal import Journal
    from .registry import Registry
    from .runtime import RuntimeGateway, GeneratedClientAdapter, ContractValidator
    authority, verifier, factory = profile.native_sources()
    value, master, actor = profile.composition, profile.master, profile.actor
    journal = Journal(path(value["journal"]))
    schema = json.loads(files("process_runtime_client").joinpath("runtime-v1.schema.json").read_text())
    gateway = RuntimeGateway(GeneratedClientAdapter(RuntimeClient(value["runtime_endpoint"])),
                             authority, journal, ContractValidator(schema))
    claims = RuntimeClaims(gateway, journal, actor_id=actor["actor_id"],
                           integration_id=actor["integration_id"], route=actor["route"])
    policy = ConnectorPolicy("hermes", actor["integration_id"], actor["actor_id"], actor["route"],
                             digest(value["provider"]), value["producer_artifact_sha256"],
                             value["normalizer_sha256"])
    capture = ConnectorCapture(journal, policy)
    producer = ConnectorResultProducer(capture=capture, claims=claims, verifier=verifier, **master["result"])
    artifacts = RuntimeArtifacts(gateway)
    test_label = (profile.execution["label"]
                  if profile.execution["mode"] == "mock" else None)
    adapter = HermesAdapter(actor["integration_id"], value["provider"], agent_factory=factory,
                            connector_capture=capture, connector_producer=producer,
                            output_materializer=RuntimeOutputMaterializer(
                                artifacts, test_label=test_label),
                            input_hydrator=RuntimeInputHydrator(artifacts))
    registry = Registry({"schema":"frank.integrations.v1", "actors":[actor], "integrations":[{
        "id":actor["integration_id"], "plugin":"hermes-live", "enabled":True, "config":{}}]},
        {"hermes-live":lambda *_:adapter})
    return Executor(gateway, registry, journal, verifier, environment="production"), adapter
