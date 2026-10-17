from __future__ import annotations
import os
from .model import Rejected
from .registry import Registry
from .integrations.matrix import MatrixAdapter
from .integrations.hermes import HermesAdapter


def check_native_hermes():
    try:
        from run_agent import AIAgent
    except ImportError:
        raise Rejected("Pinned Hermes SDK is not installed") from None
    return AIAgent


def native_hermes_factory(**kwargs):
    return check_native_hermes()(**kwargs)


native_hermes_factory.check_available = check_native_hermes


def environment_secret(reference):
    prefix = "secret:env:"
    if not reference.startswith(prefix):
        raise Rejected("No resolver configured for this secret reference")
    value = os.environ.get(reference[len(prefix) :])
    if not value:
        raise Rejected("Secret reference is unavailable")
    return value


def configured_registry(
    configuration,
    *,
    http_client,
    environment,
    extra_factories=None,
    hermes_factory=native_hermes_factory,
    secret_resolver=environment_secret,
    connector_captures=None,
):
    # Trusted execution composition only. CLI/check-config/health never supply this
    # dependency and their closed external configuration does not enable capture.
    captures = {} if connector_captures is None else dict(connector_captures)
    factories = {
        "frank.matrix.v1": lambda identifier, config: MatrixAdapter(
            identifier,
            config,
            client=http_client,
            secret_resolver=secret_resolver,
            environment=environment,
            connector_capture=captures.get(identifier),
        ),
        "frank.hermes.v1": lambda identifier, config: HermesAdapter(
            identifier, config, agent_factory=hermes_factory,
            connector_capture=captures.get(identifier),
        ),
    }
    for name, factory in (extra_factories or {}).items():
        if name in factories:
            raise Rejected("Plugin cannot replace a pinned built-in adapter")
        factories[name] = factory
    registry = Registry(configuration, factories)
    if any(identifier not in registry.adapters or not isinstance(registry.adapters[identifier], (MatrixAdapter, HermesAdapter))
           for identifier in captures):
        raise Rejected("Capture dependency has no enabled built-in connector")
    return registry
