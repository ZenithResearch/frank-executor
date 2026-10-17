"""Closed frozen process resources with explicit source or installed provenance."""
from __future__ import annotations

import base64
import hashlib
from importlib import metadata
from pathlib import Path, PurePosixPath
import sysconfig

from frank_executor.model import Rejected


RUNTIME_DISTRIBUTION = "process-runtime"
RUNTIME_VERSION = "0.1.0"
RESOURCE_SHA256 = {
    "personal-review-v1.json": "76b9c3f8481f0269dd3e30d45bda605c37abace8f3dceb5a617cf7eb3a642994",
    "personal-review-v1.compiled.json": "6af2a1dd9a1331c371703ff41da770c76bfb63ff6ba8a80e56ef8a783d2dceda",
    "personal-review-v1.md": "fdf04090ffa98b82c56af69cc9c947675c8f48a7c8c4897eb897f6c166b865dc",
    "development-sop-v1.json": "05449a8f1757b630cf08121b0849fb3c056932713218f0043747f3eaa62d078d",
    "development-sop-v1.compiled.json": "f99798f8306073446fed6847af1abd9da249c372a97dd6a330d791436081b6fd",
    "development-sop-v1.md": "aacb8f845a2410af2bb85e44fb80331c65eb008e9fbb10a3ca051b5cb1fbd318",
    "personal-review-v1.migration.json": "d5d6df4b9b6a8b352d9918a93d1d8528572e611f158c7caf49a756d9587496f3",
    "personal-review-legacy.md": "257b5ccb6d7add490500983cf2c85b8157cbf919373bcb8199e2ff82fa7d829b",
}


def _record_parts(record):
    # RECORD paths may lead with ../../../share in the supported wheel scheme.
    # Reject internal aliases before filtering ANY record, so a second spelling
    # cannot hide the same module/resource from the unique-record count. This is
    # lexical inspection of metadata's path representation, not extra file I/O.
    # Leading parents belong only to this distribution's supported data area;
    # ../site-packages/module is otherwise another hidden module spelling.
    raw = str(record)
    parts = raw.split("/")
    index = 0
    while index < len(parts) and parts[index] == "..":
        index += 1
    if (not raw or raw.startswith("/") or "\\" in raw or "\x00" in raw or
            index == len(parts) or any(part in {"", ".", ".."} for part in parts[index:]) or
            (index > 0 and
             parts[index:index + 3] != ["share", RUNTIME_DISTRIBUTION, "resources"])):
        raise Rejected("Installed Runtime noncanonical RECORD alias")
    return tuple(parts)


def _one_record(records, relative, *, module=False):
    parts = PurePosixPath(relative).parts
    canonical = [(record, _record_parts(record)) for record in records]
    matches = [record for record, received in canonical
               if (received == parts if module else received[-len(parts):] == parts)]
    if len(matches) != 1:
        raise Rejected("Installed Runtime record missing or duplicated")
    return matches[0]


def _read_record(distribution, record, expected_path, *, expected_sha256=None):
    try:
        path = Path(distribution.locate_file(record))
        if not path.is_file() or path.is_symlink():
            raise Rejected("Installed Runtime record missing or unsafe")
        if path.resolve(strict=True) != expected_path:
            raise Rejected("Installed Runtime record root mismatch")
        raw = path.read_bytes()
    except OSError as exc:
        raise Rejected("Installed Runtime record missing or unsafe") from exc
    digest = hashlib.sha256(raw).digest()
    record_hash = record.hash
    if (record_hash is None or record_hash.mode != "sha256" or
            record_hash.value != base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii") or
            type(record.size) is not int or record.size != len(raw)):
        raise Rejected("Installed Runtime RECORD hash or size mismatch")
    value = digest.hex()
    if expected_sha256 is not None and value != expected_sha256:
        raise Rejected("Frozen process resource hash mismatch")
    return raw, {"origin": str(expected_path), "record": str(record), "bytes": len(raw),
                 "sha256": value, "record_hash_algorithm": record_hash.mode,
                 "record_hash_value": record_hash.value, "record_size": record.size}


def load_process_resources(fixtures, resource_sha256, *, runtime_module_file,
                           require_installed=False):
    """Return bytes actually consumed and provenance before any provider startup.

    Installed verification supports the documented wheel-only interpreter/venv
    data scheme. Distribution RECORD ownership and sysconfig data-root identity
    are both required; external fixtures can never supply installed resources.
    This is cooperative file provenance, not a package signature or authority.
    """
    if resource_sha256 != RESOURCE_SHA256:
        raise Rejected("Frozen process resource manifest mismatch")
    if not require_installed:
        content, origins = {}, {}
        root = Path(fixtures).resolve(strict=True)
        for name, expected in RESOURCE_SHA256.items():
            try:
                path = root / name
                raw = path.read_bytes()
            except OSError as exc:
                raise Rejected("Frozen process resource missing") from exc
            if hashlib.sha256(raw).hexdigest() != expected:
                raise Rejected("Frozen process resource hash mismatch")
            content[name] = raw
            origins[name] = {"origin": str(path.resolve(strict=True)), "bytes": len(raw),
                             "sha256": expected}
        return content, {"mode": "source_fixtures", "root": str(root),
                         "installed_distribution": None, "resources": origins}
    try:
        distribution = metadata.distribution(RUNTIME_DISTRIBUTION)
    except metadata.PackageNotFoundError as exc:
        raise Rejected("Installed Runtime distribution missing") from exc
    if (distribution.metadata.get("Name") != RUNTIME_DISTRIBUTION or
            distribution.version != RUNTIME_VERSION):
        raise Rejected("Installed Runtime distribution identity mismatch")
    records = list(distribution.files or ())
    module_record = _one_record(records, "process_runtime/__init__.py", module=True)
    try:
        module_path = Path(runtime_module_file).resolve(strict=True)
        data_root = Path(sysconfig.get_path("data")).resolve(strict=True)
    except (OSError, TypeError) as exc:
        raise Rejected("Installed Runtime origin missing") from exc
    # The imported module must be owned by this exact selected distribution.
    _, module_origin = _read_record(distribution, module_record, module_path)
    bundle_root = data_root / "share" / RUNTIME_DISTRIBUTION / "resources"
    content, origins = {}, {}
    for name, expected in RESOURCE_SHA256.items():
        group = "sources" if name == "personal-review-legacy.md" else "processes"
        relative = f"share/{RUNTIME_DISTRIBUTION}/resources/{group}/{name}"
        record = _one_record(records, relative)
        raw, origin = _read_record(distribution, record, bundle_root / group / name,
                                   expected_sha256=expected)
        content[name], origins[name] = raw, origin
    return content, {"mode": "installed_distribution_resources", "root": str(bundle_root),
                     "data_root": str(data_root), "installed_distribution": {
                         "name": RUNTIME_DISTRIBUTION, "version": distribution.version,
                         "module": module_origin}, "resources": origins}
