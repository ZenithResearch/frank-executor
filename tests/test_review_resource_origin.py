"""Resource-origin regressions; synthetic layouts are NOT installed-wheel evidence.

SOURCE PREPARATION ONLY. No test in this module has been imported or executed
for the source packet. These fakes exercise distribution/resource provenance,
not actual wheel installation, provider execution or production qualification.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import shutil
from types import SimpleNamespace

import pytest

from frank_executor.model import Rejected
from frank_review_adapter import resource_origin, verify_main


FIXTURES = Path(__file__).parent / "fixtures" / "independent-review"


@dataclass
class Record:
    path: str
    hash: object
    size: int

    def __str__(self):
        return self.path


def record_for(path, base):
    raw = path.read_bytes()
    value = base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).rstrip(b"=").decode("ascii")
    return Record(os.path.relpath(path, base), SimpleNamespace(mode="sha256", value=value), len(raw))


class Distribution:
    """Fixture-only distribution protocol; never claimed as a real wheel."""
    def __init__(self, base):
        self.base = base
        self.metadata = {"Name": "process-runtime"}
        self.version = "0.1.0"
        self.files = []

    def locate_file(self, record):
        return self.base / str(record)


@pytest.fixture
def layout(tmp_path, monkeypatch):
    tmp_path = tmp_path.resolve()
    data = tmp_path / "synthetic-interpreter"
    site = data / "lib" / "python3.12" / "site-packages"
    module = site / "process_runtime" / "__init__.py"
    module.parent.mkdir(parents=True)
    module.write_bytes(b"# PUBLIC SYNTHETIC MODULE RECORD; NOT IMPORTED.\n")
    dist = Distribution(site)
    dist.files.append(record_for(module, site))
    bundle = data / "share" / "process-runtime" / "resources"
    resources = {}
    for name in resource_origin.RESOURCE_SHA256:
        group = "sources" if name == "personal-review-legacy.md" else "processes"
        path = bundle / group / name
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(FIXTURES / name, path)
        resources[name] = path
        dist.files.append(record_for(path, site))
    external = tmp_path / "external-comparison-fixtures"
    external.mkdir()
    for name in ["manifest.json", "inputs.json", "legacy-comparison.json",
                 *resource_origin.RESOURCE_SHA256]:
        shutil.copyfile(FIXTURES / name, external / name)
    monkeypatch.setattr(resource_origin.metadata, "distribution", lambda name: dist if name == "process-runtime" else None)
    monkeypatch.setattr(resource_origin.sysconfig, "get_path", lambda name: str(data) if name == "data" else None)
    return SimpleNamespace(data=data, site=site, module=module, distribution=dist,
                           bundle=bundle, resources=resources, fixtures=external)


def load(layout, **changes):
    options = {"runtime_module_file": layout.module, "require_installed": True}
    options.update(changes)
    return resource_origin.load_process_resources(
        layout.fixtures, dict(resource_origin.RESOURCE_SHA256), **options)


def resource_record(layout, name):
    matches = [record for record in layout.distribution.files if str(record).endswith("/" + name)]
    assert len(matches) == 1
    return matches[0]


def assert_valid_installed_layout(layout):
    content, origin = load(layout)
    assert set(content) == set(resource_origin.RESOURCE_SHA256)
    assert origin["mode"] == "installed_distribution_resources"
    assert origin["root"] == str(layout.bundle)
    assert origin["data_root"] == str(layout.data)
    assert origin["installed_distribution"]["name"] == "process-runtime"
    assert origin["installed_distribution"]["version"] == "0.1.0"
    assert origin["installed_distribution"]["module"]["origin"] == str(layout.module)
    for name, raw in content.items():
        proof = origin["resources"][name]
        assert raw == layout.resources[name].read_bytes()
        assert proof["origin"] == str(layout.resources[name])
        assert proof["sha256"] == resource_origin.RESOURCE_SHA256[name]
        assert proof["bytes"] == proof["record_size"] == len(raw)
        assert proof["record_hash_algorithm"] == "sha256"
    return content, origin


def test_installed_layout_reads_exact_owned_bundle_and_ignores_external_process_copies(layout):
    expected, _ = assert_valid_installed_layout(layout)
    for name in resource_origin.RESOURCE_SHA256:
        (layout.fixtures / name).write_bytes(b"TAMPERED EXTERNAL COPY; NOT EXECUTION INPUT")
    content, _ = assert_valid_installed_layout(layout)
    assert content == expected


@pytest.mark.parametrize("field,value", [("Name", "other-runtime"), ("version", "0.2.0")])
def test_wrong_distribution_identity_denies_after_own_valid_control(layout, field, value):
    assert_valid_installed_layout(layout)
    if field == "Name":
        layout.distribution.metadata[field] = value
    else:
        layout.distribution.version = value
    with pytest.raises(Rejected, match="^Installed Runtime distribution identity mismatch$"):
        load(layout)


def test_missing_distribution_denies_without_external_fallback(layout, monkeypatch):
    assert_valid_installed_layout(layout)
    def missing(name):
        raise resource_origin.metadata.PackageNotFoundError(name)
    monkeypatch.setattr(resource_origin.metadata, "distribution", missing)
    with pytest.raises(Rejected, match="^Installed Runtime distribution missing$"):
        load(layout)


@pytest.mark.parametrize("variant", ["missing", "duplicate", "absent-inventory"])
def test_missing_or_duplicate_distribution_record_denies(layout, variant):
    assert_valid_installed_layout(layout)
    record = resource_record(layout, "personal-review-v1.json")
    if variant == "missing":
        layout.distribution.files.remove(record)
    elif variant == "duplicate":
        layout.distribution.files.append(record)
    else:
        layout.distribution.files = None
    with pytest.raises(Rejected, match="^Installed Runtime record missing or duplicated$"):
        load(layout)


def test_module_record_must_match_the_imported_runtime_origin(layout, tmp_path):
    assert_valid_installed_layout(layout)
    foreign = tmp_path / "other" / "site-packages" / "process_runtime" / "__init__.py"
    foreign.parent.mkdir(parents=True)
    foreign.write_bytes(layout.module.read_bytes())
    with pytest.raises(Rejected, match="^Installed Runtime record root mismatch$"):
        load(layout, runtime_module_file=foreign)


def move_resource_record_to_foreign_root(layout, tmp_path, name):
    record = resource_record(layout, name)
    group = "sources" if name == "personal-review-legacy.md" else "processes"
    foreign = tmp_path.resolve() / "share" / "process-runtime" / "resources" / group / name
    foreign.parent.mkdir(parents=True, exist_ok=True)
    foreign.write_bytes(layout.resources[name].read_bytes())
    replacement = record_for(foreign, layout.site)
    # Keep this wrong-root fixture lexically eligible, with exact bytes/RECORD
    # metadata. It must reach the root guard rather than the alias guard.
    assert resource_origin._record_parts(replacement)[:7] == (
        "..", "..", "..", "..", "share", "process-runtime", "resources")
    assert foreign.read_bytes() == layout.resources[name].read_bytes()
    assert foreign.resolve(strict=True) != layout.resources[name].resolve(strict=True)
    layout.distribution.files[layout.distribution.files.index(record)] = replacement


def test_coherent_foreign_resource_record_denies_even_with_exact_bytes_and_hash(layout, tmp_path):
    assert_valid_installed_layout(layout)
    move_resource_record_to_foreign_root(layout, tmp_path, "personal-review-v1.json")
    with pytest.raises(Rejected, match="^Installed Runtime record root mismatch$"):
        load(layout)


@pytest.mark.parametrize("name", ["personal-review-v1.json", "personal-review-v1.compiled.json",
                                  "development-sop-v1.json", "development-sop-v1.compiled.json"])
def test_required_packaged_file_missing_denies_without_external_fallback(layout, name):
    assert_valid_installed_layout(layout)
    layout.resources[name].unlink()
    assert (layout.fixtures / name).is_file()
    with pytest.raises(Rejected, match="^Installed Runtime record missing or unsafe$"):
        load(layout)


@pytest.mark.parametrize("refresh_record", [False, True])
def test_tampered_packaged_bytes_denied_by_record_or_frozen_pin(layout, refresh_record):
    assert_valid_installed_layout(layout)
    name = "development-sop-v1.compiled.json"
    path = layout.resources[name]
    record = resource_record(layout, name)
    path.write_bytes(path.read_bytes() + b"\n")
    if refresh_record:
        layout.distribution.files[layout.distribution.files.index(record)] = record_for(path, layout.site)
    expected = "Frozen process resource hash mismatch" if refresh_record else "Installed Runtime RECORD hash or size mismatch"
    with pytest.raises(Rejected, match="^" + expected + "$"):
        load(layout)


@pytest.mark.parametrize("variant", ["hash-value", "hash-algorithm", "no-hash", "size", "boolean-size"])
def test_tampered_record_metadata_denies_after_valid_control(layout, variant):
    assert_valid_installed_layout(layout)
    record = resource_record(layout, "personal-review-v1.json")
    if variant == "hash-value":
        record.hash.value = "wrong"
    elif variant == "hash-algorithm":
        record.hash.mode = "md5"
    elif variant == "no-hash":
        record.hash = None
    elif variant == "size":
        record.size += 1
    else:
        record.size = True
    with pytest.raises(Rejected, match="^Installed Runtime RECORD hash or size mismatch$"):
        load(layout)


def test_external_manifest_cannot_repin_frozen_resources(layout):
    assert_valid_installed_layout(layout)
    changed = dict(resource_origin.RESOURCE_SHA256)
    changed["personal-review-v1.json"] = "0" * 64
    with pytest.raises(Rejected, match="^Frozen process resource manifest mismatch$"):
        resource_origin.load_process_resources(layout.fixtures, changed,
            runtime_module_file=layout.module, require_installed=True)


def test_source_mode_preserves_explicit_fixture_origin_without_distribution_claim(layout, monkeypatch):
    assert_valid_installed_layout(layout)
    def not_installed(name):
        raise AssertionError("Source mode must not select an installed distribution")
    monkeypatch.setattr(resource_origin.metadata, "distribution", not_installed)
    content, origin = load(layout, require_installed=False)
    assert origin["mode"] == "source_fixtures"
    assert origin["installed_distribution"] is None
    assert origin["root"] == str(layout.fixtures)
    for name, raw in content.items():
        assert raw == (layout.fixtures / name).read_bytes()
        assert origin["resources"][name]["origin"] == str(layout.fixtures / name)


def installed_module_paths(layout, monkeypatch):
    # Protocol fixture only: code remains source-imported. This is NOT evidence
    # of actual installed module execution; a real wheel run remains required.
    import frank_executor
    import frank_review_adapter
    import process_runtime
    import process_runtime_client
    for module in [frank_executor, frank_review_adapter, process_runtime_client]:
        monkeypatch.setattr(module, "__file__", str(layout.site / module.__name__ / "__init__.py"))
    monkeypatch.setattr(process_runtime, "__file__", str(layout.module))


@pytest.mark.parametrize("variant,expected", [
    ("missing-draft", "Installed Runtime record missing or unsafe"),
    ("missing-compiled", "Installed Runtime record missing or unsafe"),
    ("tampered", "Installed Runtime RECORD hash or size mismatch"),
    ("wrong-root", "Installed Runtime record root mismatch"),
    ("wrong-distribution", "Installed Runtime distribution identity mismatch"),
    ("module-origin", "Installed Runtime record root mismatch"),
    ("record-metadata", "Installed Runtime RECORD hash or size mismatch"),
    ("duplicate", "Installed Runtime record missing or duplicated"),
])
def test_verify_rejects_invalid_installed_bundle_before_socket_or_provider(
        layout, tmp_path, monkeypatch, variant, expected):
    assert_valid_installed_layout(layout)
    installed_module_paths(layout, monkeypatch)
    if variant == "missing-draft":
        layout.resources["personal-review-v1.json"].unlink()
    elif variant == "missing-compiled":
        layout.resources["development-sop-v1.compiled.json"].unlink()
    elif variant == "tampered":
        layout.resources["development-sop-v1.json"].write_bytes(b"tampered")
    elif variant == "wrong-root":
        move_resource_record_to_foreign_root(layout, tmp_path, "personal-review-v1.json")
    elif variant == "wrong-distribution":
        layout.distribution.metadata["Name"] = "unrelated"
    elif variant == "module-origin":
        import process_runtime
        foreign = layout.site / "foreign_runtime" / "__init__.py"
        foreign.parent.mkdir()
        foreign.write_bytes(layout.module.read_bytes())
        monkeypatch.setattr(process_runtime, "__file__", str(foreign))
    elif variant == "record-metadata":
        resource_record(layout, "personal-review-v1.json").hash.value = "wrong"
    else:
        layout.distribution.files.append(resource_record(layout, "personal-review-v1.json"))
    starts = []
    def forbidden(*args, **kwargs):
        starts.append(True)
        raise AssertionError("Socket/provider boundary crossed before resource rejection")
    monkeypatch.setattr(verify_main.socket, "socket", forbidden)
    monkeypatch.setattr(verify_main.subprocess, "Popen", forbidden)
    with pytest.raises(Rejected, match="^" + expected + "$"):
        verify_main.verify(layout.fixtures, tmp_path / "verification", require_installed=True)
    assert starts == []


def test_verify_consumes_installed_drafts_and_compiled_snapshots_before_startup(
        layout, tmp_path, monkeypatch):
    assert_valid_installed_layout(layout)
    installed_module_paths(layout, monkeypatch)
    for name in ["personal-review-v1.json", "personal-review-v1.compiled.json",
                 "development-sop-v1.json", "development-sop-v1.compiled.json"]:
        (layout.fixtures / name).write_bytes(b"NOT JSON; MUST NOT BE EXECUTED OR COMPILED")
    class BoundaryReached(Exception):
        pass
    starts = []
    def boundary(*args, **kwargs):
        starts.append("socket")
        raise BoundaryReached("Valid installed bytes passed both real compile_draft comparisons")
    def no_provider(*args, **kwargs):
        raise AssertionError("No provider is started by this synthetic test")
    monkeypatch.setattr(verify_main.socket, "socket", boundary)
    monkeypatch.setattr(verify_main.subprocess, "Popen", no_provider)
    with pytest.raises(BoundaryReached):
        verify_main.verify(layout.fixtures, tmp_path / "verification", require_installed=True)
    assert starts == ["socket"]


def reject_before_startup(layout, directory, monkeypatch, expected, *, module_file=None):
    """Invalid current-origin data must deny before compile/socket/provider."""
    installed_module_paths(layout, monkeypatch)
    import process_runtime
    from process_runtime import compiler
    if module_file is not None:
        monkeypatch.setattr(process_runtime, "__file__", str(module_file))
    starts = []
    def forbidden(*args, **kwargs):
        starts.append(True)
        raise AssertionError("Compile/socket/provider boundary crossed before origin rejection")
    monkeypatch.setattr(compiler, "compile_draft", forbidden)
    monkeypatch.setattr(verify_main.socket, "socket", forbidden)
    monkeypatch.setattr(verify_main.subprocess, "Popen", forbidden)
    with pytest.raises(Rejected, match="^" + expected + "$"):
        verify_main.verify(layout.fixtures, directory, require_installed=True)
    assert starts == []


@pytest.mark.parametrize("kind,duplicate", [("module", False), ("module", True),
                                          ("module-leading-parent", False),
                                          ("module-leading-parent", True),
                                          ("resource", False), ("resource", True)])
def test_noncanonical_record_alias_cannot_hide_ownership(layout, tmp_path, monkeypatch,
                                                        kind, duplicate):
    assert_valid_installed_layout(layout)
    if kind in {"module", "module-leading-parent"}:
        original = next(record for record in layout.distribution.files
                        if str(record) == "process_runtime/__init__.py")
        alias = ("process_runtime/../process_runtime/__init__.py" if kind == "module" else
                 "../site-packages/process_runtime/__init__.py")
    else:
        original = resource_record(layout, "personal-review-v1.json")
        assert str(original).startswith("../../../share/")
        alias = str(original).replace("/processes/", "/processes/../processes/")
    added = Record(alias, original.hash, original.size)
    assert layout.distribution.locate_file(added).resolve(strict=True) == (
        layout.distribution.locate_file(original).resolve(strict=True))
    if duplicate:
        layout.distribution.files.append(added)
    else:
        layout.distribution.files[layout.distribution.files.index(original)] = added
    reject_before_startup(layout, tmp_path / "verification", monkeypatch,
                          "Installed Runtime noncanonical RECORD alias")


@pytest.mark.parametrize("kind", ["module", "resource"])
def test_installed_current_origin_leaf_symlink_denies(layout, tmp_path, monkeypatch, kind):
    assert_valid_installed_layout(layout)
    selected = layout.module if kind == "module" else layout.resources["personal-review-v1.json"]
    target = (tmp_path / "module-leaf-target" / "site-packages" / "process_runtime" / "__init__.py"
              if kind == "module" else tmp_path / "resource-public-target")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(selected.read_bytes())
    selected.unlink()
    selected.symlink_to(target)
    assert selected.is_symlink() and selected.read_bytes() == target.read_bytes()
    if kind == "module":
        assert "site-packages" in selected.resolve(strict=True).parts
    reject_before_startup(layout, tmp_path / "verification", monkeypatch,
                          "Installed Runtime record missing or unsafe")


@pytest.mark.parametrize("placement", ["outside-bundle", "inside-bundle"])
def test_resource_ancestor_alias_cannot_change_anchored_origin(layout, tmp_path, monkeypatch,
                                                             placement):
    assert_valid_installed_layout(layout)
    original = layout.bundle / "processes"
    target = (tmp_path / "foreign-processes" if placement == "outside-bundle"
              else layout.bundle / "other-processes")
    original.rename(target)
    original.symlink_to(target, target_is_directory=True)
    assert original.is_symlink()
    # All eight file bytes and all RECORD metadata remain exactly valid; the
    # denial is the anchored current pathname, not missing or corrupt content.
    for name, path in layout.resources.items():
        assert hashlib.sha256(path.read_bytes()).hexdigest() == resource_origin.RESOURCE_SHA256[name]
    reject_before_startup(layout, tmp_path / "verification", monkeypatch,
                          "Installed Runtime record root mismatch")


@pytest.mark.parametrize("destination", ["same-root", "foreign-root", "broken-root"])
def test_sysconfig_root_alias_reports_resolved_origin_or_denies(layout, tmp_path, monkeypatch,
                                                               destination):
    assert_valid_installed_layout(layout)
    alias = tmp_path / "selected-data-root-alias"
    if destination == "same-root":
        alias.symlink_to(layout.data, target_is_directory=True)
        monkeypatch.setattr(resource_origin.sysconfig, "get_path", lambda name: str(alias))
        content, origin = load(layout)
        assert set(content) == set(resource_origin.RESOURCE_SHA256)
        assert origin["data_root"] == str(layout.data.resolve(strict=True))
        assert origin["root"] == str(layout.bundle.resolve(strict=True))
        assert all(proof["origin"] == str(layout.resources[name].resolve(strict=True))
                   for name, proof in origin["resources"].items())
        return
    target = tmp_path / "different-data-root"
    if destination == "foreign-root":
        # A valid public data bundle exists there too; exact distribution/root
        # association, not absence or byte/hash corruption, must reject it.
        shutil.copytree(layout.bundle, target / "share" / "process-runtime" / "resources")
        expected = "Installed Runtime record root mismatch"
    else:
        assert not target.exists()
        expected = "Installed Runtime origin missing"
    alias.symlink_to(target, target_is_directory=True)
    monkeypatch.setattr(resource_origin.sysconfig, "get_path", lambda name: str(alias))
    reject_before_startup(layout, tmp_path / "verification", monkeypatch, expected)


def test_module_ancestor_alias_is_current_resolved_origin_not_historical_attestation(
        layout, tmp_path, monkeypatch):
    assert_valid_installed_layout(layout)
    original = layout.module.parent
    actual = tmp_path / "alternate-module-origin" / "site-packages" / "process_runtime"
    actual.parent.mkdir(parents=True)
    original.rename(actual)
    original.symlink_to(actual, target_is_directory=True)
    content, origin = load(layout)
    assert set(content) == set(resource_origin.RESOURCE_SHA256)
    assert origin["installed_distribution"]["module"]["origin"] == str(
        (actual / "__init__.py").resolve(strict=True))
    # This current module-record agreement does not attest what an earlier
    # import read. A different current origin must still reject, even with the
    # same public bytes and a pathname containing site-packages.
    other = layout.site / "different_current_runtime" / "__init__.py"
    other.parent.mkdir()
    other.write_bytes((actual / "__init__.py").read_bytes())
    reject_before_startup(layout, tmp_path / "verification", monkeypatch,
                          "Installed Runtime record root mismatch", module_file=other)
