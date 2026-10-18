"""Explicit owner receipt migration; unit metadata is not Native authority."""
import asyncio
import copy
import hashlib
import json
from pathlib import Path

import pytest

from frank_executor.journal import Journal
from frank_executor.model import Rejected, canonical
from frank_executor.workspace_cli import (
    CleanupUnresolved, Operation, arguments, bind_journal, load_profile, migrate_binding, run,
)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def write(selected, value, mode=0o600):
    missing=[];parent=selected.parent
    while not parent.exists():missing.append(parent);parent=parent.parent
    for parent in reversed(missing):parent.mkdir(mode=0o700)
    selected.write_bytes(value if type(value) is bytes else canonical(value))
    selected.chmod(mode)
    return selected


def selected(path):
    return {"path":str(path), "sha256":sha(path.read_bytes())}


def fixtures(tmp_path):
    tmp_path.chmod(0o700)
    (tmp_path/"data").mkdir(mode=0o700)
    executable=write(tmp_path/"native/castalia-wallet-service", b"inspected unit artifact", 0o500)
    public="ab"*32
    holder={"schema":"castalia.wallet-service-custody-state.v1", "store_id":"a"*32,
        "subject_id":"service:frank-workspace", "purpose":"secs-service-holder-proof.v1",
        "application":"runtime", "state_revision":2, "key_generation":1,
        "key_id":"holder-v1", "public_key_hex":public, "public_key_sha256":sha(bytes.fromhex(public)),
        "state":"active", "created_at":90, "key_created_at":90, "published_at":100,
        "not_before":90, "not_after":999999, "revoked_at":None,
        "previous_state_sha256":"b"*64, "owner_input_sha256":"c"*64}
    issuer={"node_id":"node:workspace-command-issuer", "key_id":"issuer:workspace-command-v1", "public_key_hex":"cd"*32}
    names=[("process.draft.put","processes/","prefix"), ("process.publish","processes/","prefix"),
           ("process.get","processes/","prefix"), ("version.get","versions/","prefix"), ("events.list","events","exact")]
    def generation(generation, start, end, h, predecessor=None):
        base=tmp_path/"authority" if generation==1 else tmp_path/"authority/renewals"/str(generation)
        configs=base/"config"
        pin={"schema":"secs.wallet-current-startup-pin.v2", "store_id":h["store_id"],
            "minimum_state_revision":h["state_revision"], "minimum_key_generation":h["key_generation"],
            "expected_wallet_reference_sha256":str(generation)*64}
        native={"schema":"secs.service-authority-configuration.v1", "wallet_root":str(tmp_path/"authority/wallet"),
            "wallet_observation_pin":pin, "native_root":str(tmp_path/"authority/native"),
            "native_generation":generation, "native_sha256":str(generation+2)*64,
            "issuer_root":str(tmp_path/"authority/command-issuer"), "issuer_node_id":issuer["node_id"],
            "issuer_key_id":issuer["key_id"], "issuer_public_key_hex":issuer["public_key_hex"],
            "journal_root":str(tmp_path/"authority/command-journal"), "maximum_ttl":30,
            "journal_capacity":"local_review_pilot_512"}
        native_path=write(configs/"command-authority.json",native)
        wallet={"schema":"castalia.wallet-service-command.v1", "application":"runtime",
            "native_configuration":str(native_path), "native_configuration_sha256":sha(native_path.read_bytes()),
            "wallet_root":native["wallet_root"], "store_binding":{k:h[k] for k in ("store_id","subject_id","application","purpose")},
            "expected_state":{"state_revision":h["state_revision"], "state_sha256":sha(canonical(h))}}
        wallet["store_binding"]["minimum_revision"]=h["state_revision"]
        wallet_path=write(configs/"wallet-command.json",wallet)
        policy={"schema":"runtime.receiver-policy.v1", "audience":"runtime:v1",
            "keys":[{"key_id":issuer["key_id"], "public_key_hex":issuer["public_key_hex"],
                "status":"active", "production_authority":True, "not_before":start, "not_after":end, "revoked_at":None}],
            "descriptors":[{"operation":"runtime."+n+".v1", "fingerprint":"f"*64, "handler_id":"handler:"+n} for n,_,_ in names],
            "permissions":[{"subject_id":h["subject_id"],"key_id":h["key_id"],"operation":"runtime."+n+".v1",
                "resource":resource,"resource_match":kind,"effect":"allow","active":True,
                "not_before_ms":start*1000,"not_after_ms":end*1000} for n,resource,kind in names],
            "revoked_subject_keys":[]}
        policy_path=write(configs/"runtime-policy.json",policy)
        receiver={"schema":"runtime.receiver-configuration.v1", "audience":policy["audience"],
            "native_verifier":{"executable":str(tmp_path/"native/process-runtime-secs-check"),"sha256":"e"*64},
            "policy_file":str(policy_path)}
        write(configs/"runtime-receiver.json",receiver)
        receipt={"schema":"castalia.wallet-workspace-setup-complete.v1" if generation==1 else "castalia.wallet-workspace-renewal-complete.v1",
            "plan_sha256":str(generation+4)*64, "root":str(tmp_path),"holder":h,
            "native_generation":generation,"native_sha256":native["native_sha256"],"command_issuer":issuer,
            "configuration_hashes":{p.name:sha(p.read_bytes()) for p in configs.iterdir()},
            "not_before":start,"not_after":end,"identity_not_after":h["not_after"],
            "journal_capacity":"local_review_pilot_512","scope":"five authoring/catalog operations in one isolated Runtime store; events are store scoped",
            "activation":False,"service_started":False,"runtime_store_initialized":False,"process_created":False,"run_created":False}
        if predecessor:receipt["previous_complete"]=predecessor
        complete=write(base/"COMPLETE.json",receipt)
        master={"schema":"frank.workspace.v1", "runtime_endpoint":"http://127.0.0.1:8292",
            "journal":str(tmp_path/"data/frank-workspace.db"),"wallet":{"executable":str(executable),
                "executable_sha256":sha(executable.read_bytes()),"configuration":str(wallet_path),
                "configuration_sha256":sha(wallet_path.read_bytes())}}
        master_path=write(tmp_path/("master-"+str(generation)+".json"),master)
        return complete,master_path
    old_receipt,old_master=generation(1,100,1000,holder)
    newer=copy.deepcopy(holder);newer.update(state_revision=3,published_at=1100,
        previous_state_sha256=sha(canonical(holder)),owner_input_sha256="d"*64)
    new_receipt,new_master=generation(2,1100,2000,newer,selected(old_receipt))
    descriptor={"schema":"frank.workspace-migration.v1","previous_configuration":selected(old_master),
        "previous_complete":selected(old_receipt),"renewed_complete":selected(new_receipt)}
    profile=load_profile(str(new_master),sha(new_master.read_bytes()))
    old_profile=load_profile(str(old_master),sha(old_master.read_bytes()))
    journal=Journal(profile.value["journal"]);bind_journal(old_profile,journal)
    return profile,descriptor,journal


def invoke(profile,descriptor):
    return migrate_binding(profile,descriptor,sha(canonical(descriptor)))


def test_explicit_migration_preserves_observed_and_all_existing_rows(tmp_path):
    profile,descriptor,journal=fixtures(tmp_path)
    journal.command({"request_id":"observed","operation":"process.publish","original":"not replayed"})
    journal.command_result("observed",{"original":"old acknowledgement"})
    journal.cursor("retained","17")
    before=journal.saved_command("observed")
    receipt=invoke(profile,descriptor)
    assert receipt["schema"]=="frank.workspace-migration-result.v1" and receipt["commands_preserved"]
    assert not receipt["duplicate"] and receipt["configuration_sha256"]==profile.config_sha256
    assert journal.saved_command("observed")==before and journal.cursor("retained")=="17"
    bind_journal(profile,journal)
    assert invoke(profile,descriptor)=={**receipt,"duplicate":True}
    with journal.connection() as db:assert db.execute("SELECT COUNT(*) FROM workspace_migrations").fetchone()[0]==1


def test_pending_denies_migration_without_altering_original_intent(tmp_path):
    profile,descriptor,journal=fixtures(tmp_path)
    journal.command({"request_id":"unknown","operation":"process.publish","original":"not replayed"})
    before=journal.saved_command("unknown")
    with pytest.raises(Rejected,match="unresolved"):
        invoke(profile,descriptor)
    assert journal.saved_command("unknown")==before
    with journal.connection() as db:
        assert db.execute("SELECT configuration_sha256 FROM workspace_binding").fetchone()[0]==descriptor["previous_configuration"]["sha256"]


@pytest.mark.parametrize("change",["endpoint","journal","executable","executable-pin"])
def test_migration_rejects_composition_retarget_without_changing_binding(tmp_path,change):
    profile,descriptor,journal=fixtures(tmp_path)
    value=profile.value
    if change=="endpoint":value["runtime_endpoint"]="http://127.0.0.1:8293"
    elif change=="journal":value["journal"]=str(tmp_path/"data/other.db")
    elif change=="executable":value["wallet"]["executable"]=str(tmp_path/"other")
    else:value["wallet"]["executable_sha256"]="0"*64
    # Retarget rejection is independent of artifact availability.
    from frank_executor.workspace_cli import Profile
    altered=Profile(profile.selected,sha(canonical(value)),canonical(value))
    with pytest.raises(Rejected):invoke(altered,descriptor)
    with journal.connection() as db:assert db.execute("SELECT configuration_sha256 FROM workspace_binding").fetchone()[0]==descriptor["previous_configuration"]["sha256"]


def update_receipt(descriptor, callback):
    p=Path(descriptor["renewed_complete"]["path"]);value=json.loads(p.read_bytes());callback(value);write(p,value)
    descriptor["renewed_complete"]=selected(p)


@pytest.mark.parametrize("change",["holder-key","holder-store","holder-lineage","issuer","generation","predecessor","window","scope","activation"])
def test_migration_rejects_identity_scope_lineage_and_window_changes(tmp_path,change):
    profile,descriptor,journal=fixtures(tmp_path)
    def mutate(r):
        if change=="holder-key":r["holder"]["public_key_hex"]="ef"*32
        elif change=="holder-store":r["holder"]["store_id"]="e"*32
        elif change=="holder-lineage":r["holder"]["previous_state_sha256"]="0"*64
        elif change=="issuer":r["command_issuer"]["key_id"]="other"
        elif change=="generation":r["native_generation"]=3
        elif change=="predecessor":r["previous_complete"]["sha256"]="0"*64
        elif change=="window":r["not_after"]=r["not_before"]+3601
        elif change=="scope":r["scope"]="extra commands"
        else:r["activation"]=True
    update_receipt(descriptor,mutate)
    with pytest.raises(Rejected):invoke(profile,descriptor)
    with journal.connection() as db:assert db.execute("SELECT configuration_sha256 FROM workspace_binding").fetchone()[0]==descriptor["previous_configuration"]["sha256"]


def test_rehashed_policy_widening_denies_even_with_same_scope_prose(tmp_path):
    profile,descriptor,journal=fixtures(tmp_path)
    rpath=Path(descriptor["renewed_complete"]["path"]);policy=rpath.parent/"config/runtime-policy.json"
    value=json.loads(policy.read_bytes());value["permissions"][0]["resource"]="";write(policy,value)
    update_receipt(descriptor,lambda r:r["configuration_hashes"].update({"runtime-policy.json":sha(policy.read_bytes())}))
    with pytest.raises(Rejected):invoke(profile,descriptor)


def test_migration_requires_existing_exact_bound_journal_and_closed_pinned_evidence(tmp_path):
    profile,descriptor,journal=fixtures(tmp_path)
    wrong=copy.deepcopy(descriptor);wrong["previous_configuration"]["sha256"]="0"*64
    with pytest.raises(Rejected):invoke(profile,wrong)
    wrong=copy.deepcopy(descriptor);wrong["automatic"]=True
    with pytest.raises(Rejected):invoke(profile,wrong)
    Path(journal.path).unlink()
    with pytest.raises(Rejected):invoke(profile,descriptor)
    assert not Path(journal.path).exists()


def test_cli_migration_never_launches_wallet_or_runtime_and_cleanup_blocks_reentry(tmp_path,monkeypatch):
    profile,descriptor,journal=fixtures(tmp_path)
    body=write(tmp_path/"migration.json",descriptor)
    monkeypatch.setattr("subprocess.Popen",lambda *a,**kw:pytest.fail("migration launched subprocess"))
    monkeypatch.setattr("frank_executor.workspace_cli.RuntimeClient",lambda *a,**kw:pytest.fail("migration opened HTTP"))
    _,args=arguments(["migrate-binding","--config",str(profile.selected),"--config-sha256",profile.config_sha256,
        "--input",str(body),"--input-sha256",sha(body.read_bytes())])
    op=Operation(profile,"get")
    with pytest.raises(CleanupUnresolved):asyncio.run(run(args))
    op.finish()
    assert asyncio.run(run(args))["configuration_sha256"]==profile.config_sha256
    assert not (tmp_path/"data/frank-workspace-cleanup.json").exists()


def test_renewal_readiness_is_read_only_and_accepts_exact_old_snapshot(tmp_path,monkeypatch):
    from frank_executor.workspace_cli import renewal_ready
    profile,descriptor,journal=fixtures(tmp_path)
    old=descriptor["previous_configuration"]
    previous=load_profile(old["path"],old["sha256"])
    snapshot=write(tmp_path/"old-master-snapshot.json",previous.raw)
    previous=load_profile(str(snapshot),old["sha256"])
    before=Path(journal.path).read_bytes()
    monkeypatch.setattr(Journal,"__init__",lambda *a,**kw:pytest.fail("readiness configured journal"))
    monkeypatch.setattr("subprocess.Popen",lambda *a,**kw:pytest.fail("readiness launched child"))
    receipt=renewal_ready(previous)
    assert receipt["ready"] and receipt["journal"]=="bound" and receipt["pending_commands"]==0
    assert Path(journal.path).read_bytes()==before
    assert not (tmp_path/"data/frank-workspace-cleanup.json").exists()
    with pytest.raises(Rejected,match="bound"):renewal_ready(profile)
    Path(journal.path).unlink()
    assert renewal_ready(previous)["journal"]=="absent"
    assert not Path(journal.path).exists()


@pytest.mark.parametrize("state",["pending","unknown","observed-without-response","effect","cleanup"])
def test_renewal_readiness_denies_unresolved_without_clearing_it(tmp_path,state):
    from frank_executor.workspace_cli import renewal_ready
    profile,descriptor,journal=fixtures(tmp_path);old=descriptor["previous_configuration"]
    previous=load_profile(old["path"],old["sha256"])
    if state=="cleanup":
        write(tmp_path/"data/frank-workspace-cleanup.json",{"retained":True})
    elif state=="effect":
        journal.delivery("existing",{"retained":"effect"})
    else:
        journal.command({"request_id":"pending","retained":"exact"})
        if state!="pending":
            with journal.connection() as db:
                db.execute("UPDATE commands SET state=?",("observed" if state=="observed-without-response" else state,))
    before=Path(journal.path).read_bytes()
    with pytest.raises((Rejected,CleanupUnresolved)):renewal_ready(previous)
    assert Path(journal.path).read_bytes()==before
    if state=="cleanup":assert (tmp_path/"data/frank-workspace-cleanup.json").exists()


def test_readiness_cli_accepts_no_mutation_payload(tmp_path):
    profile,descriptor,journal=fixtures(tmp_path);old=descriptor["previous_configuration"]
    argv=["check-renewal","--config",old["path"],"--config-sha256",old["sha256"]]
    _,args=arguments(argv)
    assert asyncio.run(run(args))["ready"]
    with pytest.raises(SystemExit):arguments(argv+["--input","/extra","--input-sha256","a"*64])


@pytest.mark.parametrize("binding",["absent","malformed"])
def test_rejected_migration_preserves_unbound_or_malformed_database_bytes(tmp_path,binding):
    import sqlite3
    from frank_executor.journal import APP_ID
    profile,descriptor,journal=fixtures(tmp_path)
    selected=Path(journal.path);selected.unlink()
    db=sqlite3.connect(selected)
    try:
        db.execute("PRAGMA application_id="+str(APP_ID))
        db.execute("CREATE TABLE owner_history(retained TEXT)")
        db.execute("INSERT INTO owner_history VALUES ('exact original')")
        if binding=="malformed":db.execute("CREATE TABLE workspace_binding(unexpected TEXT)")
        db.commit()
    finally:db.close()
    selected.chmod(0o600)
    before=selected.read_bytes()
    with pytest.raises((Rejected,sqlite3.Error)):invoke(profile,descriptor)
    assert selected.read_bytes()==before
    db=sqlite3.connect(selected)
    try:
        assert db.execute("SELECT retained FROM owner_history").fetchall()==[("exact original",)]
        assert db.execute("SELECT 1 FROM sqlite_master WHERE name='commands'").fetchone() is None
    finally:db.close()


@pytest.mark.parametrize("kind",["command","delivery"])
@pytest.mark.parametrize("action",["readiness","migration"])
def test_null_retained_state_cannot_bypass_zero_unresolved_precondition(tmp_path,kind,action):
    from frank_executor.workspace_cli import renewal_ready
    profile,descriptor,journal=fixtures(tmp_path)
    with journal.connection() as db:
        if kind=="command":
            db.execute("DROP TABLE commands")
            db.execute("CREATE TABLE commands(request_id TEXT PRIMARY KEY,body TEXT,digest TEXT,state TEXT,response TEXT)")
            db.execute("INSERT INTO commands VALUES ('null-state','{}',?,NULL,'{}')",(sha(b'{}'),))
        else:
            db.execute("DROP TABLE deliveries")
            db.execute("CREATE TABLE deliveries(effect_key TEXT PRIMARY KEY,work TEXT,digest TEXT,state TEXT,result TEXT)")
            db.execute("INSERT INTO deliveries VALUES ('null-state','{}',?,NULL,'{}')",(sha(b'{}'),))
    before=Path(journal.path).read_bytes()
    with pytest.raises(Rejected,match="unresolved"):
        if action=="migration":invoke(profile,descriptor)
        else:
            old=descriptor["previous_configuration"]
            renewal_ready(load_profile(old["path"],old["sha256"]))
    assert Path(journal.path).read_bytes()==before
