"""One owner-pinned review workflow over public Runtime calls; no DAG scheduler."""
from __future__ import annotations

import asyncio
import base64
from dataclasses import dataclass
import os
from pathlib import Path

from process_runtime_client import command_envelope
from .model import Rejected, UnknownOutcome, canonical, decode_json, digest, identity
from .local_review_profile import closed, path, pin, artifact
from .wallet_authority import _pinned_file
from .local_review_cleanup import sync_directory
from frank_review_adapter.local_capture import OPERATIONS, private_directory, read_private
from frank_review_adapter.local_ports import RuntimeArtifacts


@dataclass(frozen=True)
class Workflow:
    profile: object
    selected: Path
    sha256: str
    raw: bytes
    draft_raw: bytes
    compiled_raw: bytes

    @property
    def value(self):
        return decode_json(self.raw)

    @property
    def compiled(self):
        return decode_json(self.compiled_raw)

    @property
    def process_pin(self):
        return {"process_id":"personal-review-v1", "process_version":self.value["process"]["process_version"],
                "compilation_hash":digest(self.compiled)}

    def current(self):
        self.profile.current()
        if _pinned_file(self.selected,self.sha256,65536) != self.raw:
            raise Rejected("Workflow selection changed")
        for key, expected in (("draft",self.draft_raw),("compiled",self.compiled_raw)):
            item = self.value["process"][key]
            if _pinned_file(path(item["path"]),item["sha256"],1048576) != expected:
                raise Rejected("Selected process source changed")
        for item in self.value["artifacts"]:
            body = _pinned_file(path(item["path"]),item["artifact"]["content_hash"],1048576)
            if len(body) != item["artifact"]["byte_length"]:
                raise Rejected("Selected input length changed")
        private_directory(path(self.value["export"]["root"]))

    def request_id(self, tag):
        return "local-" + digest({"workflow":self.sha256,"tag":tag})[:48]


def load_workflow(profile, selected, expected):
    raw = _pinned_file(path(selected),pin(expected),65536)
    value = closed(decode_json(raw),("schema","profile_sha256","run_id","process","inputs","artifacts","export"))
    if (value["schema"] != "frank.local-review.workflow.v1"
            or value["profile_sha256"] != profile.config_sha256
            or value["run_id"] not in profile.composition["run_ids"]):
        raise Rejected("Workflow is outside the selected profile")
    identity(value["run_id"])
    process = closed(value["process"],("draft","compiled","process_version"))
    identity(process["process_version"])
    bodies = {}
    for key in ("draft","compiled"):
        item = closed(process[key],("path","sha256"))
        bodies[key] = _pinned_file(path(item["path"]),pin(item["sha256"]),1048576)
    draft, compiled = (decode_json(bodies[key]) for key in ("draft","compiled"))
    if (type(draft) is not dict or type(compiled) is not dict
            or draft.get("schema") != "process.draft.v1" or compiled.get("schema") != "process.compiled.v1"
            or draft.get("process_id") != "personal-review-v1" or compiled.get("process_id") != "personal-review-v1"
            or type(compiled.get("steps")) is not list or len(compiled["steps"]) != 9
            or any(type(s) is not dict or type(s.get("capabilities")) is not list
                   or type(s.get("outputs")) is not dict for s in compiled["steps"])):
        raise Rejected("Selected personal-review process required")
    if type(value["inputs"]) is not dict or type(value["artifacts"]) is not list or not 1 <= len(value["artifacts"]) <= 16:
        raise Rejected("Bounded explicit workflow inputs required")
    references = {}
    for item in value["artifacts"]:
        closed(item,("path","artifact"));path(item["path"]);artifact(item["artifact"])
        ref = item["artifact"]
        if ref["content_hash"] in references or ref["byte_length"] == 0:
            raise Rejected("Unique nonempty selected input artifacts required")
        references[ref["content_hash"]] = ref
    selected_refs = [value["inputs"].get("audio_asset"),value["inputs"].get("events_asset"),
                     profile.composition["transcript"]["artifact"]]
    selected_refs += [row["artifact"] for rows in profile.composition["snapshots"].values() for row in rows]
    if any(type(ref) is not dict or references.get(ref.get("content_hash")) != ref for ref in selected_refs):
        raise Rejected("Workflow must retain every selected audio/event/transcript/source artifact")
    if value["inputs"]["audio_asset"]["content_hash"] != profile.composition["transcript"]["audio_sha256"]:
        raise Rejected("Workflow audio differs from selected transcript")
    export = closed(value["export"],("root","step_id","output"))
    root = path(export["root"]);identity(export["step_id"])
    choices = [s for s in compiled["steps"] if s.get("step_id") == export["step_id"]]
    if (len(choices) != 1 or "review.write_review" not in choices[0].get("capabilities",[])
            or export["output"] != "review_note" or choices[0].get("outputs",{}).get("review_note") != {"kind":"artifact"}
            or root.is_relative_to(path(profile.composition["capture_root"]))):
        raise Rejected("Export must select the committed review-note artifact")
    workflow = Workflow(profile,path(selected),expected,raw,bodies["draft"],bodies["compiled"])
    workflow.current()
    return workflow


async def saved_command(workflow, executor, tag, operation, payload, expected_version):
    gateway, journal = executor.gateway, executor.journal
    request_id = workflow.request_id(tag)
    envelope = command_envelope(operation,request_id=request_id,expected_version=expected_version,payload=payload)
    gateway.validate(envelope,"command")
    try:
        saved = journal.saved_command(request_id)
    except Rejected:
        return await gateway.send(envelope)
    if saved["body"] != canonical(envelope).decode():
        raise Rejected("Retained workflow command changed")
    if saved["state"] != "observed" or saved["response"] is None:
        raise UnknownOutcome("Saved workflow command requires explicit resume")
    response = decode_json(saved["response"])
    gateway.validate(response,"result")
    if any(response[n] != envelope[n] for n in ("request_id","operation","resource")):
        raise Rejected("Retained workflow response changed")
    return response


async def published(workflow, gateway):
    actual = await gateway.query("version.get",{"process_version":workflow.process_pin["process_version"]})
    if actual.get("pin") != workflow.process_pin or canonical(actual.get("compiled")) != canonical(workflow.compiled):
        raise Rejected("Actual published process differs from owner-selected source")
    return actual["compiled"]


async def run_snapshot(workflow, gateway):
    await published(workflow,gateway)
    value = await gateway.query("run.get",{"run_id":workflow.value["run_id"]})
    if (value.get("run_id") != workflow.value["run_id"] or value.get("pin") != workflow.process_pin
            or value.get("inputs") != workflow.value["inputs"] or type(value.get("steps")) is not list
            or len(value["steps"]) != 9 or {s["step_id"] for s in value["steps"]} != {s["step_id"] for s in workflow.compiled["steps"]}):
        raise Rejected("Actual run differs from selected workflow")
    return value


async def initialize(workflow, executor):
    await asyncio.to_thread(workflow.current)
    value, gateway = workflow.value, executor.gateway
    artifacts = RuntimeArtifacts(gateway)
    for index,item in enumerate(value["artifacts"]):
        ref = item["artifact"]
        body = await asyncio.to_thread(_pinned_file,path(item["path"]),ref["content_hash"],1048576)
        response = await saved_command(workflow,executor,"artifact-"+str(index),"artifact.put",
            {"artifact":ref,"content_base64":base64.b64encode(body).decode()},None)
        if response.get("result",{}).get("artifact") != ref or await artifacts.read(ref) != body:
            raise Rejected("Runtime input artifact readback changed")
    draft = decode_json(workflow.draft_raw)
    drafted = await saved_command(workflow,executor,"draft","process.draft.put",{"draft":draft,"provenance":{
        "source_id":"personal-review-v1","media_type":"application/json","content_hash":value["process"]["draft"]["sha256"],
        "parser":"explicit-json-v1","uncertainties":[]}},None)
    response = await saved_command(workflow,executor,"publish","process.publish",{"process_id":"personal-review-v1",
        "draft_revision":drafted["result"]["revision"],"version_id":value["process"]["process_version"]},drafted["version"])
    if response.get("result",{}).get("pin") != workflow.process_pin:
        raise Rejected("Published pin differs from selected compiled process")
    await published(workflow,gateway)
    actor = workflow.profile.composition["actor"]
    await saved_command(workflow,executor,"actor","actor.register",{
        "actor_id":actor["actor_id"],"capabilities":actor["capabilities"],"resources":actor["resources"]},None)
    await saved_command(workflow,executor,"run","run.create",{
        "run_id":value["run_id"],"pin":workflow.process_pin,"inputs":value["inputs"]},None)
    actual = await run_snapshot(workflow,gateway)
    return {"schema":"frank.local-review.initialized.v1","run_id":actual["run_id"],"run_state":actual["state"],"pin":actual["pin"]}


def retained_effects(workflow, journal):
    actor = workflow.profile.composition["actor"]
    result = []
    for row in journal.unresolved():
        saved = journal.get(row["effect_key"])
        work = saved["work"]
        if (work["binding"]["run_id"] == workflow.value["run_id"]
                and all(work[n] == actor[n] for n in ("actor_id","integration_id","route"))):
            result.append(row)
    return result


def selected_pending(workflow, journal):
    ids = {workflow.request_id(tag) for tag in ("draft","publish","actor","run")}
    ids.update(workflow.request_id("artifact-"+str(i)) for i in range(len(workflow.value["artifacts"])))
    rows = []
    for row in journal.pending_commands():
        command = decode_json(journal.saved_command(row["request_id"])["body"])
        if command["payload"].get("run_id") == workflow.value["run_id"] or row["request_id"] in ids:
            rows.append(row)
    return rows


async def next_step(workflow, executor, *, lease_ms, wait_seconds):
    if retained_effects(workflow,executor.journal) or selected_pending(workflow,executor.journal):
        raise UnknownOutcome("Retained workflow state requires explicit resume")
    snapshot = await run_snapshot(workflow,executor.gateway)
    if any(s["state"] == "running" for s in snapshot["steps"]):
        raise UnknownOutcome("A current claimed step requires explicit recovery")
    actor = workflow.profile.composition["actor"]["actor_id"]
    work = (await executor.work(actor,limit=100))["work"]
    offered = [w for w in work if w["run_id"] == workflow.value["run_id"]]
    if not offered:
        return {"schema":"frank.local-review.next.v1","run_id":snapshot["run_id"],"run_state":snapshot["state"],"action":"no eligible work"}
    selected = sorted(offered,key=lambda w:w["step_id"])[0]
    if selected.get("pin") != workflow.process_pin:
        raise Rejected("Runtime work pin changed")
    specs = [s for s in workflow.compiled["steps"] if s["step_id"] == selected["step_id"]]
    operations = set(specs[0]["capabilities"]) & OPERATIONS if len(specs) == 1 else set()
    if len(operations) != 1:
        raise Rejected("Published work has no unique canonical review operation")
    request_id = workflow.request_id("claim-"+selected["step_id"]+"-"+str(selected["version"]))
    attempt = await executor.claim(actor,selected,lease_ms=lease_ms,request_id=request_id)
    return await executor.run(attempt,operation=next(iter(operations)),scope="local-review",
                              lease_ms=lease_ms,wait_seconds=wait_seconds)


async def committed_output(workflow, gateway, step):
    identity_fields = {n:step[n] for n in ("step_id","attempt_id")}
    identity_fields["run_id"] = workflow.value["run_id"]
    output = await gateway.query("output.get",identity_fields)
    receipt = await gateway.query("receipt.get",{"receipt_id":output["receipt_id"]})
    actor = workflow.profile.composition["actor"]["actor_id"]
    if (any(output.get(n) != v or receipt.get(n) != v for n,v in identity_fields.items())
            or output.get("fence") != step["fence"] or receipt.get("fence") != step["fence"]
            or output.get("actor_id") != actor or receipt.get("actor_id") != actor
            or output.get("pin") != workflow.process_pin or receipt.get("pin") != workflow.process_pin
            or output.get("output_digest") != digest(output["outputs"])
            or receipt.get("output_digest") != output["output_digest"]
            or receipt.get("input_digest") != output.get("inputs_digest")
            or receipt.get("outcome") != "succeeded" or receipt.get("receipt_id") != output["receipt_id"]):
        raise Rejected("Committed output/receipt correlation changed")
    return output


async def inspect_workflow(workflow, executor):
    run = await run_snapshot(workflow,executor.gateway)
    rows, export_available = [], False
    for step in run["steps"]:
        row = {n:step[n] for n in ("step_id","state","attempt_id","fence")}
        row.update(receipt_id=None,output_digest=None)
        if step["state"] == "succeeded":
            output = await committed_output(workflow,executor.gateway,step)
            row.update(receipt_id=output["receipt_id"],output_digest=output["output_digest"])
            if step["step_id"] == workflow.value["export"]["step_id"]:
                ref = output["outputs"].get(workflow.value["export"]["output"])
                artifact(ref)
                export_available = ref["media_type"] == "text/markdown"
        rows.append(row)
    effects, pending = retained_effects(workflow,executor.journal), selected_pending(workflow,executor.journal)
    try:
        recovery_selection(workflow,executor.journal)
        recoverable = True
    except Rejected:
        recoverable = False
    return {"schema":"frank.local-review.inspection.v1","run_id":run["run_id"],"run_state":run["state"],
        "recoverable":recoverable,"export_available":export_available,"steps":rows,
        "pending_commands":pending,"unresolved_effects":effects}


def export_bytes(root, reference, raw):
    private_directory(root)
    target = root / (reference["content_hash"]+".md")
    try:
        fd = os.open(target,os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,0o600)
    except FileExistsError:
        if read_private(target,1048576) != raw:
            raise Rejected("Existing exported artifact differs")
        return str(target)
    try:
        remaining = raw
        while remaining:
            count = os.write(fd,remaining)
            if count <= 0:
                raise OSError("export short write")
            remaining = remaining[count:]
        os.fsync(fd)
    finally:
        os.close(fd)
    sync_directory(root)
    return str(target)


async def export_workflow(workflow, executor):
    run = await run_snapshot(workflow,executor.gateway)
    selected = [s for s in run["steps"] if s["step_id"] == workflow.value["export"]["step_id"] and s["state"] == "succeeded"]
    if len(selected) != 1:
        raise Rejected("Selected review note has not committed")
    output = await committed_output(workflow,executor.gateway,selected[0])
    ref = output["outputs"].get(workflow.value["export"]["output"])
    artifact(ref)
    if ref["media_type"] != "text/markdown":
        raise Rejected("Selected output is not Markdown")
    raw = await RuntimeArtifacts(executor.gateway).read(ref)
    await asyncio.to_thread(workflow.current)
    exported = await asyncio.to_thread(export_bytes,path(workflow.value["export"]["root"]),ref,raw)
    return {"schema":"frank.local-review.export.v1","run_id":run["run_id"],"path":exported,"artifact":ref,"receipt_id":output["receipt_id"]}


def recovery_selection(workflow, journal, *, renewal=False):
    effects = retained_effects(workflow,journal)
    if len(effects) == 1:
        return {"kind":"effect","effect_key":effects[0]["effect_key"]}
    if effects or renewal:
        raise Rejected("Recovery requires one exact retained effect")
    commands = selected_pending(workflow,journal)
    if len(commands) != 1 or commands[0]["operation"] in {
            "executor.complete","executor.fail","executor.effect.observe"}:
        raise Rejected("Recovery requires one exact nonterminal saved command")
    return {"kind":"command","request_id":commands[0]["request_id"]}
