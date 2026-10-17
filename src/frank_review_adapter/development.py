"""Bounded non-service fixture SOP plugin; this is not a repository editor."""
from __future__ import annotations

import ast

from frank_executor.model import decode_json

from .adapter import ReviewAdapter
from .handlers import Handlers
from .ports import ReviewFailure


class DevelopmentHandlers(Handlers):
    def __init__(self, ports):
        super().__init__(ports)
        self.operations = {"development." + name: getattr(self, name.replace("-", "_"))
                           for name in ("scope", "implement", "unit-tests", "contract-tests", "review", "package")}

    async def scope(self, inputs, binding):
        snapshot = decode_json(await self.read(inputs["repository_snapshot"]))
        if inputs["change_request"] != "Make add(a, b) return a + b." or snapshot != {"calc.py": "def add(a, b):\n    return a - b\n"}:
            raise ReviewFailure("unsupported_development_fixture")
        return {"plan": await self.write({"change_request": inputs["change_request"], "source": inputs["repository_snapshot"],
                    "verification": ["integer addition cases", "public two-argument function contract"], "qualification": "synthetic bounded fixture"})}

    async def implement(self, inputs, binding):
        plan = decode_json(await self.read(inputs["plan"]))
        snapshot = decode_json(await self.read(inputs["repository_snapshot"]))
        if plan["source"] != inputs["repository_snapshot"] or snapshot.get("calc.py") != "def add(a, b):\n    return a - b\n":
            raise ReviewFailure("development_plan_mismatch")
        return {"patch": await self.write({"before": snapshot["calc.py"], "after": snapshot["calc.py"].replace("a - b", "a + b"), "path": "calc.py"})}

    async def unit_tests(self, inputs, binding):
        patch = decode_json(await self.read(inputs["patch"]))
        tree = ast.parse(patch["after"])
        function = tree.body[0]
        expression = function.body[0].value
        safe = (isinstance(function, ast.FunctionDef) and len(function.body) == 1 and isinstance(function.body[0], ast.Return)
                and isinstance(expression, ast.BinOp) and isinstance(expression.op, ast.Add)
                and isinstance(expression.left, ast.Name) and expression.left.id == "a"
                and isinstance(expression.right, ast.Name) and expression.right.id == "b")
        cases = [{"a": a, "b": b, "actual": a + b if safe else None, "expected": expected}
                 for a, b, expected in ((2, 3, 5), (-3, 3, 0), (0, 4, 4))]
        passed = all(case["actual"] == case["expected"] for case in cases)
        if not passed:
            raise ReviewFailure("development_unit_tests_failed")
        return {"passed": passed, "report": await self.write({"cases": cases, "passed": passed, "mode": "AST-whitelisted computation; no exec"})}

    async def contract_tests(self, inputs, binding):
        patch = decode_json(await self.read(inputs["patch"]))
        tree = ast.parse(patch["after"])
        passed = (len(tree.body) == 1 and isinstance(tree.body[0], ast.FunctionDef) and tree.body[0].name == "add"
                  and [arg.arg for arg in tree.body[0].args.args] == ["a", "b"] and not tree.body[0].args.defaults)
        if not passed:
            raise ReviewFailure("development_contract_tests_failed")
        return {"passed": passed, "report": await self.write({"passed": passed, "public_signature": "add(a, b)", "qualification": "synthetic fixture"})}

    async def review(self, inputs, binding):
        unit = decode_json(await self.read(inputs["unit_report"]))
        contract = decode_json(await self.read(inputs["contract_report"]))
        approved = inputs["unit_passed"] is True and inputs["contract_passed"] is True and unit["passed"] is True and contract["passed"] is True
        if not approved:
            raise ReviewFailure("development_review_not_approved")
        await self.read(inputs["patch"])
        return {"approved": approved, "review": await self.write({"approved": approved, "unit": inputs["unit_report"],
                   "contract": inputs["contract_report"], "qualification": "automated synthetic fixture decision; no human review claim"})}

    async def package(self, inputs, binding):
        review = decode_json(await self.read(inputs["review"]))
        if inputs["approved"] is not True or review["approved"] is not True:
            raise ReviewFailure("development_review_not_approved")
        await self.read(inputs["patch"])
        return {"bundle": await self.write({"patch": inputs["patch"], "review": inputs["review"], "external_effects": "disabled"})}


class DevelopmentAdapter(ReviewAdapter):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.handlers = DevelopmentHandlers(self.ports)
