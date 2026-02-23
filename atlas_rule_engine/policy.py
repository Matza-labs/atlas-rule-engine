"""Policy-as-Code engine — customizable governance rules.

Enterprises define policies (YAML) that specify which rules must pass
and what score thresholds are required. The PolicyEngine evaluates
a graph + findings against a policy and returns a pass/fail verdict.
"""

from __future__ import annotations

import logging
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field

from atlas_sdk.models.findings import Finding
from atlas_sdk.models.graph import CICDGraph

logger = logging.getLogger(__name__)


def _new_id() -> str:
    return str(uuid4())


class PolicyRule(BaseModel):
    """A single rule requirement within a policy."""

    rule_id: str
    max_allowed: int = 0  # max findings for this rule before fail
    severity_threshold: str = "medium"  # min severity to count


class PolicyThresholds(BaseModel):
    """Score thresholds for a policy."""

    max_complexity: float = 80.0
    max_fragility: float = 70.0
    min_maturity: float = 30.0


class Policy(BaseModel):
    """A complete policy definition."""

    id: str = Field(default_factory=_new_id)
    name: str
    description: str = ""
    required_rules: list[PolicyRule] = Field(default_factory=list)
    thresholds: PolicyThresholds = Field(default_factory=PolicyThresholds)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Policy:
        """Create a Policy from a parsed YAML dict."""
        rules = [PolicyRule(**r) for r in data.get("required_rules", [])]
        thresholds = PolicyThresholds(**data.get("thresholds", {}))
        return cls(
            name=data.get("name", "Unnamed Policy"),
            description=data.get("description", ""),
            required_rules=rules,
            thresholds=thresholds,
        )


class PolicyViolation(BaseModel):
    """A single policy violation."""

    rule_id: str = ""
    metric: str = ""
    message: str
    actual: float | int = 0
    limit: float | int = 0


class PolicyResult(BaseModel):
    """Result of evaluating a graph against a policy."""

    policy_name: str
    passed: bool = True
    violations: list[PolicyViolation] = Field(default_factory=list)
    checked_rules: int = 0
    checked_thresholds: int = 3


class PolicyEngine:
    """Evaluates a CICDGraph against a Policy.

    Usage:
        engine = PolicyEngine(policy)
        result = engine.evaluate(graph, findings, scores)
    """

    def __init__(self, policy: Policy) -> None:
        self._policy = policy

    def evaluate(
        self,
        graph: CICDGraph,
        findings: list[Finding],
        scores: Any,
    ) -> PolicyResult:
        """Run all policy checks."""
        result = PolicyResult(policy_name=self._policy.name)
        result.checked_rules = len(self._policy.required_rules)

        # Check required rules
        findings_by_rule: dict[str, int] = {}
        for f in findings:
            findings_by_rule[f.rule_id] = findings_by_rule.get(f.rule_id, 0) + 1

        for req in self._policy.required_rules:
            count = findings_by_rule.get(req.rule_id, 0)
            if count > req.max_allowed:
                result.violations.append(PolicyViolation(
                    rule_id=req.rule_id,
                    message=f"Rule '{req.rule_id}' has {count} finding(s), max allowed is {req.max_allowed}",
                    actual=count,
                    limit=req.max_allowed,
                ))

        # Check score thresholds
        t = self._policy.thresholds
        if hasattr(scores, "complexity_score") and scores.complexity_score > t.max_complexity:
            result.violations.append(PolicyViolation(
                metric="complexity",
                message=f"Complexity {scores.complexity_score:.1f} exceeds max {t.max_complexity}",
                actual=scores.complexity_score,
                limit=t.max_complexity,
            ))
        if hasattr(scores, "fragility_score") and scores.fragility_score > t.max_fragility:
            result.violations.append(PolicyViolation(
                metric="fragility",
                message=f"Fragility {scores.fragility_score:.1f} exceeds max {t.max_fragility}",
                actual=scores.fragility_score,
                limit=t.max_fragility,
            ))
        if hasattr(scores, "maturity_score") and scores.maturity_score < t.min_maturity:
            result.violations.append(PolicyViolation(
                metric="maturity",
                message=f"Maturity {scores.maturity_score:.1f} below min {t.min_maturity}",
                actual=scores.maturity_score,
                limit=t.min_maturity,
            ))

        result.passed = len(result.violations) == 0

        logger.info(
            "Policy '%s': %s (%d violation(s))",
            self._policy.name,
            "PASSED" if result.passed else "FAILED",
            len(result.violations),
        )
        return result
