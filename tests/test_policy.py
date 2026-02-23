"""Tests for the Policy-as-Code engine."""

import pytest

from atlas_sdk.enums import NodeType, Severity
from atlas_sdk.models.findings import Finding
from atlas_sdk.models.graph import CICDGraph
from atlas_sdk.models.nodes import PipelineNode, JobNode

from atlas_rule_engine.policy import (
    Policy, PolicyEngine, PolicyRule, PolicyThresholds, PolicyResult
)


def _make_graph():
    g = CICDGraph(name="Test Pipeline")
    g.add_node(PipelineNode(name="CI"))
    g.add_node(JobNode(name="Build"))
    return g


class MockScores:
    complexity_score = 45.0
    fragility_score = 30.0
    maturity_score = 60.0


class TestPolicyEngine:

    def test_policy_passes_when_all_clear(self):
        policy = Policy(
            name="Standard",
            required_rules=[PolicyRule(rule_id="no-timeout", max_allowed=0)],
            thresholds=PolicyThresholds(max_complexity=80, max_fragility=70, min_maturity=30),
        )
        engine = PolicyEngine(policy)
        result = engine.evaluate(_make_graph(), [], MockScores())

        assert result.passed is True
        assert len(result.violations) == 0

    def test_policy_fails_on_rule_violation(self):
        policy = Policy(
            name="Strict",
            required_rules=[PolicyRule(rule_id="no-timeout", max_allowed=0)],
        )
        findings = [
            Finding(rule_id="no-timeout", title="No timeout", description="",
                    severity=Severity.MEDIUM),
        ]
        engine = PolicyEngine(policy)
        result = engine.evaluate(_make_graph(), findings, MockScores())

        assert result.passed is False
        assert len(result.violations) == 1
        assert result.violations[0].rule_id == "no-timeout"

    def test_policy_fails_on_score_threshold(self):
        policy = Policy(
            name="Quality Gate",
            thresholds=PolicyThresholds(max_complexity=30),  # will fail
        )
        engine = PolicyEngine(policy)
        result = engine.evaluate(_make_graph(), [], MockScores())

        assert result.passed is False
        assert any(v.metric == "complexity" for v in result.violations)

    def test_policy_from_dict(self):
        data = {
            "name": "Production Policy",
            "description": "All production pipelines",
            "required_rules": [
                {"rule_id": "no-timeout", "max_allowed": 0},
                {"rule_id": "unpinned-images", "max_allowed": 0},
            ],
            "thresholds": {"max_complexity": 60, "min_maturity": 50},
        }
        policy = Policy.from_dict(data)
        assert policy.name == "Production Policy"
        assert len(policy.required_rules) == 2
        assert policy.thresholds.max_complexity == 60

    def test_policy_allows_some_findings(self):
        policy = Policy(
            name="Relaxed",
            required_rules=[PolicyRule(rule_id="no-cache", max_allowed=2)],
        )
        findings = [
            Finding(rule_id="no-cache", title="No cache", description="", severity=Severity.LOW),
            Finding(rule_id="no-cache", title="No cache 2", description="", severity=Severity.LOW),
        ]
        engine = PolicyEngine(policy)
        result = engine.evaluate(_make_graph(), findings, MockScores())

        assert result.passed is True  # 2 findings, max_allowed=2
