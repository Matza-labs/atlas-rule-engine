"""Tests for the refactor planner system."""

import pytest

from atlas_sdk.enums import NodeType, Severity
from atlas_sdk.models.findings import Finding
from atlas_sdk.models.graph import CICDGraph
from atlas_sdk.models.nodes import PipelineNode, JobNode
from atlas_sdk.models.refactors import RefactorPlan, RefactorSuggestion

from atlas_rule_engine.refactors import REFACTOR_REGISTRY
from atlas_rule_engine.planner import RefactorPlanner


def _make_graph():
    g = CICDGraph(name="Test Pipeline")
    p = PipelineNode(name="CI")
    j = JobNode(name="Build")
    g.add_node(p)
    g.add_node(j)
    return g, j


class TestRefactorModules:

    def test_all_10_rules_have_refactors(self):
        expected = {
            "no-timeout", "no-cache", "sequential-stages", "heavy-shell",
            "unpinned-images", "missing-docs", "secret-exposure",
            "cross-repo-triggers", "artifact-coupling", "no-retry",
        }
        assert set(REFACTOR_REGISTRY.keys()) == expected

    def test_each_refactor_produces_suggestion(self):
        graph, job = _make_graph()
        for rule_id, cls in REFACTOR_REGISTRY.items():
            finding = Finding(
                rule_id=rule_id,
                title=f"Test {rule_id}",
                description="Test finding",
                severity=Severity.MEDIUM,
                affected_node_ids=[job.id],
            )
            refactor = cls()
            suggestion = refactor.suggest(finding, graph)
            assert suggestion is not None, f"No suggestion for {rule_id}"
            assert isinstance(suggestion, RefactorSuggestion)
            assert suggestion.rule_id == rule_id
            assert suggestion.before_snippet != ""
            assert suggestion.after_snippet != ""
            assert suggestion.before_snippet != suggestion.after_snippet

    def test_fix_no_timeout_details(self):
        graph, job = _make_graph()
        finding = Finding(
            rule_id="no-timeout",
            title="No timeout",
            description="Job has no timeout",
            severity=Severity.MEDIUM,
            affected_node_ids=[job.id],
        )
        refactor = REFACTOR_REGISTRY["no-timeout"]()
        suggestion = refactor.suggest(finding, graph)
        assert "timeout" in suggestion.after_snippet
        assert suggestion.risk_level == "low"


class TestRefactorPlanner:

    def test_plan_from_findings(self):
        graph, job = _make_graph()
        findings = [
            Finding(rule_id="no-timeout", title="No timeout", description="",
                    severity=Severity.MEDIUM, affected_node_ids=[job.id]),
            Finding(rule_id="unpinned-images", title="Unpinned", description="",
                    severity=Severity.HIGH, affected_node_ids=[job.id]),
            Finding(rule_id="secret-exposure", title="Secret leak", description="",
                    severity=Severity.CRITICAL, affected_node_ids=[job.id]),
        ]

        planner = RefactorPlanner()
        plan = planner.plan(graph, findings)

        assert isinstance(plan, RefactorPlan)
        assert plan.total_suggestions == 3
        assert plan.name == "Test Pipeline"
        # Low risk first
        assert plan.suggestions[0].risk_level == "low"

    def test_plan_empty_findings(self):
        graph, _ = _make_graph()
        planner = RefactorPlanner()
        plan = planner.plan(graph, [])
        assert plan.total_suggestions == 0

    def test_plan_unknown_rule_skipped(self):
        graph, job = _make_graph()
        findings = [
            Finding(rule_id="unknown-rule", title="Unknown", description="",
                    severity=Severity.LOW, affected_node_ids=[job.id]),
        ]
        planner = RefactorPlanner()
        plan = planner.plan(graph, findings)
        assert plan.total_suggestions == 0
