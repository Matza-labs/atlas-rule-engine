"""Unit tests for atlas-rule-engine."""

import pytest

from atlas_sdk.enums import DocType, EdgeType, NodeType, Platform, Severity
from atlas_sdk.models.edges import Edge
from atlas_sdk.models.graph import CICDGraph
from atlas_sdk.models.nodes import (
    ArtifactNode,
    ContainerImageNode,
    DocFileNode,
    EnvironmentNode,
    JobNode,
    PipelineNode,
    SecretRefNode,
    StageNode,
    StepNode,
)

from atlas_rule_engine.engine import RuleEngine
from atlas_rule_engine.catalog.no_timeout import NoTimeoutRule
from atlas_rule_engine.catalog.no_cache import NoCacheRule
from atlas_rule_engine.catalog.sequential_stages import SequentialStagesRule
from atlas_rule_engine.catalog.heavy_shell import HeavyShellRule
from atlas_rule_engine.catalog.unpinned_images import UnpinnedImagesRule
from atlas_rule_engine.catalog.missing_docs import MissingDocsRule
from atlas_rule_engine.catalog.cross_repo_triggers import CrossRepoTriggersRule
from atlas_rule_engine.catalog.no_retry import NoRetryRule


# ── Test helpers ──────────────────────────────────────────────────────

def _simple_graph() -> CICDGraph:
    """Graph with a pipeline + 3 stages + 1 downstream job."""
    g = CICDGraph(name="test")
    p = PipelineNode(name="build-pipeline", platform=Platform.JENKINS)
    s1 = StageNode(name="Build", order=0)
    s2 = StageNode(name="Test", order=1)
    s3 = StageNode(name="Deploy", order=2)
    j = JobNode(name="downstream-notify")

    g.add_node(p)
    g.add_node(s1)
    g.add_node(s2)
    g.add_node(s3)
    g.add_node(j)

    g.add_edge(Edge(edge_type=EdgeType.CALLS, source_node_id=p.id, target_node_id=s1.id))
    g.add_edge(Edge(edge_type=EdgeType.CALLS, source_node_id=p.id, target_node_id=s2.id))
    g.add_edge(Edge(edge_type=EdgeType.CALLS, source_node_id=p.id, target_node_id=s3.id))
    g.add_edge(Edge(edge_type=EdgeType.TRIGGERS, source_node_id=p.id, target_node_id=j.id))
    return g


# ── Engine tests ──────────────────────────────────────────────────────

class TestRuleEngine:
    def test_engine_loads_all_rules(self):
        engine = RuleEngine()
        assert engine.rule_count == 10

    def test_engine_runs_on_empty_graph(self):
        engine = RuleEngine()
        findings = engine.run(CICDGraph(name="empty"))
        # Should not crash, may produce some findings (e.g. missing docs)
        assert isinstance(findings, list)

    def test_engine_produces_findings(self):
        engine = RuleEngine()
        findings = engine.run(_simple_graph())
        assert len(findings) > 0
        # Every finding should have a rule_id
        assert all(f.rule_id for f in findings)

    def test_engine_custom_rules(self):
        engine = RuleEngine(rules=[NoTimeoutRule()])
        assert engine.rule_count == 1


# ── Individual rule tests ─────────────────────────────────────────────

class TestNoTimeoutRule:
    def test_finds_no_timeout(self):
        rule = NoTimeoutRule()
        graph = _simple_graph()
        findings = rule.evaluate(graph)
        assert len(findings) >= 1
        assert all(f.rule_id == "no-timeout" for f in findings)

    def test_passes_with_timeout(self):
        rule = NoTimeoutRule()
        g = CICDGraph(name="test")
        p = PipelineNode(name="build", metadata={"timeout_minutes": 30})
        g.add_node(p)
        findings = rule.evaluate(g)
        assert len(findings) == 0


class TestNoCacheRule:
    def test_finds_no_cache(self):
        rule = NoCacheRule()
        findings = rule.evaluate(_simple_graph())
        assert len(findings) == 1
        assert findings[0].rule_id == "no-cache"

    def test_passes_with_cache(self):
        rule = NoCacheRule()
        g = CICDGraph(name="test")
        p = PipelineNode(name="build", metadata={"cache": "pip"})
        g.add_node(p)
        findings = rule.evaluate(g)
        assert len(findings) == 0


class TestSequentialStagesRule:
    def test_passes_under_threshold(self):
        rule = SequentialStagesRule()
        findings = rule.evaluate(_simple_graph())  # only 3 stages
        assert len(findings) == 0

    def test_finds_excessive_stages(self):
        rule = SequentialStagesRule()
        g = CICDGraph(name="test")
        p = PipelineNode(name="big-pipeline")
        g.add_node(p)
        for i in range(7):
            s = StageNode(name=f"Stage-{i}", order=i)
            g.add_node(s)
            g.add_edge(Edge(edge_type=EdgeType.CALLS, source_node_id=p.id, target_node_id=s.id))
        findings = rule.evaluate(g)
        assert len(findings) == 1


class TestHeavyShellRule:
    def test_passes_under_threshold(self):
        rule = HeavyShellRule()
        g = CICDGraph(name="test")
        g.add_node(StepNode(name="sh: make", command="make", shell="sh"))
        findings = rule.evaluate(g)
        assert len(findings) == 0

    def test_finds_heavy_shell(self):
        rule = HeavyShellRule()
        g = CICDGraph(name="test")
        for i in range(6):
            g.add_node(StepNode(name=f"sh: cmd{i}", command=f"cmd{i}", shell="sh"))
        findings = rule.evaluate(g)
        assert len(findings) == 1


class TestUnpinnedImagesRule:
    def test_finds_unpinned(self):
        rule = UnpinnedImagesRule()
        g = CICDGraph(name="test")
        g.add_node(ContainerImageNode(name="python:latest", tag="latest"))
        findings = rule.evaluate(g)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_passes_pinned(self):
        rule = UnpinnedImagesRule()
        g = CICDGraph(name="test")
        g.add_node(ContainerImageNode(name="python:3.11.7", tag="3.11.7"))
        findings = rule.evaluate(g)
        assert len(findings) == 0


class TestMissingDocsRule:
    def test_finds_missing(self):
        rule = MissingDocsRule()
        g = CICDGraph(name="test")
        findings = rule.evaluate(g)
        assert len(findings) == 1
        assert "5 missing" in findings[0].title

    def test_passes_full_docs(self):
        rule = MissingDocsRule()
        g = CICDGraph(name="test")
        for dt in [DocType.README, DocType.ARCHITECTURE, DocType.RUNBOOK, DocType.SECURITY_POLICY, DocType.CODEOWNERS]:
            g.add_node(DocFileNode(name=dt.value, path=dt.value, doc_type=dt))
        findings = rule.evaluate(g)
        assert len(findings) == 0


class TestCrossRepoTriggersRule:
    def test_finds_trigger(self):
        rule = CrossRepoTriggersRule()
        findings = rule.evaluate(_simple_graph())
        assert len(findings) >= 1
        assert any("downstream" in f.title.lower() for f in findings)


class TestNoRetryRule:
    def test_finds_deploy_without_retry(self):
        rule = NoRetryRule()
        g = CICDGraph(name="test")
        g.add_node(StageNode(name="deploy-prod", order=0))
        findings = rule.evaluate(g)
        assert len(findings) == 1

    def test_passes_with_retry(self):
        rule = NoRetryRule()
        g = CICDGraph(name="test")
        g.add_node(StageNode(name="deploy-prod", order=0, metadata={"retry": 3}))
        findings = rule.evaluate(g)
        assert len(findings) == 0
