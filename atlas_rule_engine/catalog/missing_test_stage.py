"""Rule: No test stage in pipeline."""

from atlas_sdk.enums import EdgeType, NodeType, Severity
from atlas_sdk.confidence import ConfidenceScore
from atlas_sdk.models.findings import Evidence, Finding
from atlas_sdk.models.graph import CICDGraph
from atlas_rule_engine.base_rule import BaseRule

_TEST_KEYWORDS = {"test", "spec", "verify", "check", "unit", "integration", "e2e", "qa"}


class MissingTestStageRule(BaseRule):
    rule_id = "missing-test-stage"
    title = "No test stage detected"
    impact_category = "reliability"

    def evaluate(self, graph: CICDGraph) -> list[Finding]:
        findings = []
        for pipeline in graph.nodes:
            if pipeline.node_type != NodeType.PIPELINE:
                continue

            stage_ids = {
                e.target_node_id for e in graph.edges
                if e.source_node_id == pipeline.id and e.edge_type == EdgeType.CALLS
            }
            stages = [n for n in graph.nodes if n.id in stage_ids and n.node_type == NodeType.STAGE]

            if not stages:
                continue

            has_test = any(
                any(kw in s.name.lower() for kw in _TEST_KEYWORDS)
                for s in stages
            )
            if not has_test:
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=f"{self.title}: {pipeline.name}",
                    description=(
                        f"Pipeline '{pipeline.name}' has {len(stages)} stage(s) but none appear "
                        f"to run tests. Pipelines without a test stage risk shipping broken code."
                    ),
                    severity=Severity.HIGH,
                    evidence=[Evidence(
                        node_id=pipeline.id,
                        description=f"Stages found: {', '.join(s.name for s in stages)}",
                    )],
                    confidence=ConfidenceScore.medium(),
                    recommendation=(
                        "Add a dedicated test stage (unit tests, integration tests, or e2e tests) "
                        "before any deploy stage."
                    ),
                    impact_category=self.impact_category,
                    affected_node_ids=[pipeline.id],
                ))
        return findings
