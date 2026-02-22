"""Rule: Excessive sequential stages."""

from atlas_sdk.enums import EdgeType, NodeType, Severity
from atlas_sdk.confidence import ConfidenceScore
from atlas_sdk.models.findings import Evidence, Finding
from atlas_sdk.models.graph import CICDGraph
from atlas_rule_engine.base_rule import BaseRule

THRESHOLD = 6


class SequentialStagesRule(BaseRule):
    rule_id = "sequential-stages"
    title = "Excessive sequential stages"
    impact_category = "performance"

    def evaluate(self, graph: CICDGraph) -> list[Finding]:
        findings = []
        for pipeline in graph.nodes:
            if pipeline.node_type != NodeType.PIPELINE:
                continue

            stages = [
                e.target_node_id for e in graph.edges
                if e.source_node_id == pipeline.id and e.edge_type == EdgeType.CALLS
            ]
            stage_nodes = [n for n in graph.nodes if n.id in stages and n.node_type == NodeType.STAGE]

            if len(stage_nodes) >= THRESHOLD:
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=f"{self.title}: {pipeline.name} ({len(stage_nodes)} stages)",
                    description=f"Pipeline '{pipeline.name}' has {len(stage_nodes)} sequential stages. Consider parallelizing independent stages.",
                    severity=Severity.MEDIUM,
                    evidence=[Evidence(
                        node_id=pipeline.id,
                        description=f"Stages: {', '.join(s.name for s in stage_nodes)}",
                    )],
                    confidence=ConfidenceScore.high("Deterministic stage count"),
                    recommendation="Group independent stages into parallel blocks to reduce build time.",
                    impact_category=self.impact_category,
                    affected_node_ids=[pipeline.id] + [s.id for s in stage_nodes],
                ))
        return findings
