"""Rule: Cross-repo trigger chains."""

from atlas_sdk.enums import EdgeType, NodeType, Severity
from atlas_sdk.confidence import ConfidenceScore
from atlas_sdk.models.findings import Evidence, Finding
from atlas_sdk.models.graph import CICDGraph
from atlas_rule_engine.base_rule import BaseRule


class CrossRepoTriggersRule(BaseRule):
    rule_id = "cross-repo-triggers"
    title = "Cross-project trigger chain"
    impact_category = "dependencies"

    def evaluate(self, graph: CICDGraph) -> list[Finding]:
        findings = []
        trigger_edges = [e for e in graph.edges if e.edge_type == EdgeType.TRIGGERS]

        for edge in trigger_edges:
            source = graph.get_node(edge.source_node_id)
            target = graph.get_node(edge.target_node_id)
            if not source or not target:
                continue

            # If source is a pipeline and target is a job (downstream trigger)
            if source.node_type == NodeType.PIPELINE and target.node_type == NodeType.JOB:
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=f"{self.title}: {source.name} → {target.name}",
                    description=f"Pipeline '{source.name}' triggers downstream job '{target.name}'. Changes may cascade unexpectedly.",
                    severity=Severity.MEDIUM,
                    evidence=[Evidence(
                        node_id=source.id,
                        description=f"triggers → {target.name}",
                    )],
                    confidence=ConfidenceScore.high("Deterministic edge analysis"),
                    recommendation="Document trigger dependencies and add health checks between stages.",
                    impact_category=self.impact_category,
                    affected_node_ids=[source.id, target.id],
                ))

        return findings
