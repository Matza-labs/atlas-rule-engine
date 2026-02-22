"""Rule: Artifact coupling risk."""

from atlas_sdk.enums import EdgeType, NodeType, Severity
from atlas_sdk.confidence import ConfidenceScore
from atlas_sdk.models.findings import Evidence, Finding
from atlas_sdk.models.graph import CICDGraph
from atlas_rule_engine.base_rule import BaseRule

THRESHOLD = 3


class ArtifactCouplingRule(BaseRule):
    rule_id = "artifact-coupling"
    title = "High artifact coupling"
    impact_category = "dependencies"

    def evaluate(self, graph: CICDGraph) -> list[Finding]:
        findings = []
        artifacts = [n for n in graph.nodes if n.node_type == NodeType.ARTIFACT]

        for artifact in artifacts:
            consumers = [
                e for e in graph.edges
                if e.target_node_id == artifact.id and e.edge_type == EdgeType.CONSUMES
            ]
            producers = [
                e for e in graph.edges
                if e.source_node_id == artifact.id or
                (e.target_node_id == artifact.id and e.edge_type == EdgeType.PRODUCES)
            ]

            if len(consumers) >= THRESHOLD:
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=f"{self.title}: {artifact.name} ({len(consumers)} consumers)",
                    description=f"Artifact '{artifact.name}' is consumed by {len(consumers)} jobs. Breaking changes affect many downstream jobs.",
                    severity=Severity.MEDIUM,
                    evidence=[Evidence(node_id=artifact.id, description=f"{len(consumers)} consumers found")],
                    confidence=ConfidenceScore.high("Deterministic edge count"),
                    recommendation="Consider versioning this artifact or using a package registry.",
                    impact_category=self.impact_category,
                    affected_node_ids=[artifact.id],
                ))

        return findings
