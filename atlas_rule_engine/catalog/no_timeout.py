"""Rule: No timeout configured."""

from atlas_sdk.enums import NodeType, Severity
from atlas_sdk.confidence import ConfidenceScore
from atlas_sdk.models.findings import Evidence, Finding
from atlas_sdk.models.graph import CICDGraph
from atlas_rule_engine.base_rule import BaseRule


class NoTimeoutRule(BaseRule):
    rule_id = "no-timeout"
    title = "No timeout configured"
    impact_category = "reliability"

    def evaluate(self, graph: CICDGraph) -> list[Finding]:
        findings = []
        for node in graph.nodes:
            if node.node_type in (NodeType.PIPELINE, NodeType.JOB):
                if "timeout" not in str(node.metadata).lower():
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        title=f"{self.title}: {node.name}",
                        description=f"'{node.name}' has no timeout. Builds may run indefinitely.",
                        severity=Severity.HIGH,
                        evidence=[Evidence(node_id=node.id, description=f"No timeout on {node.node_type} '{node.name}'")],
                        confidence=ConfidenceScore.high("Deterministic static check"),
                        recommendation="Add a timeout (e.g. 30 minutes) to prevent hung builds.",
                        impact_category=self.impact_category,
                        affected_node_ids=[node.id],
                    ))
        return findings
