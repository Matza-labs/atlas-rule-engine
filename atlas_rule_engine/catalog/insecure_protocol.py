"""Rule: Insecure HTTP protocol used in step commands."""

from atlas_sdk.enums import NodeType, Severity
from atlas_sdk.confidence import ConfidenceScore
from atlas_sdk.models.findings import Evidence, Finding
from atlas_sdk.models.graph import CICDGraph
from atlas_rule_engine.base_rule import BaseRule


class InsecureProtocolRule(BaseRule):
    rule_id = "insecure-protocol"
    title = "Insecure HTTP protocol in step command"
    impact_category = "security"

    def evaluate(self, graph: CICDGraph) -> list[Finding]:
        findings = []
        for node in graph.nodes:
            if node.node_type != NodeType.STEP:
                continue

            command = getattr(node, "command", "") or ""
            # Flag http:// but not https:// or localhost
            if "http://" in command and "localhost" not in command and "127.0.0.1" not in command:
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=f"{self.title}: {node.name}",
                    description=(
                        f"Step '{node.name}' uses an insecure HTTP URL in its command. "
                        f"Unencrypted connections expose credentials and allow man-in-the-middle attacks."
                    ),
                    severity=Severity.MEDIUM,
                    evidence=[Evidence(
                        node_id=node.id,
                        description=f"Command contains http://: {command[:120]}",
                    )],
                    confidence=ConfidenceScore.high("Deterministic protocol check"),
                    recommendation=(
                        "Replace http:// with https:// for all external service calls. "
                        "Verify TLS certificates are validated."
                    ),
                    impact_category=self.impact_category,
                    affected_node_ids=[node.id],
                ))
        return findings
