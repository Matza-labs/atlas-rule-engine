"""Rule: Deploy jobs without retry/rollback."""

from atlas_sdk.enums import EdgeType, NodeType, Severity
from atlas_sdk.confidence import ConfidenceScore
from atlas_sdk.models.findings import Evidence, Finding
from atlas_sdk.models.graph import CICDGraph
from atlas_rule_engine.base_rule import BaseRule

_DEPLOY_KEYWORDS = {"deploy", "release", "publish", "rollout"}
_RETRY_KEYWORDS = {"retry", "rollback", "revert", "canary", "blue-green"}


class NoRetryRule(BaseRule):
    rule_id = "no-retry"
    title = "Deploy without retry/rollback"
    impact_category = "reliability"

    def evaluate(self, graph: CICDGraph) -> list[Finding]:
        findings = []
        all_text = " ".join(f"{n.name} {n.metadata}" for n in graph.nodes).lower()

        for node in graph.nodes:
            if node.node_type not in (NodeType.STAGE, NodeType.STEP):
                continue

            name_lower = node.name.lower()
            if not any(kw in name_lower for kw in _DEPLOY_KEYWORDS):
                continue

            # Check if retry/rollback is mentioned anywhere
            if any(kw in all_text for kw in _RETRY_KEYWORDS):
                continue

            findings.append(Finding(
                rule_id=self.rule_id,
                title=f"{self.title}: {node.name}",
                description=f"Deploy step '{node.name}' has no retry or rollback strategy detected.",
                severity=Severity.HIGH,
                evidence=[Evidence(node_id=node.id, description=f"Deploy step without retry/rollback")],
                confidence=ConfidenceScore.medium(),
                recommendation="Add deployment retry logic or rollback strategy (canary, blue-green).",
                impact_category=self.impact_category,
                affected_node_ids=[node.id],
            ))

        return findings
