"""Rule: Secret exposure risk."""

from atlas_sdk.enums import NodeType, Severity
from atlas_sdk.confidence import ConfidenceScore
from atlas_sdk.models.findings import Evidence, Finding
from atlas_sdk.models.graph import CICDGraph
from atlas_rule_engine.base_rule import BaseRule


class SecretExposureRule(BaseRule):
    rule_id = "secret-exposure"
    title = "Secret exposure risk"
    impact_category = "security"

    def evaluate(self, graph: CICDGraph) -> list[Finding]:
        findings = []
        secrets = [n for n in graph.nodes if n.node_type == NodeType.SECRET_REF]

        for secret in secrets:
            scope = getattr(secret, "scope", None)
            if scope and "global" in scope.lower():
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=f"{self.title}: {secret.name}",
                    description=f"Secret '{secret.name}' has global scope. Narrow scope to reduce exposure.",
                    severity=Severity.HIGH,
                    evidence=[Evidence(node_id=secret.id, description=f"Scope: {scope}")],
                    confidence=ConfidenceScore.high("Deterministic scope check"),
                    recommendation="Restrict secret scope to specific jobs or environments.",
                    impact_category=self.impact_category,
                    affected_node_ids=[secret.id],
                ))

        # Also flag if many secrets are used
        if len(secrets) > 10:
            findings.append(Finding(
                rule_id=self.rule_id,
                title=f"High secret count ({len(secrets)})",
                description=f"Found {len(secrets)} secret references. Review for consolidation.",
                severity=Severity.MEDIUM,
                evidence=[Evidence(description=f"{len(secrets)} secrets detected")],
                confidence=ConfidenceScore.medium(),
                recommendation="Audit secrets for duplicates and consider using a vault.",
                impact_category=self.impact_category,
            ))

        return findings
