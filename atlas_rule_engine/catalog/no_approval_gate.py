"""Rule: Production deployment without an approval gate."""

from atlas_sdk.enums import NodeType, Severity
from atlas_sdk.confidence import ConfidenceScore
from atlas_sdk.models.findings import Evidence, Finding
from atlas_sdk.models.graph import CICDGraph
from atlas_rule_engine.base_rule import BaseRule

_PROD_KEYWORDS = {"prod", "production", "live", "release"}
_APPROVAL_KEYWORDS = {"approval", "manual", "gate", "approve", "confirm", "review"}


class NoApprovalGateRule(BaseRule):
    rule_id = "no-approval-gate"
    title = "Production deployment without approval gate"
    impact_category = "reliability"

    def evaluate(self, graph: CICDGraph) -> list[Finding]:
        findings = []
        prod_envs = [
            n for n in graph.nodes
            if n.node_type == NodeType.ENVIRONMENT
            and any(kw in n.name.lower() for kw in _PROD_KEYWORDS)
        ]

        if not prod_envs:
            return []

        # Check if any stage has an approval-style when_condition
        all_stages = [n for n in graph.nodes if n.node_type == NodeType.STAGE]
        has_gate = any(
            getattr(s, "when_condition", None)
            and any(kw in str(getattr(s, "when_condition", "")).lower() for kw in _APPROVAL_KEYWORDS)
            for s in all_stages
        )

        if not has_gate:
            for env in prod_envs:
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=f"{self.title}: {env.name}",
                    description=(
                        f"Environment '{env.name}' looks like a production target but no "
                        f"approval gate or manual trigger was detected in any stage. "
                        f"Direct deployment to production without review increases incident risk."
                    ),
                    severity=Severity.HIGH,
                    evidence=[Evidence(
                        node_id=env.id,
                        description=f"Production environment '{env.name}' has no approval-gated stage",
                    )],
                    confidence=ConfidenceScore.medium(),
                    recommendation=(
                        "Add a manual approval step or environment protection rule before "
                        "any stage that deploys to production."
                    ),
                    impact_category=self.impact_category,
                    affected_node_ids=[env.id],
                ))
        return findings
