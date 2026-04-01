"""Rule: Privileged CI runner detected."""

from atlas_sdk.enums import NodeType, Severity
from atlas_sdk.confidence import ConfidenceScore
from atlas_sdk.models.findings import Evidence, Finding
from atlas_sdk.models.graph import CICDGraph
from atlas_rule_engine.base_rule import BaseRule


class PrivilegedRunnerRule(BaseRule):
    rule_id = "privileged-runner"
    title = "Privileged CI runner"
    impact_category = "security"

    def evaluate(self, graph: CICDGraph) -> list[Finding]:
        findings = []
        for node in graph.nodes:
            if node.node_type != NodeType.RUNNER:
                continue

            executor = getattr(node, "executor_type", "") or ""
            labels = getattr(node, "labels", []) or []
            is_privileged = (
                "privileged" in executor.lower()
                or any("privileged" in lbl.lower() for lbl in labels)
            )

            if is_privileged:
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=f"{self.title}: {node.name}",
                    description=(
                        f"Runner '{node.name}' runs in privileged mode. "
                        f"Privileged containers have full host access and can escape container isolation, "
                        f"making a compromised build a critical security incident."
                    ),
                    severity=Severity.HIGH,
                    evidence=[Evidence(
                        node_id=node.id,
                        description=f"executor_type={executor!r}, labels={labels}",
                    )],
                    confidence=ConfidenceScore.high("Deterministic executor type check"),
                    recommendation=(
                        "Replace privileged runners with rootless containers or use Docker-in-Docker "
                        "with explicit socket mounting only where absolutely required."
                    ),
                    impact_category=self.impact_category,
                    affected_node_ids=[node.id],
                ))
        return findings
