"""Rule: Heavy shell usage."""

from atlas_sdk.enums import NodeType, Severity
from atlas_sdk.confidence import ConfidenceScore
from atlas_sdk.models.findings import Evidence, Finding
from atlas_sdk.models.graph import CICDGraph
from atlas_rule_engine.base_rule import BaseRule

THRESHOLD = 5


class HeavyShellRule(BaseRule):
    rule_id = "heavy-shell"
    title = "Heavy inline shell usage"
    impact_category = "complexity"

    def evaluate(self, graph: CICDGraph) -> list[Finding]:
        shell_steps = [n for n in graph.nodes if n.node_type == NodeType.STEP and getattr(n, "shell", None)]

        if len(shell_steps) >= THRESHOLD:
            return [Finding(
                rule_id=self.rule_id,
                title=f"{self.title} ({len(shell_steps)} shell steps)",
                description=f"Found {len(shell_steps)} inline shell commands. Consider extracting to scripts or plugins.",
                severity=Severity.LOW,
                evidence=[Evidence(
                    node_id=s.id,
                    description=f"sh: {getattr(s, 'command', '')[:60]}"
                ) for s in shell_steps[:5]],
                confidence=ConfidenceScore.high("Deterministic step type check"),
                recommendation="Extract shell commands into reusable scripts or dedicated build tool steps.",
                impact_category=self.impact_category,
                affected_node_ids=[s.id for s in shell_steps],
            )]
        return []
