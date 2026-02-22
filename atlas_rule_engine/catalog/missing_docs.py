"""Rule: Missing documentation."""

from atlas_sdk.enums import NodeType, Severity
from atlas_sdk.confidence import ConfidenceScore
from atlas_sdk.models.findings import Evidence, Finding
from atlas_sdk.models.graph import CICDGraph
from atlas_rule_engine.base_rule import BaseRule

_EXPECTED = {"readme", "architecture", "runbook", "security_policy", "codeowners"}


class MissingDocsRule(BaseRule):
    rule_id = "missing-docs"
    title = "Missing documentation"
    impact_category = "documentation"

    def evaluate(self, graph: CICDGraph) -> list[Finding]:
        doc_nodes = [n for n in graph.nodes if n.node_type == NodeType.DOC_FILE]
        found_types = {getattr(n, "doc_type", "").value if hasattr(getattr(n, "doc_type", ""), "value") else str(getattr(n, "doc_type", "")) for n in doc_nodes}

        missing = _EXPECTED - found_types
        if not missing:
            return []

        return [Finding(
            rule_id=self.rule_id,
            title=f"{self.title} ({len(missing)} missing)",
            description=f"Missing documentation: {', '.join(sorted(missing))}.",
            severity=Severity.MEDIUM if len(missing) <= 2 else Severity.HIGH,
            evidence=[Evidence(description=f"Missing: {t}") for t in sorted(missing)],
            confidence=ConfidenceScore.medium(),
            recommendation="Add the missing documentation files for better project maintainability.",
            impact_category=self.impact_category,
        )]
