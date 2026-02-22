"""Rule: No caching detected."""

from atlas_sdk.enums import NodeType, Severity
from atlas_sdk.confidence import ConfidenceScore
from atlas_sdk.models.findings import Evidence, Finding
from atlas_sdk.models.graph import CICDGraph
from atlas_rule_engine.base_rule import BaseRule

_CACHE_KEYWORDS = {"cache", "caching", "ccache", "pip cache", "npm cache", "gradle cache", ".cache"}


class NoCacheRule(BaseRule):
    rule_id = "no-cache"
    title = "No caching detected"
    impact_category = "performance"

    def evaluate(self, graph: CICDGraph) -> list[Finding]:
        # Check if any node mentions caching
        all_text = " ".join(
            f"{n.name} {n.metadata}" for n in graph.nodes
        ).lower()

        if any(kw in all_text for kw in _CACHE_KEYWORDS):
            return []

        pipelines = [n for n in graph.nodes if n.node_type == NodeType.PIPELINE]
        if not pipelines:
            return []

        return [Finding(
            rule_id=self.rule_id,
            title=self.title,
            description="No caching mechanism detected. Builds may re-download dependencies every run.",
            severity=Severity.MEDIUM,
            evidence=[Evidence(description="No cache keywords found in pipeline configuration")],
            confidence=ConfidenceScore.medium(),
            recommendation="Add dependency caching (pip, npm, Maven, Docker layer caching).",
            impact_category=self.impact_category,
            affected_node_ids=[p.id for p in pipelines],
        )]
