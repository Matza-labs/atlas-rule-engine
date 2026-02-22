"""Rule: Unpinned Docker images."""

from atlas_sdk.enums import NodeType, Severity
from atlas_sdk.confidence import ConfidenceScore
from atlas_sdk.models.findings import Evidence, Finding
from atlas_sdk.models.graph import CICDGraph
from atlas_rule_engine.base_rule import BaseRule

_FLOATING_TAGS = {"latest", "stable", "main", "master", "dev", "nightly"}


class UnpinnedImagesRule(BaseRule):
    rule_id = "unpinned-images"
    title = "Unpinned Docker image"
    impact_category = "security"

    def evaluate(self, graph: CICDGraph) -> list[Finding]:
        findings = []
        for node in graph.nodes:
            if node.node_type != NodeType.CONTAINER_IMAGE:
                continue

            tag = getattr(node, "tag", None) or "latest"
            digest = getattr(node, "digest", None)
            pinned = getattr(node, "pinned", False)

            if not pinned and not digest and tag.lower() in _FLOATING_TAGS:
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=f"{self.title}: {node.name}",
                    description=f"Image '{node.name}' uses floating tag '{tag}'. Builds may break without warning.",
                    severity=Severity.HIGH,
                    evidence=[Evidence(node_id=node.id, description=f"Tag: {tag}, no digest pinning")],
                    confidence=ConfidenceScore.high("Deterministic tag check"),
                    recommendation=f"Pin the image to a specific version or SHA digest instead of '{tag}'.",
                    impact_category=self.impact_category,
                    affected_node_ids=[node.id],
                ))
        return findings
