"""Rule: Artifact produced without version or tag metadata."""

from atlas_sdk.enums import NodeType, Severity
from atlas_sdk.confidence import ConfidenceScore
from atlas_sdk.models.findings import Evidence, Finding
from atlas_sdk.models.graph import CICDGraph
from atlas_rule_engine.base_rule import BaseRule


class UntaggedArtifactRule(BaseRule):
    rule_id = "untagged-artifact"
    title = "Artifact missing version or tag"
    impact_category = "dependencies"

    def evaluate(self, graph: CICDGraph) -> list[Finding]:
        findings = []
        for node in graph.nodes:
            if node.node_type != NodeType.ARTIFACT:
                continue

            meta = node.metadata or {}
            has_version = any(
                k in meta for k in ("version", "tag", "build_number", "sha", "digest")
            )
            if not has_version:
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=f"{self.title}: {node.name}",
                    description=(
                        f"Artifact '{node.name}' has no version, tag, or digest in its metadata. "
                        f"Unversioned artifacts are not reproducible and break traceability."
                    ),
                    severity=Severity.MEDIUM,
                    evidence=[Evidence(
                        node_id=node.id,
                        description=f"Artifact metadata: {dict(list(meta.items())[:5])}",
                    )],
                    confidence=ConfidenceScore.high("Deterministic metadata check"),
                    recommendation=(
                        "Tag all produced artifacts with a version derived from git tags, "
                        "commit SHA, or build number to enable reproducible builds."
                    ),
                    impact_category=self.impact_category,
                    affected_node_ids=[node.id],
                ))
        return findings
