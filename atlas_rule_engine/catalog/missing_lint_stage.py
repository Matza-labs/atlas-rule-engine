"""Rule: No lint/code-quality stage in pipeline."""

from atlas_sdk.enums import EdgeType, NodeType, Severity
from atlas_sdk.confidence import ConfidenceScore
from atlas_sdk.models.findings import Evidence, Finding
from atlas_sdk.models.graph import CICDGraph
from atlas_rule_engine.base_rule import BaseRule

_LINT_KEYWORDS = {"lint", "quality", "sonar", "scan", "style", "format", "checkstyle", "pylint", "eslint", "ruff"}


class MissingLintStageRule(BaseRule):
    rule_id = "missing-lint-stage"
    title = "No lint or code-quality stage detected"
    impact_category = "quality"

    def evaluate(self, graph: CICDGraph) -> list[Finding]:
        findings = []
        for pipeline in graph.nodes:
            if pipeline.node_type != NodeType.PIPELINE:
                continue

            stage_ids = {
                e.target_node_id for e in graph.edges
                if e.source_node_id == pipeline.id and e.edge_type == EdgeType.CALLS
            }
            stages = [n for n in graph.nodes if n.id in stage_ids and n.node_type == NodeType.STAGE]

            if not stages:
                continue

            has_lint = any(
                any(kw in s.name.lower() for kw in _LINT_KEYWORDS)
                for s in stages
            )
            if not has_lint:
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=f"{self.title}: {pipeline.name}",
                    description=(
                        f"Pipeline '{pipeline.name}' has no lint or code-quality stage. "
                        f"Without static analysis, code style issues and common bugs go undetected."
                    ),
                    severity=Severity.MEDIUM,
                    evidence=[Evidence(
                        node_id=pipeline.id,
                        description=f"Stages found: {', '.join(s.name for s in stages)}",
                    )],
                    confidence=ConfidenceScore.medium(),
                    recommendation=(
                        "Add a lint stage using a tool appropriate for your stack "
                        "(e.g. ruff, eslint, checkstyle, SonarQube)."
                    ),
                    impact_category=self.impact_category,
                    affected_node_ids=[pipeline.id],
                ))
        return findings
