"""Rule: Pipeline with too many steps — monolithic build."""

from atlas_sdk.enums import EdgeType, NodeType, Severity
from atlas_sdk.confidence import ConfidenceScore
from atlas_sdk.models.findings import Evidence, Finding
from atlas_sdk.models.graph import CICDGraph
from atlas_rule_engine.base_rule import BaseRule

STEP_THRESHOLD = 15


class LargePipelineRule(BaseRule):
    rule_id = "large-pipeline"
    title = "Monolithic pipeline — too many steps"
    impact_category = "complexity"

    def evaluate(self, graph: CICDGraph) -> list[Finding]:
        findings = []
        for pipeline in graph.nodes:
            if pipeline.node_type != NodeType.PIPELINE:
                continue

            # Gather stage IDs directly connected to this pipeline
            stage_ids = {
                e.target_node_id for e in graph.edges
                if e.source_node_id == pipeline.id and e.edge_type == EdgeType.CALLS
            }

            # Count all steps reachable through stages
            step_ids: set[str] = set()
            for stage_id in stage_ids:
                for e in graph.edges:
                    if e.source_node_id == stage_id and e.edge_type == EdgeType.CALLS:
                        target = next((n for n in graph.nodes if n.id == e.target_node_id), None)
                        if target and target.node_type == NodeType.STEP:
                            step_ids.add(target.id)

            if len(step_ids) >= STEP_THRESHOLD:
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=f"{self.title}: {pipeline.name} ({len(step_ids)} steps)",
                    description=(
                        f"Pipeline '{pipeline.name}' contains {len(step_ids)} steps — "
                        f"significantly above the recommended threshold of {STEP_THRESHOLD}. "
                        f"Large monolithic pipelines are hard to maintain, debug, and reuse."
                    ),
                    severity=Severity.MEDIUM,
                    evidence=[Evidence(
                        node_id=pipeline.id,
                        description=f"{len(step_ids)} steps across {len(stage_ids)} stages",
                    )],
                    confidence=ConfidenceScore.high("Deterministic step count"),
                    recommendation=(
                        "Break the pipeline into smaller composable pipelines. "
                        "Use reusable workflows, templates, or shared libraries to reduce duplication."
                    ),
                    impact_category=self.impact_category,
                    affected_node_ids=[pipeline.id],
                ))
        return findings
