"""Rule: No parallelism despite many stages."""

from atlas_sdk.enums import EdgeType, NodeType, Severity
from atlas_sdk.confidence import ConfidenceScore
from atlas_sdk.models.findings import Evidence, Finding
from atlas_sdk.models.graph import CICDGraph
from atlas_rule_engine.base_rule import BaseRule

THRESHOLD = 4


class NoParallelismRule(BaseRule):
    rule_id = "no-parallelism"
    title = "No parallel stage execution"
    impact_category = "performance"

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

            if len(stages) < THRESHOLD:
                continue

            has_parallel = any(getattr(s, "parallel", False) for s in stages)
            if not has_parallel:
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=f"{self.title}: {pipeline.name} ({len(stages)} stages, none parallel)",
                    description=(
                        f"Pipeline '{pipeline.name}' has {len(stages)} stages but none are marked "
                        f"as parallel. Independent stages (e.g. test + lint) can run concurrently."
                    ),
                    severity=Severity.MEDIUM,
                    evidence=[Evidence(
                        node_id=pipeline.id,
                        description=f"Stages: {', '.join(s.name for s in stages)}",
                    )],
                    confidence=ConfidenceScore.high("Deterministic stage attribute check"),
                    recommendation=(
                        "Identify independent stages and mark them parallel=true "
                        "or use a parallel block to reduce total pipeline duration."
                    ),
                    impact_category=self.impact_category,
                    affected_node_ids=[pipeline.id] + [s.id for s in stages],
                ))
        return findings
