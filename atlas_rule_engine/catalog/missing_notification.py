"""Rule: No failure notification step in pipeline with deployments."""

from atlas_sdk.enums import EdgeType, NodeType, Severity
from atlas_sdk.confidence import ConfidenceScore
from atlas_sdk.models.findings import Evidence, Finding
from atlas_sdk.models.graph import CICDGraph
from atlas_rule_engine.base_rule import BaseRule

_DEPLOY_KEYWORDS = {"deploy", "release", "publish", "push", "ship"}
_NOTIFY_KEYWORDS = {"notify", "notification", "alert", "slack", "email", "webhook", "pagerduty", "teams"}


class MissingNotificationRule(BaseRule):
    rule_id = "missing-notification"
    title = "No failure notification configured"
    impact_category = "reliability"

    def evaluate(self, graph: CICDGraph) -> list[Finding]:
        findings = []
        for pipeline in graph.nodes:
            if pipeline.node_type != NodeType.PIPELINE:
                continue

            # Gather all stages and steps reachable from this pipeline
            stage_ids = {
                e.target_node_id for e in graph.edges
                if e.source_node_id == pipeline.id and e.edge_type == EdgeType.CALLS
            }
            stages = [n for n in graph.nodes if n.id in stage_ids and n.node_type == NodeType.STAGE]

            has_deploy_stage = any(
                any(kw in s.name.lower() for kw in _DEPLOY_KEYWORDS)
                for s in stages
            )
            if not has_deploy_stage:
                continue

            # Check all steps in graph for notification patterns
            all_steps = [n for n in graph.nodes if n.node_type == NodeType.STEP]
            has_notify = any(
                any(kw in (n.name + " " + (getattr(n, "command", "") or "")).lower() for kw in _NOTIFY_KEYWORDS)
                for n in all_steps
            )

            if not has_notify:
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=f"{self.title}: {pipeline.name}",
                    description=(
                        f"Pipeline '{pipeline.name}' has deployment stages but no failure "
                        f"notification step (Slack, email, webhook, etc.). "
                        f"Silent failures delay incident response."
                    ),
                    severity=Severity.MEDIUM,
                    evidence=[Evidence(
                        node_id=pipeline.id,
                        description="Deploy stage found but no notify/alert step detected",
                    )],
                    confidence=ConfidenceScore.medium(),
                    recommendation=(
                        "Add a post-failure notification step using Slack webhooks, "
                        "email, PagerDuty, or your team's alerting tool."
                    ),
                    impact_category=self.impact_category,
                    affected_node_ids=[pipeline.id],
                ))
        return findings
