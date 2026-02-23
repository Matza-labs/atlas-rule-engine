"""Refactor planner — generates a RefactorPlan from rule engine findings.

Wires findings to their corresponding refactor modules and produces
a prioritized plan with concrete before/after suggestions.
"""

from __future__ import annotations

import logging

from atlas_sdk.models.findings import Finding
from atlas_sdk.models.graph import CICDGraph
from atlas_sdk.models.refactors import RefactorPlan, RefactorSuggestion

from atlas_rule_engine.refactors import REFACTOR_REGISTRY

logger = logging.getLogger(__name__)


class RefactorPlanner:
    """Generates a RefactorPlan from a graph and its findings.

    Usage:
        planner = RefactorPlanner()
        plan = planner.plan(graph, findings)
    """

    def plan(self, graph: CICDGraph, findings: list[Finding]) -> RefactorPlan:
        """Generate a refactor plan from findings.

        Args:
            graph: The analyzed CI/CD graph.
            findings: List of rule engine findings.

        Returns:
            RefactorPlan with prioritized suggestions.
        """
        suggestions: list[RefactorSuggestion] = []

        for finding in findings:
            refactor_cls = REFACTOR_REGISTRY.get(finding.rule_id)
            if not refactor_cls:
                logger.debug("No refactor module for rule: %s", finding.rule_id)
                continue

            refactor = refactor_cls()
            suggestion = refactor.suggest(finding, graph)
            if suggestion:
                suggestions.append(suggestion)

        # Sort: high risk last, severity-prioritized
        risk_order = {"low": 0, "medium": 1, "high": 2}
        suggestions.sort(key=lambda s: risk_order.get(s.risk_level, 1))

        plan = RefactorPlan(
            name=graph.name,
            graph_id=graph.id,
            suggestions=suggestions,
        )

        logger.info(
            "RefactorPlan generated: %d suggestions for '%s'",
            plan.total_suggestions, graph.name,
        )
        return plan
