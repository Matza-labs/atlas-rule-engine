"""Abstract base rule for the rule engine.

All rules inherit from BaseRule and implement evaluate().
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from atlas_sdk.models.findings import Finding
from atlas_sdk.models.graph import CICDGraph


class BaseRule(ABC):
    """Abstract rule — one per CI/CD check.

    Attributes:
        rule_id: Unique identifier (e.g. 'no-timeout').
        title: Human-readable title.
        impact_category: Category for grouping (performance, reliability, security, etc.).
    """

    rule_id: str = ""
    title: str = ""
    impact_category: str = ""

    @abstractmethod
    def evaluate(self, graph: CICDGraph) -> list[Finding]:
        """Run this rule against a graph and return findings.

        Args:
            graph: The CI/CD graph to analyze.

        Returns:
            List of findings (empty if rule passes).
        """
