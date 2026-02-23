"""Abstract base refactor for the refactor planner.

Each refactor module corresponds to a rule and generates a concrete
fix suggestion with before/after CI config snippets.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from atlas_sdk.models.findings import Finding
from atlas_sdk.models.graph import CICDGraph
from atlas_sdk.models.refactors import RefactorSuggestion


class BaseRefactor(ABC):
    """Abstract refactor — one per rule.

    Attributes:
        rule_id: Must match the corresponding rule's rule_id.
    """

    rule_id: str = ""

    @abstractmethod
    def suggest(self, finding: Finding, graph: CICDGraph) -> RefactorSuggestion | None:
        """Generate a fix suggestion for a specific finding.

        Args:
            finding: The rule engine finding to fix.
            graph: The CI/CD graph for context.

        Returns:
            A RefactorSuggestion, or None if no fix can be generated.
        """
