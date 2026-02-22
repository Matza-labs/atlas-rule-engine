"""Rule execution engine.

Loads all rules from the catalog, runs them against a CICDGraph,
and aggregates findings.
"""

from __future__ import annotations

import logging

from atlas_sdk.models.findings import Finding
from atlas_sdk.models.graph import CICDGraph

from atlas_rule_engine.base_rule import BaseRule
from atlas_rule_engine.catalog.artifact_coupling import ArtifactCouplingRule
from atlas_rule_engine.catalog.cross_repo_triggers import CrossRepoTriggersRule
from atlas_rule_engine.catalog.heavy_shell import HeavyShellRule
from atlas_rule_engine.catalog.missing_docs import MissingDocsRule
from atlas_rule_engine.catalog.no_cache import NoCacheRule
from atlas_rule_engine.catalog.no_retry import NoRetryRule
from atlas_rule_engine.catalog.no_timeout import NoTimeoutRule
from atlas_rule_engine.catalog.secret_exposure import SecretExposureRule
from atlas_rule_engine.catalog.sequential_stages import SequentialStagesRule
from atlas_rule_engine.catalog.unpinned_images import UnpinnedImagesRule

logger = logging.getLogger(__name__)

# Default catalog — all built-in rules
DEFAULT_RULES: list[type[BaseRule]] = [
    NoTimeoutRule,
    NoCacheRule,
    SequentialStagesRule,
    HeavyShellRule,
    UnpinnedImagesRule,
    MissingDocsRule,
    SecretExposureRule,
    CrossRepoTriggersRule,
    ArtifactCouplingRule,
    NoRetryRule,
]


class RuleEngine:
    """Runs deterministic rules against a CI/CD graph.

    Usage:
        engine = RuleEngine()
        findings = engine.run(graph)
    """

    def __init__(self, rules: list[BaseRule] | None = None) -> None:
        if rules is not None:
            self._rules = rules
        else:
            self._rules = [cls() for cls in DEFAULT_RULES]

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    def run(self, graph: CICDGraph) -> list[Finding]:
        """Run all rules against the graph.

        Returns:
            Aggregated list of findings from all rules.
        """
        all_findings: list[Finding] = []

        for rule in self._rules:
            try:
                findings = rule.evaluate(graph)
                all_findings.extend(findings)
                if findings:
                    logger.info(
                        "Rule %s: %d finding(s)", rule.rule_id, len(findings)
                    )
            except Exception as e:
                logger.exception("Rule %s failed: %s", rule.rule_id, e)

        logger.info(
            "Engine complete: %d rules, %d findings",
            len(self._rules), len(all_findings),
        )
        return all_findings
