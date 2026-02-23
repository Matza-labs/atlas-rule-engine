"""Refactor modules for all 10 built-in rules.

Each class generates a concrete before/after fix suggestion
for the corresponding rule engine finding.
"""

from __future__ import annotations

from atlas_sdk.models.findings import Finding
from atlas_sdk.models.graph import CICDGraph
from atlas_sdk.models.refactors import RefactorSuggestion

from atlas_rule_engine.base_refactor import BaseRefactor


class FixNoTimeout(BaseRefactor):
    rule_id = "no-timeout"

    def suggest(self, finding: Finding, graph: CICDGraph) -> RefactorSuggestion:
        node_name = finding.affected_node_ids[0] if finding.affected_node_ids else "build"
        return RefactorSuggestion(
            rule_id=self.rule_id,
            finding_id=finding.id,
            description=f"Add timeout to job '{node_name}' to prevent indefinite hangs",
            before_snippet="jobs:\n  build:\n    runs-on: ubuntu-latest",
            after_snippet="jobs:\n  build:\n    runs-on: ubuntu-latest\n    timeout-minutes: 30",
            effort_estimate="2 minutes",
            risk_level="low",
            affected_node_ids=finding.affected_node_ids,
        )


class FixNoCache(BaseRefactor):
    rule_id = "no-cache"

    def suggest(self, finding: Finding, graph: CICDGraph) -> RefactorSuggestion:
        return RefactorSuggestion(
            rule_id=self.rule_id,
            finding_id=finding.id,
            description="Enable dependency caching to speed up builds",
            before_snippet="steps:\n  - run: npm install",
            after_snippet="steps:\n  - uses: actions/cache@v3\n    with:\n      path: node_modules\n      key: deps-${{ hashFiles('package-lock.json') }}\n  - run: npm install",
            effort_estimate="10 minutes",
            risk_level="low",
            affected_node_ids=finding.affected_node_ids,
        )


class FixSequentialStages(BaseRefactor):
    rule_id = "sequential-stages"

    def suggest(self, finding: Finding, graph: CICDGraph) -> RefactorSuggestion:
        return RefactorSuggestion(
            rule_id=self.rule_id,
            finding_id=finding.id,
            description="Parallelize independent stages to reduce total pipeline duration",
            before_snippet="stages:\n  - lint\n  - test\n  - build",
            after_snippet="stages:\n  - stage: parallel-checks\n    parallel:\n      - lint\n      - test\n  - build",
            effort_estimate="30 minutes",
            risk_level="medium",
            affected_node_ids=finding.affected_node_ids,
        )


class FixHeavyShell(BaseRefactor):
    rule_id = "heavy-shell"

    def suggest(self, finding: Finding, graph: CICDGraph) -> RefactorSuggestion:
        return RefactorSuggestion(
            rule_id=self.rule_id,
            finding_id=finding.id,
            description="Extract complex shell script into a dedicated script file",
            before_snippet="steps:\n  - run: |\n      set -e\n      ./configure && make\n      make test && make install",
            after_snippet="steps:\n  - run: ./scripts/build.sh",
            effort_estimate="15 minutes",
            risk_level="low",
            affected_node_ids=finding.affected_node_ids,
        )


class FixUnpinnedImages(BaseRefactor):
    rule_id = "unpinned-images"

    def suggest(self, finding: Finding, graph: CICDGraph) -> RefactorSuggestion:
        return RefactorSuggestion(
            rule_id=self.rule_id,
            finding_id=finding.id,
            description="Pin container image to a specific SHA digest for reproducibility",
            before_snippet="container:\n  image: node:latest",
            after_snippet="container:\n  image: node:20-alpine@sha256:abc123...",
            effort_estimate="5 minutes",
            risk_level="low",
            affected_node_ids=finding.affected_node_ids,
        )


class FixMissingDocs(BaseRefactor):
    rule_id = "missing-docs"

    def suggest(self, finding: Finding, graph: CICDGraph) -> RefactorSuggestion:
        return RefactorSuggestion(
            rule_id=self.rule_id,
            finding_id=finding.id,
            description="Add missing documentation files (RUNBOOK.md, CODEOWNERS)",
            before_snippet="# No RUNBOOK.md or CODEOWNERS found",
            after_snippet="# Create:\n# - RUNBOOK.md (operational procedures)\n# - CODEOWNERS (code ownership)",
            effort_estimate="1 hour",
            risk_level="low",
            affected_node_ids=finding.affected_node_ids,
        )


class FixSecretExposure(BaseRefactor):
    rule_id = "secret-exposure"

    def suggest(self, finding: Finding, graph: CICDGraph) -> RefactorSuggestion:
        return RefactorSuggestion(
            rule_id=self.rule_id,
            finding_id=finding.id,
            description="Restrict secret access to specific steps that need it",
            before_snippet="env:\n  DEPLOY_KEY: ${{ secrets.DEPLOY_KEY }}\nsteps:\n  - run: echo 'building'\n  - run: deploy.sh",
            after_snippet="steps:\n  - run: echo 'building'\n  - run: deploy.sh\n    env:\n      DEPLOY_KEY: ${{ secrets.DEPLOY_KEY }}",
            effort_estimate="10 minutes",
            risk_level="medium",
            affected_node_ids=finding.affected_node_ids,
        )


class FixCrossRepoTriggers(BaseRefactor):
    rule_id = "cross-repo-triggers"

    def suggest(self, finding: Finding, graph: CICDGraph) -> RefactorSuggestion:
        return RefactorSuggestion(
            rule_id=self.rule_id,
            finding_id=finding.id,
            description="Replace direct cross-repo triggers with event-based decoupling",
            before_snippet="trigger:\n  - project: other-repo\n    branch: main",
            after_snippet="# Use repository_dispatch or workflow_call\non:\n  repository_dispatch:\n    types: [deploy-triggered]",
            effort_estimate="1 hour",
            risk_level="high",
            affected_node_ids=finding.affected_node_ids,
        )


class FixArtifactCoupling(BaseRefactor):
    rule_id = "artifact-coupling"

    def suggest(self, finding: Finding, graph: CICDGraph) -> RefactorSuggestion:
        return RefactorSuggestion(
            rule_id=self.rule_id,
            finding_id=finding.id,
            description="Use a package registry instead of direct artifact passing",
            before_snippet="artifacts:\n  paths:\n    - build/output.jar",
            after_snippet="# Publish to package registry\nsteps:\n  - run: mvn deploy\n# Downstream consumes from registry, not artifact",
            effort_estimate="2 hours",
            risk_level="high",
            affected_node_ids=finding.affected_node_ids,
        )


class FixNoRetry(BaseRefactor):
    rule_id = "no-retry"

    def suggest(self, finding: Finding, graph: CICDGraph) -> RefactorSuggestion:
        return RefactorSuggestion(
            rule_id=self.rule_id,
            finding_id=finding.id,
            description="Add retry policy for flaky or network-dependent steps",
            before_snippet="steps:\n  - run: npm test",
            after_snippet="steps:\n  - uses: nick-fields/retry@v2\n    with:\n      max_attempts: 3\n      command: npm test",
            effort_estimate="5 minutes",
            risk_level="low",
            affected_node_ids=finding.affected_node_ids,
        )


# Registry of all refactor modules
REFACTOR_REGISTRY: dict[str, type[BaseRefactor]] = {
    cls.rule_id: cls
    for cls in [
        FixNoTimeout,
        FixNoCache,
        FixSequentialStages,
        FixHeavyShell,
        FixUnpinnedImages,
        FixMissingDocs,
        FixSecretExposure,
        FixCrossRepoTriggers,
        FixArtifactCoupling,
        FixNoRetry,
    ]
}
