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


# ── New 10 rules ──────────────────────────────────────────────────────────────

class FixNoParallelism(BaseRefactor):
    rule_id = "no-parallelism"

    def suggest(self, finding: Finding, graph: CICDGraph) -> RefactorSuggestion:
        return RefactorSuggestion(
            rule_id=self.rule_id,
            finding_id=finding.id,
            description="Enable parallel stage execution for independent stages",
            before_snippet=(
                "stages:\n  - lint\n  - test\n  - build"
            ),
            after_snippet=(
                "stages:\n"
                "  - stage: checks\n"
                "    parallel:\n"
                "      lint:\n"
                "        stage: lint\n"
                "      test:\n"
                "        stage: test\n"
                "  - build"
            ),
            effort_estimate="20 minutes",
            risk_level="low",
            affected_node_ids=finding.affected_node_ids,
        )


class FixMissingTestStage(BaseRefactor):
    rule_id = "missing-test-stage"

    def suggest(self, finding: Finding, graph: CICDGraph) -> RefactorSuggestion:
        return RefactorSuggestion(
            rule_id=self.rule_id,
            finding_id=finding.id,
            description="Add a dedicated test stage before any deployment",
            before_snippet=(
                "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make build\n  deploy:\n    needs: build\n    steps:\n      - run: make deploy"
            ),
            after_snippet=(
                "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make build\n  test:\n    needs: build\n    runs-on: ubuntu-latest\n    steps:\n      - run: make test\n  deploy:\n    needs: test\n    steps:\n      - run: make deploy"
            ),
            effort_estimate="30 minutes",
            risk_level="low",
            affected_node_ids=finding.affected_node_ids,
        )


class FixMissingLintStage(BaseRefactor):
    rule_id = "missing-lint-stage"

    def suggest(self, finding: Finding, graph: CICDGraph) -> RefactorSuggestion:
        return RefactorSuggestion(
            rule_id=self.rule_id,
            finding_id=finding.id,
            description="Add a lint/code-quality stage to catch issues early",
            before_snippet=(
                "jobs:\n  build:\n    steps:\n      - run: npm run build"
            ),
            after_snippet=(
                "jobs:\n  lint:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm run lint\n  build:\n    needs: lint\n    steps:\n      - run: npm run build"
            ),
            effort_estimate="15 minutes",
            risk_level="low",
            affected_node_ids=finding.affected_node_ids,
        )


class FixNoApprovalGate(BaseRefactor):
    rule_id = "no-approval-gate"

    def suggest(self, finding: Finding, graph: CICDGraph) -> RefactorSuggestion:
        return RefactorSuggestion(
            rule_id=self.rule_id,
            finding_id=finding.id,
            description="Add a manual approval gate before production deployment",
            before_snippet=(
                "deploy-prod:\n  stage: deploy\n  script:\n    - ./deploy.sh production"
            ),
            after_snippet=(
                "approve-prod:\n  stage: approval\n  when: manual\n  allow_failure: false\n  script:\n    - echo 'Approved'\ndeploy-prod:\n  stage: deploy\n  needs: [approve-prod]\n  script:\n    - ./deploy.sh production"
            ),
            effort_estimate="15 minutes",
            risk_level="low",
            affected_node_ids=finding.affected_node_ids,
        )


class FixPrivilegedRunner(BaseRefactor):
    rule_id = "privileged-runner"

    def suggest(self, finding: Finding, graph: CICDGraph) -> RefactorSuggestion:
        return RefactorSuggestion(
            rule_id=self.rule_id,
            finding_id=finding.id,
            description="Replace privileged runner with rootless container execution",
            before_snippet=(
                "variables:\n  DOCKER_DRIVER: overlay2\nservices:\n  - docker:dind\n\nbuild:\n  image: docker:latest\n  tags:\n    - privileged"
            ),
            after_snippet=(
                "variables:\n  DOCKER_DRIVER: overlay2\n  DOCKER_HOST: tcp://docker:2376\n  DOCKER_TLS_CERTDIR: /certs\nservices:\n  - docker:dind\n\nbuild:\n  image: docker:latest\n  # Use non-privileged socket mounting instead of privileged mode"
            ),
            effort_estimate="1 hour",
            risk_level="medium",
            affected_node_ids=finding.affected_node_ids,
        )


class FixInsecureProtocol(BaseRefactor):
    rule_id = "insecure-protocol"

    def suggest(self, finding: Finding, graph: CICDGraph) -> RefactorSuggestion:
        return RefactorSuggestion(
            rule_id=self.rule_id,
            finding_id=finding.id,
            description="Replace http:// with https:// to encrypt data in transit",
            before_snippet=(
                "steps:\n  - run: curl http://registry.example.com/package.tar.gz"
            ),
            after_snippet=(
                "steps:\n  - run: curl https://registry.example.com/package.tar.gz"
            ),
            effort_estimate="5 minutes",
            risk_level="low",
            affected_node_ids=finding.affected_node_ids,
        )


class FixMissingNotification(BaseRefactor):
    rule_id = "missing-notification"

    def suggest(self, finding: Finding, graph: CICDGraph) -> RefactorSuggestion:
        return RefactorSuggestion(
            rule_id=self.rule_id,
            finding_id=finding.id,
            description="Add a failure notification step to alert on-call engineers",
            before_snippet=(
                "deploy:\n  stage: deploy\n  script:\n    - ./deploy.sh"
            ),
            after_snippet=(
                "deploy:\n  stage: deploy\n  script:\n    - ./deploy.sh\n  after_script:\n    - |\n      if [ $CI_JOB_STATUS == 'failed' ]; then\n        curl -X POST $SLACK_WEBHOOK_URL \\\n          -d '{\"text\":\"Pipeline failed: '$CI_PIPELINE_URL'\"}'\n      fi"
            ),
            effort_estimate="20 minutes",
            risk_level="low",
            affected_node_ids=finding.affected_node_ids,
        )


class FixUntaggedArtifact(BaseRefactor):
    rule_id = "untagged-artifact"

    def suggest(self, finding: Finding, graph: CICDGraph) -> RefactorSuggestion:
        return RefactorSuggestion(
            rule_id=self.rule_id,
            finding_id=finding.id,
            description="Tag artifacts with a version derived from git ref or build number",
            before_snippet=(
                "steps:\n  - run: docker build -t myapp ."
            ),
            after_snippet=(
                "steps:\n  - run: |\n      VERSION=${GITHUB_SHA::8}\n      docker build -t myapp:${VERSION} .\n      docker tag myapp:${VERSION} myapp:latest"
            ),
            effort_estimate="10 minutes",
            risk_level="low",
            affected_node_ids=finding.affected_node_ids,
        )


class FixLargePipeline(BaseRefactor):
    rule_id = "large-pipeline"

    def suggest(self, finding: Finding, graph: CICDGraph) -> RefactorSuggestion:
        return RefactorSuggestion(
            rule_id=self.rule_id,
            finding_id=finding.id,
            description="Decompose the monolithic pipeline into focused reusable workflows",
            before_snippet=(
                "# Single pipeline with 20+ steps performing build, test, lint,\n# security scan, docs, deploy-staging, deploy-prod, notify..."
            ),
            after_snippet=(
                "# ci.yml — orchestrator\njobs:\n  call-build:\n    uses: ./.github/workflows/build.yml\n  call-test:\n    uses: ./.github/workflows/test.yml\n    needs: call-build\n  call-deploy:\n    uses: ./.github/workflows/deploy.yml\n    needs: call-test"
            ),
            effort_estimate="2 hours",
            risk_level="medium",
            affected_node_ids=finding.affected_node_ids,
        )


class FixMissingBuildStage(BaseRefactor):
    rule_id = "missing-build-stage"

    def suggest(self, finding: Finding, graph: CICDGraph) -> RefactorSuggestion:
        return RefactorSuggestion(
            rule_id=self.rule_id,
            finding_id=finding.id,
            description="Add an explicit build/compile stage to make the pipeline self-documenting",
            before_snippet=(
                "stages:\n  - prepare\n  - check\n  - ship"
            ),
            after_snippet=(
                "stages:\n  - prepare\n  - build\n  - check\n  - ship\n\nbuild:\n  stage: build\n  script:\n    - make build"
            ),
            effort_estimate="10 minutes",
            risk_level="low",
            affected_node_ids=finding.affected_node_ids,
        )


# Registry of all refactor modules (original 10 + new 10)
REFACTOR_REGISTRY: dict[str, type[BaseRefactor]] = {
    cls.rule_id: cls
    for cls in [
        # Original 10
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
        # New 10
        FixNoParallelism,
        FixMissingTestStage,
        FixMissingLintStage,
        FixNoApprovalGate,
        FixPrivilegedRunner,
        FixInsecureProtocol,
        FixMissingNotification,
        FixUntaggedArtifact,
        FixLargePipeline,
        FixMissingBuildStage,
    ]
}
