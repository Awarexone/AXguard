"""GitHub App adapter — delivery interface over AXGuard core engines.

Architecture::

    AXGuard Core (engines/*)
            ↑
    GitHub Adapter (engines.github)
            ↑
    GitHub App / webhooks / Checks

Never executes repository code. Short-lived installation tokens only.
Stdlib-first; JWT signing optionally uses PyJWT/cryptography.
"""

from __future__ import annotations

from engines.github.app import (
    GitHubApp,
    GitHubAppCredentials,
    InstallationToken,
    create_app_jwt,
)
from engines.github.checks import (
    CHECK_NAME,
    CheckRunResult,
    annotations_from_findings,
    create_or_update_check_run,
    github_conclusion,
    start_in_progress_check,
)
from engines.github.client import GitHubClient, HttpGitHubClient, MockGitHubClient
from engines.github.config import (
    AIConfig,
    GitHubBotConfig,
    PolicyConfig,
    load_github_config,
    resolve_ai_credentials,
)
from engines.github.diff import DiffContext, changed_files_from_compare, extract_pr_diff
from engines.github.installation import (
    InstallationRecord,
    InstallationStore,
    handle_installation_event,
    repo_ref_authorized,
)
from engines.github.models import (
    AnalysisFailure,
    FindingLifecycle,
    FindingView,
    Mode,
    PipelineResult,
    PolicyVerdict,
    PullRequestRef,
    RepoRef,
    WebhookDelivery,
)
from engines.github.permissions import (
    MINIMUM_PERMISSIONS,
    as_manifest_permissions,
    permission_reasons,
    validate_granted,
)
from engines.github.pipeline import (
    analyze_local,
    publish_result,
    run_preship,
    run_review,
    run_watch,
    run_webhook_pipeline,
)
from engines.github.policy import map_policy_verdict, verdict_to_check_conclusion
from engines.github.privacy import EphemeralWorkspace, redact_secrets, redact_text
from engines.github.reviews import (
    COMMENT_MARKER,
    FOOTER,
    build_summary_body,
    upsert_pr_summary_comment,
)
from engines.github.server import make_webhook_handler, run_server_forever, serve_webhooks
from engines.github.untrusted import (
    UntrustedContentError,
    assert_never_execute,
    sanitize_untrusted_text,
)
from engines.github.webhooks import (
    PR_REVIEW_ACTIONS,
    ReplayCache,
    ReplayError,
    SignatureError,
    verify_and_parse,
    verify_signature,
)

__all__ = [
    "AIConfig",
    "AnalysisFailure",
    "CHECK_NAME",
    "COMMENT_MARKER",
    "CheckRunResult",
    "DiffContext",
    "EphemeralWorkspace",
    "FOOTER",
    "FindingLifecycle",
    "FindingView",
    "GitHubApp",
    "GitHubAppCredentials",
    "GitHubBotConfig",
    "GitHubClient",
    "HttpGitHubClient",
    "InstallationRecord",
    "InstallationStore",
    "InstallationToken",
    "MINIMUM_PERMISSIONS",
    "Mode",
    "MockGitHubClient",
    "PR_REVIEW_ACTIONS",
    "PipelineResult",
    "PolicyConfig",
    "PolicyVerdict",
    "PullRequestRef",
    "ReplayCache",
    "ReplayError",
    "RepoRef",
    "SignatureError",
    "UntrustedContentError",
    "WebhookDelivery",
    "analyze_local",
    "annotations_from_findings",
    "as_manifest_permissions",
    "assert_never_execute",
    "build_summary_body",
    "changed_files_from_compare",
    "create_app_jwt",
    "create_or_update_check_run",
    "extract_pr_diff",
    "github_conclusion",
    "handle_installation_event",
    "load_github_config",
    "make_webhook_handler",
    "map_policy_verdict",
    "permission_reasons",
    "publish_result",
    "redact_secrets",
    "redact_text",
    "repo_ref_authorized",
    "resolve_ai_credentials",
    "run_preship",
    "run_review",
    "run_server_forever",
    "run_watch",
    "run_webhook_pipeline",
    "sanitize_untrusted_text",
    "serve_webhooks",
    "start_in_progress_check",
    "upsert_pr_summary_comment",
    "validate_granted",
    "verdict_to_check_conclusion",
    "verify_and_parse",
    "verify_signature",
]
