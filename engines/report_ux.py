"""Interactive approval + UX layer for the HTML audit report.

This module owns the *presentation* of AXguard's consent model. It never runs
analysis and never mutates the audit result — it only turns an already-computed,
already-redacted ``result`` dict into banner/controls/dialog markup plus the CSS
and JavaScript that gate interactive actions client-side.

Approval model (mirrors the product principle):

* **AUTO** — parse, path composition, evidence, and generating this report were
  done server-side already. No dialog; the banner just states what happened.
* **APPROVAL REQUIRED** — expanding the full attack graph, revealing full source
  context, or exporting a detailed report. These are read-only but heavier /
  more revealing, so they open a clear Approve / Cancel dialog first.
* **HIGH-RISK** — Apply Fix, Active Verification, External Share. These open a
  dialog and are then **stubbed**: this static report build never executes them.

Everything here is client-side only: no network calls, no source mutation, and
secrets are already ``[REDACTED]`` upstream (we re-run the redaction guard on the
embedded attack-path payload as belt-and-suspenders).
"""

from __future__ import annotations

import html
import json
from typing import Any

from engines.dataflow.schema import ensure_no_secret_values

# Expansion is gated behind an extra "Load Full Attack Graph?" approval once the
# graph is large enough that expanding everything is a heavier (if still local)
# operation. Kept conservative and documented so it is easy to reason about.
FULL_GRAPH_EDGE_THRESHOLD = 100
FULL_GRAPH_PATH_THRESHOLD = 20

# The six pipeline stages whose presence defines "advanced analysis" coverage.
_ADVANCED_STAGES: tuple[tuple[str, str], ...] = (
    ("application_model_summary", "surface"),
    ("dataflow_summary", "dataflow"),
    ("verification_summary", "verify"),
    ("adversary_summary", "adversary"),
    ("evidence_summary", "evidence"),
    ("attack_graph_summary", "attack-graph"),
)


def _attack_graph(result: dict) -> dict:
    return result.get("attack_graph") or {}


def analysis_coverage(result: dict) -> dict[str, Any]:
    """Compute which advanced pipeline stages ran and whether analysis is limited."""
    present = [label for key, label in _ADVANCED_STAGES if result.get(key)]
    missing = [label for key, label in _ADVANCED_STAGES if not result.get(key)]
    total = len(_ADVANCED_STAGES)
    return {
        "present": present,
        "missing": missing,
        "present_count": len(present),
        "total": total,
        "limited": bool(missing),
    }


def _graph_size(result: dict) -> tuple[int, int]:
    graph = _attack_graph(result).get("graph") or {}
    return len(graph.get("edges") or []), len(_attack_graph(result).get("paths") or [])


def is_large_graph(result: dict) -> bool:
    """True when expanding the whole graph should ask for one extra approval."""
    edges, paths = _graph_size(result)
    return edges > FULL_GRAPH_EDGE_THRESHOLD or paths > FULL_GRAPH_PATH_THRESHOLD


# ---------------------------------------------------------------------------
# Embedded attack-path payload (consumed by client JS on "View detailed path")
# ---------------------------------------------------------------------------
def attack_paths_payload(result: dict) -> dict[str, Any] | None:
    """Return a redacted, self-contained JSON payload for the embedded script.

    Only fields needed to render detailed hops/evidence client-side are copied.
    Never emits raw source snippets or secret values.
    """
    graph = _attack_graph(result)
    paths = graph.get("paths") or []
    if not paths:
        return None

    inner = graph.get("graph") or {}
    labels = {
        str(n.get("id")): str(n.get("label") or n.get("id"))
        for n in inner.get("nodes") or []
    }
    node_types = {
        str(n.get("id")): str(n.get("type") or "node") for n in inner.get("nodes") or []
    }

    out_paths: list[dict[str, Any]] = []
    for p in paths:
        hops = [str(h) for h in p.get("hops") or []]
        out_paths.append(
            {
                "id": str(p.get("id") or ""),
                "status": str(p.get("status") or "UNVERIFIED"),
                "confidence_level": str(p.get("confidence_level") or "UNKNOWN"),
                "score": p.get("score"),
                "tags": [str(t) for t in p.get("tags") or []],
                "selection": [str(s) for s in p.get("selection") or []],
                "status_reasons": [str(r) for r in p.get("status_reasons") or []],
                "hops": [{"id": h, "label": labels.get(h, h), "type": node_types.get(h, "node")} for h in hops],
                "edge_types": [str(e) for e in p.get("edge_types") or []],
                "controls_encountered": [
                    {
                        "id": str(c.get("id") or ""),
                        "effectiveness": str(c.get("effectiveness") or "unknown"),
                    }
                    for c in p.get("controls_encountered") or []
                ],
                "evidence_ref_count": len(p.get("evidence_refs") or []),
            }
        )

    edges, path_count = _graph_size(result)
    payload = {
        "generated_at": str(result.get("finished_at") or ""),
        "summary": {
            "path_count": path_count,
            "edge_count": edges,
            "node_count": len(inner.get("nodes") or []),
            "dead_end_count": len((graph.get("dead_ends") or [])),
            "by_status": (graph.get("summary") or {}).get("by_status") or {},
        },
        "thresholds": {
            "edges": FULL_GRAPH_EDGE_THRESHOLD,
            "paths": FULL_GRAPH_PATH_THRESHOLD,
            "large": is_large_graph(result),
        },
        "paths": out_paths,
    }
    # Belt-and-suspenders: never let a secret leak into the embedded JSON.
    ensure_no_secret_values(payload)
    return payload


def attack_paths_script(result: dict) -> str:
    """Embedded ``<script type="application/json">`` block, or empty string."""
    payload = attack_paths_payload(result)
    if payload is None:
        return ""
    # </script> can't appear literally inside a script element.
    body = json.dumps(payload, indent=2).replace("</", "<\\/")
    return (
        '<script type="application/json" id="axguard-attack-paths">\n'
        f"{body}\n"
        "</script>"
    )


def session_state_script() -> str:
    """The initial, scoped, client-side session state (temporary + auditable)."""
    state = {"analysis_mode": "read_only", "approved_actions": [], "activity_log": []}
    body = json.dumps(state, indent=2).replace("</", "<\\/")
    return (
        '<script type="application/json" id="axguard-session-state">\n'
        f"{body}\n"
        "</script>"
    )


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
def approval_banner_html(result: dict, target: str, when: str) -> str:
    """Top-of-report READ-ONLY analysis banner + limited-analysis notice."""
    cov = analysis_coverage(result)
    coverage_line = ""
    if cov["present"]:
        coverage_line = (
            '<div class="ab-row"><span class="ab-key">Coverage</span>'
            f'<span class="ab-val">{cov["present_count"]}/{cov["total"]} analysis stages · '
            f'{html.escape(", ".join(cov["present"]))}</span></div>'
        )

    limited_html = ""
    if cov["limited"]:
        missing = html.escape(", ".join(cov["missing"]))
        limited_html = (
            '<div class="ab-limited" id="axguard-limited">'
            '<span class="ab-limited-tag">LIMITED ANALYSIS</span> '
            f"<span>Advanced analysis not available: {missing}.</span> "
            '<button type="button" class="ax-btn ax-btn-ghost" '
            'data-axguard-action="review_available" '
            'onclick="axguardReviewAvailable()">Review Available Analysis</button>'
            "</div>"
        )

    return (
        '<section class="approval-banner" id="axguard-approval-banner" '
        'data-analysis-mode="read_only">'
        '<div class="ab-head">'
        '<span class="ab-dot" aria-hidden="true"></span>'
        '<span class="ab-mode">Analysis mode: READ-ONLY</span>'
        '<span class="ab-auto">AUTO analysis complete</span>'
        "</div>"
        '<div class="ab-grid">'
        f'<div class="ab-row"><span class="ab-key">Target</span>'
        f'<span class="ab-val"><code>{target}</code></span></div>'
        f'<div class="ab-row"><span class="ab-key">Generated</span>'
        f'<span class="ab-val">{when}</span></div>'
        f"{coverage_line}"
        "</div>"
        '<p class="ab-assurance">No source files were modified. '
        "No external requests were made.</p>"
        f"{limited_html}"
        "</section>"
    )


# ---------------------------------------------------------------------------
# Interactive controls (approval-gated) + activity panel + modal
# ---------------------------------------------------------------------------
def _action_button(
    label: str,
    action: str,
    category: str,
    *,
    hint: str = "",
) -> str:
    """A single approval-gated action button.

    Every action button routes through ``axguardRequestApproval`` — there is no
    direct ``onclick`` that runs an action without going through the gate.
    """
    hint_html = f'<span class="ax-action-hint">{html.escape(hint)}</span>' if hint else ""
    return (
        f'<div class="ax-action" data-axguard-action="{html.escape(action)}" '
        f'data-axguard-category="{html.escape(category)}" data-state="available">'
        f'<div class="ax-action-main">'
        f'<button type="button" class="ax-btn" data-axguard-gate="{html.escape(action)}" '
        f"onclick=\"axguardRequestApproval('{html.escape(action)}')\">"
        f"{html.escape(label)}</button>"
        f'<span class="ax-state-badge" data-state-label>AVAILABLE</span>'
        "</div>"
        f"{hint_html}"
        "</div>"
    )


def interactive_controls_html(result: dict) -> str:
    """Approval-gated action panel, high-risk (stubbed) panel, and activity log."""
    has_graph = bool(_attack_graph(result).get("paths"))

    approval_actions = []
    if has_graph:
        large = is_large_graph(result)
        hint = (
            "Large graph — extra approval before loading everything."
            if large
            else "Reveals every hop and evidence ref, client-side."
        )
        approval_actions.append(
            _action_button("Expand full attack graph", "expand_attack_graph", "approval", hint=hint)
        )
    approval_actions.append(
        _action_button(
            "Show full source context",
            "show_full_source",
            "approval",
            hint="Longer proprietary source excerpts (secrets stay [REDACTED]).",
        )
    )
    approval_actions.append(
        _action_button(
            "Export report",
            "export_report",
            "approval",
            hint="Summary (default) or Detailed. Local download only — no upload.",
        )
    )
    approval_actions.append(
        _action_button(
            "Run extended analysis",
            "extended_analysis",
            "approval",
            hint="Placeholder for deeper secondary analysis.",
        )
    )

    high_risk_actions = [
        _action_button(
            "Apply fix",
            "apply_fix",
            "high_risk",
            hint="Would modify source — not available in this report build.",
        ),
        _action_button(
            "Active verification",
            "active_verification",
            "high_risk",
            hint="Would send live requests — requires the CLI.",
        ),
        _action_button(
            "External share",
            "external_share",
            "high_risk",
            hint="Would transmit findings externally — disabled here.",
        ),
    ]

    return (
        '<section class="ax-actions" id="axguard-actions">'
        "<h2>Interactive actions</h2>"
        '<p class="ax-actions-note">Analysis above ran automatically (read-only). '
        "The actions below need your explicit approval — nothing runs until you approve, "
        "and Cancel is always available.</p>"
        '<div class="ax-action-group">'
        '<h3>Approval required <span class="ax-tag ax-tag-approval">read-only</span></h3>'
        f'<div class="ax-action-list">{"".join(approval_actions)}</div>'
        "</div>"
        '<div class="ax-action-group">'
        '<h3>High-risk <span class="ax-tag ax-tag-risk">stubbed</span></h3>'
        '<p class="ax-actions-note">These are never executed by the report. Approving only '
        "shows what a real run would require.</p>"
        f'<div class="ax-action-list">{"".join(high_risk_actions)}</div>'
        "</div>"
        "</section>"
        + _activity_panel_html()
        + _modal_html()
    )


def _activity_panel_html() -> str:
    return (
        '<section class="ax-activity" id="axguard-activity">'
        "<h2>Analysis activity</h2>"
        '<p class="ax-activity-note">A scoped, temporary audit trail of what you '
        "approved or expanded in this report session. No secrets are logged.</p>"
        '<ol class="ax-activity-log" id="axguard-activity-log">'
        '<li class="ax-activity-item ax-activity-seed">'
        "AUTO · read-only analysis completed server-side (parse, paths, evidence, report)."
        "</li>"
        "</ol>"
        "</section>"
    )


def _modal_html() -> str:
    """A single reusable, no-dark-pattern approval modal.

    Cancel is always rendered, always easy to reach, and never preselected as an
    action. High-risk actions are never auto-run — the modal only ever *asks*.
    """
    return (
        '<div class="ax-modal" id="axguard-modal" role="dialog" aria-modal="true" '
        'aria-labelledby="axguard-modal-title" aria-hidden="true" hidden>'
        '<div class="ax-modal-backdrop" data-axguard-cancel></div>'
        '<div class="ax-modal-card" role="document">'
        '<h3 class="ax-modal-title" id="axguard-modal-title"></h3>'
        '<p class="ax-modal-body" id="axguard-modal-body"></p>'
        '<div class="ax-modal-actions" id="axguard-modal-actions"></div>'
        "</div>"
        "</div>"
    )


# ---------------------------------------------------------------------------
# CSS + JS (returned as strings; interpolated verbatim into the report)
# ---------------------------------------------------------------------------
def report_ux_css() -> str:
    """Extra CSS — dark, Syne + IBM Plex Mono, accent teal; mobile-friendly."""
    return """
.approval-banner {
  border: 1px solid var(--line);
  border-left: 4px solid var(--accent);
  background: linear-gradient(160deg, #12201d 0%, #10161e 100%);
  padding: 18px 20px;
  margin: 18px 0 8px;
}
.approval-banner .ab-head {
  display: flex; align-items: center; gap: 10px; flex-wrap: wrap;
  font-family: Syne, system-ui, sans-serif;
}
.approval-banner .ab-dot {
  width: 9px; height: 9px; border-radius: 50%;
  background: var(--accent); box-shadow: 0 0 0 4px rgba(61,214,198,0.15);
}
.approval-banner .ab-mode {
  font-weight: 700; letter-spacing: 0.06em; text-transform: uppercase;
  font-size: 0.8rem; color: var(--accent);
}
.approval-banner .ab-auto {
  margin-left: auto; font-size: 0.7rem; letter-spacing: 0.08em;
  text-transform: uppercase; color: var(--muted);
  border: 1px solid var(--line); padding: 2px 8px;
}
.approval-banner .ab-grid { display: grid; gap: 6px; margin: 14px 0 10px; }
.approval-banner .ab-row { display: flex; gap: 12px; flex-wrap: wrap; font-size: 0.86rem; }
.approval-banner .ab-key { color: var(--muted); min-width: 84px; text-transform: uppercase; font-size: 0.72rem; letter-spacing: 0.06em; }
.approval-banner .ab-val { color: var(--ink); }
.approval-banner .ab-assurance { margin: 8px 0 0; color: #b7f0e7; font-size: 0.86rem; }
.approval-banner .ab-limited {
  margin-top: 14px; padding-top: 12px; border-top: 1px dashed var(--line);
  display: flex; gap: 10px; align-items: center; flex-wrap: wrap;
  color: var(--medium); font-size: 0.84rem;
}
.approval-banner .ab-limited-tag {
  font-family: Syne, system-ui, sans-serif; font-weight: 700;
  text-transform: uppercase; letter-spacing: 0.06em; color: var(--medium);
  border: 1px solid #5a4f1f; padding: 2px 8px; font-size: 0.72rem;
}
.ax-btn {
  font-family: "IBM Plex Mono", ui-monospace, monospace;
  background: var(--accent); color: #06231f; border: 1px solid var(--accent);
  padding: 8px 14px; font-size: 0.82rem; font-weight: 600; cursor: pointer;
}
.ax-btn:hover { filter: brightness(1.08); }
.ax-btn:focus-visible { outline: 2px solid #baf4ec; outline-offset: 2px; }
.ax-btn-ghost { background: transparent; color: var(--accent); }
.ax-btn-neutral { background: transparent; color: var(--ink); border-color: var(--line); }
.ax-btn-danger { background: transparent; color: var(--high); border-color: #5a3d1f; }
.ax-btn[disabled] { opacity: 0.5; cursor: not-allowed; }
.ax-actions, .ax-activity { margin-top: 36px; }
.ax-actions-note, .ax-activity-note { color: var(--muted); font-size: 0.86rem; margin: 0 0 14px; }
.ax-action-group { margin-top: 18px; }
.ax-action-group h3 {
  font-family: Syne, system-ui, sans-serif; font-size: 1rem; margin: 0 0 10px;
  display: flex; align-items: center; gap: 10px;
}
.ax-tag { font-size: 0.66rem; text-transform: uppercase; letter-spacing: 0.06em; padding: 2px 7px; border: 1px solid var(--line); color: var(--muted); font-family: "IBM Plex Mono", ui-monospace, monospace; font-weight: 400; }
.ax-tag-approval { color: var(--accent); border-color: #1f5a52; }
.ax-tag-risk { color: var(--high); border-color: #5a3d1f; }
.ax-action-list { display: grid; gap: 10px; }
.ax-action {
  background: var(--panel); border: 1px solid var(--line);
  border-left: 3px solid var(--line); padding: 12px 14px;
}
.ax-action[data-state="waiting_for_approval"] { border-left-color: var(--medium); }
.ax-action[data-state="running"] { border-left-color: var(--low); }
.ax-action[data-state="completed"] { border-left-color: var(--accent); }
.ax-action[data-state="blocked"] { border-left-color: var(--high); }
.ax-action[data-state="failed"] { border-left-color: var(--critical); }
.ax-action[data-state="cancelled"] { border-left-color: var(--muted); }
.ax-action-main { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
.ax-state-badge {
  margin-left: auto; font-size: 0.68rem; letter-spacing: 0.06em;
  text-transform: uppercase; color: var(--muted); border: 1px solid var(--line);
  padding: 2px 8px;
}
.ax-action-hint { display: block; color: var(--muted); font-size: 0.78rem; margin-top: 8px; }
.ax-detail { margin-top: 10px; padding: 10px 12px; background: #0a0f14; border: 1px solid var(--line); font-size: 0.82rem; color: #d5e4f5; }
.ax-detail[hidden] { display: none; }
.ax-detail ul { margin: 6px 0 0; padding-left: 1.1rem; }
.ax-activity-log { margin: 0; padding-left: 1.1rem; color: var(--muted); font-size: 0.84rem; display: grid; gap: 6px; }
.ax-activity-item { color: var(--ink); }
.ax-activity-seed { color: var(--muted); }
.ax-modal[hidden] { display: none; }
.ax-modal {
  position: fixed; inset: 0; z-index: 50;
  display: flex; align-items: center; justify-content: center; padding: 20px;
}
.ax-modal-backdrop { position: absolute; inset: 0; background: rgba(4,8,12,0.72); }
.ax-modal-card {
  position: relative; max-width: 460px; width: 100%;
  background: var(--panel); border: 1px solid var(--line); border-top: 3px solid var(--accent);
  padding: 22px 22px 18px;
}
.ax-modal-title { font-family: Syne, system-ui, sans-serif; font-size: 1.1rem; margin: 0 0 10px; }
.ax-modal-body { color: #c5d2e2; font-size: 0.88rem; margin: 0 0 18px; }
.ax-modal-actions { display: flex; gap: 10px; flex-wrap: wrap; justify-content: flex-end; }
@media (max-width: 720px) {
  .approval-banner .ab-auto { margin-left: 0; }
  .ax-action-main { align-items: flex-start; }
  .ax-state-badge { margin-left: 0; }
  .ax-modal-actions { justify-content: stretch; }
  .ax-modal-actions .ax-btn { flex: 1 1 auto; }
}
""".strip()


def report_ux_js() -> str:
    """Client-side approval gate + audit-trail engine (no network, no mutation)."""
    return r"""
(function () {
  "use strict";

  // Scoped, temporary, auditable session state. One approval never implies
  // another: approved_actions tracks each granted action individually.
  var seed = document.getElementById("axguard-session-state");
  var axguardState = { analysis_mode: "read_only", approved_actions: [], activity_log: [] };
  if (seed) {
    try { axguardState = JSON.parse(seed.textContent); } catch (e) { /* keep default */ }
  }
  window.axguardState = axguardState;

  var STATES = {
    AVAILABLE: "available",
    WAITING: "waiting_for_approval",
    RUNNING: "running",
    COMPLETED: "completed",
    BLOCKED: "blocked",
    FAILED: "failed",
    CANCELLED: "cancelled"
  };

  var HIGH_RISK = { apply_fix: 1, active_verification: 1, external_share: 1 };

  var ACTIONS = {
    expand_attack_graph: {
      title: "Load full attack graph?",
      body: "This expands every hop and evidence reference from data already embedded in this report. It is read-only and runs entirely in your browser — no network requests.",
      approve: "Approve & expand"
    },
    show_full_source: {
      title: "Show full source context?",
      body: "This reveals longer excerpts of proprietary source already included (and redacted) in this report. Secrets remain [REDACTED]. Nothing is uploaded.",
      approve: "Approve & reveal"
    },
    export_report: {
      title: "Export report",
      body: "Choose how much detail to include. Export is a local download only — nothing is uploaded anywhere.",
      approve: "Detailed"
    },
    extended_analysis: {
      title: "Run extended analysis?",
      body: "Extended secondary analysis is a placeholder in this report build. Approving records the request in the activity log but performs no extra analysis.",
      approve: "Approve"
    },
    apply_fix: {
      title: "Apply fix — high risk",
      body: "Applying a fix would modify your source files. This static report never edits code.",
      approve: "I understand",
      highRisk: true
    },
    active_verification: {
      title: "Active verification — high risk",
      body: "Active verification would send live requests to a target. This static report never makes network requests.",
      approve: "I understand",
      highRisk: true
    },
    external_share: {
      title: "External share — high risk",
      body: "Sharing would transmit findings to an external destination. This static report never sends data anywhere.",
      approve: "I understand",
      highRisk: true
    }
  };

  function logActivity(message) {
    var stamp = new Date().toISOString();
    axguardState.activity_log.push({ at: stamp, message: message });
    var log = document.getElementById("axguard-activity-log");
    if (!log) return;
    var li = document.createElement("li");
    li.className = "ax-activity-item";
    li.textContent = stamp + " · " + message;
    log.appendChild(li);
  }
  window.axguardLogActivity = logActivity;

  function actionEl(action) {
    return document.querySelector('[data-axguard-action="' + action + '"]');
  }

  function setActionState(action, state, badgeText) {
    var el = actionEl(action);
    if (!el) return;
    el.setAttribute("data-state", state);
    var badge = el.querySelector("[data-state-label]");
    if (badge) badge.textContent = badgeText || state.replace(/_/g, " ").toUpperCase();
  }
  window.axguardSetActionState = setActionState;

  // ---- Modal (single reusable dialog; Cancel is always present) ----
  var modal = document.getElementById("axguard-modal");
  var modalTitle = document.getElementById("axguard-modal-title");
  var modalBody = document.getElementById("axguard-modal-body");
  var modalActions = document.getElementById("axguard-modal-actions");
  var activeAction = null;
  var lastFocus = null;

  function closeModal() {
    if (!modal) return;
    modal.setAttribute("aria-hidden", "true");
    modal.hidden = true;
    activeAction = null;
    if (lastFocus && lastFocus.focus) lastFocus.focus();
  }

  function cancel() {
    var action = activeAction;
    closeModal();
    if (action) {
      setActionState(action, STATES.CANCELLED, "CANCELLED");
      logActivity("Cancelled: " + action);
    }
  }
  window.axguardCancel = cancel;

  // Cancel-friendly: Escape and backdrop always cancel.
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape" && modal && !modal.hidden) cancel();
  });
  if (modal) {
    modal.addEventListener("click", function (e) {
      if (e.target && e.target.hasAttribute && e.target.hasAttribute("data-axguard-cancel")) {
        cancel();
      }
    });
  }

  function makeBtn(label, className, onClick) {
    var b = document.createElement("button");
    b.type = "button";
    b.className = "ax-btn " + className;
    b.textContent = label;
    b.addEventListener("click", onClick);
    return b;
  }

  // Open the approval dialog. NEVER runs the action itself — it only asks.
  // Cancel is added first (leftmost / easy) and is never a destructive default.
  function openDialog(action, buttons) {
    if (!modal) return;
    var meta = ACTIONS[action] || { title: action, body: "Approve this action?", approve: "Approve" };
    modalTitle.textContent = meta.title;
    modalBody.textContent = meta.body;
    modalActions.innerHTML = "";
    lastFocus = document.activeElement;
    activeAction = action;

    var cancelBtn = makeBtn("Cancel", "ax-btn-neutral", cancel);
    modalActions.appendChild(cancelBtn);
    (buttons || []).forEach(function (spec) {
      modalActions.appendChild(makeBtn(spec.label, spec.className, spec.onClick));
    });

    modal.hidden = false;
    modal.setAttribute("aria-hidden", "false");
    // Focus Cancel by default — the safe choice, never the dangerous one.
    cancelBtn.focus();
  }

  function recordApproval(action) {
    if (axguardState.approved_actions.indexOf(action) === -1) {
      axguardState.approved_actions.push(action);
    }
  }

  // ---- Approval entry point for every gated action button ----
  function requestApproval(action) {
    var meta = ACTIONS[action] || {};
    setActionState(action, STATES.WAITING, "WAITING FOR APPROVAL");
    logActivity("Approval requested: " + action);

    if (action === "export_report") {
      openDialog(action, [
        { label: "Summary", className: "ax-btn-neutral", onClick: function () { runExport(action, "summary"); } },
        { label: "Detailed", className: "ax-btn", onClick: function () { runExport(action, "detailed"); } }
      ]);
      return;
    }

    openDialog(action, [
      {
        label: meta.approve || "Approve",
        className: meta.highRisk ? "ax-btn-danger" : "ax-btn",
        onClick: function () { approve(action); }
      }
    ]);
  }
  window.axguardRequestApproval = requestApproval;

  function approve(action) {
    closeModal();
    recordApproval(action);
    logActivity("Approved: " + action);

    if (HIGH_RISK[action]) {
      // High-risk is NEVER executed by this report build. Stub only.
      setActionState(action, STATES.BLOCKED, "BLOCKED");
      logActivity(action + " not available in this report build (requires CLI).");
      return;
    }

    setActionState(action, STATES.RUNNING, "RUNNING");
    try {
      if (action === "expand_attack_graph") expandAttackGraph();
      else if (action === "show_full_source") showFullSource();
      else if (action === "extended_analysis") {
        logActivity("Extended analysis is a placeholder — no additional analysis performed.");
      }
      setActionState(action, STATES.COMPLETED, "COMPLETED");
    } catch (err) {
      setActionState(action, STATES.FAILED, "FAILED");
      logActivity("Failed: " + action);
    }
  }
  window.axguardApprove = approve;

  // ---- Handlers (all read-only, client-side) ----
  function attackPaths() {
    var el = document.getElementById("axguard-attack-paths");
    if (!el) return null;
    try { return JSON.parse(el.textContent); } catch (e) { return null; }
  }

  function expandAttackGraph() {
    var data = attackPaths();
    var host = document.getElementById("axguard-attack-detail");
    if (!data || !host) return;
    var parts = [];
    (data.paths || []).forEach(function (p) {
      var hops = (p.hops || []).map(function (h) { return h.label; }).join(" \u2192 ");
      var reasons = (p.status_reasons || []).map(function (r) {
        return "<li>" + escapeHtml(r) + "</li>";
      }).join("");
      parts.push(
        '<div class="ax-detail">' +
        "<strong>" + escapeHtml(p.id) + "</strong> — " + escapeHtml(p.status) +
        " (confidence " + escapeHtml(p.confidence_level) + ", score " + escapeHtml(String(p.score)) + ")<br>" +
        "<code>" + escapeHtml(hops) + "</code>" +
        (reasons ? "<ul>" + reasons + "</ul>" : "") +
        "<div>evidence refs: " + escapeHtml(String(p.evidence_ref_count)) + "</div>" +
        "</div>"
      );
    });
    host.innerHTML = parts.join("");
    host.hidden = false;
    logActivity("Expanded full attack graph (" + (data.paths || []).length + " paths).");
  }

  function showFullSource() {
    document.querySelectorAll("[data-axguard-source-full]").forEach(function (node) {
      node.hidden = false;
    });
    logActivity("Revealed full source context (secrets remain [REDACTED]).");
  }

  // ---- Export (Summary reduced / Detailed full) — local download only ----
  function runExport(action, mode) {
    closeModal();
    recordApproval(action);
    setActionState(action, STATES.RUNNING, "RUNNING");
    try {
      var data = attackPaths() || {};
      var payload;
      if (mode === "summary") {
        payload = { analysis_mode: axguardState.analysis_mode, summary: data.summary || {}, exported: "summary" };
      } else {
        payload = {
          analysis_mode: axguardState.analysis_mode,
          summary: data.summary || {},
          paths: data.paths || [],
          activity_log: axguardState.activity_log,
          exported: "detailed"
        };
      }
      download("axguard-export-" + mode + ".json", JSON.stringify(payload, null, 2));
      setActionState(action, STATES.COMPLETED, "COMPLETED");
      logActivity("Exported " + mode + " report (local download, no upload).");
    } catch (err) {
      setActionState(action, STATES.FAILED, "FAILED");
      logActivity("Export failed.");
    }
  }
  window.axguardExport = runExport;

  function download(name, text) {
    try {
      var blob = new Blob([text], { type: "application/json" });
      var url = URL.createObjectURL(blob);
      var a = document.createElement("a");
      a.href = url;
      a.download = name;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (e) {
      // Fallback: open a data URL so nothing is uploaded regardless.
      window.open("data:application/json," + encodeURIComponent(text), "_blank");
    }
  }

  function reviewAvailable() {
    var target = document.getElementById("axguard-actions") ||
                 document.getElementById("axguard-approval-banner");
    if (target && target.scrollIntoView) target.scrollIntoView({ behavior: "smooth" });
    logActivity("Reviewed available analysis.");
  }
  window.axguardReviewAvailable = reviewAvailable;

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }
})();
""".strip()
