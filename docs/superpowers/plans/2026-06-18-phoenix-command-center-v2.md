# Phoenix Command Center V2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make every visible Phoenix Guardian web UI tab call a real local backend workflow with scoped, defensive, report-ready behavior.

**Architecture:** Keep the existing zero-install Python server and static web UI. Add a small API route matrix in `tools/serve_web_ui.py`, then have `web_ui/app.js` render tab-specific controls and outputs against those routes. Use a smoke script to verify the main endpoints and guardrails.

**Tech Stack:** Python 3 standard library HTTP server, existing `phoenix_guardian.py` engine functions, static HTML/CSS/JavaScript.

---

### Task 1: Smoke Harness

**Files:**
- Create: `tools/smoke_web_ui.py`

- [ ] Add a smoke harness that checks the expected production tab endpoints on `http://127.0.0.1:8787`.
- [ ] Run it before implementation and confirm new endpoint checks fail.
- [ ] Run it after implementation and confirm all checks pass.

### Task 2: Backend Route Matrix

**Files:**
- Modify: `tools/serve_web_ui.py`

- [ ] Add JSON helpers for serializing findings.
- [ ] Add GET routes for Burp status, wordlists, web intelligence, guardrails, tool matrix, and HackerOne readiness.
- [ ] Add POST routes for bug bounty report drafts, autopilot, defensive drone, fraud report, safe WSL command, Groq chat, browser context, and finding clearing.
- [ ] Keep scope checks on any target-based workflow.

### Task 3: Real Tab UI

**Files:**
- Modify: `web_ui/index.html`
- Modify: `web_ui/app.js`
- Modify: `web_ui/styles.css`

- [ ] Replace the single generic action row with a tab-aware action toolbar.
- [ ] Add inputs for target, search/query, WSL command, fraud CSV path, chat prompt, Groq key/model, HackerOne handle, and distro.
- [ ] Render tab-specific actions and outputs.
- [ ] Update severity chart and KPI counters from live API status.

### Task 4: Verification

**Files:**
- Read/verify: `phoenix_guardian.py`
- Run: `python3 -m py_compile phoenix_guardian.py tools/serve_web_ui.py tools/smoke_web_ui.py`
- Run: `node --check web_ui/app.js`
- Run: `python3 tools/smoke_web_ui.py`

- [ ] Confirm pages load.
- [ ] Confirm endpoint smoke passes.
- [ ] Confirm unauthorized target audit remains blocked.
- [ ] Commit and push.
