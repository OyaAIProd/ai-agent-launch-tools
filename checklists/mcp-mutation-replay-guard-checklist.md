# MCP Mutation Replay Guard Checklist

Use this before shipping an MCP server or agent HTTP endpoint where a model can trigger writes, sends, deletes, workflow starts, patch application, task routing, deployment, or other state-changing actions.

The goal is simple: exact duplicate retries should be safe, different mutations should not collide, and failed originals should never be replayed as successful work.

## 1. Classify Mutations Before Runtime

- Maintain a typed tool/action catalog that marks every public mode as read-only or mutation-capable.
- Treat nested modes as separate action classes when one endpoint can read in one mode and mutate in another.
- Include workflow starts/cancels, task routing, refresh operations, patch application, file writes, sends, deletes, deployment, permission changes, credential changes, and billing-like actions.
- Fail closed when the catalog is missing, stale, malformed, or cannot classify a tool.

## 2. Build A Stable Mutation Digest

The replay key should cover the actual effective mutation, not just redacted audit text.

Include:

- Tenant, workspace, repo, session, or actor boundary.
- Tool name, action class, and mode.
- Destination or resource identifier.
- Normalized JSON arguments after defaults are applied.
- Relevant hidden defaults such as sandbox id, package name, upgrade flag, branch, target path, dry-run flag, and user-selected scope.
- Idempotency key, if the client supplied one.

Do not include:

- Secrets, tokens, raw customer records, full names, private handles, payment details, or full transaction IDs.
- Volatile timestamps that would make exact retries look different.
- Redacted audit-only payloads that omit real mutating inputs.

## 3. Handle The First Mutation Carefully

- Create the replay journal entry before dispatching the mutation.
- Mark the entry as `started`, `applied`, `failed`, or `expired`.
- Store only non-sensitive digest metadata and redacted evidence.
- Finish the journal entry in both normal return and exception paths.
- If the process crashes mid-flight, later retries should see a non-success state and avoid silently running the mutation again.

## 4. Replay Exact Duplicates Safely

For an exact duplicate:

- If the original reached `applied`, suppress re-execution and return a deterministic duplicate response.
- If the original is `started`, `pending`, `failed`, or `expired`, do not report success.
- Do not re-run the mutation path for a failed original unless a human or upstream policy explicitly creates a new mutation intent.
- Emit an audit event that says the duplicate was suppressed, including only non-sensitive digest and status data.

## 5. Reject Different Mutations With The Same Key

If the idempotency key matches but the digest differs:

- Fail closed.
- Return a conflict or validation error.
- Do not execute either mutation as a fallback.
- Log redacted evidence that shows which digest fields differed, without secrets or customer data.

## 6. Keep Read-Only Paths Unaffected

- Read-only tools and read-only modes should not create replay journal entries.
- Status checks, dry-run preview, catalog reads, and health checks should remain usable when mutation replay protection is enabled.
- Tests should prove read-only calls do not pollute the journal or block later valid mutations.

## 7. Regression Fixtures

Add fixtures for these cases:

- Successful original mutation, then exact duplicate: second call does not execute.
- Original mutation raises after the journal starts: duplicate returns a failed duplicate response and does not execute.
- Original mutation is pending or crashed: duplicate does not report success.
- Same idempotency key with different prompt, patch, destination, mode, or sandbox field: conflict, no mutation.
- Mutation-capable public path outside the main wrapper: duplicate is still guarded.
- Read-only mode on the same endpoint: no journal entry.
- Redacted audit proof: no secrets, private customer records, payment data, private handles, full names, or full transaction IDs.

## 8. Launch Evidence

Before launch, keep a non-sensitive evidence note with:

- Tool/action catalog version.
- Replay guard config and enabled scope.
- Test command names.
- Fixture ids.
- Counts for applied, duplicate-suppressed, failed-duplicate, and conflict-denied cases.
- Known unsupported tools or modes.
- Rollback plan if the guard blocks valid traffic.

## Scope Limit

This checklist is launch hygiene, not legal advice, compliance certification, penetration testing, or a security guarantee. It is meant to catch common replay/idempotency failures before a small agent or MCP workflow reaches real users.

Free browser tools and the full AI Agent Launch Pack are here:

https://ai-launch-risk-check-public.vercel.app/

