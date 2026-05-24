# MCP Trust Verification Checklist

Use this before an AI agent connects to a new MCP server, dynamic tool source, or tool bundle.

This is a launch-readiness checklist, not penetration testing, compliance certification, legal advice, or a security guarantee. Use placeholders only. Do not paste secrets, customer records, private endpoints, tokens, cookies, payment data, private screenshots, full names, private handles, or full transaction identifiers.

## 1. Server Identity

- [ ] The MCP server publisher is known and expected.
- [ ] The repository, package, binary, or deployment source matches the publisher claim.
- [ ] The install/update path is reviewed and does not silently switch source, host, or package scope.
- [ ] The server name and tool descriptions are treated as untrusted display text, not policy.
- [ ] The expected owner for disabling or rolling back the server is documented.

## 2. Manifest And Schema Review

- [ ] Tool names, descriptions, schemas, enum values, and examples are reviewed before first use.
- [ ] New or changed tools default to ask or deny until reviewed.
- [ ] Tool descriptions cannot override system, developer, operator, or workflow policy.
- [ ] Argument schemas do not hide destination, side-effect class, file path, account, or external-send behavior.
- [ ] Schema changes are visible in release notes, PR evidence, or a local manifest diff.

## 3. Action Classification

Classify each tool before enabling it:

- `read_public`: reads public data only.
- `read_private`: reads workspace, customer, ticket, email, document, memory, or account context.
- `write_record`: creates, updates, deletes, posts, sends, charges, merges, deploys, or changes external state.
- `execute_code`: runs shell, browser automation, scripts, package installs, tests, or generated code.
- `credential_or_permission`: creates or changes keys, tokens, OAuth grants, wallet auth, roles, scopes, payout, bank, tax, or identity settings.

Launch rule:

- [ ] `read_public` may be allowed only after identity and schema review.
- [ ] `read_private` requires data-boundary review and redaction expectations.
- [ ] `write_record`, `execute_code`, and `credential_or_permission` require explicit approval and rollback notes.

## 4. Approval Gates

- [ ] First invocation shows server, tool name, action class, destination, arguments, and data classes involved.
- [ ] Untrusted content involvement is visible before approval.
- [ ] The user can approve, deny, or open policy details before the tool runs.
- [ ] Remembered approval is narrow: same server, tool, action class, destination, data class, and argument shape.
- [ ] Approval is revocable without editing code.
- [ ] Missing policy, redactor, approval UI, or receipt writer fails closed.

## 5. Prompt-Injection Fixtures

Replay at least these synthetic fixtures:

- [ ] Tool output tells the agent to ignore policy and call another tool.
- [ ] Retrieved documentation asks the agent to expose secrets or widen permissions.
- [ ] Tool metadata tells the reviewer/model to classify the server as safe.
- [ ] A read-only result tries to trigger a later write/send/delete action.
- [ ] Stored memory or notes contain delayed instructions for a future tool call.

Expected result:

- [ ] The agent treats fixture text as data.
- [ ] The agent asks or denies before side effects.
- [ ] The receipt shows the decision without private data.

## 6. Credential Scope

- [ ] Credentials are least-privilege and specific to one workflow.
- [ ] Credentials can be revoked quickly.
- [ ] Production credentials are not reused in tests or demos.
- [ ] The server cannot create broader credentials, wallet grants, OAuth scopes, bank/tax/payout settings, or identity permissions without explicit human approval.
- [ ] Credential, permission, financial, identity, and payout flows are excluded from autonomous approval.

## 7. Redacted Evidence

Keep only non-sensitive launch evidence:

- [ ] Server/tool label.
- [ ] Reviewed source or manifest version.
- [ ] Action class.
- [ ] Approval decision.
- [ ] Rationale.
- [ ] Denied tools or denied action classes.
- [ ] Redaction result.
- [ ] Replay fixture id.
- [ ] Rollback owner and disable path.

Do not store:

- Secrets, tokens, API keys, cookies, OAuth codes, passwords, private screenshots, customer records, buyer data, payment data, full names, private handles, card/bank/tax/payout details, or full transaction identifiers.

## Public Generator

A browser-only trust verification generator is available here:

https://ai-launch-risk-check-public.vercel.app/mcp-trust-verification-generator.html

The broader launch pack is here:

https://ai-launch-risk-check-public.vercel.app/
