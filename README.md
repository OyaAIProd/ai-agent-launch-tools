# AI Agent Launch Tools

Small, dependency-free checks for builders launching AI agents, MCP servers, and tool-using workflows.

The first tool is a public launch-surface scanner for sites you own or have permission to test. It checks basic launch hygiene signals before you ship:

- Security headers
- Overbroad CORS
- Cookie flags
- Source-map exposure hints
- Public build variable clues

The repo also includes practical MCP/tool-call launch checklists:

- [MCP prompt-injection launch checklist](checklists/mcp-prompt-injection-launch-checklist.md)
- [MCP mutation replay guard checklist](checklists/mcp-mutation-replay-guard-checklist.md)
- [MCP trust verification checklist](checklists/mcp-trust-verification-checklist.md)

It now includes a small config reviewer and `tools/list` importer. The config reviewer turns a redacted Claude Desktop-style MCP config into a pre-install BLOCK / CAUTION / REVIEW report. The importer turns MCP tool metadata into an allow / ask / deny permission matrix with a snapshot digest for re-reviewing changed tools, without invoking any tools. It also recursively scans tool names, descriptions, and every string inside `inputSchema` for metadata/schema injection signals, including nested parameter descriptions, enum values, defaults, and titles. It flags schema-quality drift such as missing or empty `inputSchema`, object schemas without properties, missing `required` arrays, undocumented parameters, and JSON Schema `$ref` entries that some MCP clients or LLM tool adapters may not dereference before argument generation. It can also print a Codex `config.toml` review snippet that keeps sandbox settings separate from MCP tool approval.

Need the full launch workflow? The $25 AI Agent Launch Pack includes the local app, safe-intake builder, checklist, templates, sample report, and optional fixed-scope 24-hour review path:

https://ai-launch-risk-check-public.vercel.app/

## Buy Now If

The paid pack is a fit when:

- You are launching one agent workflow this week.
- The workflow can read private context or trigger tool calls.
- You need launch evidence, templates, and a safer intake path today.

Start with the free tools instead when:

- You cannot describe one workflow without secrets or customer records.
- You need legal advice, compliance certification, or penetration testing.
- You only need general reading and the free checklists already cover it.

Free readiness report:

https://ai-launch-risk-check-public.vercel.app/launch-readiness-report.html

If the scope fits, the digital pack checkout starts here:

https://ai-launch-risk-check-public.vercel.app/checkout-after-scope.html#digital-pack

## Use

Run the MCP trust verification planner:

```bash
npx --package github:kayalopez/ai-agent-launch-tools#v0.1.11 mcp-trust-check --server "candidate MCP server" --workflow "one AI workflow that can read docs and call approved tools"
```

Review a redacted MCP client config before installing or approving servers:

```bash
npx --package github:kayalopez/ai-agent-launch-tools#v0.1.11 mcp-config-risk --file claude_desktop_config.redacted.json
```

Try the included redacted example after cloning:

```bash
node scripts/mcp-config-risk.mjs --file examples/mcp-client-config-redacted.json
```

JSON output:

```bash
npx --package github:kayalopez/ai-agent-launch-tools#v0.1.11 mcp-config-risk --file claude_desktop_config.redacted.json --json
```

JSON output:

```bash
npx --package github:kayalopez/ai-agent-launch-tools#v0.1.11 mcp-trust-check --server "candidate MCP server" --json
```

Generate an MCP permission matrix from a `tools/list` JSON result:

```bash
npx --package github:kayalopez/ai-agent-launch-tools#v0.1.11 mcp-permission-matrix --file tools-list.json --server "candidate MCP server"
```

Try the included example after cloning:

```bash
node scripts/mcp-permission-matrix.mjs --file examples/mcp-tools-list-example.json
```

Try the schema-injection example after cloning:

```bash
node scripts/mcp-permission-matrix.mjs --file examples/mcp-tools-list-schema-injection-example.json
```

Try the schema-quality example after cloning:

```bash
node scripts/mcp-permission-matrix.mjs --file examples/mcp-tools-list-schema-quality-example.json
```

Try the `$ref` schema-risk example after cloning:

```bash
node scripts/mcp-permission-matrix.mjs --file examples/mcp-tools-list-schema-ref-example.json
```

JSON output:

```bash
npx --package github:kayalopez/ai-agent-launch-tools#v0.1.11 mcp-permission-matrix --file tools-list.json --json
```

Compare against a prior JSON matrix snapshot:

```bash
npx --package github:kayalopez/ai-agent-launch-tools#v0.1.11 mcp-permission-matrix --file tools-list.json --baseline previous-matrix.json
```

Print only a Codex `config.toml` review snippet:

```bash
npx --package github:kayalopez/ai-agent-launch-tools#v0.1.11 mcp-permission-matrix --file tools-list.json --server "candidate MCP server" --codex-config
```

Run the public launch-surface scanner from GitHub:

```bash
npx --package github:kayalopez/ai-agent-launch-tools#v0.1.11 public-surface-scan https://example.com
```

Or after cloning:

```bash
node scripts/public-surface-scan.mjs https://example.com
```

JSON output:

```bash
npx --package github:kayalopez/ai-agent-launch-tools#v0.1.11 public-surface-scan https://example.com --json
```

Markdown report:

```bash
npx --package github:kayalopez/ai-agent-launch-tools#v0.1.11 public-surface-scan https://example.com --markdown
```

The scanner blocks localhost, private, reserved, and non-standard-port targets. It is for public launch hygiene only, not penetration testing, vulnerability scanning, legal advice, compliance certification, or a security guarantee.

The MCP trust planner blocks obvious secret-like inputs and prints a non-sensitive launch checklist. The MCP config reviewer refuses likely unredacted secret env values, prints env key names but not values, and never starts servers, calls tools, fetches URLs, or validates safety. The MCP permission matrix importer reads metadata only, never invokes MCP tools, recursively scans nested schema strings for prompt-injection and tool-selection-bias signals, flags schema-quality drift that can make clients lose argument metadata, and now highlights `$ref`-based schemas that may need dereferencing or inlining before launch. It can compare a new metadata snapshot against a prior JSON matrix so added, removed, or changed tools re-enter review. The Codex snippet maps `allow` to `approval_mode = "approve"`, `ask` to `approval_mode = "prompt"`, and `deny` to `disabled_tools`; it does not disable sandboxing. These tools are for review planning only, not approval automation or a guarantee that a server is safe.

## Free Browser Tools

These no-login tools are live:

- Launch readiness report: https://ai-launch-risk-check-public.vercel.app/launch-readiness-report.html
- Public surface scan: https://ai-launch-risk-check-public.vercel.app/public-surface-scan.html
- MCP fixture generator: https://ai-launch-risk-check-public.vercel.app/mcp-fixture-generator.html
- MCP prompt-injection eval guide: https://ai-launch-risk-check-public.vercel.app/mcp-prompt-injection-eval.html
- MCP prompt-injection fixture library: https://ai-launch-risk-check-public.vercel.app/mcp-prompt-injection-fixtures.html
- MCP tools/list health report: https://ai-launch-risk-check-public.vercel.app/mcp-tools-list-health-report.html
- Agent tool permission matrix: https://ai-launch-risk-check-public.vercel.app/agent-tool-permission-matrix.html
- MCP first-invoke approval checklist: https://ai-launch-risk-check-public.vercel.app/mcp-first-invoke-approval-checklist.html
- MCP tool approval criteria generator: https://ai-launch-risk-check-public.vercel.app/mcp-tool-approval-criteria.html
- MCP trust verification generator: https://ai-launch-risk-check-public.vercel.app/mcp-trust-verification-generator.html
- Agent API key bootstrap checklist: https://ai-launch-risk-check-public.vercel.app/agent-api-key-bootstrap-checklist.html

The full paid pack and fixed-scope review are described on the product page:

https://ai-launch-risk-check-public.vercel.app/

## Safe Use

Only scan public URLs you own or have permission to assess. Do not paste secrets, tokens, private customer data, cookies, payment pages, internal hosts, or non-public endpoints into this tool.
