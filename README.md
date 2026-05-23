# AI Agent Launch Tools

Small, dependency-free checks for builders launching AI agents, MCP servers, and tool-using workflows.

The first tool is a public launch-surface scanner for sites you own or have permission to test. It checks basic launch hygiene signals before you ship:

- Security headers
- Overbroad CORS
- Cookie flags
- Source-map exposure hints
- Public build variable clues

The repo also includes a practical MCP/tool-call launch checklist:

- [MCP prompt-injection launch checklist](checklists/mcp-prompt-injection-launch-checklist.md)

Need the full launch workflow? The $25 AI Agent Launch Pack includes the local app, safe-intake builder, checklist, templates, sample report, and optional fixed-scope 24-hour review path:

https://ai-launch-risk-check-public.vercel.app/

If the scope fits, the digital pack checkout starts here:

https://ai-launch-risk-check-public.vercel.app/checkout-after-scope.html#digital-pack

## Use

Run directly from GitHub:

```bash
npx github:kayalopez/ai-agent-launch-tools https://example.com
```

Or after cloning:

```bash
node scripts/public-surface-scan.mjs https://example.com
```

JSON output:

```bash
npx github:kayalopez/ai-agent-launch-tools https://example.com --json
```

Markdown report:

```bash
npx github:kayalopez/ai-agent-launch-tools https://example.com --markdown
```

The scanner blocks localhost, private, reserved, and non-standard-port targets. It is for public launch hygiene only, not penetration testing, vulnerability scanning, legal advice, compliance certification, or a security guarantee.

## Free Browser Tools

These no-login tools are live:

- Launch readiness report: https://ai-launch-risk-check-public.vercel.app/launch-readiness-report.html
- Public surface scan: https://ai-launch-risk-check-public.vercel.app/public-surface-scan.html
- MCP fixture generator: https://ai-launch-risk-check-public.vercel.app/mcp-fixture-generator.html
- MCP prompt-injection eval guide: https://ai-launch-risk-check-public.vercel.app/mcp-prompt-injection-eval.html
- MCP prompt-injection fixture library: https://ai-launch-risk-check-public.vercel.app/mcp-prompt-injection-fixtures.html
- Agent tool permission matrix: https://ai-launch-risk-check-public.vercel.app/agent-tool-permission-matrix.html
- Agent API key bootstrap checklist: https://ai-launch-risk-check-public.vercel.app/agent-api-key-bootstrap-checklist.html

The full paid pack and fixed-scope review are described on the product page:

https://ai-launch-risk-check-public.vercel.app/

## Safe Use

Only scan public URLs you own or have permission to assess. Do not paste secrets, tokens, private customer data, cookies, payment pages, internal hosts, or non-public endpoints into this tool.
