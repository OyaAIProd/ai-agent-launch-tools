# MCP Prompt-Injection Launch Checklist

Use this before shipping a small AI agent, MCP server, browser agent, support workflow, or tool-calling demo to real users.

## 1. Map The Tool Surface

- List every tool the agent can call.
- Mark tools that read files, write files, send messages, open URLs, run commands, call APIs, update memory, access CRM/support data, email users, or touch customer-visible state.
- Separate read-only tools from tools that change state.
- Remove any tool the first launch does not need.

## 2. Put Approval Gates Near The Action

- Do not rely only on prompt instructions for dangerous actions.
- Require explicit approval before outbound email, file writes, browser actions, command execution, external API writes, memory updates, payments, deletion, or account changes.
- Show the actual tool name and arguments before approval.
- Keep approvals narrow: one approval should not unlock unrelated future actions.

## 3. Treat Tool Output As Untrusted

- Webpages, tickets, docs, emails, comments, retrieved chunks, and MCP tool descriptions can all carry hostile instructions.
- Scan or classify untrusted content before it reaches the agent.
- Scan again immediately before action over the final tool name and arguments.
- Keep the enforcement point outside the same model that is reading the hostile content.

## 4. Build A Small Replayable Eval

Create a few fixtures that imitate realistic failure chains:

- Webpage text asks the agent to email a fake secret.
- A support ticket tells the agent to ignore policy and refund.
- A retrieved doc tells the agent to overwrite memory.
- An MCP tool description asks for broader permission than expected.
- A comment or issue body attempts to redirect a coding agent into leaking files.

Each fixture should record:

- Source of untrusted text.
- Expected safe refusal or approval prompt.
- Tool call that must be blocked.
- Evidence to capture when the guard works.

## 5. Keep Secrets Out Of The Test

- Use fictional data only.
- Do not paste customer records, OAuth tokens, API keys, cookies, private URLs, cards, bank details, tax details, or production credentials into tests.
- If a workflow requires a secret, test with a fake value and verify the real workflow keeps the value outside model-visible text.

## 6. Launch With A Narrow Scope

- Start with one workflow.
- Freeze the tool list for the first launch.
- Log only non-sensitive evidence.
- Review misses after the first real usage before adding more tools.

Free browser tools and the full AI Agent Launch Pack are here:

https://ai-launch-risk-check-public.vercel.app/
