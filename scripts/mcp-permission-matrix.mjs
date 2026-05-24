#!/usr/bin/env node

import fs from "node:fs";

const GATES = {
  allow: {
    label: "allow",
    evidence: "Record source, purpose, data class, and untrusted-content handling.",
  },
  ask: {
    label: "ask",
    evidence: "Show action class, destination, data classes, arguments, approver, receipt, and rollback path.",
  },
  deny: {
    label: "deny",
    evidence: "Keep blocked unless a human-owned manual flow or sandboxed exception is documented.",
  },
};

const RULES = [
  {
    actionClass: "credential_or_permission",
    gate: "deny",
    patterns: [
      "api_key",
      "apikey",
      "bearer",
      "credential",
      "oauth",
      "password",
      "permission",
      "role",
      "scope",
      "secret",
      "token",
    ],
    reason: "Credential, identity, permission, or access-scope action.",
  },
  {
    actionClass: "financial_or_identity",
    gate: "deny",
    patterns: [
      "bank",
      "billing",
      "card",
      "charge",
      "checkout",
      "invoice",
      "payment",
      "payout",
      "purchase",
      "subscription",
      "tax",
      "transfer",
    ],
    reason: "Financial, tax, billing, payout, or identity-sensitive action.",
  },
  {
    actionClass: "execute_code",
    gate: "deny",
    patterns: [
      "bash",
      "command",
      "deploy",
      "exec",
      "execute",
      "install",
      "npm",
      "python",
      "run_code",
      "shell",
      "subprocess",
      "terminal",
    ],
    reason: "Code, shell, package, or deployment execution.",
  },
  {
    actionClass: "destructive_write",
    gate: "ask",
    patterns: [
      "archive",
      "cancel",
      "delete",
      "destroy",
      "drop",
      "erase",
      "purge",
      "remove",
      "revoke",
      "truncate",
    ],
    reason: "Destructive or hard-to-reverse state change.",
  },
  {
    actionClass: "external_send_or_publish",
    gate: "ask",
    patterns: [
      "comment",
      "dm",
      "email",
      "message",
      "notify",
      "post",
      "publish",
      "reply",
      "send",
      "share",
      "slack",
      "sms",
      "tweet",
    ],
    reason: "External or customer-visible communication.",
  },
  {
    actionClass: "write_record",
    gate: "ask",
    patterns: [
      "add",
      "append",
      "commit",
      "create",
      "edit",
      "insert",
      "merge",
      "patch",
      "save",
      "set",
      "submit",
      "update",
      "upload",
      "write",
    ],
    reason: "Mutates a record, file, repository, ticket, task, or system state.",
  },
  {
    actionClass: "read_private",
    gate: "ask",
    patterns: [
      "customer",
      "database",
      "drive",
      "file",
      "inbox",
      "issue",
      "private",
      "record",
      "repo",
      "sql",
      "ticket",
      "user",
      "workspace",
    ],
    reason: "May read private business context or tenant data.",
  },
  {
    actionClass: "read_public",
    gate: "allow",
    patterns: [
      "browse",
      "fetch",
      "find",
      "get",
      "list",
      "read",
      "search",
    ],
    reason: "Read-only action with no obvious private-data or mutation signal.",
  },
];

const SECRET_PATTERNS = [
  /\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9_]{12,}\b/,
  /\b(?:api[_ -]?key|oauth|bearer|password|secret|token)\b\s*[:=]\s*["']?[^"',\s]{8,}/i,
  /\b(?:\d[ -]*?){13,19}\b/,
];

function usage() {
  return [
    "Usage: mcp-permission-matrix [options]",
    "",
    "Reads an MCP tools/list JSON result and prints a non-sensitive permission matrix.",
    "",
    "Options:",
    "  --file <path>          Read JSON from a file instead of stdin.",
    "  --server <label>       Server label for the report.",
    "  --json                 Print structured JSON.",
    "  --markdown             Print Markdown. Default.",
    "  --help                 Show this help.",
    "",
    "Accepted input shapes:",
    "  { \"tools\": [...] }",
    "  { \"result\": { \"tools\": [...] } }",
    "  [ ...tools ]",
    "",
    "This tool never calls MCP tools. It only classifies metadata.",
  ].join("\n");
}

function readOption(args, name, fallback) {
  const index = args.indexOf(name);
  if (index === -1) return fallback;
  const value = args[index + 1];
  if (!value || value.startsWith("--")) {
    throw new Error(`${name} requires a value.`);
  }
  return value;
}

function readInput(args) {
  const file = readOption(args, "--file", "");
  if (file) return fs.readFileSync(file, "utf8");
  if (process.stdin.isTTY) {
    throw new Error("No input provided. Pass --file <path> or pipe tools/list JSON on stdin.");
  }
  return fs.readFileSync(0, "utf8");
}

function assertNoSensitiveInput(raw) {
  for (const pattern of SECRET_PATTERNS) {
    if (pattern.test(raw)) {
      throw new Error("Input appears to contain sensitive data. Remove secrets before generating a matrix.");
    }
  }
}

function extractTools(parsed) {
  if (Array.isArray(parsed)) return parsed;
  if (Array.isArray(parsed?.tools)) return parsed.tools;
  if (Array.isArray(parsed?.result?.tools)) return parsed.result.tools;
  if (Array.isArray(parsed?.data?.tools)) return parsed.data.tools;
  throw new Error("Could not find a tools array. Expected { tools: [...] }, { result: { tools: [...] } }, or an array.");
}

function stringifySchemaKeys(schema) {
  const keys = [];
  const properties = schema?.properties && typeof schema.properties === "object" ? schema.properties : {};
  for (const [key, value] of Object.entries(properties)) {
    keys.push(key);
    if (typeof value?.description === "string") keys.push(value.description);
    if (Array.isArray(value?.enum)) keys.push(value.enum.join(" "));
  }
  return keys.join(" ");
}

function normalizeTool(tool, index) {
  const name = typeof tool?.name === "string" && tool.name.trim() ? tool.name.trim() : `tool_${index + 1}`;
  const description = typeof tool?.description === "string" ? tool.description.trim() : "";
  const schemaText = stringifySchemaKeys(tool?.inputSchema ?? tool?.input_schema ?? {});
  const metaText = [
    tool?._meta?.tool_configuration?.require_approval,
    tool?._meta?.tool_configuration?.server_label,
    tool?._meta?.tool_configuration?.type,
  ].filter(Boolean).join(" ");
  return {
    name,
    description,
    searchable: `${name} ${description} ${schemaText} ${metaText}`.toLowerCase(),
  };
}

function hasPromptInjectionSignal(text) {
  return [
    "ignore previous",
    "ignore all previous",
    "do not tell",
    "developer message",
    "system prompt",
    "reveal secret",
    "exfiltrate",
    "override",
  ].some((term) => text.includes(term));
}

function classify(normalized) {
  if (hasPromptInjectionSignal(normalized.searchable)) {
    return {
      actionClass: "metadata_injection_signal",
      gate: "deny",
      reason: "Tool metadata contains instruction-like or exfiltration language.",
    };
  }

  for (const rule of RULES) {
    if (rule.patterns.some((pattern) => normalized.searchable.includes(pattern))) {
      return {
        actionClass: rule.actionClass,
        gate: rule.gate,
        reason: rule.reason,
      };
    }
  }

  return {
    actionClass: "unknown",
    gate: "ask",
    reason: "No confident classification. Review before first invocation.",
  };
}

function buildMatrix({ tools, server }) {
  const rows = tools.map((tool, index) => {
    const normalized = normalizeTool(tool, index);
    const classification = classify(normalized);
    return {
      tool: normalized.name,
      description: normalized.description || "(no description)",
      actionClass: classification.actionClass,
      defaultGate: classification.gate,
      reason: classification.reason,
      evidence: GATES[classification.gate].evidence,
    };
  });

  const totals = rows.reduce((acc, row) => {
    acc[row.defaultGate] = (acc[row.defaultGate] ?? 0) + 1;
    return acc;
  }, { allow: 0, ask: 0, deny: 0 });

  return {
    ok: true,
    server,
    generatedBy: "ai-agent-launch-tools mcp-permission-matrix",
    toolCount: rows.length,
    totals,
    rows,
    launchRule: "New or changed MCP tools should default to ask or deny until their action class, data boundary, approval UI, receipt, and rollback path are reviewed.",
    safety: "Do not include secrets, customer records, private screenshots, payment data, OAuth tokens, cookies, API keys, card, bank, tax, payout, or full transaction identifiers in tools/list examples or reports.",
  };
}

function escapeCell(value) {
  return String(value).replace(/\|/g, "\\|").replace(/\n+/g, " ").trim();
}

function printMarkdown(matrix) {
  console.log("# MCP Permission Matrix");
  console.log("");
  console.log(`- Server: ${matrix.server}`);
  console.log(`- Tools reviewed: ${matrix.toolCount}`);
  console.log(`- Default gates: allow ${matrix.totals.allow}, ask ${matrix.totals.ask}, deny ${matrix.totals.deny}`);
  console.log(`- Generated by: ${matrix.generatedBy}`);
  console.log("");
  console.log("| Tool | Action class | Default gate | Reason | Evidence to keep |");
  console.log("| --- | --- | --- | --- | --- |");
  for (const row of matrix.rows) {
    console.log(`| ${escapeCell(row.tool)} | ${escapeCell(row.actionClass)} | ${escapeCell(row.defaultGate)} | ${escapeCell(row.reason)} | ${escapeCell(row.evidence)} |`);
  }
  console.log("");
  console.log("## Launch Rule");
  console.log("");
  console.log(matrix.launchRule);
  console.log("");
  console.log("## Safety");
  console.log("");
  console.log(matrix.safety);
}

function main() {
  const args = process.argv.slice(2);
  if (args.includes("--help") || args.includes("-h")) {
    console.log(usage());
    return 0;
  }

  const json = args.includes("--json");
  const markdown = args.includes("--markdown");
  if (json && markdown) {
    console.error("Error: use either --json or --markdown, not both.");
    return 1;
  }

  let raw;
  let parsed;
  let server;
  try {
    raw = readInput(args);
    assertNoSensitiveInput(raw);
    parsed = JSON.parse(raw);
    server = readOption(args, "--server", parsed?.server_label ?? parsed?.serverLabel ?? "candidate MCP server");
  } catch (error) {
    console.error(`Error: ${error instanceof Error ? error.message : String(error)}`);
    return 1;
  }

  let matrix;
  try {
    matrix = buildMatrix({ tools: extractTools(parsed), server });
  } catch (error) {
    console.error(`Error: ${error instanceof Error ? error.message : String(error)}`);
    return 1;
  }

  if (json) console.log(JSON.stringify(matrix, null, 2));
  else printMarkdown(matrix);
  return 0;
}

process.exitCode = main();
