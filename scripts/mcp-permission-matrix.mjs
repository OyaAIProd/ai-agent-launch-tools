#!/usr/bin/env node

import fs from "node:fs";
import crypto from "node:crypto";

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
    "  --baseline <path>      Compare against a prior JSON matrix snapshot.",
    "  --server <label>       Server label for the report.",
    "  --codex-config         Print only a Codex config.toml review snippet.",
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

function stableStringify(value) {
  if (Array.isArray(value)) {
    return `[${value.map(stableStringify).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function digest(value) {
  return crypto.createHash("sha256").update(stableStringify(value)).digest("hex");
}

function shortDigest(value) {
  return digest(value).slice(0, 12);
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
  const annotations = tool?.annotations && typeof tool.annotations === "object" ? tool.annotations : {};
  const schemaText = stringifySchemaKeys(tool?.inputSchema ?? tool?.input_schema ?? {});
  const metaText = [
    tool?._meta?.tool_configuration?.require_approval,
    tool?._meta?.tool_configuration?.server_label,
    tool?._meta?.tool_configuration?.type,
  ].filter(Boolean).join(" ");
  return {
    name,
    description,
    annotations,
    sourceDigest: shortDigest({
      name,
      description,
      inputSchema: tool?.inputSchema ?? tool?.input_schema ?? null,
      annotations,
      toolConfiguration: tool?._meta?.tool_configuration ?? null,
    }),
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
    const policyKey = `${server}.${normalized.name}`.replace(/\s+/g, "_");
    return {
      tool: normalized.name,
      policyKey,
      metadataDigest: normalized.sourceDigest,
      description: normalized.description || "(no description)",
      annotationHints: {
        readOnlyHint: normalized.annotations.readOnlyHint ?? null,
        destructiveHint: normalized.annotations.destructiveHint ?? null,
        idempotentHint: normalized.annotations.idempotentHint ?? null,
        openWorldHint: normalized.annotations.openWorldHint ?? null,
      },
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
    snapshotDigest: shortDigest({
      server,
      tools: rows.map((row) => ({
        policyKey: row.policyKey,
        metadataDigest: row.metadataDigest,
        defaultGate: row.defaultGate,
        actionClass: row.actionClass,
      })),
    }),
    totals,
    rows,
    launchRule: "New or changed MCP tools should default to ask or deny until their action class, data boundary, approval UI, receipt, and rollback path are reviewed.",
    safety: "Do not include secrets, customer records, private screenshots, payment data, OAuth tokens, cookies, API keys, card, bank, tax, payout, or full transaction identifiers in tools/list examples or reports.",
  };
}

function readBaseline(file) {
  if (!file) return null;
  const raw = fs.readFileSync(file, "utf8");
  assertNoSensitiveInput(raw);
  const parsed = JSON.parse(raw);
  const rows = Array.isArray(parsed?.rows) ? parsed.rows : Array.isArray(parsed) ? parsed : [];
  if (!rows.length) {
    throw new Error("Baseline file must be JSON output from this tool or an array of rows.");
  }
  return {
    source: file,
    snapshotDigest: parsed?.snapshotDigest ?? null,
    rows,
  };
}

function compareBaseline(matrix, baseline) {
  if (!baseline) return null;
  const before = new Map();
  for (const row of baseline.rows) {
    const key = row.policyKey || row.tool;
    if (key) before.set(key, row);
  }
  const after = new Map(matrix.rows.map((row) => [row.policyKey || row.tool, row]));
  const changes = [];

  for (const [key, row] of after.entries()) {
    const prior = before.get(key);
    if (!prior) {
      changes.push({ policyKey: key, change: "added", previousGate: null, currentGate: row.defaultGate, previousDigest: null, currentDigest: row.metadataDigest });
      continue;
    }
    if ((prior.metadataDigest ?? "") !== row.metadataDigest || (prior.defaultGate ?? "") !== row.defaultGate) {
      changes.push({
        policyKey: key,
        change: "changed",
        previousGate: prior.defaultGate ?? null,
        currentGate: row.defaultGate,
        previousDigest: prior.metadataDigest ?? null,
        currentDigest: row.metadataDigest,
      });
    }
  }

  for (const [key, row] of before.entries()) {
    if (!after.has(key)) {
      changes.push({ policyKey: key, change: "removed", previousGate: row.defaultGate ?? null, currentGate: null, previousDigest: row.metadataDigest ?? null, currentDigest: null });
    }
  }

  const totals = changes.reduce((acc, item) => {
    acc[item.change] = (acc[item.change] ?? 0) + 1;
    return acc;
  }, { added: 0, changed: 0, removed: 0 });

  return {
    baseline: baseline.source,
    previousSnapshotDigest: baseline.snapshotDigest,
    currentSnapshotDigest: matrix.snapshotDigest,
    unchanged: matrix.rows.length - totals.added - totals.changed,
    totals,
    reviewRequired: changes.length > 0,
    changes,
  };
}

function escapeCell(value) {
  return String(value).replace(/\|/g, "\\|").replace(/\n+/g, " ").trim();
}

function quoteTomlString(value) {
  return JSON.stringify(String(value));
}

function codexApprovalMode(gate) {
  if (gate === "allow") return "approve";
  return "prompt";
}

function buildCodexConfig(matrix) {
  const allowRows = matrix.rows.filter((row) => row.defaultGate === "allow");
  const askRows = matrix.rows.filter((row) => row.defaultGate === "ask");
  const denyRows = matrix.rows.filter((row) => row.defaultGate === "deny");
  const allTools = matrix.rows.map((row) => row.tool);

  const lines = [
    "# Codex MCP approval review snippet",
    `# Server label reviewed: ${matrix.server}`,
    `# Reviewed tools/list snapshot: ${matrix.snapshotDigest}`,
    "# Codex approval_mode values from the current schema: auto, prompt, approve.",
    "# Keep sandbox/read-only settings separate from MCP tool approval.",
    "",
    `[mcp_servers.${quoteTomlString(matrix.server)}]`,
    '# Add your reviewed transport here, for example command/args or url.',
    'default_tools_approval_mode = "prompt"',
  ];

  if (allTools.length) {
    lines.push(`enabled_tools = [${allTools.map(quoteTomlString).join(", ")}]`);
  }
  if (denyRows.length) {
    lines.push(`disabled_tools = [${denyRows.map((row) => quoteTomlString(row.tool)).join(", ")}]`);
  }

  for (const row of [...allowRows, ...askRows]) {
    lines.push("");
    lines.push(`[mcp_servers.${quoteTomlString(matrix.server)}.tools.${quoteTomlString(row.tool)}]`);
    lines.push(`approval_mode = ${quoteTomlString(codexApprovalMode(row.defaultGate))}`);
    lines.push(`# ${row.policyKey} digest ${row.metadataDigest}: ${row.reason}`);
  }

  const reviewNotes = [
    "Paste only after reviewing the transport, command/url, cwd, env boundary, and each tool's data boundary.",
    "Deny is represented with disabled_tools because Codex tool approval modes are auto, prompt, and approve.",
    "If the snapshot digest or any metadata digest changes, re-run review before inheriting prior approval.",
    "This snippet does not disable Codex sandboxing and does not call MCP tools.",
  ];

  return {
    server: matrix.server,
    snapshotDigest: matrix.snapshotDigest,
    allowTools: allowRows.map((row) => row.tool),
    askTools: askRows.map((row) => row.tool),
    disabledTools: denyRows.map((row) => row.tool),
    toml: lines.join("\n"),
    reviewNotes,
  };
}

function printMarkdown(matrix) {
  console.log("# MCP Permission Matrix");
  console.log("");
  console.log(`- Server: ${matrix.server}`);
  console.log(`- Tools reviewed: ${matrix.toolCount}`);
  console.log(`- Default gates: allow ${matrix.totals.allow}, ask ${matrix.totals.ask}, deny ${matrix.totals.deny}`);
  console.log(`- Snapshot digest: ${matrix.snapshotDigest}`);
  console.log(`- Generated by: ${matrix.generatedBy}`);
  console.log("");
  console.log("| Tool | Policy key | Digest | Action class | Default gate | Reason | Evidence to keep |");
  console.log("| --- | --- | --- | --- | --- | --- | --- |");
  for (const row of matrix.rows) {
    console.log(`| ${escapeCell(row.tool)} | ${escapeCell(row.policyKey)} | ${escapeCell(row.metadataDigest)} | ${escapeCell(row.actionClass)} | ${escapeCell(row.defaultGate)} | ${escapeCell(row.reason)} | ${escapeCell(row.evidence)} |`);
  }
  if (matrix.baselineComparison) {
    console.log("");
    console.log("## Snapshot Comparison");
    console.log("");
    console.log(`- Baseline: ${matrix.baselineComparison.baseline}`);
    console.log(`- Previous snapshot: ${matrix.baselineComparison.previousSnapshotDigest ?? "(not recorded)"}`);
    console.log(`- Current snapshot: ${matrix.baselineComparison.currentSnapshotDigest}`);
    console.log(`- Changes: added ${matrix.baselineComparison.totals.added}, changed ${matrix.baselineComparison.totals.changed}, removed ${matrix.baselineComparison.totals.removed}`);
    console.log(`- Review required: ${matrix.baselineComparison.reviewRequired ? "yes" : "no"}`);
    if (matrix.baselineComparison.changes.length) {
      console.log("");
      console.log("| Policy key | Change | Previous gate | Current gate | Previous digest | Current digest |");
      console.log("| --- | --- | --- | --- | --- | --- |");
      for (const change of matrix.baselineComparison.changes) {
        console.log(`| ${escapeCell(change.policyKey)} | ${escapeCell(change.change)} | ${escapeCell(change.previousGate ?? "")} | ${escapeCell(change.currentGate ?? "")} | ${escapeCell(change.previousDigest ?? "")} | ${escapeCell(change.currentDigest ?? "")} |`);
      }
    }
  }
  console.log("");
  console.log("## Launch Rule");
  console.log("");
  console.log(matrix.launchRule);
  console.log("");
  console.log("## Codex Config Review Snippet");
  console.log("");
  console.log("For Codex, `allow` maps to `approval_mode = \"approve\"`, `ask` maps to `approval_mode = \"prompt\"`, and `deny` maps to `disabled_tools`.");
  console.log("");
  console.log("```toml");
  console.log(matrix.codexConfig.toml);
  console.log("```");
  console.log("");
  for (const note of matrix.codexConfig.reviewNotes) {
    console.log(`- ${note}`);
  }
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
  const codexConfigOnly = args.includes("--codex-config");
  const outputModes = [json, markdown, codexConfigOnly].filter(Boolean).length;
  if (outputModes > 1) {
    console.error("Error: use only one output mode: --json, --markdown, or --codex-config.");
    return 1;
  }

  let raw;
  let parsed;
  let server;
  let baseline;
  try {
    raw = readInput(args);
    assertNoSensitiveInput(raw);
    parsed = JSON.parse(raw);
    server = readOption(args, "--server", parsed?.server_label ?? parsed?.serverLabel ?? "candidate MCP server");
    baseline = readBaseline(readOption(args, "--baseline", ""));
  } catch (error) {
    console.error(`Error: ${error instanceof Error ? error.message : String(error)}`);
    return 1;
  }

  let matrix;
  try {
    matrix = buildMatrix({ tools: extractTools(parsed), server });
    matrix.baselineComparison = compareBaseline(matrix, baseline);
    matrix.codexConfig = buildCodexConfig(matrix);
  } catch (error) {
    console.error(`Error: ${error instanceof Error ? error.message : String(error)}`);
    return 1;
  }

  if (json) console.log(JSON.stringify(matrix, null, 2));
  else if (codexConfigOnly) {
    console.log(matrix.codexConfig.toml);
    console.log("");
    for (const note of matrix.codexConfig.reviewNotes) {
      console.log(`# ${note}`);
    }
  }
  else printMarkdown(matrix);
  return 0;
}

process.exitCode = main();
