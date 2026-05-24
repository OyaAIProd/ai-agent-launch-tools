#!/usr/bin/env node

import fs from "node:fs";
import crypto from "node:crypto";

const SENSITIVE_ENV_KEY = /(?:^|[_-])(?:api[_-]?key|auth|bearer|client[_-]?secret|cookie|credential|oauth|password|private[_-]?key|secret|session|token)(?:$|[_-])/i;
const REDACTED_VALUE = /^(?:|<[^>]*>|REDACTED|redacted|\*\*\*|xxx|xxxx|\$[A-Z0-9_]+)$/;
const SHELL_COMMANDS = new Set(["bash", "cmd", "fish", "pwsh", "powershell", "sh", "zsh"]);
const PACKAGE_RUNNERS = new Set(["npx", "npm", "pnpm", "yarn", "bunx", "uvx", "pipx"]);
const RISKY_SHELL_TOKENS = [
  "&&",
  "||",
  "|",
  ";",
  "`",
  "$(",
  ">",
  "<",
  "curl",
  "wget",
  "chmod",
  "chown",
  "sudo",
  "rm -rf",
  "Invoke-WebRequest",
  "iwr",
];

function usage() {
  return [
    "Usage: mcp-config-risk [options]",
    "",
    "Reads a redacted MCP client config and prints a pre-install risk report.",
    "",
    "Options:",
    "  --file <path>          Read config from a file instead of stdin.",
    "  --label <label>        Config label for the report.",
    "  --json                 Print structured JSON.",
    "  --markdown             Print Markdown. Default.",
    "  --help                 Show this help.",
    "",
    "Accepted input:",
    "  Claude Desktop-style JSON: { \"mcpServers\": { ... } }",
    "",
    "Redact env values before use. This tool refuses likely unredacted secrets.",
    "It does not start servers, call tools, fetch URLs, or validate safety.",
  ].join("\n");
}

function readOption(args, name, fallback) {
  const index = args.indexOf(name);
  if (index === -1) return fallback;
  const value = args[index + 1];
  if (!value || value.startsWith("--")) throw new Error(`${name} requires a value.`);
  return value;
}

function readInput(args) {
  const file = readOption(args, "--file", "");
  if (file) return fs.readFileSync(file, "utf8");
  if (process.stdin.isTTY) throw new Error("No input provided. Pass --file <path> or pipe redacted config JSON on stdin.");
  return fs.readFileSync(0, "utf8");
}

function stableStringify(value) {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
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

function normalizeCommand(command) {
  if (typeof command !== "string") return "";
  const parts = command.split(/[\\/]/);
  return parts[parts.length - 1].toLowerCase().replace(/\.exe$/, "");
}

function stringifyList(values) {
  if (!Array.isArray(values)) return [];
  return values.map((value) => String(value));
}

function looksPinnedPackage(arg) {
  if (!arg || arg.startsWith("-") || arg.startsWith("/") || arg.startsWith(".") || arg.includes("\\")) return true;
  if (/^@[a-z0-9_.-]+\/[a-z0-9_.-]+@[a-z0-9_.-]+$/i.test(arg)) return true;
  if (/^[a-z0-9_.-]+@[a-z0-9_.-]+$/i.test(arg)) return true;
  if (/^(?:git\+)?https?:\/\//i.test(arg) && /(?:#|\/releases\/tag\/)/i.test(arg)) return true;
  return false;
}

function isBroadPath(arg) {
  const value = String(arg).replace(/\\/g, "/");
  return (
    value === "/" ||
    value === "~" ||
    /^\/Users\/[^/]+\/?$/.test(value) ||
    /^\/home\/[^/]+\/?$/.test(value) ||
    /^[A-Za-z]:\/Users\/[^/]+\/?$/.test(value) ||
    /\/(?:Desktop|Downloads|Documents)\/?$/.test(value)
  );
}

function containsRiskyShellToken(text) {
  return RISKY_SHELL_TOKENS.some((token) => text.includes(token));
}

function extractServers(parsed) {
  const servers = parsed?.mcpServers || parsed?.servers || parsed?.mcp_servers;
  if (!servers || typeof servers !== "object" || Array.isArray(servers)) {
    throw new Error("Could not find an MCP server object. Expected { \"mcpServers\": { ... } }.");
  }
  return Object.entries(servers).map(([name, config]) => ({ name, config: config || {} }));
}

function validateRedactedEnv(name, config) {
  const env = config?.env;
  if (!env || typeof env !== "object" || Array.isArray(env)) return;
  for (const [key, value] of Object.entries(env)) {
    if (SENSITIVE_ENV_KEY.test(String(key)) && !REDACTED_VALUE.test(String(value))) {
      throw new Error(`Server "${name}" has likely unredacted env value for "${key}". Replace it with "<redacted>" before review.`);
    }
  }
}

function addFinding(findings, severity, code, message) {
  findings.push({ severity, code, message });
}

function reviewServer(server) {
  const { name, config } = server;
  const command = normalizeCommand(config.command);
  const args = stringifyList(config.args);
  const url = typeof config.url === "string" ? config.url : "";
  const envKeys = config.env && typeof config.env === "object" && !Array.isArray(config.env) ? Object.keys(config.env).sort() : [];
  const findings = [];

  if (!command && !url) addFinding(findings, "high", "missing-entrypoint", "No command or URL entrypoint was found.");

  if (command) {
    if (SHELL_COMMANDS.has(command)) addFinding(findings, "high", "shell-wrapper", `Starts through ${command}; review the full shell string manually.`);
    if (PACKAGE_RUNNERS.has(command)) addFinding(findings, "medium", "package-runner", `Starts through ${command}; package source and update path need review.`);
    if (["node", "python", "python3", "ruby", "deno"].includes(command)) addFinding(findings, "medium", "runtime-entrypoint", `Starts a local runtime (${command}); review the script path and dependencies.`);
  }

  const joinedArgs = args.join(" ");
  if (containsRiskyShellToken(joinedArgs)) {
    addFinding(findings, "high", "risky-argument", "Arguments contain shell, network download, permission, or destructive-operation syntax.");
  }
  if (args.some((arg) => arg === "-y" || arg === "--yes")) {
    addFinding(findings, "medium", "auto-confirm-install", "Package install auto-confirm is enabled; require publisher/package review before first run.");
  }
  if (PACKAGE_RUNNERS.has(command)) {
    const candidate = args.find((arg) => !arg.startsWith("-"));
    if (candidate && !looksPinnedPackage(candidate)) {
      addFinding(findings, "medium", "unpinned-package", `Package "${candidate}" does not appear pinned to a reviewed version or immutable source.`);
    }
  }
  for (const arg of args) {
    if (isBroadPath(arg)) addFinding(findings, "medium", "broad-filesystem-scope", `Broad filesystem path "${arg}" should be narrowed before approval.`);
  }

  if (url) {
    let parsedUrl;
    try {
      parsedUrl = new URL(url);
    } catch {
      addFinding(findings, "high", "invalid-url", "Remote server URL is not a valid absolute URL.");
    }
    if (parsedUrl) {
      if (parsedUrl.username || parsedUrl.password || parsedUrl.search) {
        addFinding(findings, "high", "credentialed-url", "URL includes credentials or query parameters; move secrets out of the URL.");
      }
      if (parsedUrl.protocol !== "https:" && !["localhost", "127.0.0.1", "::1"].includes(parsedUrl.hostname)) {
        addFinding(findings, "high", "non-https-remote", "Remote MCP URL is not HTTPS.");
      }
    }
  }

  const sensitiveEnvKeys = envKeys.filter((key) => SENSITIVE_ENV_KEY.test(key));
  if (sensitiveEnvKeys.length) {
    addFinding(findings, "medium", "secret-env-required", `Requires sensitive env key names: ${sensitiveEnvKeys.join(", ")}. Keep values redacted and scope credentials tightly.`);
  }
  if (!findings.length) addFinding(findings, "low", "manual-review-required", "No obvious high-risk config pattern found; still review tool metadata before use.");

  const maxSeverity = findings.some((item) => item.severity === "high")
    ? "high"
    : findings.some((item) => item.severity === "medium")
      ? "medium"
      : "low";
  const verdict = maxSeverity === "high" ? "BLOCK" : maxSeverity === "medium" ? "CAUTION" : "REVIEW";

  return {
    name,
    verdict,
    command: command || null,
    hasUrl: Boolean(url),
    envKeys,
    configDigest: shortDigest({
      name,
      command: config.command || "",
      args,
      url: summarizeUrlForDigest(url),
      envKeys,
    }),
    findings,
  };
}

function summarizeUrlForDigest(url) {
  if (!url) return "";
  try {
    const parsed = new URL(url);
    return parsed.origin + parsed.pathname;
  } catch {
    return "invalid-url";
  }
}

function buildReport({ label, raw }) {
  const parsed = JSON.parse(raw);
  const servers = extractServers(parsed);
  for (const server of servers) validateRedactedEnv(server.name, server.config);
  const reviewedServers = servers.map(reviewServer);
  const verdict = reviewedServers.some((server) => server.verdict === "BLOCK")
    ? "BLOCK"
    : reviewedServers.some((server) => server.verdict === "CAUTION")
      ? "CAUTION"
      : "REVIEW";
  return {
    ok: true,
    label,
    generatedBy: "ai-agent-launch-tools mcp-config-risk",
    configDigest: shortDigest(reviewedServers.map((server) => ({ name: server.name, digest: server.configDigest }))),
    verdict,
    servers: reviewedServers,
    nextSteps: [
      "Do not run a new local MCP server until the command, package source, env keys, filesystem paths, and update path are reviewed.",
      "After first connection, run a tools/list metadata review and keep added or changed tools in ask/deny until reviewed.",
      "Keep real env values, OAuth tokens, cookies, customer records, payment data, and private endpoints out of public reports.",
    ],
    links: {
      toolsListImporter: "https://ai-launch-risk-check-public.vercel.app/mcp-permission-matrix-importer.html",
      trustPlanner: "https://ai-launch-risk-check-public.vercel.app/mcp-trust-verification-generator.html",
    },
  };
}

function printMarkdown(report) {
  console.log("# MCP Config Risk Report");
  console.log("");
  console.log(`- Config label: ${report.label}`);
  console.log(`- Overall verdict: ${report.verdict}`);
  console.log(`- Reviewed config digest: ${report.configDigest}`);
  console.log(`- Generated by: ${report.generatedBy}`);
  console.log("");

  for (const server of report.servers) {
    console.log(`## ${server.name}`);
    console.log("");
    console.log(`- Verdict: ${server.verdict}`);
    console.log(`- Entrypoint: ${server.command || (server.hasUrl ? "remote URL" : "missing")}`);
    console.log(`- Env keys: ${server.envKeys.length ? server.envKeys.join(", ") : "none"}`);
    console.log(`- Config digest: ${server.configDigest}`);
    console.log("");
    for (const finding of server.findings) {
      console.log(`- ${finding.severity.toUpperCase()} ${finding.code}: ${finding.message}`);
    }
    console.log("");
  }

  console.log("## Next Steps");
  console.log("");
  for (const step of report.nextSteps) console.log(`- ${step}`);
  console.log("");
  console.log("## Links");
  console.log("");
  console.log(`- tools/list importer: ${report.links.toolsListImporter}`);
  console.log(`- Trust planner: ${report.links.trustPlanner}`);
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

  try {
    const raw = readInput(args);
    const label = readOption(args, "--label", "redacted MCP config");
    const report = buildReport({ label, raw });
    if (json) console.log(JSON.stringify(report, null, 2));
    else printMarkdown(report);
    return 0;
  } catch (error) {
    console.error(`Error: ${error instanceof Error ? error.message : String(error)}`);
    return 1;
  }
}

process.exitCode = main();
