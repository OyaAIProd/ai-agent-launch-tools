#!/usr/bin/env node
import dns from "node:dns/promises";
import net from "node:net";

const STANDARD_PORTS = new Set(["", "80", "443"]);

function usage() {
  return [
    "Usage: node scripts/public-surface-scan.mjs <https-url> [--json|--markdown]",
    "",
    "Scans only public http(s) URLs you own or have permission to test.",
  ].join("\n");
}

function ipToInt(ip) {
  return ip.split(".").reduce((acc, part) => (acc << 8) + Number(part), 0) >>> 0;
}

function inRange(ip, cidr) {
  const [base, bitsText] = cidr.split("/");
  const bits = Number(bitsText);
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (ipToInt(ip) & mask) === (ipToInt(base) & mask);
}

function isBlockedIp(address) {
  if (net.isIP(address) === 4) {
    return [
      "0.0.0.0/8",
      "10.0.0.0/8",
      "100.64.0.0/10",
      "127.0.0.0/8",
      "169.254.0.0/16",
      "172.16.0.0/12",
      "192.0.0.0/24",
      "192.0.2.0/24",
      "192.168.0.0/16",
      "198.18.0.0/15",
      "198.51.100.0/24",
      "203.0.113.0/24",
      "224.0.0.0/4",
      "240.0.0.0/4",
    ].some((cidr) => inRange(address, cidr));
  }

  if (net.isIP(address) === 6) {
    const normalized = address.toLowerCase();
    return (
      normalized === "::1" ||
      normalized.startsWith("fc") ||
      normalized.startsWith("fd") ||
      normalized.startsWith("fe80:")
    );
  }

  return true;
}

async function assertPublicTarget(rawUrl) {
  let url;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new Error("Target must be a valid URL.");
  }

  if (!["http:", "https:"].includes(url.protocol)) {
    throw new Error("Only http and https URLs are supported.");
  }
  if (url.username || url.password) {
    throw new Error("URLs with embedded credentials are blocked.");
  }
  if (!STANDARD_PORTS.has(url.port)) {
    throw new Error("Non-standard ports are blocked.");
  }

  const host = url.hostname.toLowerCase();
  if (host === "localhost" || host.endsWith(".localhost")) {
    throw new Error("Localhost targets are blocked.");
  }

  const records = net.isIP(host)
    ? [{ address: host }]
    : await dns.lookup(host, { all: true, verbatim: true });
  if (!records.length || records.some((record) => isBlockedIp(record.address))) {
    throw new Error("Private, local, and reserved targets are blocked.");
  }

  return url;
}

function hasHeader(headers, name) {
  return headers.has(name);
}

function scoreFindings(findings) {
  const penalties = findings.reduce((total, finding) => total + finding.penalty, 0);
  return Math.max(0, 100 - penalties);
}

async function scan(rawUrl) {
  const url = await assertPublicTarget(rawUrl);
  const response = await fetch(url, {
    redirect: "follow",
    headers: {
      "user-agent": "ai-agent-launch-tools/0.1 public-surface-scan",
    },
  });
  const text = await response.text();
  const headers = response.headers;
  const findings = [];

  const requiredHeaders = [
    ["content-security-policy", "Missing Content-Security-Policy.", 14],
    ["x-content-type-options", "Missing X-Content-Type-Options.", 8],
    ["x-frame-options", "Missing X-Frame-Options.", 8],
    ["referrer-policy", "Missing Referrer-Policy.", 6],
    ["permissions-policy", "Missing Permissions-Policy.", 5],
  ];

  for (const [header, message, penalty] of requiredHeaders) {
    if (!hasHeader(headers, header)) findings.push({ severity: "medium", message, penalty });
  }

  const cors = headers.get("access-control-allow-origin") || "";
  if (cors.trim() === "*") {
    findings.push({
      severity: "high",
      message: "Access-Control-Allow-Origin is wildcard.",
      penalty: 14,
    });
  }

  const setCookie = headers.getSetCookie ? headers.getSetCookie() : [];
  for (const cookie of setCookie) {
    if (!/;\s*httponly/i.test(cookie)) {
      findings.push({ severity: "medium", message: "Cookie lacks HttpOnly.", penalty: 5 });
    }
    if (!/;\s*secure/i.test(cookie) && url.protocol === "https:") {
      findings.push({ severity: "medium", message: "Cookie lacks Secure.", penalty: 5 });
    }
    if (!/;\s*samesite=/i.test(cookie)) {
      findings.push({ severity: "low", message: "Cookie lacks SameSite.", penalty: 3 });
    }
  }

  if (/sourceMappingURL=|\.map(?:["')\s>]|$)|\/_next\/static\/[^"'\s>]+\.map/.test(text)) {
    findings.push({ severity: "medium", message: "Source-map hint found in HTML.", penalty: 8 });
  }
  if (/NEXT_PUBLIC_|PUBLIC_[A-Z0-9_]*KEY|VITE_[A-Z0-9_]*KEY/.test(text)) {
    findings.push({ severity: "medium", message: "Public build-variable clue found.", penalty: 8 });
  }

  return {
    ok: true,
    target: url.toString(),
    status: response.status,
    finalUrl: response.url,
    score: scoreFindings(findings),
    findings,
  };
}

function printText(result) {
  console.log(`Target: ${result.target}`);
  console.log(`HTTP status: ${result.status}`);
  console.log(`Score: ${result.score}/100`);
  if (!result.findings.length) {
    console.log("Findings: none");
    return;
  }
  console.log("Findings:");
  for (const finding of result.findings) {
    console.log(`- [${finding.severity}] ${finding.message}`);
  }
}

function printMarkdown(result) {
  console.log(`# Public Launch Surface Scan`);
  console.log("");
  console.log(`- Target: ${result.target}`);
  console.log(`- Final URL: ${result.finalUrl}`);
  console.log(`- HTTP status: ${result.status}`);
  console.log(`- Score: ${result.score}/100`);
  console.log("");

  if (!result.findings.length) {
    console.log("## Findings");
    console.log("");
    console.log("No launch-surface findings were detected by this lightweight check.");
    console.log("");
  } else {
    console.log("## Findings");
    console.log("");
    for (const finding of result.findings) {
      console.log(`- **${finding.severity}**: ${finding.message}`);
    }
    console.log("");
  }

  console.log("## Scope");
  console.log("");
  console.log(
    "This is a lightweight public launch hygiene scan. It is not penetration testing, compliance certification, legal advice, or a security guarantee."
  );
  console.log("");
  console.log("## Next Checks");
  console.log("");
  console.log("- Confirm the scanned URL is owned by you or explicitly approved for testing.");
  console.log("- Review data exposure, tool permissions, logging, rollback, and human approval boundaries before launch.");
  console.log("- Do not paste secrets, customer data, private endpoints, cookies, or payment details into public tools.");
}

async function main() {
  const args = process.argv.slice(2);
  const json = args.includes("--json");
  const markdown = args.includes("--markdown");
  const target = args.find((arg) => !["--json", "--markdown"].includes(arg));

  if (!target || args.includes("--help") || args.includes("-h")) {
    console.log(usage());
    return target ? 0 : 1;
  }

  if (json && markdown) {
    console.error("Error: use either --json or --markdown, not both.");
    return 1;
  }

  try {
    const result = await scan(target);
    if (json) console.log(JSON.stringify(result, null, 2));
    else if (markdown) printMarkdown(result);
    else printText(result);
    return 0;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (json) console.log(JSON.stringify({ ok: false, error: message }, null, 2));
    else console.error(`Error: ${message}`);
    return 1;
  }
}

process.exitCode = await main();
