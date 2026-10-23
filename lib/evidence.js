/**
 * `policyseed evidence`: a read-only SOC 2 evidence collector.
 *
 * It runs the cloud CLIs the user already has installed and authenticated (aws, gcloud, gh) with
 * fixed, read-only argument arrays, and saves each result as timestamped JSON plus an INDEX.md
 * that maps every file to a SOC 2 criterion and the auditor question it answers.
 *
 * Safety rules, enforced here rather than left to each collector:
 * - Commands run through child_process.execFile with `shell: false` and an argument array. User
 *   input (--repo, --org, --project) and values read from CLI output (bucket names, trail ARNs,
 *   the default branch) only ever become whole argv elements or parts of an API path. Nothing is
 *   interpolated into a shell string.
 * - Every collector is a read: AWS Describe/Get/List actions (plus iam:GenerateCredentialReport,
 *   which IAM classifies as a Read action), gcloud list/get-iam-policy, and `gh api` GET requests
 *   with no -f/-F fields (fields would switch gh to POST).
 * - Everything written to disk or printed goes through the redactor first.
 */
import { execFile } from "node:child_process";
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export const PROVIDERS = ["aws", "gcp", "github"];

/** Executable for each provider. */
export const PROVIDER_CLI = { aws: "aws", gcp: "gcloud", github: "gh" };

/** Read-only version probe per CLI. Its first output line is recorded as the CLI version. */
const VERSION_ARGS = { aws: ["--version"], gcloud: ["--version"], gh: ["--version"] };

export const DEFAULT_MAX_BUCKETS = 50;
const COMMAND_TIMEOUT_MS = 120_000;
const MAX_OUTPUT_BYTES = 128 * 1024 * 1024;

/**
 * Environment for every child process: no pagers, no prompts, no colors, no update checks. A CLI
 * that wants to ask the user something fails instead of hanging (stdin is also closed).
 */
const CLI_ENV = {
  AWS_PAGER: "",
  AWS_CLI_AUTO_PROMPT: "off",
  GH_PAGER: "",
  GH_PROMPT_DISABLED: "1",
  GH_NO_UPDATE_NOTIFIER: "1",
  CLOUDSDK_CORE_DISABLE_PROMPTS: "1",
  NO_COLOR: "1",
};

/** What a placeholder in a collector's args needs, for dry-run output and "not collected" reasons. */
const PLACEHOLDERS = {
  repo: { shown: "<owner/name>", missing: "needs --repo owner/name" },
  org: { shown: "<org>", missing: "needs --org name" },
  branch: { shown: "<default-branch>", missing: "default branch unknown because github-repo-settings was not collected" },
  project: { shown: "<project>", missing: "needs --project, or a default project from `gcloud config set project`" },
};

/* ---------------------------------------------------------------------------------------------
 * Collector table
 *
 * Each entry: id, provider, criteria (the first one names the file), description (what the file
 * shows), question (what an auditor asks that it answers), args (argv after the CLI name; {repo},
 * {org}, {branch} and {project} are filled in per run), and redact (the redaction rule: "secrets"
 * always applies; dropKeys removes fields the evidence does not need).
 *
 * Optional: parse ("json" default, "json-pages" for gh --paginate), before (a command that must
 * report readiness first), each (follow-up commands per item of the output, capped), absentOn (an
 * error that is itself the evidence, such as "no password policy is set"), transform, note and
 * provides (values later collectors need, such as the default branch).
 * ------------------------------------------------------------------------------------------- */

export const COLLECTORS = [
  /* ----------------------------------------- GitHub ----------------------------------------- */
  {
    id: "github-repo-settings",
    provider: "github",
    criteria: ["CC7.1"],
    description: "Repository settings, including default branch, visibility and the security_and_analysis block (secret scanning, push protection, Dependabot security updates).",
    question: "Is secret scanning turned on for the repository, and is the default branch the one you protect?",
    args: ["api", "repos/{repo}"],
    redact: { rule: "secrets" },
    provides: { branch: (out) => (out && typeof out.default_branch === "string" ? out.default_branch : undefined) },
    note: (out) =>
      out && out.security_and_analysis === undefined
        ? "GitHub returns security_and_analysis only to repository admins and organization owners or security managers; this token did not get it."
        : undefined,
  },
  {
    id: "github-branch-protection",
    provider: "github",
    criteria: ["CC8.1"],
    description: "Classic branch protection on the default branch: required reviews, status checks, admin enforcement, force-push and deletion rules.",
    question: "Are changes to the production branch reviewed and checked before they merge?",
    args: ["api", "repos/{repo}/branches/{branch}/protection"],
    redact: { rule: "secrets" },
    absentOn: {
      pattern: /Branch not protected/i,
      output: { protected: false },
      note: "The default branch has no classic branch protection rule. Rulesets may still apply; see github-branch-rules.",
    },
  },
  {
    id: "github-branch-rules",
    provider: "github",
    criteria: ["CC8.1"],
    description: "Every active ruleset rule (repository and organization rulesets) that applies to the default branch.",
    question: "Which rules, such as required pull requests and blocked force pushes, are enforced on the production branch?",
    args: ["api", "--paginate", "repos/{repo}/rules/branches/{branch}"],
    parse: "json-pages",
    redact: { rule: "secrets" },
  },
  {
    id: "github-dependabot-alerts",
    provider: "github",
    criteria: ["CC7.1"],
    description: "Whether Dependabot alerts are enabled for the repository.",
    question: "How do you find out about known vulnerabilities in your dependencies?",
    args: ["api", "repos/{repo}/vulnerability-alerts"],
    redact: { rule: "secrets" },
    transform: () => ({ dependabot_alerts_enabled: true }),
    absentOn: {
      pattern: /HTTP 404/,
      output: { dependabot_alerts_enabled: false },
      note: "GitHub answers 404 both when Dependabot alerts are disabled and when the token lacks admin read access to the repository. Confirm in Settings > Code security if this is unexpected.",
    },
  },
  {
    id: "github-org-2fa",
    provider: "github",
    criteria: ["CC6.1"],
    description: "Organization settings, including two_factor_requirement_enabled (members must use 2FA).",
    question: "Is two-factor authentication required for everyone with access to your source code?",
    args: ["api", "orgs/{org}"],
    redact: { rule: "secrets", dropKeys: ["billing_email"] },
    note: (out) =>
      out && (out.two_factor_requirement_enabled === undefined || out.two_factor_requirement_enabled === null)
        ? "GitHub returns two_factor_requirement_enabled only to organization owners; this token did not get it."
        : undefined,
  },
  {
    id: "github-org-admins",
    provider: "github",
    criteria: ["CC6.3"],
    description: "Members of the organization with the admin (owner) role.",
    question: "Who holds administrative access to your source code organization, and is that list appropriate?",
    args: ["api", "--paginate", "orgs/{org}/members?role=admin"],
    parse: "json-pages",
    redact: { rule: "secrets" },
  },

  /* ------------------------------------------ AWS ------------------------------------------- */
  {
    id: "aws-iam-account-summary",
    provider: "aws",
    criteria: ["CC6.1"],
    description: "IAM account summary, including AccountMFAEnabled (root user MFA) and AccountAccessKeysPresent (root access keys).",
    question: "Does the root user have MFA, and does it have no access keys?",
    args: ["iam", "get-account-summary", "--output", "json"],
    redact: { rule: "secrets" },
  },
  {
    id: "aws-iam-credential-report",
    provider: "aws",
    criteria: ["CC6.1", "CC6.2"],
    description: "IAM credential report, reduced to MFA, password and access-key age columns per user.",
    question: "Do all IAM users with a console password have MFA, and are access keys rotated and unused keys removed?",
    before: {
      args: ["iam", "generate-credential-report", "--output", "json"],
      ready: (out) => out && out.State === "COMPLETE",
      attempts: 10,
      delayMs: 2000,
    },
    args: ["iam", "get-credential-report", "--output", "json"],
    redact: { rule: "secrets" },
    transform: (out, { now }) => credentialReport(out, now),
  },
  {
    id: "aws-iam-password-policy",
    provider: "aws",
    criteria: ["CC6.1"],
    description: "IAM account password policy: minimum length, character classes, rotation and reuse rules.",
    question: "What password requirements apply to IAM users?",
    args: ["iam", "get-account-password-policy", "--output", "json"],
    redact: { rule: "secrets" },
    absentOn: {
      pattern: /NoSuchEntity/,
      output: { PasswordPolicy: null },
      note: "No custom account password policy is set; IAM applies its default policy.",
    },
  },
  {
    id: "aws-cloudtrail",
    provider: "aws",
    criteria: ["CC7.2"],
    description: "CloudTrail trails (multi-region, log file validation, KMS key) and each trail's status (IsLogging, latest delivery).",
    question: "Is API activity in the account logged, across all regions, and is logging actually on?",
    args: ["cloudtrail", "describe-trails", "--output", "json"],
    redact: { rule: "secrets" },
    each: {
      items: (out) => (Array.isArray(out?.trailList) ? out.trailList.map((t) => t.TrailARN).filter(isString) : []),
      placeholder: "<trail-arn>",
      resultKey: "trail_status",
      commands: {
        status: { args: (arn) => ["cloudtrail", "get-trail-status", "--name", arn, "--output", "json"] },
      },
    },
  },
  {
    id: "aws-ebs-default-encryption",
    provider: "aws",
    criteria: ["CC6.1"],
    description: "Whether new EBS volumes are encrypted by default, in the CLI's configured region.",
    question: "Are new disks encrypted at rest without anyone having to remember to?",
    args: ["ec2", "get-ebs-encryption-by-default", "--output", "json"],
    redact: { rule: "secrets" },
  },
  {
    id: "aws-s3-buckets",
    provider: "aws",
    criteria: ["CC6.1", "CC6.6"],
    description: "S3 buckets with each bucket's default encryption and Block Public Access settings (capped by --max-buckets).",
    question: "Is data in S3 encrypted at rest, and are buckets blocked from public access?",
    args: ["s3api", "list-buckets", "--output", "json"],
    redact: { rule: "secrets" },
    each: {
      items: (out) => (Array.isArray(out?.Buckets) ? out.Buckets.map((b) => b.Name).filter(isString) : []),
      limit: "maxBuckets",
      placeholder: "<bucket>",
      resultKey: "bucket_settings",
      commands: {
        encryption: {
          args: (bucket) => ["s3api", "get-bucket-encryption", "--bucket", bucket, "--output", "json"],
          absentOn: { pattern: /ServerSideEncryptionConfigurationNotFoundError/, output: null, note: "No default encryption configuration." },
        },
        public_access_block: {
          args: (bucket) => ["s3api", "get-public-access-block", "--bucket", bucket, "--output", "json"],
          absentOn: { pattern: /NoSuchPublicAccessBlockConfiguration/, output: null, note: "No bucket-level Block Public Access configuration." },
        },
      },
    },
  },
  {
    id: "aws-rds-instances",
    provider: "aws",
    criteria: ["CC6.1", "A1.2"],
    description: "RDS DB instances with StorageEncrypted, KmsKeyId, BackupRetentionPeriod, MultiAZ, PubliclyAccessible and DeletionProtection, in the CLI's configured region.",
    question: "Are databases encrypted at rest and backed up automatically, and for how long are backups kept?",
    args: [
      "rds", "describe-db-instances",
      "--query",
      "DBInstances[].{DBInstanceIdentifier:DBInstanceIdentifier,Engine:Engine,StorageEncrypted:StorageEncrypted,KmsKeyId:KmsKeyId,BackupRetentionPeriod:BackupRetentionPeriod,MultiAZ:MultiAZ,PubliclyAccessible:PubliclyAccessible,DeletionProtection:DeletionProtection}",
      "--output", "json",
    ],
    redact: { rule: "secrets" },
  },

  /* ---------------------------------------- Google Cloud ------------------------------------ */
  {
    id: "gcp-project-iam-policy",
    provider: "gcp",
    criteria: ["CC6.3"],
    description: "The project's IAM policy: every role binding and its members.",
    question: "Who has which role on the production project, and is access least-privilege?",
    args: ["projects", "get-iam-policy", "{project}", "--format=json"],
    redact: { rule: "secrets" },
  },
  {
    id: "gcp-logging-sinks",
    provider: "gcp",
    criteria: ["CC7.2"],
    description: "Cloud Logging sinks in the project: where logs are exported and with which filter.",
    question: "Where are logs kept, and are they exported somewhere durable?",
    args: ["logging", "sinks", "list", "--project", "{project}", "--format=json"],
    redact: { rule: "secrets" },
  },
  {
    id: "gcp-sql-instances",
    provider: "gcp",
    criteria: ["A1.2", "CC6.1"],
    description: "Cloud SQL instances, including settings.backupConfiguration (automated backups, point-in-time recovery, retention).",
    question: "Are managed databases backed up automatically, and can they be restored to a point in time?",
    args: ["sql", "instances", "list", "--project", "{project}", "--format=json"],
    redact: { rule: "secrets" },
  },
  {
    id: "gcp-compute-disks",
    provider: "gcp",
    criteria: ["CC6.1"],
    description: "Compute Engine disks. Google encrypts every disk at rest; diskEncryptionKey appears when a customer-managed or customer-supplied key is used.",
    question: "Are disks encrypted at rest, and with whose keys?",
    args: ["compute", "disks", "list", "--project", "{project}", "--format=json"],
    redact: { rule: "secrets" },
  },
  {
    id: "gcp-organizations",
    provider: "gcp",
    criteria: ["CC6.1"],
    description: "Google Cloud organizations the account can see.",
    question: "Which Google Cloud organization is in scope, so organization-level IAM and policies apply to its projects?",
    args: ["organizations", "list", "--format=json"],
    redact: { rule: "secrets" },
  },
];

function isString(v) {
  return typeof v === "string" && v.length > 0;
}

/* ---------------------------------------------------------------------------------------------
 * Redaction
 * ------------------------------------------------------------------------------------------- */

/** Object keys whose values are always removed, whatever they hold. */
const SECRET_KEY_RE =
  /^(?:aws_?)?(?:secret_?access_?key|session_?token|security_?token|access_?token|refresh_?token|id_?token|client_?secret|private_?key(?:_?data)?|password|passwd|secret|token)$/i;

/** Values that look like credentials anywhere in a string. */
const SECRET_PATTERNS = [
  { name: "private-key", re: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g },
  { name: "github-token", re: /\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})\b/g },
  { name: "aws-access-key-id", re: /\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b/g },
  { name: "aws-session-token", re: /\b(?:IQoJb3JpZ2luX2Vj|FwoGZXIvYXdz|AQoDYXdz)[A-Za-z0-9/+=]{20,}/g },
  { name: "google-api-key", re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { name: "google-oauth-token", re: /\bya29\.[0-9A-Za-z_-]{20,}/g },
  { name: "slack-token", re: /\bxox[abposr]-[0-9A-Za-z-]{10,}/g },
  { name: "jwt", re: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g },
];

/** `secret_key=...`, `token: ...` and similar assignments inside text: keep the name, drop the value. */
const ASSIGNMENT_RE =
  /\b((?:aws_)?(?:secret(?:_access)?_key|session_token|password|passwd|api[_-]?key|access[_-]?token|client[_-]?secret|token))(\s*[:=]\s*)(["']?)[^\s"',;&]{8,}/gi;

/** A 12-digit AWS account ID (GCP project numbers have the same shape). */
const ACCOUNT_ID_RE = /(?<!\d)\d{8}(\d{4})(?!\d)/g;

/**
 * Build a redactor. `scrub` cleans one string; `value` walks parsed JSON, dropping secret-named
 * keys and the collector's dropKeys, and scrubbing every string (keys included). `count` is the
 * number of values removed so far.
 */
export function createRedactor({ redactAccountIds = false } = {}) {
  let count = 0;

  function scrub(text) {
    if (typeof text !== "string" || text === "") return text;
    let out = text;
    for (const { name, re } of SECRET_PATTERNS) {
      out = out.replace(re, () => {
        count++;
        return `[REDACTED:${name}]`;
      });
    }
    out = out.replace(ASSIGNMENT_RE, (_m, key, sep, quote) => {
      count++;
      return `${key}${sep}${quote}[REDACTED]`;
    });
    if (redactAccountIds) out = out.replace(ACCOUNT_ID_RE, (_m, last4) => `********${last4}`);
    return out;
  }

  function value(v, dropKeys = []) {
    if (typeof v === "string") return scrub(v);
    if (Array.isArray(v)) return v.map((x) => value(x, dropKeys));
    if (v && typeof v === "object") {
      const out = {};
      for (const [k, x] of Object.entries(v)) {
        if (dropKeys.includes(k)) continue;
        if (SECRET_KEY_RE.test(k) && x !== null && x !== "" && typeof x !== "boolean") {
          count++;
          out[scrub(k)] = "[REDACTED]";
          continue;
        }
        out[scrub(k)] = value(x, dropKeys);
      }
      return out;
    }
    return v;
  }

  return { scrub, value, get count() { return count; } };
}

/* ---------------------------------------------------------------------------------------------
 * Output parsing
 * ------------------------------------------------------------------------------------------- */

/**
 * Parse stdout that may hold several JSON documents back to back, which is what `gh api
 * --paginate` prints for paginated arrays on gh versions without --slurp. Arrays are flattened.
 */
export function parseJsonPages(text) {
  const docs = [];
  let depth = 0;
  let inString = false;
  let escaped = false;
  let start = -1;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inString) {
      if (escaped) escaped = false;
      else if (c === "\\") escaped = true;
      else if (c === '"') inString = false;
      continue;
    }
    if (c === '"') {
      inString = true;
      if (depth === 0 && start === -1) start = i;
    } else if (c === "{" || c === "[") {
      if (depth === 0) start = i;
      depth++;
    } else if (c === "}" || c === "]") {
      depth--;
      if (depth === 0) {
        docs.push(JSON.parse(text.slice(start, i + 1)));
        start = -1;
      }
    } else if (depth === 0 && !/\s/.test(c)) {
      throw new Error("unexpected text between JSON documents");
    }
  }
  if (depth !== 0 || inString) throw new Error("truncated JSON");
  if (docs.length === 0) return null;
  if (docs.every(Array.isArray)) return docs.flat();
  return docs.length === 1 ? docs[0] : docs;
}

function parseOutput(stdout, mode) {
  const text = stdout.trim();
  if (text === "") return null;
  if (mode === "json-pages") return parseJsonPages(text);
  return JSON.parse(text);
}

/** Minimal RFC 4180 CSV parser (quoted fields, doubled quotes). */
export function parseCsv(text) {
  const rows = [];
  let row = [];
  let field = "";
  let quoted = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quoted) {
      if (c === '"' && text[i + 1] === '"') {
        field += '"';
        i++;
      } else if (c === '"') quoted = false;
      else field += c;
    } else if (c === '"') quoted = true;
    else if (c === ",") {
      row.push(field);
      field = "";
    } else if (c === "\n" || c === "\r") {
      if (c === "\r" && text[i + 1] === "\n") i++;
      row.push(field);
      rows.push(row);
      row = [];
      field = "";
    } else field += c;
  }
  if (field !== "" || row.length) {
    row.push(field);
    rows.push(row);
  }
  return rows.filter((r) => r.length > 1 || r[0] !== "");
}

/** Credential report columns kept in the evidence file. */
export const CREDENTIAL_REPORT_COLUMNS = [
  "user", "arn", "user_creation_time",
  "password_enabled", "password_last_used", "password_last_changed", "mfa_active",
  "access_key_1_active", "access_key_1_last_rotated", "access_key_1_last_used_date",
  "access_key_2_active", "access_key_2_last_rotated", "access_key_2_last_used_date",
];

function ageDays(isoDate, now) {
  const t = Date.parse(isoDate);
  if (Number.isNaN(t)) return null;
  return Math.floor((now.getTime() - t) / 86400000);
}

/** Decode `aws iam get-credential-report` output and keep the MFA, password and key-age columns. */
export function credentialReport(out, now = new Date()) {
  if (!out || typeof out.Content !== "string") throw new Error("credential report has no Content");
  let csv = Buffer.from(out.Content, "base64").toString("utf8");
  if (!csv.startsWith("user,")) csv = out.Content; // some CLI versions print the CSV undecoded
  const [header, ...rows] = parseCsv(csv);
  if (!header || header[0] !== "user") throw new Error("credential report is not the expected CSV");
  const users = rows.map((cells) => {
    const all = Object.fromEntries(header.map((h, i) => [h, cells[i] ?? ""]));
    const kept = Object.fromEntries(CREDENTIAL_REPORT_COLUMNS.filter((c) => c in all).map((c) => [c, all[c]]));
    for (const n of [1, 2]) {
      if (all[`access_key_${n}_active`] === "true") kept[`access_key_${n}_age_days`] = ageDays(all[`access_key_${n}_last_rotated`], now);
    }
    return kept;
  });
  return { GeneratedTime: out.GeneratedTime ?? null, columns: CREDENTIAL_REPORT_COLUMNS, users };
}

/* ---------------------------------------------------------------------------------------------
 * Running commands
 * ------------------------------------------------------------------------------------------- */

/**
 * Run one CLI command: execFile, no shell, argv array, stdin closed, bounded time and output.
 * Never rejects; spawn failures come back as `errno` (for example "ENOENT").
 */
export function execCli(cli, args) {
  return new Promise((resolvePromise) => {
    let child;
    try {
      child = execFile(
        cli,
        args,
        {
          shell: false,
          encoding: "utf8",
          timeout: COMMAND_TIMEOUT_MS,
          maxBuffer: MAX_OUTPUT_BYTES,
          windowsHide: true,
          env: { ...process.env, ...CLI_ENV },
        },
        (error, stdout, stderr) => {
          if (!error) return resolvePromise({ code: 0, stdout, stderr, errno: null, timedOut: false });
          resolvePromise({
            code: typeof error.code === "number" ? error.code : null,
            errno: typeof error.code === "string" ? error.code : null,
            timedOut: Boolean(error.killed && error.signal),
            stdout: stdout ?? "",
            stderr: stderr ?? "",
          });
        }
      );
    } catch (err) {
      resolvePromise({ code: null, errno: err.code ?? "ESPAWN", timedOut: false, stdout: "", stderr: err.message });
      return;
    }
    child.stdin?.on("error", () => {});
    child.stdin?.end();
  });
}

/** Quote one argv element for display so the printed command can be pasted into a POSIX shell. */
function shellQuote(arg) {
  return /^[A-Za-z0-9_@%+=:,./-]+$/.test(arg) ? arg : `'${arg.replace(/'/g, `'\\''`)}'`;
}

export function formatCommand(argv) {
  return argv.map(shellQuote).join(" ");
}

const AUTH_RE =
  /Unable to locate credentials|ExpiredToken|InvalidClientTokenId|UnrecognizedClientException|security token included in the request is (?:invalid|expired)|Token has expired|SSO session|aws sso login|You do not currently have an active account|gcloud auth login|Reauthentication|refresh token|gh auth login|HTTP 401|Bad credentials|authentication required/i;
const PERMISSION_RE =
  /AccessDenied|UnauthorizedOperation|not authorized to perform|PERMISSION_DENIED|does not have .*permission|HTTP 403|Resource not accessible|Must have admin rights|Forbidden/i;
const API_DISABLED_RE = /SERVICE_DISABLED|has not been used in project|API .* is not enabled|it is disabled/i;

/** Turn a failed command into a short "not collected" reason. `kind` drives provider-wide skips. */
export function classifyFailure(cli, result) {
  if (result.errno === "ENOENT") return { kind: "missing-cli", reason: `${cli} CLI not found on PATH` };
  if (result.errno) return { kind: "error", reason: `could not run ${cli} (${result.errno})` };
  if (result.timedOut) return { kind: "error", reason: `${cli} timed out after ${COMMAND_TIMEOUT_MS / 1000}s` };
  const text = `${result.stderr}\n${result.stdout}`;
  const detail = firstErrorLine(result);
  if (AUTH_RE.test(text)) return { kind: "auth", reason: `missing or expired ${cli} credentials (${detail})` };
  if (API_DISABLED_RE.test(text)) return { kind: "error", reason: `API not enabled (${detail})` };
  if (PERMISSION_RE.test(text)) return { kind: "permission", reason: `permission denied (${detail})` };
  if (/HTTP 404|NotFound|NOT_FOUND/i.test(text)) return { kind: "error", reason: `not found (${detail})` };
  return { kind: "error", reason: `${cli} exited with code ${result.code} (${detail})` };
}

function firstErrorLine(result) {
  const line = `${result.stderr}\n${result.stdout}`.split(/\r?\n/).map((l) => l.trim()).find(Boolean) ?? "no output";
  return line.length > 200 ? `${line.slice(0, 197)}...` : line;
}

/* ---------------------------------------------------------------------------------------------
 * Planning: fill placeholders, list commands (also what --dry-run prints)
 * ------------------------------------------------------------------------------------------- */

/** Replace {name} placeholders inside each argv element. Returns the args and any unknown names. */
export function fillArgs(args, values, { placeholders = false } = {}) {
  const missing = new Set();
  const filled = args.map((a) =>
    a.replace(/\{(repo|org|branch|project)\}/g, (_m, name) => {
      const v = values[name];
      if (v !== undefined && v !== null && v !== "") return name === "branch" ? encodeURIComponent(v) : v;
      missing.add(name);
      return placeholders ? PLACEHOLDERS[name].shown : "";
    })
  );
  return { args: filled, missing: [...missing] };
}

/** Exact commands a run would execute, as display strings, grouped by collector. */
export function planCommands(collectors, values, { maxBuckets = DEFAULT_MAX_BUCKETS } = {}) {
  const lines = [];
  const providers = [...new Set(collectors.map((c) => c.provider))];
  for (const p of providers) {
    const cli = PROVIDER_CLI[p];
    lines.push(`# ${p}: version check`);
    lines.push(formatCommand([cli, ...VERSION_ARGS[cli]]));
    if (p === "gcp" && !values.project) {
      lines.push("# gcp: default project (only when --project is not given)");
      lines.push(formatCommand(["gcloud", "config", "get-value", "project"]));
    }
  }
  for (const c of collectors) {
    const cli = PROVIDER_CLI[c.provider];
    const { args, missing } = fillArgs(c.args, values, { placeholders: true });
    const needs = missing.filter((m) => m !== "branch" && m !== "project");
    lines.push("");
    lines.push(`# ${c.id} (${c.criteria.join(", ")})${needs.length ? ` -- not run: ${needs.map((m) => PLACEHOLDERS[m].missing).join("; ")}` : ""}`);
    if (missing.includes("branch")) lines.push("# <default-branch> is read from the github-repo-settings output");
    if (c.before) {
      lines.push(`${formatCommand([cli, ...c.before.args])}   # repeated until the report is ready`);
    }
    lines.push(formatCommand([cli, ...args]));
    if (c.each) {
      const cap = c.each.limit === "maxBuckets" ? `, up to ${maxBuckets}` : "";
      for (const cmd of Object.values(c.each.commands)) {
        lines.push(`${formatCommand([cli, ...cmd.args(c.each.placeholder)])}   # once per ${c.each.placeholder.slice(1, -1)}${cap}`);
      }
    }
  }
  return lines;
}

/* ---------------------------------------------------------------------------------------------
 * Collection
 * ------------------------------------------------------------------------------------------- */

export function selectCollectors(providers) {
  return COLLECTORS.filter((c) => providers.includes(c.provider));
}

export function evidenceFileName(c) {
  return `${c.criteria[0]}-${c.id}.json`;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Run one command for a collector. Returns { ok, output, note, command } or { ok: false, failure }.
 * `absentOn` turns a matching error into a successful, documented "absent" result.
 */
async function runOne({ cli, args, exec, redactor, parse, absentOn }) {
  const result = await exec(cli, args);
  const command = { command: redactor.scrub(formatCommand([cli, ...args])), exit_code: result.code };
  if (result.code === 0) {
    try {
      return { ok: true, command, output: parseOutput(result.stdout, parse) };
    } catch (err) {
      return { ok: false, command, failure: { kind: "error", reason: `could not parse ${cli} output as JSON (${err.message})` } };
    }
  }
  if (absentOn && !result.errno && absentOn.pattern.test(`${result.stderr}\n${result.stdout}`)) {
    return { ok: true, command, output: absentOn.output, note: absentOn.note };
  }
  const failure = classifyFailure(cli, result);
  return { ok: false, command, failure: { ...failure, reason: redactor.scrub(failure.reason) } };
}

async function runCollector(c, { values, exec, redactor, maxBuckets, now }) {
  const cli = PROVIDER_CLI[c.provider];
  const { args, missing } = fillArgs(c.args, values);
  if (missing.length) return { ok: false, failure: { kind: "input", reason: missing.map((m) => PLACEHOLDERS[m].missing).join("; ") } };

  const commands = [];
  if (c.before) {
    let ready = false;
    for (let attempt = 0; attempt < c.before.attempts && !ready; attempt++) {
      if (attempt > 0) await sleep(c.before.delayMs);
      const r = await runOne({ cli, args: c.before.args, exec, redactor });
      if (attempt === 0) commands.push(r.command);
      if (!r.ok) return { ok: false, commands, failure: r.failure };
      ready = c.before.ready(r.output);
    }
    if (!ready) return { ok: false, commands, failure: { kind: "error", reason: "report was not ready in time; run again in a minute" } };
  }

  const main = await runOne({ cli, args, exec, redactor, parse: c.parse, absentOn: c.absentOn });
  commands.push(main.command);
  if (!main.ok) return { ok: false, commands, failure: main.failure };
  const exitCode = main.command.exit_code;

  let output = main.output;
  const notes = [];
  if (main.note) notes.push(main.note);
  else if (c.transform) {
    try {
      output = c.transform(output, { now });
    } catch (err) {
      return { ok: false, commands, failure: { kind: "error", reason: err.message } };
    }
  }
  const provided = {};
  if (c.provides) for (const [k, fn] of Object.entries(c.provides)) provided[k] = fn(main.output);

  if (c.each) {
    const all = c.each.items(main.output).filter((item) => !item.startsWith("-"));
    const cap = c.each.limit === "maxBuckets" ? maxBuckets : all.length;
    const items = all.slice(0, cap);
    const perItem = {};
    for (const item of items) {
      const entry = {};
      for (const [name, cmd] of Object.entries(c.each.commands)) {
        const r = await runOne({ cli, args: cmd.args(item), exec, redactor, absentOn: cmd.absentOn });
        commands.push(r.command);
        entry[name] = r.ok ? (r.note ? { result: r.output, note: r.note } : r.output) : { not_collected: r.failure.reason };
      }
      perItem[item] = entry;
    }
    output = { ...(output && typeof output === "object" && !Array.isArray(output) ? output : { items: output }) };
    output[c.each.resultKey] = perItem;
    if (all.length > items.length) {
      notes.push(`Checked the first ${items.length} of ${all.length}; raise the cap with --max-buckets.`);
      output.truncated = { total: all.length, checked: items.length };
    }
  }

  if (c.note) {
    const n = c.note(main.output);
    if (n) notes.push(n);
  }
  return { ok: true, commands, exitCode, output, notes, provided };
}

async function cliVersion(cli, exec) {
  const r = await exec(cli, VERSION_ARGS[cli]);
  if (r.errno) return { failure: classifyFailure(cli, r) };
  const line = `${r.stdout}\n${r.stderr}`.split(/\r?\n/).map((l) => l.trim()).find(Boolean);
  return { version: line ?? "unknown" };
}

/** `gcloud config get-value project`: reads local gcloud config only, no API call. */
async function gcloudDefaultProject(exec) {
  const r = await exec("gcloud", ["config", "get-value", "project"]);
  const v = r.code === 0 ? r.stdout.trim() : "";
  return v && !v.startsWith("(") && !v.startsWith("-") ? v : undefined;
}

/**
 * Collect evidence. Writes <outDir>/<YYYY-MM-DD>/<criterion>-<collector-id>.json for each
 * collected item and an INDEX.md, and returns the per-collector results.
 */
export async function collectEvidence(options, { exec = execCli, log = () => {}, now = () => new Date(), toolVersion = "0.0.0" } = {}) {
  const { providers, outDir, repo, org, maxBuckets = DEFAULT_MAX_BUCKETS, redactAccountIds = false } = options;
  const startedAt = now();
  const day = startedAt.toISOString().slice(0, 10);
  const dayDir = join(outDir, day);
  const redactor = createRedactor({ redactAccountIds });
  const values = { repo, org, project: options.project, branch: undefined };
  const collectors = selectCollectors(providers);

  // CLI versions double as the "is it installed?" check.
  const cliInfo = {};
  for (const p of providers) {
    const cli = PROVIDER_CLI[p];
    cliInfo[p] = await cliVersion(cli, exec);
    if (cliInfo[p].version) cliInfo[p].version = redactor.scrub(cliInfo[p].version);
  }
  if (providers.includes("gcp") && !values.project && cliInfo.gcp.version) {
    values.project = await gcloudDefaultProject(exec);
  }

  const results = [];
  const providerBlocked = {};
  for (const c of collectors) {
    const cli = PROVIDER_CLI[c.provider];
    let r;
    if (cliInfo[c.provider].failure) r = { ok: false, failure: cliInfo[c.provider].failure };
    else if (providerBlocked[c.provider]) r = { ok: false, failure: providerBlocked[c.provider] };
    else r = await runCollector(c, { values, exec, redactor, maxBuckets, now: startedAt });

    if (!r.ok && r.failure.kind === "auth") providerBlocked[c.provider] = r.failure;
    if (r.ok && r.provided) for (const [k, v] of Object.entries(r.provided)) if (v !== undefined) values[k] = v;

    const before = redactor.count;
    let doc;
    if (r.ok) {
      const output = redactor.value(r.output, c.redact.dropKeys ?? []);
      doc = {
        policyseed_evidence: 1,
        collector: c.id,
        provider: c.provider,
        criteria: c.criteria,
        description: c.description,
        auditor_question: c.question,
        collected_at: now().toISOString(),
        collected_by: `policyseed ${toolVersion}`,
        cli: { name: cli, version: cliInfo[c.provider].version },
        ...(c.provider === "aws" ? { aws_context: redactor.value(awsContext()) } : {}),
        ...(c.provider === "gcp" ? { gcp_project: redactor.scrub(values.project ?? null) } : {}),
        ...(c.provider === "github" ? { github: { repo: repo ?? null, org: org ?? null } } : {}),
        commands: r.commands,
        exit_code: r.exitCode,
        redaction: {
          rule: c.redact.rule,
          dropped_fields: c.redact.dropKeys ?? [],
          values_redacted: 0,
          account_ids_truncated: redactAccountIds,
        },
        notes: r.notes.map((n) => redactor.scrub(n)),
        output,
      };
      doc.redaction.values_redacted = redactor.count - before;
    }
    results.push({ collector: c, ok: r.ok, file: r.ok ? evidenceFileName(c) : null, reason: r.ok ? null : redactor.scrub(r.failure.reason), doc });
    log(r.ok ? `  ok    ${c.id.padEnd(28)} ${evidenceFileName(c)}` : `  skip  ${c.id.padEnd(28)} ${redactor.scrub(r.failure.reason)}`);
  }

  writeEvidence({ dayDir, day, results, providers, startedAt, toolVersion, redactor });
  return { day, dayDir, results, collected: results.filter((r) => r.ok).length };
}

function awsContext() {
  return {
    profile: process.env.AWS_PROFILE || "default chain",
    region: process.env.AWS_REGION || process.env.AWS_DEFAULT_REGION || "CLI default",
  };
}

/* ---------------------------------------------------------------------------------------------
 * Writing files and INDEX.md
 * ------------------------------------------------------------------------------------------- */

/**
 * Write this run's files into the day folder. Files of the selected providers' collectors from an
 * earlier run today are replaced (or removed, if not collected this time); files of providers not
 * selected this time are kept and listed in the index. Nothing else in the folder is touched.
 */
function writeEvidence({ dayDir, day, results, providers, startedAt, toolVersion, redactor }) {
  mkdirSync(dayDir, { recursive: true });
  const ownIds = new Set(results.map((r) => r.collector.id));
  for (const f of readdirSync(dayDir)) {
    const m = /^[A-Z]+\d*(?:\.\d+)?-([a-z0-9-]+)\.json$/.exec(f);
    if (m && ownIds.has(m[1])) rmSync(join(dayDir, f), { force: true });
  }
  for (const r of results) {
    if (r.ok) writeFileSync(join(dayDir, r.file), `${JSON.stringify(r.doc, null, 2)}\n`, "utf8");
  }

  // Earlier same-day files for providers not selected in this run.
  const earlier = new Map();
  for (const c of COLLECTORS) {
    if (providers.includes(c.provider)) continue;
    const file = evidenceFileName(c);
    const path = join(dayDir, file);
    if (!existsSync(path)) continue;
    try {
      const doc = JSON.parse(readFileSync(path, "utf8"));
      if (doc.collector === c.id) earlier.set(c.id, file);
    } catch {
      // not ours or unreadable; leave it alone and leave it out of the index
    }
  }

  const index = renderIndex({ day, results, providers, earlier, startedAt, toolVersion });
  writeFileSync(join(dayDir, "INDEX.md"), redactor.scrub(index), "utf8");
}

function cell(text) {
  return String(text).replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
}

function compareCriteria(a, b) {
  return a.localeCompare(b, "en", { numeric: true });
}

export function renderIndex({ day, results, providers, earlier = new Map(), startedAt, toolVersion }) {
  const byId = new Map(results.map((r) => [r.collector.id, r]));
  const rows = [];
  COLLECTORS.forEach((c, order) => {
    const r = byId.get(c.id);
    let fileCell;
    if (r && r.ok) fileCell = `[${r.file}](./${r.file})`;
    else if (r) fileCell = `not collected: ${r.reason}`;
    else if (earlier.has(c.id)) fileCell = `[${earlier.get(c.id)}](./${earlier.get(c.id)}) (earlier run today)`;
    else fileCell = `not collected: ${c.provider} not in --providers for this run`;
    for (const criterion of c.criteria) rows.push({ criterion, order, fileCell, c });
  });
  rows.sort((a, b) => compareCriteria(a.criterion, b.criterion) || a.order - b.order);

  const collected = results.filter((r) => r.ok).length;
  const lines = [
    `# SOC 2 evidence, ${day}`,
    "",
    `Collected by \`policyseed evidence\` ${toolVersion} at ${startedAt.toISOString()} for: ${providers.join(", ")}.`,
    `This run collected ${collected} of ${results.length} items.`,
    "",
    "Each JSON file holds the redacted output of one read-only CLI command, or a short fixed",
    "sequence of them, with the exact command, the time, the CLI version and the exit code.",
    "This is supporting evidence for your auditor, not an audit result, and it does not replace",
    "the auditor's own testing.",
    "",
    "| Criterion | File | What it shows | Auditor question |",
    "| --- | --- | --- | --- |",
    ...rows.map((r) => `| ${r.criterion} | ${cell(r.fileCell)} | ${cell(r.c.description)} | ${cell(r.c.question)} |`),
    "",
  ];
  return lines.join("\n");
}
