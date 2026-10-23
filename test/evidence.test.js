import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, existsSync, writeFileSync, chmodSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { createRedactor, parseJsonPages, parseCsv, credentialReport, COLLECTORS } from "../lib/evidence.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const BIN = resolve(__dirname, "..", "bin", "policyseed.js");

// The fake CLIs are Node scripts with a shebang, which Windows cannot execute from PATH.
const skip = process.platform === "win32" ? "fake CLIs need a POSIX shebang" : false;

const ACCOUNT = "123456789012";
const GH_TOKEN = `ghp_${"A1b2C3d4E5".repeat(4)}`;
const SESSION_TOKEN = `IQoJb3JpZ2luX2Vj${"x".repeat(60)}`;

/**
 * A fake CLI: records its name and argv as one JSON line in $FAKE_CLI_LOG, then answers from the
 * fixture map in $FAKE_CLI_RESPONSES, keyed by "<name> <argv joined by spaces>". It never runs a
 * shell, so an argument that reaches it intact proves the caller didn't use one either.
 */
const FAKE_CLI_SOURCE = `#!${process.execPath}
const { appendFileSync, readFileSync } = require("node:fs");
const { basename } = require("node:path");
const name = basename(process.argv[1]);
const argv = process.argv.slice(2);
appendFileSync(process.env.FAKE_CLI_LOG, JSON.stringify({ cli: name, argv }) + "\\n");
const responses = JSON.parse(readFileSync(process.env.FAKE_CLI_RESPONSES, "utf8"));
const r = responses[[name, ...argv].join(" ")];
if (!r) {
  process.stderr.write("fake " + name + ": no fixture for: " + argv.join(" ") + "\\n");
  process.exit(2);
}
if (r.stdout) process.stdout.write(r.stdout);
if (r.stderr) process.stderr.write(r.stderr);
process.exit(r.code ?? 0);
`;

const json = (v) => ({ stdout: `${JSON.stringify(v)}\n` });

const CREDENTIAL_CSV = [
  "user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,access_key_2_last_used_region,access_key_2_last_used_service,cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated",
  `<root_account>,arn:aws:iam::${ACCOUNT}:root,2020-01-01T00:00:00+00:00,not_supported,2026-10-01T00:00:00+00:00,not_supported,not_supported,true,false,N/A,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A`,
  `alice,arn:aws:iam::${ACCOUNT}:user/alice,2021-01-01T00:00:00+00:00,true,2026-10-20T00:00:00+00:00,2026-01-01T00:00:00+00:00,N/A,false,true,2025-01-01T00:00:00+00:00,2026-10-01T00:00:00+00:00,us-east-1,s3,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A`,
].join("\n");

const TRAIL_ARN = `arn:aws:cloudtrail:us-east-1:${ACCOUNT}:trail/main`;

const RESPONSES = {
  // GitHub
  "gh --version": { stdout: "gh version 2.60.0 (2024-10-01)\nhttps://github.com/cli/cli/releases/tag/v2.60.0\n" },
  "gh api repos/acme/app": json({
    full_name: "acme/app",
    default_branch: "main",
    visibility: "private",
    description: `deploy key note: ${GH_TOKEN}`,
    security_and_analysis: { secret_scanning: { status: "enabled" }, secret_scanning_push_protection: { status: "enabled" } },
  }),
  "gh api repos/acme/app/branches/main/protection": json({
    required_pull_request_reviews: { required_approving_review_count: 1 },
    enforce_admins: { enabled: true },
  }),
  // Two pages, printed back to back the way `gh api --paginate` does without --slurp.
  "gh api --paginate repos/acme/app/rules/branches/main": {
    stdout: '[{"type":"pull_request","ruleset_id":1}]\n[{"type":"non_fast_forward","ruleset_id":2}]\n',
  },
  "gh api repos/acme/app/vulnerability-alerts": { stderr: "gh: Not Found (HTTP 404)\n", stdout: '{"message":"Not Found","status":"404"}', code: 1 },
  "gh api orgs/acme": json({ login: "acme", two_factor_requirement_enabled: true, billing_email: "billing@acme.example" }),
  "gh api --paginate orgs/acme/members?role=admin": json([{ login: "alice", site_admin: false }]),

  // AWS
  "aws --version": { stdout: "aws-cli/2.17.0 Python/3.11.9 Linux/6.8 exe/x86_64\n" },
  "aws iam get-account-summary --output json": json({
    SummaryMap: { AccountMFAEnabled: 1, AccountAccessKeysPresent: 0, Users: 2 },
    SessionToken: SESSION_TOKEN,
    Debug: "config had aws_secret_access_key=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY in it",
  }),
  "aws iam generate-credential-report --output json": json({ State: "COMPLETE" }),
  "aws iam get-credential-report --output json": json({
    Content: Buffer.from(CREDENTIAL_CSV).toString("base64"),
    ReportFormat: "text/csv",
    GeneratedTime: "2026-10-23T10:00:00+00:00",
  }),
  "aws iam get-account-password-policy --output json": {
    stderr: `\nAn error occurred (NoSuchEntity) when calling the GetAccountPasswordPolicy operation: The Password Policy with domain name ${ACCOUNT} cannot be found.\n`,
    code: 254,
  },
  "aws cloudtrail describe-trails --output json": json({ trailList: [{ Name: "main", TrailARN: TRAIL_ARN, IsMultiRegionTrail: true }] }),
  [`aws cloudtrail get-trail-status --name ${TRAIL_ARN} --output json`]: json({ IsLogging: true }),
  "aws ec2 get-ebs-encryption-by-default --output json": json({ EbsEncryptionByDefault: true }),
  "aws s3api list-buckets --output json": json({
    Buckets: [{ Name: `logs-${ACCOUNT}` }, { Name: "data" }, { Name: "extra" }],
    Owner: { ID: "abc" },
  }),
  [`aws s3api get-bucket-encryption --bucket logs-${ACCOUNT} --output json`]: json({
    ServerSideEncryptionConfiguration: { Rules: [{ ApplyServerSideEncryptionByDefault: { SSEAlgorithm: "AES256" } }] },
  }),
  [`aws s3api get-public-access-block --bucket logs-${ACCOUNT} --output json`]: json({
    PublicAccessBlockConfiguration: { BlockPublicAcls: true, IgnorePublicAcls: true, BlockPublicPolicy: true, RestrictPublicBuckets: true },
  }),
  "aws s3api get-bucket-encryption --bucket data --output json": json({
    ServerSideEncryptionConfiguration: { Rules: [{ ApplyServerSideEncryptionByDefault: { SSEAlgorithm: "aws:kms" } }] },
  }),
  "aws s3api get-public-access-block --bucket data --output json": {
    stderr: "\nAn error occurred (NoSuchPublicAccessBlockConfiguration) when calling the GetPublicAccessBlock operation: The public access block configuration was not found\n",
    code: 254,
  },
  [`aws rds describe-db-instances --query ${COLLECTORS.find((c) => c.id === "aws-rds-instances").args[3]} --output json`]: {
    stderr: `\nAn error occurred (AccessDenied) when calling the DescribeDBInstances operation: User: arn:aws:iam::${ACCOUNT}:user/bob is not authorized to perform: rds:DescribeDBInstances\n`,
    code: 254,
  },
};

const INJECTION_PROJECT = "x$(touch pwned)";
const GCP_RESPONSES = {
  "gcloud --version": { stdout: "Google Cloud SDK 500.0.0\nbq 2.1.9\ncore 2024.11.08\n" },
  [`gcloud projects get-iam-policy ${INJECTION_PROJECT} --format=json`]: json({ bindings: [{ role: "roles/owner", members: ["user:alice@acme.example"] }] }),
  [`gcloud logging sinks list --project ${INJECTION_PROJECT} --format=json`]: json([{ name: "_Required" }]),
  [`gcloud sql instances list --project ${INJECTION_PROJECT} --format=json`]: json([{ name: "db", settings: { backupConfiguration: { enabled: true } } }]),
  [`gcloud compute disks list --project ${INJECTION_PROJECT} --format=json`]: json([{ name: "disk-1" }]),
  "gcloud organizations list --format=json": { stderr: "ERROR: (gcloud.organizations.list) PERMISSION_DENIED: The caller does not have permission\n", code: 1 },
};

/** Temp workspace with fake CLIs on a PATH that contains nothing else. */
function withFakes(clis, fn) {
  const root = mkdtempSync(join(tmpdir(), "policyseed-evidence-"));
  try {
    const bin = join(root, "bin");
    const work = join(root, "work");
    mkdirSync(bin);
    mkdirSync(work);
    for (const cli of clis) {
      writeFileSync(join(bin, cli), FAKE_CLI_SOURCE, "utf8");
      chmodSync(join(bin, cli), 0o755);
    }
    const responses = join(root, "responses.json");
    writeFileSync(responses, JSON.stringify({ ...RESPONSES, ...GCP_RESPONSES }), "utf8");
    const logPath = join(root, "argv.log");
    writeFileSync(logPath, "", "utf8");

    const run = (args) => {
      const r = spawnSync(process.execPath, [BIN, "evidence", ...args], {
        cwd: work,
        encoding: "utf8",
        env: { PATH: bin, HOME: root, FAKE_CLI_LOG: logPath, FAKE_CLI_RESPONSES: responses },
      });
      return { status: r.status, stdout: r.stdout, stderr: r.stderr };
    };
    const calls = () =>
      readFileSync(logPath, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
    return fn({ root, bin, work, run, calls });
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

function dayDirOf(work, out = "evidence") {
  const days = readdirSync(join(work, out));
  assert.equal(days.length, 1, `expected one day folder, got ${days.join(", ")}`);
  assert.match(days[0], /^\d{4}-\d{2}-\d{2}$/);
  return join(work, out, days[0]);
}

const readJson = (p) => JSON.parse(readFileSync(p, "utf8"));

describe("policyseed evidence", { skip }, () => {
  test("runs the exact read-only argv, writes one file per item and an INDEX.md", () => {
    withFakes(["aws", "gh"], ({ work, run, calls }) => {
      const r = run(["--providers", "github,aws", "--repo", "acme/app", "--org", "acme", "--max-buckets", "2"]);
      assert.equal(r.status, 0, r.stderr);

      assert.deepEqual(
        calls().map((c) => [c.cli, ...c.argv]),
        [
          ["aws", "--version"],
          ["gh", "--version"],
          ["gh", "api", "repos/acme/app"],
          ["gh", "api", "repos/acme/app/branches/main/protection"],
          ["gh", "api", "--paginate", "repos/acme/app/rules/branches/main"],
          ["gh", "api", "repos/acme/app/vulnerability-alerts"],
          ["gh", "api", "orgs/acme"],
          ["gh", "api", "--paginate", "orgs/acme/members?role=admin"],
          ["aws", "iam", "get-account-summary", "--output", "json"],
          ["aws", "iam", "generate-credential-report", "--output", "json"],
          ["aws", "iam", "get-credential-report", "--output", "json"],
          ["aws", "iam", "get-account-password-policy", "--output", "json"],
          ["aws", "cloudtrail", "describe-trails", "--output", "json"],
          ["aws", "cloudtrail", "get-trail-status", "--name", TRAIL_ARN, "--output", "json"],
          ["aws", "ec2", "get-ebs-encryption-by-default", "--output", "json"],
          ["aws", "s3api", "list-buckets", "--output", "json"],
          ["aws", "s3api", "get-bucket-encryption", "--bucket", `logs-${ACCOUNT}`, "--output", "json"],
          ["aws", "s3api", "get-public-access-block", "--bucket", `logs-${ACCOUNT}`, "--output", "json"],
          ["aws", "s3api", "get-bucket-encryption", "--bucket", "data", "--output", "json"],
          ["aws", "s3api", "get-public-access-block", "--bucket", "data", "--output", "json"],
          ["aws", "rds", "describe-db-instances", "--query", COLLECTORS.find((c) => c.id === "aws-rds-instances").args[3], "--output", "json"],
        ]
      );

      const dir = dayDirOf(work);
      assert.deepEqual(readdirSync(dir).sort(), [
        "CC6.1-aws-ebs-default-encryption.json",
        "CC6.1-aws-iam-account-summary.json",
        "CC6.1-aws-iam-credential-report.json",
        "CC6.1-aws-iam-password-policy.json",
        "CC6.1-aws-s3-buckets.json",
        "CC6.1-github-org-2fa.json",
        "CC6.3-github-org-admins.json",
        "CC7.1-github-dependabot-alerts.json",
        "CC7.1-github-repo-settings.json",
        "CC7.2-aws-cloudtrail.json",
        "CC8.1-github-branch-protection.json",
        "CC8.1-github-branch-rules.json",
        "INDEX.md",
      ]);

      // Metadata wrapper.
      const summary = readJson(join(dir, "CC6.1-aws-iam-account-summary.json"));
      assert.equal(summary.collector, "aws-iam-account-summary");
      assert.deepEqual(summary.criteria, ["CC6.1"]);
      assert.equal(summary.cli.name, "aws");
      assert.equal(summary.cli.version, "aws-cli/2.17.0 Python/3.11.9 Linux/6.8 exe/x86_64");
      assert.deepEqual(summary.commands, [{ command: "aws iam get-account-summary --output json", exit_code: 0 }]);
      assert.equal(summary.exit_code, 0);
      assert.ok(!Number.isNaN(Date.parse(summary.collected_at)));
      assert.equal(summary.output.SummaryMap.AccountMFAEnabled, 1);

      // gh --paginate pages are merged into one array.
      assert.deepEqual(readJson(join(dir, "CC8.1-github-branch-rules.json")).output.map((x) => x.type), ["pull_request", "non_fast_forward"]);

      // Errors that are themselves the evidence.
      const dependabot = readJson(join(dir, "CC7.1-github-dependabot-alerts.json"));
      assert.deepEqual(dependabot.output, { dependabot_alerts_enabled: false });
      assert.equal(dependabot.exit_code, 1);
      assert.match(dependabot.notes[0], /404/);
      assert.deepEqual(readJson(join(dir, "CC6.1-aws-iam-password-policy.json")).output, { PasswordPolicy: null });

      // Credential report: decoded, reduced to the kept columns, with key age.
      const report = readJson(join(dir, "CC6.1-aws-iam-credential-report.json"));
      assert.equal(report.commands.length, 2);
      const alice = report.output.users.find((u) => u.user === "alice");
      assert.equal(alice.mfa_active, "false");
      assert.equal(alice.access_key_1_last_rotated, "2025-01-01T00:00:00+00:00");
      assert.equal(typeof alice.access_key_1_age_days, "number");
      assert.ok(!("cert_1_active" in alice));
      assert.ok(!("access_key_1_last_used_service" in alice));
      assert.ok(alice.arn.includes(ACCOUNT), "account IDs are kept unless --redact-account-ids is given");

      // S3: capped at --max-buckets, per-bucket results, missing configuration recorded.
      const s3 = readJson(join(dir, "CC6.1-aws-s3-buckets.json"));
      assert.deepEqual(Object.keys(s3.output.bucket_settings), [`logs-${ACCOUNT}`, "data"]);
      assert.deepEqual(s3.output.truncated, { total: 3, checked: 2 });
      assert.equal(s3.output.bucket_settings.data.public_access_block.result, null);
      assert.equal(s3.commands.length, 5);

      const trail = readJson(join(dir, "CC7.2-aws-cloudtrail.json"));
      assert.equal(trail.output.trail_status[TRAIL_ARN].status.IsLogging, true);

      // INDEX.md
      const index = readFileSync(join(dir, "INDEX.md"), "utf8");
      assert.match(index, /^# SOC 2 evidence, \d{4}-\d{2}-\d{2}/);
      assert.match(index, /\| Criterion \| File \| What it shows \| Auditor question \|/);
      assert.match(index, /\| CC8\.1 \| \[CC8\.1-github-branch-protection\.json\]\(\.\/CC8\.1-github-branch-protection\.json\) \| Classic branch protection/);
      assert.match(index, /\| CC6\.6 \| \[CC6\.1-aws-s3-buckets\.json\]/);
      assert.match(index, /\| A1\.2 \| not collected: permission denied \(An error occurred \(AccessDenied\)/);
      assert.match(index, /\| CC6\.3 \| not collected: gcp not in --providers for this run/);
      assert.match(index, /does not replace\nthe auditor's own testing/);
      assert.match(index, /This run collected 12 of 13 items\./);
      // Rows are ordered by criterion.
      const criteria = [...index.matchAll(/^\| ((?:A|CC)\d\.\d) \|/gm)].map((m) => m[1]);
      assert.deepEqual(criteria, [...criteria].sort((a, b) => a.localeCompare(b, "en", { numeric: true })));

      assert.match(r.stdout, /skip  aws-rds-instances\s+permission denied/);
      assert.match(r.stdout, /Collected 12 of 13\./);
    });
  });

  test("redacts tokens, session tokens and key-like values; drops fields the rule names", () => {
    withFakes(["aws", "gh"], ({ work, run }) => {
      run(["--providers", "github,aws", "--repo", "acme/app", "--org", "acme"]);
      const dir = dayDirOf(work);
      const all = readdirSync(dir).map((f) => readFileSync(join(dir, f), "utf8")).join("\n");
      assert.ok(!all.includes(GH_TOKEN), "GitHub token leaked");
      assert.ok(!all.includes(SESSION_TOKEN), "session token leaked");
      assert.ok(!all.includes("wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY"), "secret key leaked");
      assert.ok(!all.includes("billing@acme.example"), "dropKeys not applied");

      const repo = readJson(join(dir, "CC7.1-github-repo-settings.json"));
      assert.equal(repo.output.description, "deploy key note: [REDACTED:github-token]");
      assert.equal(repo.redaction.values_redacted, 1);
      const summary = readJson(join(dir, "CC6.1-aws-iam-account-summary.json"));
      assert.equal(summary.output.SessionToken, "[REDACTED]");
      assert.equal(summary.output.Debug, "config had aws_secret_access_key=[REDACTED] in it");
      assert.deepEqual(readJson(join(dir, "CC6.1-github-org-2fa.json")).redaction.dropped_fields, ["billing_email"]);
    });
  });

  test("--redact-account-ids truncates 12-digit account IDs everywhere, including commands and INDEX.md", () => {
    withFakes(["aws"], ({ work, run }) => {
      const r = run(["--providers", "aws", "--redact-account-ids"]);
      assert.equal(r.status, 0, r.stderr);
      const dir = dayDirOf(work);
      for (const f of readdirSync(dir)) {
        assert.ok(!readFileSync(join(dir, f), "utf8").includes(ACCOUNT), `${f} still contains the account ID`);
      }
      assert.ok(!r.stdout.includes(ACCOUNT));
      const s3 = readJson(join(dir, "CC6.1-aws-s3-buckets.json"));
      assert.ok(Object.keys(s3.output.bucket_settings).includes("logs-********9012"));
      assert.ok(s3.commands.some((c) => c.command.includes("logs-********9012")));
      assert.match(readFileSync(join(dir, "INDEX.md"), "utf8"), /arn:aws:iam::\*\*\*\*\*\*\*\*9012:user\/bob/);
    });
  });

  test("a missing CLI is recorded in INDEX.md and the run continues", () => {
    withFakes(["gh"], ({ work, run, calls }) => {
      const r = run(["--repo", "acme/app"]);
      assert.equal(r.status, 0, r.stderr);
      const index = readFileSync(join(dayDirOf(work), "INDEX.md"), "utf8");
      assert.match(index, /\| CC6\.1 \| not collected: aws CLI not found on PATH \| IAM account summary/);
      assert.match(index, /\| CC6\.3 \| not collected: gcloud CLI not found on PATH \| The project's IAM policy/);
      assert.match(index, /\| CC6\.3 \| not collected: needs --org name \| Members of the organization/);
      assert.match(index, /\[CC7\.1-github-repo-settings\.json\]/);
      assert.ok(calls().every((c) => c.cli === "gh"));
    });
  });

  test("exits 1 only when nothing at all was collected", () => {
    withFakes([], ({ work, run }) => {
      const r = run([]);
      assert.equal(r.status, 1);
      assert.match(r.stderr, /nothing was collected/);
      const dir = dayDirOf(work);
      assert.deepEqual(readdirSync(dir), ["INDEX.md"]);
      const index = readFileSync(join(dir, "INDEX.md"), "utf8");
      assert.match(index, /not collected: gh CLI not found on PATH/);
      assert.match(index, /This run collected 0 of 18 items\./);
    });
  });

  test("no shell is involved: an argument containing $(touch pwned) reaches the CLI literally", () => {
    withFakes(["gcloud"], ({ root, work, run, calls }) => {
      const r = run(["--providers", "gcp", "--project", INJECTION_PROJECT]);
      assert.equal(r.status, 0, r.stderr);
      assert.deepEqual(
        calls().map((c) => [c.cli, ...c.argv]),
        [
          ["gcloud", "--version"],
          ["gcloud", "projects", "get-iam-policy", INJECTION_PROJECT, "--format=json"],
          ["gcloud", "logging", "sinks", "list", "--project", INJECTION_PROJECT, "--format=json"],
          ["gcloud", "sql", "instances", "list", "--project", INJECTION_PROJECT, "--format=json"],
          ["gcloud", "compute", "disks", "list", "--project", INJECTION_PROJECT, "--format=json"],
          ["gcloud", "organizations", "list", "--format=json"],
        ]
      );
      assert.ok(!existsSync(join(work, "pwned")));
      assert.ok(!existsSync(join(root, "pwned")));
      const dir = dayDirOf(work);
      assert.equal(readJson(join(dir, "CC6.3-gcp-project-iam-policy.json")).gcp_project, INJECTION_PROJECT);
      assert.match(readFileSync(join(dir, "INDEX.md"), "utf8"), /not collected: permission denied \(ERROR: \(gcloud\.organizations\.list\) PERMISSION_DENIED/);
    });
  });

  test("--dry-run prints the exact commands and runs and writes nothing", () => {
    withFakes(["aws", "gh", "gcloud"], ({ work, run, calls }) => {
      const r = run(["--dry-run", "--repo", "acme/app", "--org", "acme", "--project", "prod-1", "--max-buckets", "7"]);
      assert.equal(r.status, 0, r.stderr);
      assert.deepEqual(calls(), []);
      assert.ok(!existsSync(join(work, "evidence")));
      const lines = r.stdout.split("\n");
      for (const expected of [
        "gh api repos/acme/app",
        "gh api 'repos/acme/app/branches/<default-branch>/protection'",
        "gh api --paginate 'orgs/acme/members?role=admin'",
        "aws iam get-account-summary --output json",
        "aws s3api get-bucket-encryption --bucket '<bucket>' --output json   # once per bucket, up to 7",
        "gcloud projects get-iam-policy prod-1 --format=json",
        "gcloud organizations list --format=json",
      ]) {
        assert.ok(lines.includes(expected), `missing dry-run line: ${expected}\n${r.stdout}`);
      }
      assert.ok(!lines.includes("gcloud config get-value project"), "no default-project lookup when --project is given");
    });
  });

  test("--list prints the collector table", () => {
    withFakes([], ({ run, calls }) => {
      const r = run(["--list"]);
      assert.equal(r.status, 0);
      assert.match(r.stdout, /18 evidence collectors/);
      for (const c of COLLECTORS) assert.match(r.stdout, new RegExp(`^${c.id}\\s`, "m"));
      assert.deepEqual(calls(), []);
    });
  });

  test("a same-day re-run replaces only its own providers' files and keeps everything else", () => {
    withFakes(["aws", "gh"], ({ work, run }) => {
      run(["--providers", "github", "--repo", "acme/app", "--org", "acme"]);
      const dir = dayDirOf(work);
      writeFileSync(join(dir, "screenshot-notes.txt"), "mine", "utf8");
      writeFileSync(join(dir, "CC8.1-github-branch-protection.json"), '{"collector":"github-branch-protection","stale":true}', "utf8");

      run(["--providers", "aws"]);
      const files = readdirSync(dir);
      assert.ok(files.includes("screenshot-notes.txt"));
      assert.equal(readFileSync(join(dir, "screenshot-notes.txt"), "utf8"), "mine");
      assert.ok(files.includes("CC7.1-github-repo-settings.json"));
      assert.ok(files.includes("CC6.1-aws-iam-account-summary.json"));
      const index = readFileSync(join(dir, "INDEX.md"), "utf8");
      assert.match(index, /\[CC7\.1-github-repo-settings\.json\]\(\.\/CC7\.1-github-repo-settings\.json\) \(earlier run today\)/);

      // Re-running github replaces its files.
      run(["--providers", "github", "--repo", "acme/app", "--org", "acme"]);
      assert.equal(readJson(join(dir, "CC8.1-github-branch-protection.json")).stale, undefined);
    });
  });

  test("rejects unknown flags and values that are not GitHub names or project IDs", () => {
    withFakes([], ({ run, calls }) => {
      assert.match(run(["--provider", "aws"]).stderr, /unknown argument "--provider"/);
      assert.match(run(["--providers", "azure"]).stderr, /--providers must be/);
      assert.match(run(["--repo", "../../user"]).stderr, /--repo must look like owner\/name/);
      assert.match(run(["--org", "acme/x"]).stderr, /--org must be/);
      assert.match(run(["--project", "-impersonate"]).stderr, /--project requires a value|--project must be/);
      assert.deepEqual(calls(), []);
    });
  });
});

describe("evidence helpers", () => {
  test("parseJsonPages merges concatenated arrays and keeps a single object", () => {
    assert.deepEqual(parseJsonPages('[1,2]\n[3]'), [1, 2, 3]);
    assert.deepEqual(parseJsonPages('{"a":"[}"}'), { a: "[}" });
    assert.equal(parseJsonPages(""), null);
    assert.throws(() => parseJsonPages("[1"), /truncated/);
  });

  test("parseCsv handles quoted fields", () => {
    assert.deepEqual(parseCsv('a,b\n"x,1","y ""q"""\n'), [["a", "b"], ["x,1", 'y "q"']]);
  });

  test("credentialReport computes key age from the collection time", () => {
    const out = credentialReport({ Content: Buffer.from(CREDENTIAL_CSV).toString("base64") }, new Date("2026-01-01T00:00:00Z"));
    assert.equal(out.users.find((u) => u.user === "alice").access_key_1_age_days, 365);
  });

  test("redactor leaves ordinary values alone", () => {
    const r = createRedactor();
    const input = { password_enabled: "true", PasswordPolicy: { MinimumPasswordLength: 14 }, sha: "a".repeat(40), arn: `arn:aws:iam::${ACCOUNT}:root` };
    assert.deepEqual(r.value(input), input);
    assert.equal(r.count, 0);
  });
});
