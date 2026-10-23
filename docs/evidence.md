# Collecting GitHub evidence on a schedule

`policyseed evidence` is described in the [README](../README.md#collecting-audit-evidence). This
page shows how to run its GitHub collectors from GitHub Actions every month and keep the output
as a workflow artifact, so you have dated evidence for the whole audit period without anyone
remembering to collect it.

The bundled action (`uses: odedmoshe/policyseed@v1`) runs only `check` and `build`; its
`command` input does not accept `evidence`, and its default behavior is unchanged. The workflow
below runs the CLI directly with `npx` instead.

## Workflow

Save as `.github/workflows/soc2-evidence.yml` in the repository you want evidence for:

```yaml
name: SOC 2 evidence (GitHub)

on:
  schedule:
    - cron: "17 6 1 * *" # 06:17 UTC on the 1st of every month
  workflow_dispatch: {}

permissions:
  contents: read

jobs:
  evidence:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-node@v4
        with:
          node-version: "22"

      # gh is preinstalled on GitHub-hosted runners and reads GH_TOKEN.
      # Use a release tag that includes the evidence command, or a full commit SHA.
      - name: Collect evidence
        env:
          GH_TOKEN: ${{ secrets.POLICYSEED_EVIDENCE_TOKEN || github.token }}
        run: >
          npx --yes github:odedmoshe/policyseed#v1
          evidence --providers github
          --repo "$GITHUB_REPOSITORY"
          --org "$GITHUB_REPOSITORY_OWNER"
          --out evidence

      - name: Upload evidence
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: soc2-evidence-${{ github.run_id }}
          path: evidence/
          retention-days: 90
```

Notes:

- `npx github:odedmoshe/policyseed#v1` downloads the CLI from GitHub when the job runs. The
  evidence commands themselves are `gh api` GET requests against your repository and organization.
- `if: always()` uploads INDEX.md even when the step fails, so you can see why nothing was
  collected. The step fails only when nothing at all was collected.
- Drop `--org` for a repository owned by a personal account; the organization collectors are then
  recorded as not collected.
- Artifacts expire. `retention-days` can be at most what your repository or organization allows
  (90 days by default), so download the artifacts you need for the audit, or commit them
  somewhere durable, before they expire.

## Which token to use

The default `GITHUB_TOKEN` (`github.token`) can read the repository settings and the ruleset rules
that apply to the default branch. It cannot read:

- classic branch protection, the `security_and_analysis` block or the Dependabot alerts setting,
  which need repository admin read access;
- the organization's `two_factor_requirement_enabled`, which GitHub returns only to organization
  owners;
- private organization membership, so the admin list would include only members who made their
  membership public.

For the full set, create a fine-grained personal access token (or a GitHub App installation token)
with repository **Administration: read** and **Metadata: read** and organization
**Members: read**, owned by an organization owner, and store it as the repository secret
`POLICYSEED_EVIDENCE_TOKEN`. The workflow uses it when it exists and falls back to
`GITHUB_TOKEN` otherwise. Anything the token can't read is listed in INDEX.md as
`not collected: permission denied (...)`, never as a pass.

## AWS and Google Cloud in CI

The same command collects AWS and Google Cloud evidence when `aws` and `gcloud` are signed in on
the runner, for example with `aws-actions/configure-aws-credentials` or
`google-github-actions/auth` and OIDC, using a role limited to the read-only permissions listed
in the [README](../README.md#permissions-it-needs). Add `aws` or `gcp` to `--providers` and, for
Google Cloud, pass `--project`.
