# Repository Governance Setup

This document is for repository administrators. Policies in `AGENTS.md` and
`CONTRIBUTING.md` guide contributors, but GitHub rulesets enforce the controls
that cannot be guaranteed by documentation alone.

## Protect `main`

Create and activate a branch ruleset targeting the default branch (`main`) with
these settings:

1. Require a pull request before merging.
2. Require at least one approving review from someone other than the latest
   pusher.
3. Dismiss stale approvals when new commits are pushed.
4. Require approval of the most recent reviewable push.
5. Require branches to be up to date before merging.
6. Block force pushes and branch deletion.
7. Do not grant GitHub Actions, bots, or administrators a bypass unless a
   documented emergency procedure requires it.

These settings prevent direct changes to `main`, invalidate approval when a
pull request changes, and ensure the final version receives independent review.

## Require checks before merge

After each workflow has run successfully at least once, add its check to the
same ruleset as a required status check. At minimum require:

- `Verify contributor attestation`
- `lefthook`
- the applicable smoke-test and provider test jobs
- `vet` when the pull request changes code or dependencies

Enable the "branch must be up to date" setting for required checks. Do not
make an AI review result the sole required approval: automated review can
triage changes but cannot replace accountable human review.

## Configure ownership deliberately

Add a `CODEOWNERS` file only after identifying active maintainers or teams.
Require code-owner review for release automation, GitHub Actions workflows,
provider authentication code, and security-sensitive configuration. Do not add
placeholder owners: an unavailable owner blocks legitimate contributors
without protecting the code.

## Restrict credentials and automation

- Give coding agents read-only credentials. Never expose a personal access
  token, deploy key, or GitHub App credential with repository write access to
  an agent environment.
- Keep workflow permissions at the minimum required level. Review any workflow
  that grants `contents: write`, `pull-requests: write`, or uses
  `pull_request_target`.
- Ensure `.github/workflows/prow-pr-automerge.yml` cannot bypass the protected
  branch rules. If that cannot be verified, disable automatic merging until it
  can.
- Limit release publishing to maintainers and protected release tags.

## Periodic review

Review ruleset bypass actors, repository collaborators, GitHub App
installations, deploy keys, and workflow permissions at least quarterly and
after maintainer changes. Test the ruleset with a non-maintainer account before
depending on it for protection.
