# AI-Assisted Contribution Policy

This policy applies to any AI model, coding agent, bot, or automation used to
contribute to this repository. It complements, but does not replace,
[`CONTRIBUTING.md`](CONTRIBUTING.md).

## Human accountability

The human contributor remains the author and is accountable for every change
submitted under their account. Before submission, they must be able to:

- explain the purpose, design, and security implications of the change;
- review and modify every AI-produced file included in the contribution;
- run the relevant checks or explain in the pull request why they could not be
  run; and
- respond to reviewer questions and implement requested changes themselves.

Submitting AI output that the contributor has not reviewed or does not
understand is not permitted.

## No autonomous repository actions

AI models and automated agents must not perform remote write operations. They
must not run `git push`, create or merge pull requests, create releases, post
issues or comments, submit reviews, or invoke tools that perform an equivalent
remote action.

Do not provide an agent with a personal access token, deploy key, GitHub App
credential, or other credential that can write to this repository. Read-only
repository access is sufficient for analysis and local development.

## Mandatory review checkpoint

Before a human pushes AI-assisted changes or submits them in a pull request,
the agent must:

1. show the relevant diff or a concise file-by-file summary;
2. report tests and checks run, including failures or checks not run;
3. identify material assumptions, security-sensitive changes, and unreviewed
   areas; and
4. explicitly ask the human to review the changes.

The agent must wait for the human to confirm that they reviewed the changes.
Approval to edit, test, stage, or commit does not authorize an agent to push
or make any remote repository change.

## Submission quality

AI-assisted contributions must be focused on one problem, avoid unrelated
refactors, and not duplicate an existing issue or pull request. Substantial
AI assistance must be disclosed in the pull request using the repository
template. Maintainers may close contributions that are unreviewed,
unexplained, duplicative, or unnecessarily broad.

## Permitted local work

Agents may inspect repository state and run read-only Git commands such as
`git status`, `git diff`, and `git log`. They may make local changes and run
the requested checks, subject to the review checkpoint above.
