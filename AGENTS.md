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

## Pull request reviews and remote actions

Any AI coding agent may post PR review comments on behalf of a contributor or
maintainer when that person asks the agent to review a specific pull request
or publish an existing review. This includes review summaries posted as PR
comments, inline review comments, and replies in review threads. The request
authorizes publishing through that person's configured authentication without
a separate confirmation step. The contributor or maintainer remains
responsible for review content posted under their account. Avoid posting
duplicate comments when the findings are already present.

Use a comment review by default. Submit an approving or changes-requested
review only when the user explicitly requests that review state.

Other remote write operations remain prohibited. Agents must not run
`git push`, create or merge pull requests, create releases, post issues or
comments unrelated to an authorized PR review, or invoke equivalent remote
actions.

Agents may use configured authentication to publish authorized reviews. Prefer
credentials scoped to repository read access and pull request review writes.
Review access does not authorize repository content writes or other remote
actions.

## Mandatory review checkpoint

Before a human pushes AI-assisted changes or submits them in a pull request,
the agent must:

1. show the relevant diff or a concise file-by-file summary;
2. report tests and checks run, including failures or checks not run;
3. identify material assumptions, security-sensitive changes, and unreviewed
   areas; and
4. explicitly ask the human to review the changes.

The agent must wait for the human to confirm that they reviewed the changes.
This checkpoint applies to code and documentation contributions; authorized
PR reviews follow the publishing permission above. Approval to edit, test,
stage, or commit does not authorize an agent to push or perform other remote
write operations.

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
