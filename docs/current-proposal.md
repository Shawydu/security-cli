# Current proposal — from local proof toward a useful remediation CLI

Status: **local proof implemented; future phases proposed, not authorized for deployment**. This replaces the assumptions of the [original proposal](../Security_Remediation_Proposal.md) with decisions confirmed during the pilot. Refer to [current design](current-design.md) for as-built behavior and [phased plan](phased-plan.md) for sequencing and exit gates.

## Goal and value test

For one saved Python dependency alert and a clean disposable Git checkout, produce either a small **locally verified** candidate patch and evidence or a clear blocked result. Try ordinary deterministic uv resolution first; use the installed pi coding agent only when repository investigation or a narrowly permitted source adaptation might add value. Compare any agent repair with the no-agent resolver path. If pi only repeats a routine version bump, it has not justified the cost or added risk.

The completed pilot proves a deterministic path, not unattended remediation: urllib3 2.0.6 → 2.8.0 on 2026-10-01, 12 passing checks, nine to zero **reported** audit findings, zero pi calls. The offline fixtures cover selected refusals and restart behavior but are labeled simulated. Pi headless skill routing was smoke-tested without an agent-authored patch. Results depend on the live advisory feed and chosen pilot environment.

## Decisions actually made

| Question | Current decision |
| --- | --- |
| Agent/model | Use one **preconfigured pi** CLI and skill. No custom model routing, provider auth layer or multi-agent framework. Count up to three *pi CLI invocations* per local operation, not tokens or underlying model requests. |
| Inputs and environment | Saved alert JSON; clean Git source; operator policy, state and output outside source; one uv-managed Python 3.12.14/default-runtime/public-PyPI-wheels pilot. No automatic GitHub reads or private production sources yet. |
| Verification | Trusted runner owns diff/policy checks and fresh installed-environment lock, inventory, tests and pip-audit checks. Demand baseline target mapping, candidate target removal, complete observed coverage and no new **reported** findings; disclose unchanged unrelated findings instead of pretending everything is clean. |
| Failure and persistence | Reserve before agent invocation; conflicts do not reset attempts. Local file-backed state survives process restarts on the same machine, not deletion or machine loss. An explicit operator new-operation ID + reason preserves earlier history. |
| Security and publication | This is a **supervised, local-only synthetic experiment**. No enforceable sandbox/credential separation; no publisher, PR, merge, dismissal or Jenkins integration. No unattended or production-source claim. |

## Why the next investment is not a publisher

The first live candidate needed no agent and no isolation was proven. Publishing that evidence as an autonomous PR capability would overstate both agent value and security. **Recommended next phase:** demonstrate a real pi-authored repair on a disposable non-sensitive fixture, and establish an enforceable worker boundary for agent tools, package resolution/installation and project tests. Validate what target commands can read, where process children run, and whether credentials, state and original source are inaccessible. Choose the isolation design with the operator; if proof fails, keep the tool supervised and local. Tighten known evidence gaps before enlarging the threat surface.

Only after these gates and another explicit approval should the project consider a read-only GitHub alert adapter; a writable exact-candidate PR publisher is a later, separately gated phase requiring scoped trusted credentials, persistent backed-up state, crash-safe publication intent and idempotent reconciliation. Jenkins is orchestration **after** manual integration works, not a replacement for runner decisions. Human review and branch protection remain necessary. See [phased plan](phased-plan.md).

## Explicitly out of scope until revisited

CodeQL remediation, broad Python ecosystem/group/extra support, transitive parent migrations, private registries, automatic merging/alert dismissal, production deployment, dashboards, queues and multi-repository orchestration. A passed scanner/test suite is evidence for those checks on one candidate at a point in time—not proof of complete vulnerability removal, full compatibility or safe execution of untrusted code.
