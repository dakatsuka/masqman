# Masqman Agent Guide

This proxy server acts as an intermediary between MySQL Server and the client, parsing the results and masking the values of fields that are not permitted.

This file is the small, stable entry point for agentic development. Treat the repository documentation as the source of truth; do not turn this file into a large manual.

## Repository Map
- `docs/design-docs/`: architecture, design constraints, subsystem designs, and Architecture Decision Records.
- `docs/exec-plans/`: active and completed execution plans for substantial implementation work.
- `docs/product-specs/`: product-facing requirements, API behavior, and compatibility expectations.
- `docs/references/`: copied or summarized external references that agents need during implementation.

Start with the relevant index before making changes:

- [Design Docs](docs/design-docs/index.md)
- [Execution Plans](docs/exec-plans/index.md)
- [Product Specs](docs/product-specs/index.md)
- [References](docs/references/index.md)

## Engineering Constraints
- Target Go 1.26.x
- Prefer small, explicit modules with behavior documented by tests.
- Keep public APIs narrow until requirements are captured in a product spec.
- Define public APIs, function signatures, and types before filling in internal implementation details.
- Document public interfaces and contracts with block comments.
- Keep modules, classes, functions, methods, and values focused on the smallest practical responsibility.
- Prefer names and structure that future maintainers and agentic AI can follow during operations and incident analysis.
- Write repository documentation, source comments, commit messages, and public technical artifacts in English.
- Write commit messages according to [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/).
- Include a commit body for non-trivial changes. The body should explain why
  the change is needed first, then summarize what changed to support that
  reason.

## Collaboration Rules
- If instructions are unclear, ask clarifying questions before making assumptions.
- After design work, ask a context-free sub-agent for third-party review. Treat the feedback as input rather than authority: evaluate it critically, incorporate only well-justified changes and refine the design.
- After implementation, ask a context-free sub-agent for code review. Fix any findings and repeat review until the review passes.

## Documentation Workflow
- New product behavior starts in `docs/product-specs/`.
- New architecture or internal design starts in `docs/design-docs/`.
- Substantial implementation work gets an execution plan in
  `docs/exec-plans/active/`, then moves to `docs/exec-plans/completed/` when
  finished.
- Major design changes require both an updated design document and a new ADR in
  `docs/design-docs/adr/`.
- External references that materially affect implementation should be captured
  under `docs/references/` so future agents can operate from repository-local
  context.
- As a rule, update the CHANGELOG and website together immediately before a
  version bump.

## Quality Bar
- Use an Explore -> Red -> Green -> Refactor cycle for implementation work.
- Create unit test files per module.
- Use available static analysis and formatting tools for the language and fix
  their findings. Do not use prompts or manual AI edits as a substitute for
  tool-driven formatting or static checks.
- Before finishing implementation work, run the most specific available test
  command and record the result in the final response.
- If no test harness exists yet, state that explicitly and prefer adding one as
  part of the next implementation plan.
- Do not hide unresolved design questions in code comments; record them in the
  relevant spec, design doc, or execution plan.
