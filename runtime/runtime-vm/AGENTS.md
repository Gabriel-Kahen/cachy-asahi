# Contributor and agent instructions

- Be honest. Distinguish proposed, source-audited, built, installed, and hardware-tested work.
- Use as many subagents as the task needs without asking. Give each agent bounded scope and explicit file ownership; keep integration with one coordinator.
- Read the roadmap and package inventory before implementing a task.
- Preserve Asahi's working platform stack for the first milestone. Do not add PC bootloader or hardware-detection assumptions.
- Pin upstream revisions when packaging. Record sources, licenses, dependencies, build commands, and actual results.
- An upstream architecture declaration is not proof of a successful ARM build or M2 compatibility.
- Do not mark hardware checks passed based on compilation, emulation, README claims, or another Mac model.
- Do not claim performance gains without measurements against a documented baseline.
- Make package installation and removal behavior reviewable. Keep system mutation out of research and build scripts.
- Avoid simultaneous edits to shared manifests. Report proposed manifest changes to the coordinator.
- Run checks appropriate to the change. Documentation-only changes do not require implementation tests.
- Report blockers and unfinished work plainly; do not silently skip failed packages while claiming a complete overlay.
