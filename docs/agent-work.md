# Agent work plan

Use a coordinator and three focused workers initially. This is a work allocation proposal, not a running autonomous service or model performance guarantee.

| Role | Owns | Required result |
| --- | --- | --- |
| Desktop packaging | Hyprland configuration audit and later desktop recipes | Pinned inputs, dependency map, conflicts, package contents, build evidence |
| Tools and defaults | Shell configuration audits and selected system settings | ARM dependency availability, Apple assumptions, license notes, narrowly selected defaults |
| Build and validation | Clean-build specification and later build/check tooling | Recorded base, reproducible commands, artifact inspection, upgrade checks |
| Coordinator | Shared manifest, integration, scope, reviews | Reconciled package set, integration checks, explicit unresolved work |

Workers should propose changes to shared manifests rather than edit them concurrently. Review integrated behavior, not just each worker's report. Use independent review for platform-affecting changes.

GPT-6.1 Sol is a reasonable candidate for the worker roles. Actual project success depends on access to an ARM Linux build environment, the target MacBook, useful logs, and an accountable integration process. More simultaneous agents do not replace those inputs.

Agents can audit recipes, implement builds, resolve compilation issues, and inspect results. Hardware acceptance requires real execution on the target: sleep/wake, audio, graphics, firmware, external displays, battery, and thermals cannot be certified by reading source.

Model and reasoning choices are runtime settings, not project dependencies. Avoid adding paid API infrastructure just to start package development.
