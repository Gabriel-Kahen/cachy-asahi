# Performance evidence

Final-system baseline-versus-release measurements are **NOT RUN** for both M2 Air sizes. No improvement, battery-life or thermal claim is established.

The [measurement framework](performance/README.md), [CLI contract](performance/cli.md), [instrumentation plan](performance/instrumentation.md) and [experiment supplement](performance/experiment-template.md) prepare those runs. Local smoke workloads and tests exercise software only.

Publish separate 13-inch and 15-inch reports with exact source/release/base/machine records, frozen workload/control/acceptance budgets, raw trials and independent review. Each report must cover throughput, interactive latency under load, memory, graphics, idle/load power and battery, suspend drain, sustained thermals, correctness, functional regressions and exercised recovery. Publish the final system even when no tuning experiment wins. CLI elapsed thresholds cannot satisfy these requirements.

The coordinator owns report integration and full-goal acceptance through `docs/acceptance.md`.
