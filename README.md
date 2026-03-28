# Lanternis

**Lanternis** is a hobby/OSS tool for the household “IT person”: **LAN discovery**, honest device inventory, and (later) **evidence-backed** security intel—without pretending to know what the network does not reveal.

This repository is **early**: specs and plans are in place; the **M1** vertical slice (SQLite, discovery, localhost API, audit) is still to be implemented. See **`docs/ENGINEERING-PLAN.md`** for the execution plan.

## Documentation

| Doc | Purpose |
|-----|---------|
| [`docs/INCEPTION.md`](docs/INCEPTION.md) | Why the project exists, principles, milestone summary |
| [`docs/ENGINEERING-PLAN.md`](docs/ENGINEERING-PLAN.md) | Packages, security, SQLite audit, tests, failure modes |
| [`docs/UI-PLAN.md`](docs/UI-PLAN.md) | Localhost console IA, states, accessibility, UI tokens |
| [`DESIGN.md`](DESIGN.md) | Visual system: color, type, spacing, motion, dark mode (source of truth for UI code) |
| [`TODOS.md`](TODOS.md) | Deferred work and follow-ups |

Design deep-dives and some QA artifacts also live under **`~/.gstack/projects/lanternis/`** on the author’s machine (see links in `docs/INCEPTION.md`).

## Built with gstack

Planning, review passes (office-hours, engineering/design plan reviews), and supporting artifacts for this project were produced using **[gstack](https://github.com/garrytan/gstack)**—agent skills and workflows for AI-assisted development (browse/QA, ship, retros, etc.). The **application code** here is ordinary Go; gstack mainly shaped **how** the plans and repo were iterated.

## Quick start

Requires [Go](https://go.dev/) 1.26+ (see `go.mod`).

```bash
go build -o lanternis ./cmd/lanternis
./lanternis
```

## License

[MIT](LICENSE)
