# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Language

Always respond and work in English, even if the user's prompt is written in another language.

## Development Commands

```bash
# Development
DEV_PORTS=8080                                   # Port(s) the dev server listens on
START_COMMAND="./build/firewallo-web -c etc/firewallo/firewallo.json -w web -p 8080"
PREDEV_COMMAND="make all"                        # Build before starting
VERIFY_COMMAND="make clean && make all && make test"  # Quality gate

# Testing
TEST_FRAMEWORK="custom C test harness"           # Built-in assert-based tests
TEST_COMMAND="make test"                          # Runs all 4 test suites
TEST_FILE_PATTERN="tests/test_*.c"                # Test file naming

# CI
CI_RUNTIME_SETUP="# GCC is pre-installed on Debian runners"

# Release
RELEASE_BRANCH="main"                            # Stable release branch
MANIFEST_PATHS="etc/firewallo/firewallo.json"     # Version lives here
CHANGELOG_FILE="CHANGELOG.md"
TAG_PREFIX="v"
GITHUB_REPO_URL="https://github.com/un1x80/firewallo"

# Common commands:
# make              — Build both binaries (firewallo + firewallo-web)
# make lib          — Build core library only
# make cli          — Build CLI binary only
# make web          — Build web server binary only
# make debug        — Build with -g -O0 -fsanitize=address
# make test         — Run all test suites (344 tests)
# make clean        — Remove build directory
# make install      — Install to /usr/local
# ./debian/build-deb.sh — Build .deb package
```

**Important:** Your project's verify command must pass before closing any task. Define it above and reference it throughout the skills.

## Environment Setup

- **OS:** Debian 12+ (target platform)
- **Compiler:** GCC with C17 support
- **Build:** GNU Make
- **Dependencies:** None (pure C17 + POSIX only)
- **Install build tools:** `apt install build-essential`

## Architecture

- **`src/lib/`** — `libfirewallo.a` static library (shared by CLI and web)
  - `json.c` — Recursive descent JSON parser/serializer
  - `config.c` — JSON <-> `fw_config_t` struct mapping
  - `validate.c` — IP, port, interface, protocol validators
  - `rule_compiler.c` — Orchestrates config -> command list generation
  - `backend_nft.c` / `backend_ipt.c` — nftables/iptables command generation
  - `zone.c` — 5 zones, 25 chain name management
  - `sysctl.c` — `/proc/sys` writes, `system()` execution
  - `log.c`, `i18n.c`, `util.c` — Supporting modules
- **`src/cli/`** — CLI binary entry point and command dispatch
- **`src/web/`** — HTTP server, router, REST API, static file serving
- **`include/firewallo/`** — All public headers
- **`web/`** — Frontend (vanilla HTML/CSS/JS SPA)

### Key Types

- `fw_config_t` — Master configuration struct (defined in `types.h`)
- `fw_chain_t` — One of 25 filter chains with TCP/UDP ports and explicit rules
- `fw_cmdlist_t` — Ordered list of shell commands to execute
- `fw_backend_ops_t` — Backend vtable (function pointers for nft/ipt)

### Config File

Single JSON file at `/etc/firewallo/firewallo.json`. Contains: version, language, backend, interfaces, DNS, ranges, sysctl, 25 filter chains, NAT, mangle, routes, DPI, suricata.

### Coding Conventions

- C17 standard, compiled with `-Wall -Wextra -Wpedantic`
- No external libraries — only libc + POSIX
- Functions prefixed with `fw_` for library, `cmd_` for CLI, `api_` for REST
- Fixed-size arrays in structs (no dynamic allocation in config)
- All user input validated before use

<!-- CTDF:START -->
## Key Patterns

### Task Files

Tasks are split across three files by status:

| File | Status | Symbol |
|------|--------|--------|
| `to-do.txt` | Pending tasks | `[ ]` |
| `progressing.txt` | In-progress tasks | `[~]` |
| `done.txt` | Completed tasks | `[x]` |

When a task changes status, move it to the corresponding file.

**Additional platform label:** Tasks in `progressing.txt` may also carry `status:to-test` on the platform, indicating they are awaiting test verification. Task branches must not be merged into the release branch until testing is confirmed.

### Idea Files

Ideas are stored separately from tasks and must be explicitly approved before entering the task pipeline:

| File | Purpose |
|------|---------|
| `ideas.txt` | Ideas awaiting evaluation |
| `idea-disapproved.txt` | Rejected ideas archive |

Use `/idea-create` to add ideas, `/idea-approve` to promote an idea to a task, `/idea-refactor` to update ideas based on codebase changes, and `/idea-disapprove` to reject an idea. Ideas must never be picked up directly by `/task-pick`.

### Task & Idea Management Modes

Tasks and ideas support three operating modes, controlled by `.claude/issues-tracker.json`:

| `enabled` | `sync` | Mode | Data Source |
|-----------|--------|------|-------------|
| `true` | `false` (or absent) | **Platform-only** | GitHub Issues or GitLab Issues only. No local files. |
| `true` | `true` | **Dual sync** | Local files first, then platform issues. |
| `false` | — | **Local only** | Local text files only (default). |

The `platform` field (`"github"` or `"gitlab"`) determines which CLI tool (`gh` or `glab`) is used. If omitted, defaults to `"github"`.

## Cross-Platform Notes

This framework supports **Windows, macOS, and Linux** with automatic OS detection.

- **Python command:** All scripts and skills reference `python3`. On Windows where only `python` is available, substitute `python` for `python3` in all commands.
- **Port management:** `app_manager.py` automatically uses the correct OS tools — `lsof`/`ss` on Unix, `netstat`/`taskkill` on Windows.
- **File search:** `task_manager.py find-files` provides cross-platform file discovery (replaces Unix `find`).
<!-- CTDF:END -->

## File Naming Conventions

- C source files: `snake_case.c`
- Headers: `snake_case.h` under `include/firewallo/`
- Test files: `test_*.c` under `tests/`
- Frontend: `kebab-case` for HTML/CSS, `camelCase` for JS
