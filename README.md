# Prowl

> **Autonomous vulnerability discovery and exploit validation.** Prowl reads a codebase, generates hypotheses, then builds and runs the actual target project in a Docker sandbox to prove vulnerabilities are real — compiling C/C++ binaries with ASAN, starting Python/Node servers and sending crafted requests, or exercising Go/Rust/Java binaries with crafted inputs.

```bash
pip install "prowl-sec[anthropic]"
export ANTHROPIC_API_KEY=sk-ant-...        # https://console.anthropic.com/settings/keys
prowl scan /path/to/project
```

Prefer a `.env` file? Drop `ANTHROPIC_API_KEY=sk-ant-...` into `.env` in the directory you run `prowl scan` from — it's picked up automatically.

Reconnaissance is fully deterministic (tree-sitter, no LLM — same codebase always produces the same target list). The LLM layers are rubric-constrained, confidence-gated, and cached. PoC generation runs as an agent loop via [Claw Code](https://github.com/ultraworkers/claw-code) inside a hardened Docker sandbox.

## Prowl vs. SAST

| Prowl | SAST (semgrep, CodeQL) |
|-------|------------------------|
| Reasons about *intent*, then proves exploitability | Matches syntactic patterns |
| Builds the actual project, runs the real binary/server with crafted inputs — ASAN crashes on the real binary, HTTP requests to the running server | Source line flags |
| LLM reasoning; costs tokens, takes minutes | Deterministic, fast, free |
| Research workbench | Good for CI |

Run both. `semgrep --config auto .` catches known patterns at merge time; `prowl scan .` finds the three-step API call sequence that lets an unauthenticated user approve their own refund, then generates the HTTP request sequence that demonstrates it.

| Domain | What Prowl produces |
|--------|---------------------|
| Web app vulns | Installs deps, starts the actual server, sends HTTP requests proving unauthorized access / invalid state transition |
| Injection | Starts the real application, sends crafted input extracting data through the exact sink |
| Memory safety (C/C++/Rust unsafe) | Compiles the actual project with ASAN, runs the real binary with crafted input triggering an ASAN report |
| Concurrency | Builds and runs the real binary/server, sends concurrent requests proving the race window |
| Multi-finding chains | Chain identification + end-to-end validation against the running application (SSRF + no internal auth → internal network access) |

## How it works

```
Target codebase
    │
    ▼
RECONNAISSANCE (deterministic, no LLM)
    Tree-sitter parsing → function extraction → risk signal detection
    → vulnerability scoring → call graph → taint tracking → target ranking
    │
    ▼  (ranked target list)
LAYER 1: HYPOTHESIS (LLM)
    Context builder scopes each target function (~4K tokens)
    LLM hypothesizes vulnerabilities against detection rubrics
    Confidence gating: promote (≥0.7) / batch (0.4–0.7) / suppress (<0.4)
    │
    ▼  (confidence-gated hypotheses)
LAYER 2: TRIAGE + CHAIN ANALYSIS (LLM)
    Individual + batch triage: exploitable / mitigated / false_positive / uncertain
    Deterministic chain grouping + LLM chain evaluation
    Severity gating for Layer 3
    │
    ▼  (exploitable + uncertain findings)
LAYER 3: EXPLOIT VALIDATION (Claw Code + Docker sandbox)
    Claw Code agent builds the actual project inside Docker
    C/C++: compiles with ASAN/UBSAN, runs the real binary with crafted inputs
    Python/Node: installs deps, starts the actual server, sends crafted HTTP requests
    Go/Rust/Java: builds with native toolchain, runs with crafted inputs
    Per-vuln-class validation (ASAN crashes, injection markers, auth bypass, ...)
    Optional patch generation with compile + test validation
    │
    ▼
VULNERABILITY REPORT (text / JSON / SARIF / AI / Markdown)
```

**Structured output enforcement** at every LLM hop: Pydantic schemas in the prompt, `model_validate_json` on the response, one retry with error context, skip the target on second failure. **Dependency injection** for the LLM client and sandbox manager, so the whole pipeline runs under `MockLLMClient` + `MockSandboxManager` in tests (385 tests, ~1 s). **Async with bounded parallelism** via `anyio.CapacityLimiter` — 8 concurrent hypotheses, 4 triage, 2 validations.

## Requirements

- Python 3.11+
- Docker (for Layer 3 PoC validation in sandboxed containers)
- An API key for at least one LLM provider (OpenAI, Anthropic, Google, or a local Ollama instance)
- [Claw Code](https://github.com/ultraworkers/claw-code) (auto-installed in Docker sandbox for Layer 3 PoC validation)

## Installation

From PyPI (published as `prowl-sec`; the CLI command and import name stay `prowl`):

```bash
pip install "prowl-sec[anthropic]"   # Anthropic (default)
pip install "prowl-sec[openai]"      # OpenAI
pip install "prowl-sec[google]"      # Google
pip install "prowl-sec[ollama]"      # Ollama (local models)
pip install "prowl-sec[all-llm]"     # All providers
```

From source (editable, for development):

```bash
cd prowl
pip install -e ".[dev,anthropic]"    # Anthropic (default)
pip install -e ".[dev,openai]"       # OpenAI
pip install -e ".[dev,google]"       # Google
pip install -e ".[dev,ollama]"       # Ollama (local models)
pip install -e ".[dev,all-llm]"      # All providers
```

If you cannot do an editable install (e.g., missing setuptools), set `PYTHONPATH` directly:

```bash
export PYTHONPATH=/path/to/prowl/src
```

Verify the install:

```bash
python -m prowl --help
```

## LLM Configuration

Set your API key as an environment variable:

```bash
export ANTHROPIC_API_KEY=your-key    # for Anthropic (default)
export OPENAI_API_KEY=your-key       # for OpenAI
export GOOGLE_API_KEY=your-key       # for Google
```

Configure the provider and model in `prowl.yml`:

```yaml
llm:
  provider: anthropic                  # openai | anthropic | google | ollama
  model: claude-opus-4-6
  temperature: 0.0

  # Per-layer model overrides (optional)
  hypothesis:
    model: claude-haiku-4-5-20251001   # fast/cheap for high-volume Layer 1
  triage:
    model: claude-opus-4-6             # strong reasoning for Layer 2
  validation:
    model: claude-opus-4-6             # code generation for Layer 3
```

For local models via Ollama:

```yaml
llm:
  provider: ollama
  model: llama3
  base_url: http://localhost:11434
```

## Usage

### CLI

```bash
# Full scan on a project
prowl scan /path/to/project

# Scan with verbose logging
prowl -v scan /path/to/project

# Specific vulnerability categories only
prowl scan --categories memory,auth,injection /path/to/project

# Output formats: text (default), json, sarif, ai, markdown
prowl scan --format json /path/to/project
prowl scan --format sarif /path/to/project > results.sarif
prowl scan --format ai /path/to/project
prowl scan --format markdown /path/to/project

# Write report to a file
prowl scan --format markdown -o report.md /path/to/project
prowl scan --format json -o results.json /path/to/project

# Generate patches for confirmed findings
prowl scan --fix /path/to/project

# Resume an interrupted scan
prowl scan --resume /path/to/project

# Force full rescan (ignore cache)
prowl scan --no-cache /path/to/project

# Override PoC iteration budget
prowl scan --iterations 8 /path/to/project
```

### Managing findings

```bash
# Check scan status
prowl status

# List findings (from last scan)
prowl findings
prowl findings --severity critical,high
prowl findings --category auth,injection

# Suppress a false positive
prowl suppress prowl-sqli-handler.py-84 --reason "input validated in middleware" --scope function

# Suppression scopes:
#   finding   - this exact finding
#   function  - all findings for this function (survives line changes)
#   rule      - all findings matching this rule in this file
#   project   - all findings matching this rule project-wide

# Report a vulnerability Prowl missed
prowl missed src/handlers/admin.py:47 --category auth --description "missing admin check on delete endpoint"

# Clean up persisted scan state
prowl clean-state
```

## PoC validation via Claw Code

Layer 3 validation uses [Claw Code](https://github.com/ultraworkers/claw-code) as an autonomous agent inside the Docker sandbox. Instead of generating standalone PoC code, Claw builds and runs the actual target project, then exercises it with crafted inputs to confirm the vulnerability is real.

**How it works per language:**

- **C/C++:** Auto-detects the build system (cmake, autotools, meson, make), injects `ASAN_OPTIONS` and `UBSAN_OPTIONS` flags, compiles the real project, runs the binary with crafted inputs, and checks that ASAN traces include the target function.
- **Python/Node:** Installs dependencies (`pip install` / `npm install`), starts the actual application server, and sends crafted HTTP requests to the vulnerable endpoint.
- **Go/Rust/Java:** Builds with the native toolchain (`go build -race`, `cargo build`, `mvn package`), then runs the binary with crafted inputs.

Each language gets an enriched Docker image with full build toolchains. Containers run with elevated resources: 2 GB RAM, 1 GB tmpfs, 1024 PIDs, 30-minute timeout, and up to 50 Claw agent turns. On success, Claw writes the `ARGUS_VALIDATED` marker and saves a `test.sh` script for reproducibility.

```yaml
validation:
  claw_timeout_build: 1800       # 30 minutes for full-project builds
  claw_max_turns_build: 50       # Claw agent turns for build+test
  claw_api_key_env: null         # auto-detected from LLM config

sandbox:
  mem_limit_build: "2g"          # 2 GB for compilation
  cpu_quota_build: 400000        # double CPU for build phase
```

The Claw container needs network access for LLM API calls. See the [spec](prowl.md) for the full security model.

## Configuration

Create `prowl.yml` in your project root. All fields are optional.

<details>
<summary><b>Full defaults (click to expand)</b></summary>

```yaml
scan:
  include: []                        # paths to scan (default: entire project)
  exclude: []                        # paths to skip
  languages: []                      # auto-detected if omitted
  project_type: "auto"               # "auto", "application", "library"
  detection_categories:              # all 9 enabled by default
    - auth
    - data_access
    - crypto
    - input
    - financial
    - privilege
    - memory
    - injection
    - concurrency

reconnaissance:
  min_likelihood_score: 1.0          # skip functions below this
  max_review_chunks: 100             # cap targets per scan
  interaction_targets: true          # detect shared-state interaction targets
  auto_exclude: true                 # auto-exclude generated/vendored code
  auto_exclude_override: []          # paths to force-include despite auto-exclude

scoring:
  hypothesis_confidence_threshold: 0.7
  batch_confidence_threshold: 0.4
  max_promoted_findings: 100

triage:
  reachability: true
  chain_analysis: true
  patch: true                        # generate remediation patches
  patch_iterations: 3

validation:
  enabled: true
  severity_gate: "high"              # generate PoCs for high+ severity only
  max_exploits: 10                   # cap PoC attempts per scan
  max_iterations_simple: 3           # missing auth, basic injection
  max_iterations_medium: 5           # business logic, race conditions
  max_iterations_memory: 5           # ASAN crash confirmation
  max_iterations_chain: 8            # multi-finding chains
  instrumentation:
    - asan
    - ubsan
    - coverage
  # Claw Code PoC validation settings
  claw_timeout_build: 1800           # 30 minutes for full-project builds
  claw_max_turns_build: 50           # Claw agent turns for build+test
  claw_api_key_env: null             # API key env var forwarded to container (auto-detected)

sandbox:
  runtime: docker
  timeout_default: 180               # seconds
  timeout_race_condition: 720
  timeout_max: 1800
  timeout_startup: 180                # container startup budget
  mem_limit: "512m"
  mem_limit_build: "2g"              # 2 GB for compilation
  cpu_quota: 200000                  # 2 CPU cores
  cpu_quota_build: 400000            # double CPU for build phase
  pids_limit: 256
  network: none                      # no network egress
  tier3_services: [postgres, mysql, redis]

concurrency:
  max_concurrent_hypotheses: 8
  max_concurrent_triage: 4
  max_concurrent_validations: 2

budget:
  max_tokens_per_scan: null          # null = unlimited
  max_cost_per_scan: null
  layer3_budget_fraction: 0.4

cache:
  enabled: true
  invalidation: "interface"          # "interface" (scoped) or "any_change"
  cross_cutting_invalidation: true

output:
  format: "text"                      # text, json, sarif, ai, markdown
  include_poc: true
  include_reasoning: false

resume:
  enabled: true
  state_dir: ".prowl/scan-state"

llm:
  provider: "anthropic"              # openai | anthropic | google | ollama
  model: "claude-opus-4-6"
  api_key_env: null                  # auto-detected per provider
  base_url: null                     # for ollama/vLLM
  temperature: 0.0
  hypothesis:                        # per-layer overrides (all optional)
    provider: null
    model: null
    temperature: null
    max_tokens: null
  triage:
    provider: null
    model: null
    temperature: null
    max_tokens: null
  validation:
    provider: null
    model: null
    temperature: null
    max_tokens: null
```

</details>

### Custom rubrics

Add custom detection rules by placing YAML files in `.prowl/rubrics/`:

```yaml
# .prowl/rubrics/custom-ssrf.yml
category: injection
detection_rules:
  - name: internal_ssrf
    instruction: "Check if any URL parameter is used to make server-side HTTP
    requests without restricting the target to allowed hosts."

calibration:
  test_cases:
    - file: "tests/vulns/ssrf_vulnerable.py"
      function: "fetch_url"
      expected: true
    - file: "tests/vulns/ssrf_safe.py"
      function: "fetch_url"
      expected: false
```

Custom rubrics extend the built-in rubrics -- they don't replace them.

## Output formats

### Text (default)

Human-readable terminal output with severity-sorted findings, attack scenarios, and PoC validation status.

### JSON

Full structured report via `--format json`. Contains all finding fields, chain analysis, scan progress, and budget usage.

### SARIF 2.1.0

Standard static analysis format via `--format sarif`. Compatible with VS Code, GitHub Code Scanning, Defect Dojo, and other SARIF consumers. Each finding maps to a SARIF result with rule ID, severity level, locations, and PoC in properties.

### AI

Structured for consumption by downstream LLM agents via `--format ai`. Includes natural-language attack narratives and actionable remediation context per finding.

### Markdown

Detailed, self-contained report via `--format markdown`. Designed for sharing with security teams and for reproducibility. Each finding includes:

- Severity, classification, confidence, and location metadata
- Full description, attack scenario, and analysis reasoning
- **Complete PoC source code** in fenced code blocks with language highlighting
- **Step-by-step reproduction instructions** tailored to the vulnerability category (e.g. ASAN compilation flags for memory bugs)
- **Execution output** (stdout/stderr) from the sandbox validation run
- **Sanitizer output** with violation type and details (for memory safety bugs)
- **Suggested patches** when available
- Attack chain relationships between findings

Write to a file with `-o`:

```bash
prowl scan --format markdown -o report.md /path/to/project
```

## Project state

Prowl stores runtime state in `.prowl/` in the project root:

| Path | Purpose | VCS |
|------|---------|-----|
| `.prowl/suppressions.json` | Suppressed findings | Commit (shared across team) |
| `.prowl/missed.json` | Reported false negatives | Commit (shared across team) |
| `.prowl/cache/` | LLM result cache | Gitignore |
| `.prowl/scan-state/` | In-progress scan state for resume | Gitignore |
| `.prowl/calibration/` | Confidence calibration data | Gitignore |

## Vulnerability categories

| Category | Weight | What Prowl looks for |
|----------|--------|---------------------|
| `auth` | 1.5 | Missing checks, broken access control, privilege escalation, session fixation |
| `data_access` | 1.0 | Unscoped queries, IDOR, SQL injection |
| `input` | 1.0 | Type confusion, missing validation, unsafe deserialization |
| `crypto` | 1.2 | Weak randomness, wrong algorithm, timing side-channels |
| `financial` | 1.3 | Invalid state transitions, double-spend, missing idempotency |
| `privilege` | 1.4 | Incomplete privilege drops, TOCTOU in privilege boundaries |
| `memory` | 1.5 | Buffer overflows, use-after-free, integer overflow, format strings |
| `injection` | 1.5 | Command injection, SSTI, LDAP injection, header injection |
| `concurrency` | 1.0 | Race conditions, TOCTOU, double-fetch |

## Supported languages

Prowl uses tree-sitter for parsing and supports:

Python, JavaScript, TypeScript, TSX, Java, Go, Rust, C, C++, Ruby, PHP

Language is auto-detected from file extensions. Override with `scan.languages` in config.

## Development

### Running tests

```bash
# All tests (385 tests, ~1 second)
pytest tests/ -v --ignore=tests/fixtures

# Specific module
pytest tests/test_recon/ -v

# Single test class
pytest tests/test_recon/test_signals.py::TestSqlInjectionSignals -v

# With coverage
coverage run -m pytest tests/ && coverage report
```

### Linting

```bash
ruff check src/prowl/
ruff check src/prowl/ --fix    # auto-fix
```

### Project structure

```
src/prowl/
    models/          # Pydantic v2 data models (core, scan, context, finding, etc.)
    recon/           # Reconnaissance: parsing, extraction, signals, scoring, call graph
    context_builder/ # Context assembly for each layer, framework/sanitizer detection
    rubrics/         # YAML detection/triage/exploit rubrics (28 files, 9 categories)
    hypothesis/      # Layer 1: parallel hypothesis generation + confidence gating
    triage/          # Layer 2: classification, chain analysis
    validation/      # Layer 3: Claw Code agentic PoC generation + sandbox execution
    sandbox/         # Docker container lifecycle, security policy, instrumentation
    llm/             # LangChain multi-provider LLM client, schema validation, retry, budget, calibration
    cache/           # Content-addressed cache with cross-cutting invalidation
    pipeline/        # Orchestrator, resume, concurrency management
    suppression/     # False positive/negative management
    output/          # Text, JSON, SARIF 2.1.0, AI, Markdown output formats
    cli.py           # Click CLI
    config.py        # prowl.yml loading

tests/
    fixtures/        # Intentionally vulnerable codebases (Python, C, Node.js)
    test_recon/      # Parser, exclusions, extractor, signals, scorer, call graph
    test_context_builder/
    test_hypothesis/
    test_triage/
    test_cache/
    test_suppression/
    test_output/
    test_pipeline/   # Integration with mocked LLM + sandbox
    test_llm/        # LangChain client, provider routing, config
    test_sandbox/    # Docker sandbox manager, image build, instrumentation
    test_validation/ # Claw backend, result checking, patch generation
    test_integration/
```

## Limitations

- **No kernel-mode validation.** The Docker sandbox runs userspace code. Kernel bugs get Layer 1-2 analysis without PoC confirmation.
- **No cross-service chains.** Analysis operates within a single repository.
- **No cross-language taint tracking.** In multi-language projects (Python calling C via FFI), each language is analyzed independently.
- **Call graph is approximate.** Dynamic dispatch, callbacks, and metaprogramming create gaps. The LLM compensates using context, but precision varies by language.
- **Not a CI gate.** Prowl is a research tool, not a linter. CI pipelines should use deterministic tools.

## Spec

The full specification is in [`prowl.md`](prowl.md).
