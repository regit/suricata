# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Suricata is a high-performance network IDS, IPS and NSM engine (OISF). It is a large,
security-critical C codebase with a growing Rust component; it processes mostly untrusted
network input, so correctness and memory-safety matter more than convenience.

**Performance is a first-order constraint.** Suricata is expected to inspect *every* packet on
links running at **100 Gbps and beyond** — it runs in the hot path of the whole pipeline, per
packet, per flow, across many threads. So performance is not a nice-to-have: if the engine
can't keep up it drops packets, and a packet Suricata never sees is a threat that can never be
detected — packet loss is itself a detection failure. Design and review with this in mind:
prefer the efficient path, avoid per-packet allocations/locks/syscalls and unnecessary work on
the hot path, and be wary of anything that adds fixed per-packet or per-flow cost. This is a
deliberate trade-off *in favor of performance* — **but never at the expense of security or
correctness**: an evasion, a memory-safety bug, or a wrong verdict defeats the point of running
an IDS at all. When performance and safety genuinely conflict, keep it safe and make it fast
another way (better algorithm/data structure, batching, doing the work off the hot path).

**Cross-platform**: Suricata is multi-OS and must stay that way — it supports Linux,
FreeBSD, OpenBSD, macOS (Darwin), and **Windows** (built via mingw32). Do not assume Linux.
OS-specific code is guarded by the defines set in `configure.ac` (`OS_WIN32`, `OS_FREEBSD`,
`OS_DARWIN`, `__OpenBSD__`, …); Windows-specific implementations live in `src/win32-*.c`
(service, syscall, misc, syslog shims). New code that touches OS facilities (paths, sockets,
signals, threads, filesystem, capabilities/sandboxing) must either be portable or be guarded
and given an implementation/fallback for the other platforms — a Linux-only feature should
degrade gracefully (compile-guarded no-op) elsewhere rather than break the build.

**Architecture & endianness**: multiple CPU architectures are supported, including x86/x86_64
and **ARM/aarch64**. Do not assume little-endian: protocol/decode code handles network byte
order explicitly, and `src/suricata-common.h` provides the portable byte-order macros
(`__BYTE_ORDER`, `__BIG_ENDIAN`/`__LITTLE_ENDIAN`, normalized across Linux/Darwin/Windows) —
use those and the byte-parsing helpers rather than raw casts over wire data. CPU intrinsics
(SSE etc.) must stay behind feature guards (`#ifdef __SSE2__`, `__aarch64__`, …) with a
portable fallback, as in `src/util-cpu.c`.

## Build & Configure

The build uses autotools; Rust is built into a static lib and linked into the C engine.
Dependencies: clang, cargo/rustc, cbindgen, pcre2, vectorscan, jansson, libyaml, libpcap,
and friends (install via the platform's package manager). On NixOS, `shell.nix` provides
them all via `nix-shell`; it is a convenience for Nix users, not a build requirement.

```sh
./autogen.sh                    # regenerate configure after configure.ac changes
./configure --enable-unittests  # add --enable-debug and sanitizers for a dev build
make -j$(nproc)                 # build engine + rust
make -j$(nproc) -C src suricata # rebuild just the binary after a C change
```

- For development, configure with `--enable-unittests` (so the `-u`/`-U` tests are compiled
  in) and typically `CC=clang` with ASAN (`-fsanitize=address`) plus `-Werror`; such a build
  is slower but catches memory bugs. The tree is often already configured — prefer `make`
  over reconfiguring.
- `--enable-debug-validation` cannot be combined with `--enable-unittests` (configure
  errors out). `--enable-debug` (debug output) is independent and does combine with
  unittests. Unit-test code only compiles under `--enable-unittests`.
- After editing `configure.ac`, run `./autogen.sh` and reconfigure.

## Tests

Three distinct test systems — pick the right one for the change:

1. **C unit tests** — compiled into the binary (`#ifdef UNITTESTS`), run by the engine itself.
   **The unit tests must pass before any change is accepted** — run them after every change:
   ```sh
   ./src/suricata -u                        # run all unit tests
   ./src/suricata -U <pcre-regex>           # run a single/subset by name, e.g. -U DetectFtp
   ./src/suricata --list-unittests          # list test names
   ```
2. **Rust unit tests** — standard `cargo test` inside `rust/`.
3. **suricata-verify** — pcap/rule integration tests in a separate repo
   (https://github.com/OISF/suricata-verify), usually checked out as a sibling of the
   Suricata root (`../suricata-verify/`), and pointed at a build with its `run.py`.
   **suricata-verify must be run and pass for a PR to be accepted.** New keywords,
   protocol parsers, and bug fixes should ship a suricata-verify test; add C/Rust unit tests
   only when a verify test isn't possible.

## CI

The main CI runs on **GitHub Actions** (`.github/workflows/`) and gates every PR — a PR
with failing builds is not considered. Key workflows: `builds.yml` (the large build/test
matrix across OSes, compilers, and configure options), `rust-checks.yml` (Rust lint/clippy/
fmt/tests), `formatting.yml` (clang-format), `commits.yml` (commit-message rules),
`scan-build.yml`/`codeql.yml`/`cifuzz.yml` (static analysis + fuzzing), and `landlock.yml`.
Match these locally before pushing: build with `-Werror`, run unit tests, `cargo` checks,
and clang-format. (A separate private QA suite runs later for OISF members — see README.md.)

## Architecture

Packet flow, roughly: **capture source → decode → flow tracking → stream reassembly →
app-layer parsing → detection → output**. Each stage is a *thread module* (`tm-*`) wired
into a runmode.

- **Capture sources** (`src/source-*.c`): af-packet, pcap, netmap, nfqueue, etc. A
  **runmode** (`src/runmode-*.c`, `src/util-runmodes.c`) picks a source and assembles the
  thread-module pipeline for that deployment. `workers` is the primary/most-used runmode
  (each thread runs the full pipeline for its packets); `autofp` and `single` also exist.
- **Decode** (`src/decode-*.c`): protocol decoders down to L4, filling a `Packet`.
- **Flow & stream** (`src/flow-*.c`, `src/stream-tcp*.c`): flow table, TCP state machine and
  reassembly that feed ordered data to the app layer.
- **App-layer parsers**: the protocol parsers. Newer protocols live in **Rust**
  (`rust/src/<proto>/`, e.g. dns, smb, http2, quic, ldap, mqtt); older ones and the
  registration glue are in C (`src/app-layer-*.c`). Parsers register via `AppLayerParser*`
  and expose two things detection can address: **transactions** (`tx`, a request/response
  unit) and **frames** (stream annotations marking where a protocol record sits in the
  reassembled stream — introduced in 7.0, `src/app-layer-frames.c` / `rust/src/frames.rs`).
  A new parser should register frames and transactions so keywords can match on it. HTTP
  parsing is `libhtp`, an in-tree Rust component (`rust/htp/`, a workspace member). New
  protocol work should be done in Rust, and **byte-level parsing must
  use the `nom` parser-combinator crate** (hand-rolled parsing is not accepted). Both major
  versions are vendored as renamed deps in `rust/Cargo.toml`: `nom7` (7.1) and `nom8` (8.0);
  most existing parsers use `nom7`.
- **Detection engine** (`src/detect-*.c`, ~210 files — the largest subsystem): loads and
  compiles rules, builds MPM (multi-pattern matcher, vectorscan/hyperscan) prefilters, then
  runs per-rule inspection. Each keyword is a `detect-<keyword>.c` (or `rust/src/detect/`)
  that self-registers a `SigTableElmt` in a `DetectXRegister()` function. Adding a keyword =
  add the file + call its register fn in `src/detect-engine-register.c`. Every new keyword
  must set `sigmatch_table[DETECT_X].desc` and `.url` (the `.url` points into the userguide
  rules docs) so it shows up documented in `suricata --list-keywords` — verify with
  `./src/suricata --list-keywords=<name>` after adding it, alongside the userguide page.
- **Output** (`src/output-*.c`, `src/log-*.c`): EVE JSON (`jsonbuilder`, mirrored in Rust)
  and other loggers, driven per-transaction/per-packet.
- **Utilities** (`src/util-*.c`, ~137 files): allocator wrappers, hashing, byte parsing,
  config (`SCConf*`), and platform bits (e.g. `util-landlock.c` for the Landlock sandbox).

### Landlock sandbox (first-class)

Suricata self-sandboxes on Linux via **Landlock** (`src/util-landlock.c` / `.h`), and it is a
first-class, actively maintained feature with its own CI gate (`.github/workflows/landlock.yml`)
and config under `security.landlock` in `suricata.yaml`. The sandbox denies filesystem and
network access by default, so **any feature that opens a file/directory or binds/connects a
socket must register a Landlock grant or it will be denied at runtime when the sandbox is on.**

- Grant through the public `SC`-prefixed API, never by hand-rolling `landlock_*` syscalls:
  `SCLandlockGrantReadPath` / `SCLandlockGrantWritePath`, and the deliberately-narrow variants
  (`SCLandlockGrantWriteReferPath`, `SCLandlockGrantWriteRemovePath`, `SCLandlockGrantRewritePath`,
  `SCLandlockGrantSocketPath`, `SCLandlockGrantFile`, `SCLandlockRegisterFile`,
  `SCLandlockGrantNetBindTCP/ConnectTCP`). Dangerous accesses (REMOVE, TRUNCATE, MAKE_SOCK,
  REFER) are kept out of the default write grant because they are anti-forensics primitives —
  opt into them explicitly and only on directories the module owns.
- Output modules declare their paths via a `LandlockEnable` hook that iterates instances with
  `SCLandlockForEachOutput()` (an `outputs.<n>.<name>` YAML sequence — don't walk it by hand).
- Every helper is a **no-op when Landlock is not compiled in or the kernel lacks support**, so
  grants are always safe to call unconditionally. Keep it that way when adding new grant sites.

### libsuricata & plugins (first-class)

OISF actively promotes using Suricata **as a library** (`libsuricata`) and extending it via
**plugins** — treat both as first-class consumers of the codebase, not afterthoughts. The
engine builds as a linkable library (`libsuricata.so`, or static `libsuricata_c` +
`libsuricata_rust`); downstream builds get flags via the generated `libsuricata-config`
(`--cflags`/`--libs`/`--static`). Plugins are dynamic libraries listed under `plugins:` in
`suricata.yaml` that export a `SCPluginRegister` entry point (versioned by `SC_API_VERSION`);
app-layer plugins mirror an in-tree parser (parser/detect/log/registration files) and register
via `SCPluginRegisterAppLayer` with an `SCAppLayerPlugin`. See `examples/plugins/` (e.g.
`altemplate`) and `doc/userguide/devguide/libsuricata/`.

Practical implications for any change:

- **This is *why* the public API is `SC`-prefixed**: those symbols are the stable library/plugin
  surface. When adding functionality that a plugin or embedder could reasonably need, expose it
  through the `SC` API (and the Rust FFI) rather than leaving it internal — and avoid gratuitous
  breaking changes to existing `SC*` signatures.
- Plugins must **not** rely on non-`repr(C)` Rust structs from the `suricata` crate; go through
  the C API (e.g. use the opaque `JsonBuilder` C API, never its Rust fields) so struct layout is
  stable across the plugin/engine boundary.
- A plugin that needs filesystem/network access must declare its Landlock permissions like an
  in-tree module (see the Landlock section).

### C ↔ Rust boundary

Rust compiles to a static library linked into the C binary. `cbindgen` generates
`rust/gen/rust-bindings.h` from the Rust FFI (`rust/src/**/ffi`, config in `rust/cbindgen.toml`);
C calls Rust through those headers. `make` runs cbindgen automatically. When adding a Rust
function that C must call, expose it through the FFI layer so it lands in the generated header.

## Conventions

- **Code style**: enforced by `.clang-format` (LLVM-based, custom) and **checked in CI
  (`formatting.yml`) — a mis-formatted PR fails and will not be considered**, so clang-format
  is a mandatory pre-submission step. The repo ships `scripts/clang-format.sh`: run
  `./scripts/clang-format.sh check-branch` to verify your branch's commits (add `--diff`/
  `--fix` to see or apply changes), matching what CI does. CI pins **clang-format-17**; using
  a very different clang-format version can produce spurious diffs. Full rules in
  `doc/userguide/devguide/codebase/code-style.rst`.
- **Naming**: public/exported functions are **always** `SC`-prefixed (`SCLandlockGrantFile`,
  `SCConfGetBool`) — new public API must use this prefix. Internal/module-local functions use
  PascalCase (`DetectEngineCtxInit`).
- **Allocation**: use the `SC*` wrappers (`SCMalloc`, `SCCalloc`, `SCRealloc`, `SCFree`,
  `SCStrdup`), not bare libc — they carry instrumentation.
- **Banned libc functions** (use the safe replacement): `sprintf`→`snprintf`,
  `strcpy`→`strlcpy`, `strcat`→`strlcat`, `strtok`→`strtok_r`, `bzero`→`memset`; also avoid
  `rand`/`rand_r`, `strncpy`, `index`/`rindex`, `strndup`, `strchrnul`.
- **Doxygen**: function documentation lives at the **definition in the `.c` file**
  (`/** \brief … \param … \retval … */`), not in the header. Headers carry lighter comments
  for typedefs, macros, and public declarations.
- **User-facing docs**: the user guide is **Sphinx / reStructuredText** under
  `doc/userguide/` (`conf.py`, `.rst`). Any user-facing addition or change — a new keyword,
  config option, output field, command-line flag, or behavior change — **must** land a
  corresponding `.rst` update in the same PR (keyword docs live in
  `doc/userguide/rules/*-keywords.rst`, and the keyword's `.url` should point at that page).
- **New config settings**: a new setting should be added to `suricata.yaml.in` (the template
  that generates the shipped `suricata.yaml`) so it is discoverable in the default config —
  *unless* it is a specific/corner-case feature, in which case documenting it in the Sphinx
  user guide is sufficient and it can be left out of `suricata.yaml.in`.
- **Runtime control via unix socket**: **restarting Suricata is a no-go in most deployments** —
  a restart drops all in-memory network state (flow table, TCP stream reassembly, app-layer
  transactions), so the engine loses track of everything currently on the wire and detection
  gaps open while it comes back up. Therefore anything that changes the *running* configuration or
  state at runtime (rule reloads, dataset add/remove, hostbits, config get/set, capture
  control, …) **must be doable live**, and the mechanism is the unix socket command interface
  (`src/unix-manager.c`, `src/runmode-unix-socket.c`; client `suricatasc`). Prefer a live
  socket command over any change that would require an operator to restart the process.
  Register commands with `UnixManagerRegisterCommand("<keyword>", handler, ctx, flags)` (use
  `UNIX_CMD_TAKE_ARGS` when the command takes arguments), and document them in the Sphinx guide.
- **Commit messages**: `module: short summary` subject, blank line, body explaining *why*,
  and a trailing `Ticket: #NNNN` referencing the Redmine tracker
  (redmine.openinfosecfoundation.org). One branch per PR; a PR that adds/changes a feature
  should include a docs update commit and a test.

## Licensing & contribution agreement

- **Contribution Agreement**: before code can be merged, the contributor must sign OISF's
  Contribution Agreement (https://suricata.io/contribution-agreements/), which assigns
  ownership/copyright of the contributed code to OISF. Contributions from someone who has not
  signed cannot be accepted.
- **License & dual-licensing**: Suricata is **GPL-2.0-only**, and OISF also offers it under a
  separate **commercial license** (dual-licensing). Because OISF must be able to relicense the
  whole codebase commercially, every dependency and any new third-party code must be
  license-compatible with *both* GPLv2 and that commercial offering. **Adding a library whose
  license would block dual-licensing (e.g. incompatible copyleft, or terms that forbid
  relicensing) is a blocker** — pick a permissively-licensed alternative or raise it with the
  team before adding the dependency. This applies to Rust crates (`rust/Cargo.toml`) as well as
  C libraries.

## Releases & backports

Development happens on `main` (the development branch; see `configure.ac` `AC_INIT` for the
current dev version), with stable releases on long-lived `main-<major>.<minor>.x` branches.
Which stable branches are still maintained changes over time — older ones reach end-of-life
and stop receiving fixes. Don't hardcode the maintained set; the authoritative lists are the
EOL policy (https://suricata.io/our-story/eol-policy/) and the feature support-status page
(https://docs.suricata.io/en/latest/support-status.html).

Security and bug fixes are **backported** to the still-maintained stable branches (features
usually are not). The team tags tickets with *Needs backport* labels which spawn backport
tickets; a backport is a focused, minimal cherry-pick of the fix onto the stable branch. When
fixing a bug, consider whether it also affects a maintained stable release. See
`doc/userguide/devguide/contributing/backports-guide.rst`.

**Security issues**: Suricata is itself a security tool — report vulnerabilities per
`SECURITY.md` (do not open a public issue/PR for an unfixed vulnerability). Features are graded
by support tier (Tier 1 / Tier 2 / Community / Unmaintained), and issue severity plus which
versions get a fix follow from that tier — see `SECURITY.md` and the support-status page.

## Further reading

The in-tree developer guide (`doc/userguide/devguide/`, published at
https://docs.suricata.io/en/latest/devguide/) is the authoritative how-to and worth consulting
before non-trivial work:

- `extending/` — step-by-step guides for adding an app-layer parser, a decoder, a detection
  keyword/transform, a capture method, and output (EVE hooks/filetypes), plus threads and
  flow-lifecycle callbacks.
- `internals/` — engine internals: the packet pipeline, threading model, stream engine, and
  core data structures.
- `codebase/` — code style, C and Rust unit tests, fuzz testing, and build-from-git.
- `libsuricata/` — using Suricata as a library and writing plugins (see the libsuricata &
  plugins section above, and `examples/plugins/`).

## Security posture

This engine parses adversarial input; a crash can take a network offline (IPS) or a
compromise can leak captured data (IDS). Treat all decode/parse/detection code as handling
untrusted input: bounds-check, avoid the banned functions above, and prefer adding parsers in
Rust. The extensive QA process (ASAN/LSAN/valgrind, fuzzing via oss-fuzz/clusterfuzzlite,
regression + suricata-verify suites) reflects this — see README.md.
