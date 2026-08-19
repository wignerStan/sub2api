"""Rust crate suite via the rules_rust toolchain on the Linux RBE worker.

The GHA-like image only executes the toolchain. Do not use rustup or PATH cargo.
"""

def _linux_transition_impl(_settings, _attr):
    return {"//command_line_option:platforms": str(Label("//:rbe_linux"))}

_linux_transition = transition(
    implementation = _linux_transition_impl,
    inputs = [],
    outputs = ["//command_line_option:platforms"],
)

def _toolchain_files(tc):
    extras = []
    for attr in ("rustc", "cargo", "rust_doc", "rustfmt", "sysroot_anchor"):
        f = getattr(tc, attr, None)
        if f:
            extras.append(f)
    transitive = []
    for attr in ("rust_std", "rustc_lib", "all_files"):
        d = getattr(tc, attr, None)
        if d:
            transitive.append(d)
    return depset(extras, transitive = transitive)

def _rust_mod_test_impl(ctx):
    tc = ctx.toolchains["@rules_rust//rust:toolchain_type"]
    sysroot_short = ""
    if getattr(tc, "sysroot_anchor", None):
        sysroot_short = tc.sysroot_anchor.short_path.rsplit("/", 1)[0]
    runner = ctx.actions.declare_file(ctx.label.name + "_runner.sh")
    ctx.actions.write(
        output = runner,
        is_executable = True,
        content = """#!/usr/bin/env bash
set -euo pipefail
if [[ "$(uname -s)" != "Linux" ]]; then
  echo "FAIL: expected Linux RBE worker, got $(uname -s)" >&2
  exit 1
fi
RUSTC="$PWD/{rustc_short}"
CARGO="$PWD/{cargo_short}"
if [[ ! -x "$RUSTC" || ! -x "$CARGO" ]]; then
  echo "FAIL: hermetic rustc/cargo not executable" >&2
  echo "rustc=$RUSTC cargo=$CARGO" >&2
  find . -name rustc -o -name cargo | head -40 >&2
  exit 1
fi
export RUSTC
export CARGO
export PATH="$(dirname "$CARGO"):$(dirname "$RUSTC"):$PATH"
if [[ -n "{sysroot_short}" && -d "$PWD/{sysroot_short}" ]]; then
  export RUSTFLAGS="--sysroot $PWD/{sysroot_short} ${{RUSTFLAGS:-}}"
fi
if command -v gcc >/dev/null 2>&1; then
  export CC=gcc
  export CXX="${{CXX:-g++}}"
fi
export CARGO_HOME="${{TEST_TMPDIR:-/tmp}}/cargo-home"
export CARGO_TARGET_DIR="${{TEST_TMPDIR:-/tmp}}/cargo-target"
export CARGO_NET_GIT_FETCH_WITH_CLI=true
export RUSTUP_HOME="${{TEST_TMPDIR:-/tmp}}/rustup-missing"
unset RUSTUP || true
mkdir -p "$CARGO_HOME" "$CARGO_TARGET_DIR"
echo "rust_mod: $($RUSTC --version) $($CARGO --version) host=$(hostname) rustc=$RUSTC"
ROOT=""
for candidate in "$PWD/rustsidecar" "${{TEST_SRCDIR:-}}/_main/rustsidecar"; do
  if [[ -f "$candidate/Cargo.toml" ]]; then
    ROOT="$candidate"
    break
  fi
done
if [[ -z "$ROOT" ]]; then
  echo "FAIL: rustsidecar/Cargo.toml not in runfiles" >&2
  exit 1
fi
WORK="${{TEST_TMPDIR:-/tmp}}/rustsidecar-src"
rm -rf "$WORK"
cp -a "$ROOT" "$WORK"
cd "$WORK"
if ! "$CARGO" test --workspace --locked --offline; then
  echo "rust_mod: offline miss, fetching crates" >&2
  "$CARGO" test --workspace --locked
fi
""".format(
            rustc_short = tc.rustc.short_path,
            cargo_short = tc.cargo.short_path,
            sysroot_short = sysroot_short,
        ),
    )
    runfiles = ctx.runfiles(
        files = [runner, tc.rustc, tc.cargo] + ctx.files.srcs,
        transitive_files = _toolchain_files(tc),
    )
    return [DefaultInfo(executable = runner, runfiles = runfiles)]

rust_mod_test = rule(
    implementation = _rust_mod_test_impl,
    test = True,
    toolchains = ["@rules_rust//rust:toolchain_type"],
    cfg = _linux_transition,
    attrs = {
        "srcs": attr.label_list(allow_files = True),
        "_allowlist_function_transition": attr.label(
            default = "@bazel_tools//tools/allowlists/function_transition_allowlist",
        ),
    },
)
