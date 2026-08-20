"""Go test/build via the rules_go toolchain on the Linux RBE worker.

The GHA-like image only executes the toolchain. Do not use @go_sdk//:bin/go
(host SDK) or a system go on the worker.
"""

def _linux_transition_impl(_settings, _attr):
    return {"//command_line_option:platforms": str(Label("//:rbe_linux"))}

_linux_transition = transition(
    implementation = _linux_transition_impl,
    inputs = [],
    outputs = ["//command_line_option:platforms"],
)

def _sdk_files(sdk):
    return depset(
        [sdk.go, sdk.root_file, sdk.package_list],
        transitive = [sdk.headers, sdk.srcs, sdk.libs, sdk.tools],
    )

def _go_mod_test_impl(ctx):
    sdk = ctx.toolchains["@rules_go//go:toolchain"].sdk
    cmds = {
        "test-unit": '"$GO" test -tags=unit -count=1 ./...',
        "test-integration": '"$GO" test -tags=integration -count=1 -timeout=20m ./...',
        "test-e2e": '"$GO" test -tags=e2e -count=1 -timeout=300s -v ./internal/integration/ -run TestCodexHardening',
    }
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
GO="$(dirname "$0")/$(basename "{go_short}")"
if [[ ! -x "$GO" ]]; then
  GO="$PWD/{go_short}"
fi
if [[ ! -x "$GO" ]]; then
  echo "FAIL: toolchain go not executable" >&2
  find . -name go -type f | head >&2
  exit 1
fi
export GOTOOLCHAIN=local
unset GOROOT || true
export CGO_ENABLED=0
export GOOS=linux
export GOARCH=amd64
export GOCACHE="${{TEST_TMPDIR:-/tmp}}/gocache"
export GOMODCACHE="${{TEST_TMPDIR:-/tmp}}/gomodcache"
export GOPROXY="${{GOPROXY:-https://goproxy.cn,https://proxy.golang.org,direct}}"
mkdir -p "$GOCACHE" "$GOMODCACHE"
echo "go_mod: mode={mode} $($GO version) host=$(hostname) go=$GO"
BACKEND=""
for candidate in "$PWD/backend" "${{TEST_SRCDIR:-}}/_main/backend"; do
  if [[ -f "$candidate/go.mod" ]]; then
    BACKEND="$candidate"
    break
  fi
done
if [[ -z "$BACKEND" ]]; then
  echo "FAIL: backend/go.mod not in runfiles" >&2
  exit 1
fi
cd "$BACKEND"
{cmd}
""".format(
            go_short = sdk.go.short_path,
            mode = ctx.attr.mode,
            cmd = cmds[ctx.attr.mode],
        ),
    )
    runfiles = ctx.runfiles(
        files = [runner, sdk.go] + ctx.files.srcs,
        transitive_files = _sdk_files(sdk),
    )
    return [DefaultInfo(executable = runner, runfiles = runfiles)]

def _go_mod_binary_impl(ctx):
    sdk = ctx.toolchains["@rules_go//go:toolchain"].sdk
    out = ctx.outputs.out
    ctx.actions.run_shell(
        outputs = [out],
        inputs = depset(ctx.files.srcs, transitive = [_sdk_files(sdk)]),
        tools = [sdk.go],
        command = """
set -euo pipefail
export GOTOOLCHAIN=local
unset GOROOT || true
export CGO_ENABLED=0
export GOOS=linux
export GOARCH=amd64
export GOCACHE="$PWD/.gocache"
export GOMODCACHE="$PWD/.gomodcache"
export GOPROXY="https://goproxy.cn,https://proxy.golang.org,direct"
mkdir -p "$GOCACHE" "$GOMODCACHE"
"{go}" version
"{go}" build -C backend -tags embed -ldflags="-s -w -X main.Version=0.1.179" -trimpath -o "$PWD/{out}" ./cmd/server
""".format(
            go = sdk.go.path,
            out = out.path,
        ),
        mnemonic = "GoModBuild",
        use_default_shell_env = True,
    )
    return [DefaultInfo(files = depset([out]), executable = out)]

go_mod_test = rule(
    implementation = _go_mod_test_impl,
    test = True,
    toolchains = ["@rules_go//go:toolchain"],
    cfg = _linux_transition,
    attrs = {
        "srcs": attr.label_list(allow_files = True),
        "mode": attr.string(mandatory = True, values = ["test-unit", "test-integration", "test-e2e"]),
        "_allowlist_function_transition": attr.label(
            default = "@bazel_tools//tools/allowlists/function_transition_allowlist",
        ),
    },
)

go_mod_binary = rule(
    implementation = _go_mod_binary_impl,
    executable = True,
    toolchains = ["@rules_go//go:toolchain"],
    cfg = _linux_transition,
    attrs = {
        "srcs": attr.label_list(allow_files = True),
        "out": attr.output(mandatory = True),
        "_allowlist_function_transition": attr.label(
            default = "@bazel_tools//tools/allowlists/function_transition_allowlist",
        ),
    },
)
