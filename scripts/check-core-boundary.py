#!/usr/bin/env python3
"""Enforce ADR 0030 without a GUI toolchain."""

import json
from pathlib import Path
import re
import subprocess
import sys

ADR = Path("docs/decisions/0030-public-core-boundary.md")
MANIFEST = "src-tauri/Cargo.toml"
CORE = "muniment-core"
STAY_FEATURE = "desktop-integration"

# Each source exception names a caller that needs a port-owned contract.
# Remove an entry when its caller stops using that staying module.
SOURCE_EXCEPTIONS = {
    # Attach needs port-owned process readers and session contracts.
    ("src-tauri/core/src/attach/connection_route.rs", "browser_control"),
    ("src-tauri/core/src/attach/desktop_client_admission.rs", "browser_control"),
    ("src-tauri/core/src/attach/desktop_service.rs", "auth"),
    ("src-tauri/core/src/attach/desktop_service.rs", "chat_grant"),
    ("src-tauri/core/src/attach/linux.rs", "browser_control"),
    ("src-tauri/core/src/attach/mod.rs", "auth"),
    ("src-tauri/core/src/attach/peer_authority.rs", "browser_control"),
    ("src-tauri/core/src/attach/presenter_admission.rs", "browser_control"),
    ("src-tauri/core/src/attach/thread_service.rs", "auth"),
    # Run callers need local launch values separate from cloud grants and tokens.
    ("src-tauri/core/src/chat_coordinate.rs", "chat_grant"),
    ("src-tauri/core/src/chat_resume.rs", "auth"),
    ("src-tauri/core/src/chat_resume.rs", "chat_grant"),
    ("src-tauri/core/src/pi_launch.rs", "chat_grant"),
    ("src-tauri/core/src/run_start.rs", "auth"),
    ("src-tauri/core/src/run_start.rs", "chat_grant"),
    # Keep all contract tests until port-owned contracts separate these callers.
    ("src-tauri/core/tests/api_base_url.rs", "auth"),
    ("src-tauri/core/tests/attach_connection_route.rs", "browser_control"),
    ("src-tauri/core/tests/attach_desktop_client_admission.rs", "browser_control"),
    ("src-tauri/core/tests/attach_desktop_client_session.rs", "auth"),
    ("src-tauri/core/tests/attach_linux_session.rs", "browser_control"),
    ("src-tauri/core/tests/attach_migration_authority.rs", "browser_control"),
    ("src-tauri/core/tests/attach_presenter_admission.rs", "browser_control"),
    ("src-tauri/core/tests/auth_entitlement_snapshot.rs", "auth"),
    ("src-tauri/core/tests/browser_control_linux_identity.rs", "browser_control"),
    ("src-tauri/core/tests/browser_control_linux_transport.rs", "browser_control"),
    ("src-tauri/core/tests/browser_control_windows_identity.rs", "browser_control"),
    ("src-tauri/core/tests/native_authorization.rs", "auth"),
    ("src-tauri/core/tests/native_devices.rs", "auth"),
    ("src-tauri/core/tests/native_registration.rs", "auth"),
    ("src-tauri/core/tests/native_revocation.rs", "auth"),
    ("src-tauri/core/tests/native_session.rs", "auth"),
    ("src-tauri/core/tests/native_sign_in.rs", "auth"),
    ("src-tauri/core/tests/native_token.rs", "auth"),
    ("src-tauri/core/tests/oidc_flow.rs", "auth"),
    ("src-tauri/core/tests/pi_launch.rs", "chat_grant"),
    ("src-tauri/core/tests/pi_sidecar.rs", "chat_grant"),
    # The runtime needs the same port-owned session and launch contracts.
    ("src-tauri/runtime/src/attach_boundaries.rs", "auth"),
    ("src-tauri/runtime/src/attach_boundaries.rs", "chat_grant"),
    ("src-tauri/runtime/src/attach_listener.rs", "browser_control"),
    ("src-tauri/runtime/src/attach_state.rs", "auth"),
    ("src-tauri/runtime/src/service/run.rs", "auth"),
    ("src-tauri/runtime/src/service/run.rs", "chat_grant"),
    ("src-tauri/runtime/src/service/session.rs", "auth"),
    ("src-tauri/runtime/tests/attach_boundaries.rs", "auth"),
    ("src-tauri/runtime/tests/attach_desktop_client.rs", "auth"),
    ("src-tauri/runtime/tests/attach_service.rs", "auth"),
    ("src-tauri/runtime/tests/common/mod.rs", "auth"),
    ("src-tauri/runtime/tests/common/mod.rs", "chat_grant"),
    ("src-tauri/runtime/tests/devices.rs", "auth"),
    ("src-tauri/runtime/tests/entitlement.rs", "auth"),
    ("src-tauri/runtime/tests/grant.rs", "chat_grant"),
    ("src-tauri/runtime/tests/permission.rs", "auth"),
    ("src-tauri/runtime/tests/run.rs", "auth"),
    ("src-tauri/runtime/tests/run_boundaries.rs", "auth"),
    ("src-tauri/runtime/tests/session.rs", "auth"),
    ("src-tauri/runtime/tests/session_status.rs", "auth"),
    ("src-tauri/runtime/tests/sign_in.rs", "auth"),
    ("src-tauri/runtime/tests/sign_out.rs", "auth"),
    ("src-tauri/runtime/tests/sink.rs", "chat_grant"),
    ("src-tauri/runtime/tests/steer.rs", "auth"),
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def inventory(text):
    tables = {"Port": {"crate": set(), "module": set()},
              "Stay": {"crate": set(), "module": set()}}
    section = None
    seen = set()
    for line in text.splitlines():
        if line.startswith("## "):
            section = line[3:] if line[3:] in tables else None
        if section and line.startswith("| "):
            cells = [cell.strip() for cell in line.strip("|").split("|")]
            if cells[0] in ("Kind", "---"):
                continue
            require(len(cells) == 3, "The boundary table needs three columns.")
            kind, name, reason = cells
            require(kind in ("crate", "module") and reason,
                    "The boundary row needs a kind and a reason.")
            require(re.fullmatch(r"[a-z][a-z0-9_-]*", name),
                    f"The boundary name is invalid: {name}")
            require((kind, name) not in seen, f"The boundary repeats {kind} {name}.")
            seen.add((kind, name))
            tables[section][kind].add(name)
    for section, kinds in tables.items():
        for kind, names in kinds.items():
            require(names, f"The {section} table has no {kind} entries.")
    return tables


def rust_code(text):
    """Remove comments and literals while preserving Rust identifiers."""
    result = []
    position = 0
    while position < len(text):
        rest = text[position:]
        if rest.startswith("//"):
            end = text.find("\n", position)
            position = len(text) if end < 0 else end
        elif rest.startswith("/*"):
            position += 2
            depth = 1
            while depth and position < len(text):
                if text.startswith("/*", position):
                    depth += 1
                    position += 2
                elif text.startswith("*/", position):
                    depth -= 1
                    position += 2
                else:
                    position += 1
            require(depth == 0, "A Rust block comment has no end.")
        elif match := re.match(r'(?:br|cr|r)(#*)"', rest):
            closing = '"' + match[1]
            end = text.find(closing, position + len(match[0]))
            require(end >= 0, "A Rust raw string has no end.")
            position = end + len(closing)
        elif match := re.match(r'''(?:b|c)?"(?:\\.|[^"\\])*"|b?'(?:\\.|[^'\\])' ''', rest, re.S | re.X):
            position += len(match[0])
        else:
            result.append(text[position])
            position += 1
            continue
        result.append(" ")
    return "".join(result)


def source_edges(packages, staying_modules):
    edges = set()
    for package in packages:
        root = Path(package["manifest_path"]).parent
        for path in sorted(root.rglob("*.rs")):
            relative = path.relative_to(root)
            parts = relative.parts
            if (package["name"] == CORE and parts[0] == "src" and len(parts) > 1
                    and parts[1].removesuffix(".rs") in staying_modules):
                continue
            text = path.read_text()
            code = rust_code(text)
            if package["name"] == CORE and relative.as_posix() == "src/lib.rs":
                for name in staying_modules:
                    code = re.sub(rf"pub mod {name}\s*;", "", code)
            # Reserve these identifiers even in grouped imports and aliases.
            # This conservative rule also checks inactive platform code.
            names = set(re.findall(r"\b[a-zA-Z_][a-zA-Z_0-9]*\b", code))
            caller = path.relative_to(Path.cwd()).as_posix()
            for name in names & staying_modules:
                edges.add((caller, name))
            require(not re.search(
                r"\b(?:crate|muniment_core)\s*::\s*(?:\{[^;]*?)?\*", code),
                f"A root glob can hide a staying module in {caller}.")
            require(not re.search(r"\b(?:crate|muniment_core|self)\s+as\s+(?!muniment_core\b)\w+", code),
                    f"A root alias can hide a staying module in {caller}.")
            require(not re.search(r"\binclude\s*!", code),
                    f"A source include needs a boundary review in {caller}.")
            for source in re.findall(r'#\[path\s*=\s*"([^"]+)"\]', text):
                for name in {Path(part).stem for part in Path(source).parts} & staying_modules:
                    edges.add((caller, name))
    return edges


def check_edges(edges):
    new = edges - SOURCE_EXCEPTIONS
    stale = SOURCE_EXCEPTIONS - edges
    require(not new and not stale,
            "The source boundary changed.\n"
            + "".join(f"{path} imports {module} without an exception.\n" for path, module in sorted(new))
            + "".join(f"Remove the stale exception: {path} -> {module}.\n" for path, module in sorted(stale)))


def check_tree(text, staying_crates, package):
    names = {line.split()[0] for line in text.splitlines() if line.strip()}
    require(package in names, f"Cargo returned no root for {package}.")
    forbidden = {name for name in names if name in staying_crates
                 or name == "tauri" or name.startswith("tauri-")}
    require(not forbidden, f"{package} depends on staying packages: {sorted(forbidden)}")
    for line in text.splitlines():
        if not line.strip():
            continue
        fields = line.removesuffix(" (*)").split("|", 1)
        if fields[0].split()[0] == CORE:
            require(len(fields) == 2, "Cargo omitted the core feature list.")
            features = set(fields[1].strip().split(",")) - {""}
            # The runtime enables core defaults. Only this named edge may do so.
            allowed = {"keyring"}
            if package in (CORE, "muniment-runtime"):
                allowed.add(STAY_FEATURE)
            if package == "muniment-runtime":
                # The installed runtime needs TLS for native-auth cloud calls.
                allowed.update({"default", "tls"})
            require(features <= allowed,
                    f"{package} enables unexpected core features: {sorted(features - allowed)}")


def check_inventory(tables, packages, lib):
    declared = tables["Port"]["crate"] | tables["Stay"]["crate"]
    require(declared == set(packages), "The ADR must classify every workspace crate exactly once.")
    modules = set()
    depth = 0
    tokens = re.findall(r"\b\w+\b|[{}]", rust_code(lib))
    for index, token in enumerate(tokens):
        if token == "mod" and depth == 0:
            require(index + 1 < len(tokens), "A core module needs a name.")
            modules.add(tokens[index + 1])
        depth += (token == "{") - (token == "}")
    declared = tables["Port"]["module"] | tables["Stay"]["module"]
    require(declared == modules, "The ADR must classify every core module exactly once.")
    for module in tables["Stay"]["module"]:
        require(re.search(
            rf'#\[cfg\(feature = "{STAY_FEATURE}"\)\]\s*(?:#\[[^\n]+\]\s*)*pub mod {module};', lib),
            f"The staying module {module} needs the {STAY_FEATURE} gate.")
    require(packages[CORE]["features"]["default"] == [STAY_FEATURE]
            and packages[CORE]["features"][STAY_FEATURE] == [],
            "The core default feature exception must enable only desktop-integration.")


def main():
    require(len(sys.argv) == 1, "The core boundary check accepts no arguments.")
    tables = inventory(ADR.read_text())
    metadata = json.loads(subprocess.check_output([
        "cargo", "metadata", "--manifest-path", MANIFEST,
        "--locked", "--no-deps", "--format-version", "1"], text=True))
    packages = {p["name"]: p for p in metadata["packages"]
                if p["id"] in metadata["workspace_members"]}
    check_inventory(tables, packages, Path("src-tauri/core/src/lib.rs").read_text())
    port = [packages[name] for name in sorted(tables["Port"]["crate"])]
    check_edges(source_edges(port, tables["Stay"]["module"]))
    commands = []
    for package in port:
        name = package["name"]
        args = ["--manifest-path", MANIFEST, "--package", name,
                "--locked", "--no-default-features"]
        if name == CORE:
            # Named exception: port callers still need the three staying contracts.
            args += ["--features", f"keyring,{STAY_FEATURE}"]
        tree = subprocess.check_output([
            "cargo", "tree", *args, "--target", "all", "--edges", "normal,build,dev",
            "--prefix", "none", "--format", "{p}|{f}"], text=True)
        check_tree(tree, tables["Stay"]["crate"], name)
        command = ["cargo", "test", *args]
        if name == CORE:
            # Match the core CI lane so stub child processes get CPU time.
            command += ["--", "--test-threads=1"]
        commands.append(command)
    print(f"Core boundary allows {len(SOURCE_EXCEPTIONS)} named source edges.", flush=True)
    print("Core tests enable desktop-integration. The runtime enables core defaults.", flush=True)
    for command in commands:
        subprocess.run(command, check=True)
    print("Core boundary checks passed with the named exceptions.")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, subprocess.CalledProcessError) as error:
        print(f"Core boundary failed: {error}", file=sys.stderr)
        sys.exit(1)
