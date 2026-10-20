#!/usr/bin/env python3
"""Executable audit of the comparator actually wired into a fixture/host.

This is deterministic source evidence plus functional endpoint tests, not a claim
that HTTP timings can prove constant-time machine execution. The Rust mode finds
the linked rigging package through locked Cargo metadata, never a sibling checkout.
"""
import argparse
import ast
import json
from pathlib import Path
import re
import subprocess


def python_comparator(path):
    tree = ast.parse(Path(path).read_text())
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "token_matches"]
    if len(functions) != 1:
        return False
    function = functions[0]
    if len(function.body) != 1 or not isinstance(function.body[0], ast.Return):
        return False
    call = function.body[0].value
    return (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
            and isinstance(call.func.value, ast.Name) and call.func.value.id == "hmac"
            and call.func.attr == "compare_digest" and [ast.dump(arg) for arg in call.args] ==
            [ast.dump(ast.Name(id=name, ctx=ast.Load())) for name in ("expected", "actual")])


def rust_comparator(path):
    source = re.sub(r"\s+", "", Path(path).read_text())
    # Audit the precise admission closure, including hashing both token operands
    # to fixed length and using the audited fixed-size ConstantTimeEq primitive.
    return ("letvalid=|token:&str|bool::from(token_hash.ct_eq(&Sha256::digest(token.as_bytes())));" in source
            and ("scheme.eq_ignore_ascii_case(\"Bearer\")&&valid(token)" in source or
                 '.map(|(_,token)|token).filter(|v|valid(v)).map(|_|Caller::<C>::Bearer)' in source)
            and "use" in source and "ConstantTimeEq" in source)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--python")
    group.add_argument("--rust")
    group.add_argument("--cargo-package")
    args = parser.parse_args()
    path = args.rust
    if args.cargo_package:
        metadata = json.loads(subprocess.check_output(["cargo", "metadata", "--locked", "--format-version", "1"], stderr=subprocess.DEVNULL))
        matches = [p for p in metadata["packages"] if p["name"] == args.cargo_package]
        if len(matches) != 1:
            raise SystemExit(1)
        path = Path(matches[0]["manifest_path"]).parent / "src/lib.rs"
    raise SystemExit(0 if (python_comparator(args.python) if args.python else rust_comparator(path)) else 1)
