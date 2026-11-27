#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Bounded software-perf ABI and original perf(1) acceptance.

The caller prepares an official distribution root containing unmodified perf.
Every command has a deadline; failures are collected before returning. No tool
output or expected result is rewritten. The native mode runs inside Linux.
"""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", choices=["native", "interpreter", "hvf"], required=True)
    parser.add_argument("--runner", type=Path)
    parser.add_argument("--seed-runner", type=Path, help="Rootfs importer for interpreter storage")
    parser.add_argument("--rootfs", type=Path)
    parser.add_argument("--tool-root", type=Path, help="Prepared native Linux chroot")
    parser.add_argument("--reuse-store", type=Path, help="Reuse an already imported guest image")
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cpus", type=int, default=2)
    parser.add_argument("--timeout", type=int, default=90)
    parser.add_argument("--modes", nargs="*", default=["abi", "count", "fault-modes", "scope", "sample", "mapping", "cgroup", "secure-exec", "stat", "record", "script"])
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    report = {"backend": args.backend, "cpus": args.cpus, "fixture_sha256": hashlib.sha256(args.fixture.read_bytes()).hexdigest(), "rows": [], "passed": False}
    environment = dict(os.environ, TRAMES_MAC_BUNDLED="1")

    def save():
        (args.output / "results.json").write_text(json.dumps(report, indent=2) + "\n")

    def execute(label, command, required=True):
        if shutil.disk_usage(args.output).free < 3 * 1024**3:
            raise RuntimeError("validation disk floor: 3 GiB")
        started = time.monotonic()
        row = {"name": label, "command": list(map(str, command))}
        try:
            with (args.output / (label + ".stdout")).open("wb") as stdout, (args.output / (label + ".stderr")).open("wb") as stderr:
                process = subprocess.Popen(command, stdout=stdout, stderr=stderr, env=environment, start_new_session=True)
                try:
                    row["exit_code"] = process.wait(timeout=args.timeout)
                except subprocess.TimeoutExpired:
                    import signal
                    os.killpg(process.pid, signal.SIGTERM)
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait()
                    row.update(exit_code=124, timeout=True)
        except OSError as error:
            row.update(exit_code=127, error=str(error))
        row.update(elapsed_seconds=round(time.monotonic()-started, 3), required=required)
        report["rows"].append(row)
        save()
        print(json.dumps(row), flush=True)
        return row["exit_code"] == 0

    fixture = "/opt/trames-perf/perf-tools"
    native_suid = None
    paranoid = None
    store = args.reuse_store or args.output / "store"
    try:
        if args.backend == "native":
            if os.geteuid() != 0 or not args.tool_root:
                parser.error("native requires root and --tool-root")
            # Keep setuid on a Linux filesystem: the shared source may be nosuid.
            native_suid = Path("/var/tmp") / ("trames-perf-suid-" + str(os.getpid()))
            shutil.copyfile(args.fixture, native_suid)
            os.chown(native_suid, 0, 0)
            native_suid.chmod(0o4755)
            destination = args.tool_root / fixture.lstrip("/")
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(args.fixture, destination)
            destination.chmod(0o755)
            (args.tool_root / "results").mkdir(exist_ok=True)
            # Execute this harness in a private mount namespace; bind mounts die
            # with it. The harness restores the one VM-wide sysctl it changes.
            for directory in ("proc", "sys"):
                target = args.tool_root / directory
                target.mkdir(exist_ok=True)
                subprocess.run(["mount", "--rbind", "/" + directory, str(target)], check=True)
                subprocess.run(["mount", "--make-rslave", str(target)], check=True)
            policy = Path("/proc/sys/kernel/perf_event_paranoid")
            paranoid = policy.read_text()
            policy.write_text("0\n")
        else:
            if not args.runner or not args.rootfs:
                parser.error("guest requires --runner and --rootfs")
            report["runner_sha256"] = hashlib.sha256(args.runner.read_bytes()).hexdigest()
            importer = args.seed_runner or args.runner
            import_command = [str(importer), "--storage", str(store)]
            if args.reuse_store:
                report["seed_manifest_sha256"] = hashlib.sha256((store / "manifest").read_bytes()).hexdigest()
            else:
                import_command += ["--rootfs", str(args.rootfs)]
            if not execute("import", import_command + ["--fs", "--", "ls", "/usr/bin"]):
                return 1

        def command(guest):
            if args.backend == "native":
                return ["chroot", str(args.tool_root)] + guest
            base = [str(args.runner), "--storage", str(store), "--cpus", str(args.cpus), "--network", "loopback"]
            if args.backend == "hvf":
                base += ["--no-pty", "--no-windows", "--timeout", str(args.timeout-5)]
            else:
                base += ["--memory-budget", "2GiB", "--process-memory-budget", "1GiB", "--max-instructions", "200000000000", "--guest"]
            return base + ["--"] + guest

        if args.backend != "native":
            if not execute("upload", [str(args.seed_runner or args.runner), "--storage", str(store), "--fs", "--", "put", "--replace", str(args.fixture), fixture]):
                return 1
            setup = command(["/bin/sh", "-c", "chown 0:0 " + fixture + "; chmod 4755 " + fixture])
            if not execute("fixture", setup):
                return 1

        for mode in args.modes:
            if mode in ("stat", "record", "script"):
                if mode == "stat":
                    guest = ["/usr/bin/perf", "stat", "-e", "task-clock,context-switches,cpu-migrations,page-faults", "--", fixture, "cpu", "500000"]
                elif mode == "record":
                    guest = ["/usr/bin/perf", "record", "-e", "task-clock:u", "-F", "99", "-m", "8", "--no-buildid", "--no-buildid-cache", "-o", "/results/perf.data", "--", fixture, "cpu", "5000000"]
                else:
                    guest = ["/usr/bin/perf", "script", "-i", "/results/perf.data"]
                ok = execute(mode, command(guest))
                if ok:
                    output = (args.output / (mode + ".stdout")).read_text(errors="replace")
                    error = (args.output / (mode + ".stderr")).read_text(errors="replace")
                    if mode == "stat":
                        ok = all(name in error for name in ("task-clock", "context-switches", "cpu-migrations", "page-faults")) and "not supported" not in error and "not counted" not in error
                    elif mode == "script":
                        ok = "task-clock" in output and "perf-tools" in output
                    if mode == "stat":
                        faults = re.search(r"^\s*([0-9,]+)\s+page-faults\b", error, re.MULTILINE)
                        ok = ok and faults is not None and int(faults.group(1).replace(",", "")) >= 64
                    report["rows"][-1]["semantic_output"] = ok
                    save()
            elif mode == "secure-exec" and args.backend == "native":
                execute(mode, [str(native_suid), mode, str(native_suid)])
            elif args.backend == "native":
                execute(mode, [str(args.fixture), mode])
            else:
                execute(mode, command([fixture, mode, fixture] if mode == "secure-exec" else [fixture, mode]))

        if args.backend != "native":
            execute("export", [str(args.seed_runner or args.runner), "--storage", str(store), "--fs", "--", "get", "/results", str(args.output / "guest-results")])
        report["passed"] = all(row["exit_code"] == 0 and row.get("semantic_output", True) for row in report["rows"] if row["required"])
        save()
        return 0 if report["passed"] else 1
    finally:
        if paranoid is not None:
            Path("/proc/sys/kernel/perf_event_paranoid").write_text(paranoid)
        if native_suid is not None:
            native_suid.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
