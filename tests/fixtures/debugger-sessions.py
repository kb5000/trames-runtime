#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Original ARM64 debugger sessions, run after the implementation batch.

Run inside a disposable guest with the matching ELF and original tools.
Independent cases all run; each subprocess has a deadline and owned process
session. Failure transcripts and the exact case plan remain in the output.
"""
import argparse
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import select
import shutil
import signal
import subprocess
import time

MEMORY = 0x22334455
REGISTER = 4660


def kill(process):
    # Kill the owned group before reaping its leader, including descendants of
    # a failed GDB/server. Every subprocess below starts a new session.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass


def ready_line(process, prefix, timeout=20, contains=False):
    deadline = time.monotonic() + timeout
    line = bytearray()
    transcript = bytearray()
    while time.monotonic() < deadline:
        readable, _, _ = select.select([process.stdout], [], [], max(0, deadline - time.monotonic()))
        if not readable:
            break
        byte = os.read(process.stdout.fileno(), 1)
        if not byte:
            break
        transcript.extend(byte)
        line.extend(byte)
        if byte == b'\n':
            text = line.decode(errors='replace').strip()
            if text.startswith(prefix) or contains and prefix in text:
                process.prefix_output = transcript.decode(errors='replace')
                return text
            line.clear()
    process.prefix_output = transcript.decode(errors='replace')
    raise RuntimeError(f'no {prefix!r} before deadline; child status={process.poll()}')


class Batch:
    def __init__(self, args):
        self.args = args
        self.logs = args.output
        self.logs.mkdir(parents=True, exist_ok=False)
        self.rows, self.commands = [], []
        self.report = dict(passed=False, machine=platform.machine(), kernel=platform.release(),
                           fixture_sha256=hashlib.sha256(args.fixture.read_bytes()).hexdigest(),
                           rows=self.rows, commands=self.commands, tools={})

    def save(self):
        (self.logs / 'sessions.json').write_text(json.dumps(self.report, indent=2) + '\n')

    def command(self, name, command, timeout=45, expected=0):
        started = time.monotonic()
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, start_new_session=True)
        timed_out = False
        try:
            out, err = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            kill(process)
            out, err = process.communicate(timeout=5)
        finally:
            kill(process)
        (self.logs / (name + '.stdout')).write_text(out)
        (self.logs / (name + '.stderr')).write_text(err)
        self.commands.append(dict(name=name, argv=command, exit=process.returncode,
                                  timeout=timed_out, seconds=time.monotonic() - started))
        if timed_out:
            raise RuntimeError(name + ': deadline exceeded')
        if expected is not None and process.returncode != expected:
            raise RuntimeError(f'{name}: exit {process.returncode}, expected {expected}; retained logs')
        return process.returncode, out, err

    def target(self, mode='live', threads=2, expected=17, register=17):
        process = subprocess.Popen([str(self.args.fixture), mode, str(threads), str(expected), str(register)],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, start_new_session=True)
        try:
            line = ready_line(process, 'DEBUGGER-READY ')
            initial = 1 if mode == 'dynamic' else threads + 1
            if line != f'DEBUGGER-READY {process.pid} {initial}':
                raise RuntimeError('wrong original target identity: ' + line)
        except BaseException:
            kill(process)
            out, err = process.communicate(timeout=5)
            (self.logs / f'target-{process.pid}.startup.stdout').write_text(getattr(process, 'prefix_output', '') + out)
            (self.logs / f'target-{process.pid}.startup.stderr').write_text(err)
            raise
        return process

    def finish(self, name, target, release=False, expected=17, register=17, threads=2):
        if release:
            os.kill(target.pid, signal.SIGUSR1)
        try:
            out, err = target.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            kill(target)
            out, err = target.communicate(timeout=5)
            (self.logs / (name + '.target.stdout')).write_text(getattr(target, 'prefix_output', '') + out)
            (self.logs / (name + '.target.stderr')).write_text(err)
            raise RuntimeError(name + ': target remained stopped or blocked')
        (self.logs / (name + '.target.stdout')).write_text(getattr(target, 'prefix_output', '') + out)
        (self.logs / (name + '.target.stderr')).write_text(err)
        marker = f'DEBUGGER-DONE {threads + 1} {expected} {register}'
        if target.returncode != 0 or marker not in out:
            raise RuntimeError(name + ': original target did not execute the expected state: ' + out + err)

    def gdb(self, name, commands):
        script = self.logs / (name + '.gdb')
        common = ['set confirm off', 'set pagination off', 'set debuginfod enabled off',
                  'set sysroot /',
                  'set disable-randomization off', 'set startup-with-shell off',
                  'set auto-load python-scripts off', 'set auto-load local-gdbinit off']
        script.write_text('\n'.join(common + commands) + '\n')
        return [self.args.gdb, '-nx', '-q', '-batch', str(self.args.fixture), '-x', str(script)]

    @staticmethod
    def edits():
        return [f'set variable debugger_value = {MEMORY}',
                f'if debugger_value != {MEMORY}\nquit 1\nend']

    @staticmethod
    def checkpoints(count, release='signal SIGUSR1'):
        return ['set $hits = 0', 'break debugger_register_store', 'break debugger_checkpoint',
                'commands 2\nsilent\nset $hits = $hits + 1\ncontinue\nend',
                'handle SIGUSR1 nostop noprint pass', release,
                'echo REGISTER_STOP\\n', f'set $x19 = {REGISTER}',
                'set $before = $pc', 'stepi',
                f'if $pc != $before + 4 || debugger_register_value != {REGISTER}\nquit 1\nend',
                'delete 1', 'continue',
                f'if $hits != {count}\nquit 1\nend', 'echo DEBUGGER-GDB-PASSED\\n']

    def server(self, name, arguments):
        path = self.logs / (name + '.server')
        stream = path.open('w')
        process = subprocess.Popen([self.args.gdbserver, '--once', '--no-startup-with-shell', *arguments],
                                   stdout=stream, stderr=stream, start_new_session=True)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            text = path.read_text()
            match = re.search(r'Listening on port (\d+)', text)
            if match:
                return process, stream, 'target remote 127.0.0.1:' + match[1]
            if process.poll() is not None:
                break
            time.sleep(.01)
        kill(process)
        stream.close()
        raise RuntimeError(name + ': server did not listen; ' + path.read_text())

    def attach(self, name, threads, mode='live', remote=False):
        target = self.target(mode, threads, MEMORY, REGISTER)
        server = stream = None
        try:
            if remote:
                server, stream, connect = self.server(name, ['--attach', '127.0.0.1:0', str(target.pid)])
                commands = [connect]
            else:
                commands = [f'attach {target.pid}']
            _, out, _ = self.command(name, self.gdb(name, commands + ['info threads', *self.edits(), *self.checkpoints(threads + 1)]))
            if 'DEBUGGER-GDB-PASSED' not in out or 'REGISTER_STOP' not in out:
                raise RuntimeError(name + ': missing original debugger completion')
            self.finish(name, target, expected=MEMORY, register=REGISTER, threads=threads)
            if server is not None and server.wait(timeout=10) != 0:
                raise RuntimeError(name + ': gdbserver failed')
        finally:
            kill(target)
            if server is not None:
                kill(server)
                stream.close()

    def detach(self, name, remote=False):
        target = self.target(expected=MEMORY)
        server = stream = None
        try:
            if remote:
                server, stream, connect = self.server(name, ['--attach', '127.0.0.1:0', str(target.pid)])
            else:
                connect = f'attach {target.pid}'
            _, out, _ = self.command(name, self.gdb(name, [connect, *self.edits(), 'detach', 'echo DETACHED\\n']))
            if 'DETACHED' not in out:
                raise RuntimeError(name + ': detach marker absent')
            self.finish(name, target, release=True, expected=MEMORY)
        finally:
            kill(target)
            if server is not None:
                kill(server)
                stream.close()

    def server_launch(self):
        name = 'gdbserver-launch'
        server, stream, connect = self.server(name, ['127.0.0.1:0', str(self.args.fixture), 'launch', '2', '17', str(REGISTER)])
        try:
            _, out, _ = self.command(name, self.gdb(name, [connect, *self.checkpoints(3, 'continue')]))
            if 'DEBUGGER-GDB-PASSED' not in out or server.wait(timeout=10) != 0:
                raise RuntimeError(name + ': launch did not finish')
            stream.flush()
            if f'DEBUGGER-DONE 3 17 {REGISTER}' not in out + (self.logs / (name + '.server')).read_text():
                raise RuntimeError(name + ': original launched CPU result absent')
        finally:
            kill(server)
            stream.close()

    def denied(self):
        target = self.target(mode='denied', threads=0)
        try:
            command = [str(self.args.fixture), 'exec-unprivileged', *self.gdb('attach-denied', [f'attach {target.pid}'])]
            code, out, err = self.command('attach-denied', command, expected=None)
            if code == 0 or not re.search(r'not permitted|permission denied', out + err, re.I):
                raise RuntimeError('unprivileged nondumpable attach was not denied')
            self.finish('attach-denied', target, release=True, threads=0)
        finally:
            kill(target)

    def held_debugger(self, name, target):
        script = self.logs / (name + '.gdb')
        script.write_text(f'set confirm off\nset pagination off\nattach {target.pid}\n' +
                          '\n'.join(self.edits()) + '\necho TRACER-HELD\\n\n')
        debugger = subprocess.Popen([self.args.gdb, '-nx', '-q', str(self.args.fixture), '-x', str(script)],
                                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, start_new_session=True)
        try:
            ready_line(debugger, 'TRACER-HELD')
            return debugger
        except BaseException:
            kill(debugger)
            out, _ = debugger.communicate(timeout=5)
            (self.logs / (name + '.gdb.stdout')).write_text(getattr(debugger, 'prefix_output', '') + out)
            raise

    def stop_debugger(self, name, debugger):
        kill(debugger)
        if not debugger.stdout.closed:
            out, _ = debugger.communicate(timeout=5)
            (self.logs / (name + '.gdb.stdout')).write_text(getattr(debugger, 'prefix_output', '') + out)

    def tracer_exit(self):
        name = 'tracer-abrupt-exit'
        target = self.target(expected=MEMORY)
        debugger = None
        try:
            debugger = self.held_debugger(name, target)
            kill(debugger)
            (self.logs / (name + '.gdb.stdout')).write_text(getattr(debugger, 'prefix_output', ''))
            self.finish(name, target, release=True, expected=MEMORY)
        finally:
            if debugger is not None:
                self.stop_debugger(name, debugger)
            kill(target)

    def target_exit(self):
        name = 'target-early-exit'
        target = self.target('early-exit', 0)
        try:
            _, out, _ = self.command(name, self.gdb(name, [f'attach {target.pid}',
                'handle SIGUSR1 nostop noprint pass', 'signal SIGUSR1',
                'if $_exitcode != 23\nquit 1\nend', 'echo TRACEE-EXIT-PASSED\\n']))
            rest, err = target.communicate(timeout=10)
            (self.logs / (name + '.target.stdout')).write_text(getattr(target, 'prefix_output', '') + rest)
            if target.returncode != 23 or 'TRACEE-EXIT-PASSED' not in out:
                raise RuntimeError(name + ': wrong original exit ownership')
        finally:
            kill(target)

    def target_killed(self):
        name = 'target-killed-while-stopped'
        target = self.target(expected=MEMORY)
        debugger = None
        try:
            debugger = self.held_debugger(name, target)
            os.kill(target.pid, signal.SIGKILL)
            # GDB can first reject stale sibling register reads with ESRCH,
            # then collect SIGKILL asynchronously on native Linux as well.
            # Wait for the actual terminal event before issuing quit.
            held = debugger.prefix_output
            debugger.stdin.write('continue\n')
            debugger.stdin.flush()
            try:
                ready_line(debugger, 'Program terminated with signal SIGKILL', contains=True)
            finally:
                debugger.prefix_output = held + debugger.prefix_output
            out, _ = debugger.communicate(input='quit\n', timeout=20)
            text = getattr(debugger, 'prefix_output', '') + out
            (self.logs / (name + '.gdb.stdout')).write_text(text)
            target.communicate(timeout=10)
            if target.returncode != -signal.SIGKILL or 'SIGKILL' not in text or debugger.returncode != 0:
                raise RuntimeError(name + ': tracee death did not unblock debugger and parent')
        finally:
            if debugger is not None:
                self.stop_debugger(name, debugger)
            kill(target)

    def strace(self, name, mode, expected):
        trace = self.logs / (name + '.trace')
        _, out, _ = self.command(name, [self.args.strace, '-f', '-o', str(trace),
                                        str(self.args.fixture), mode], expected=expected)
        text = trace.read_text()
        if ('DEBUGGER-EXEC-CHILD' not in out or not re.search(r'clone\(|clone3\(|fork\(', text)
                or 'exec-child' not in text or 'exited with 42' not in text):
            raise RuntimeError(name + ': original strace missed clone/exec/exit')

    def ownership(self):
        _, out, _ = self.command('ptrace-thread-ownership', [str(self.args.fixture), 'ptrace-ownership'])
        if 'DEBUGGER-OWNERSHIP-PASSED' not in out:
            raise RuntimeError('missing original ptracer ownership result')

    def run(self):
        for tool in ['gdb', 'gdbserver', 'strace']:
            executable = shutil.which(getattr(self.args, tool))
            if not executable:
                raise RuntimeError('missing original tool: ' + tool)
            _, out, err = self.command('version-' + tool, [executable, '--version'])
            self.report['tools'][tool] = dict(path=executable, version=(out + err).splitlines()[0],
                                             sha256=hashlib.sha256(Path(executable).read_bytes()).hexdigest())
        cases = [
            ('ptrace-thread-ownership', self.ownership),
            ('live-attach', lambda: self.attach('live-attach', 0)),
            ('multithread-attach', lambda: self.attach('multithread-attach', 2)),
            ('clone-while-traced', lambda: self.attach('clone-while-traced', 3, 'dynamic')),
            ('explicit-detach', lambda: self.detach('explicit-detach')),
            ('gdbserver-attach', lambda: self.attach('gdbserver-attach', 2, remote=True)),
            ('gdbserver-launch', self.server_launch),
            ('gdbserver-detach', lambda: self.detach('gdbserver-detach', remote=True)),
            ('attach-denied', self.denied),
            ('tracer-abrupt-exit', self.tracer_exit),
            ('target-early-exit', self.target_exit),
            ('target-killed-while-stopped', self.target_killed),
            ('strace-fork-exec', lambda: self.strace('strace-fork-exec', 'fork-exec', 0)),
            ('strace-thread-exec', lambda: self.strace('strace-thread-exec', 'thread-exec', 42)),
        ]
        patterns = self.args.cases.split(',')
        cases = [(name, run) for name, run in cases if any(fnmatch.fnmatchcase(name, pattern) for pattern in patterns)]
        if not cases:
            raise RuntimeError('case filter selected no original sessions')
        self.report['plan'] = [name for name, _ in cases]
        try:
            for name, run in cases:
                began = time.monotonic()
                try:
                    run()
                    row = dict(name=name, status='passed')
                except Exception as error:
                    row = dict(name=name, status='failed', error=str(error))
                row['seconds'] = time.monotonic() - began
                self.rows.append(row)
                self.save()
                print('DEBUGGER-CASE ' + name + ' ' + row['status'], flush=True)
            self.report['passed'] = all(row['status'] == 'passed' for row in self.rows)
        finally:
            self.save()
        return self.report['passed']


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixture', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--gdb', default='gdb')
    parser.add_argument('--gdbserver', default='gdbserver')
    parser.add_argument('--strace', default='strace')
    parser.add_argument('--cases', default='*', help='comma-separated case globs; focused reruns preserve original case names')
    args = parser.parse_args()
    args.fixture = args.fixture.resolve(strict=True)
    args.output = args.output.resolve()
    if platform.machine() not in ('aarch64', 'arm64'):
        parser.error('ARM64 native reference or Trames guest required')
    raise SystemExit(0 if Batch(args).run() else 1)
