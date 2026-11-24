#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Resolve pinned Linux/ARM64 C++ test dependencies without evaluating Starlark.

Only the two upstream test packages and known external C++ libraries are
accepted. Unknown expressions/dependencies are reported as build blockers.
Test sources and expectations are never rewritten.
"""
import ast
import hashlib
import json
from pathlib import Path

PACKAGES = ('test/syscalls/linux', 'test/util', 'test/syscalls/linux/rseq')


def canonical(label):
    if label.startswith('//') and ':' not in label:
        return label + ':' + label.rsplit('/', 1)[-1]
    return label


def value(node):
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, (ast.List, ast.Tuple)):
        return [value(n) for n in node.elts]
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return value(node.left) + value(node.right)
    if isinstance(node, ast.Name) and node.id in ('gbenchmark', 'gbenchmark_internal'):
        return '@benchmark'
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
        name = node.func.id
        kwargs = {k.arg: value(k.value) for k in node.keywords}
        if name == 'select_arch':
            if 'arm64' in kwargs:
                return kwargs['arm64']
            if 'default' in kwargs:
                return kwargs['default']
            raise ValueError('No upstream ARM64 selection')
        if name == 'select_system':
            return kwargs.get('linux', ['__linux__'])
        if name == 'select_gtest':
            return ['@gtest']
        if name in ('coreutil', 'default_net_util'):
            return []
    raise ValueError('Unsupported upstream expression: ' + ast.dump(node)[:180])


def rules(source):
    found = {}
    for package in PACKAGES:
        for stmt in ast.parse((source / package / 'BUILD').read_text()).body:
            if not isinstance(stmt, ast.Expr) or not isinstance(stmt.value, ast.Call):
                continue
            call = stmt.value
            if not isinstance(call.func, ast.Name) or call.func.id not in ('cc_binary', 'cc_library', 'sh_binary', 'genrule'):
                continue
            fields = {k.arg: k.value for k in call.keywords}
            name = value(fields['name'])
            found['//' + package + ':' + name] = dict(kind=call.func.id, package=package, name=name, fields=fields)
            if call.func.id == 'genrule' and package == 'test/syscalls/linux/rseq' and name == 'rseq_binary':
                # Bazel exposes this generated output as the package's default
                # target. Preserve that exact upstream runfile identity.
                if value(fields['outs']) != ['rseq']:
                    raise ValueError('Unexpected pinned rseq outputs')
                found['//' + package + ':rseq'] = found['//' + package + ':' + name]
    return found


def generate(source, destination):
    source, destination = Path(source), Path(destination)
    nodes = rules(source)
    objects = {}
    lines = ['add_library(gvisor_test_main STATIC "${GVISOR_SOURCE}/test/util/test_main.cc")']
    suites, blocked, helpers = [], [], {}

    def resolve(label, stack=()):
        label = canonical(label)
        if label in stack:
            raise ValueError('Dependency cycle: ' + label)
        if label in ('@gtest', '@benchmark'):
            return set(), set(), []
        if label.startswith('@com_google_absl//absl/'):
            target = label.split(':')[-1] if ':' in label else label.rsplit('/', 1)[-1]
            target = {'random':'random_random'}.get(target,target)
            return set(), {'absl::' + target}, []
        if label == '@bazel_tools//tools/cpp/runfiles':
            return {'tools/cpp/runfiles/runfiles_src.cc'}, set(), []
        if label not in nodes:
            raise ValueError('Unavailable dependency: ' + label)
        node = nodes[label]
        if node['kind'] == 'genrule':
            raise ValueError('Generated dependency is not a C++ library: ' + label)
        fields = {k: value(n) for k, n in node['fields'].items() if k in ('srcs', 'deps', 'data', 'malloc', 'defines')}
        if node['kind'] == 'sh_binary':
            return set(), set(), [(label, node, fields)]
        srcs = {node['package'] + '/' + p for p in fields.get('srcs', []) if p.endswith(('.cc', '.c', '.S'))}
        libraries, data = set(), []
        deps = fields.get('deps', []) + ([fields['malloc']] if fields.get('malloc') else [])
        for dep in deps:
            if dep.startswith(':'):
                dep = '//' + node['package'] + dep
            s, libs, assets = resolve(dep, (*stack, label))
            srcs.update(s); libraries.update(libs); data.extend(assets)
        for dep in fields.get('data', []):
            if dep.startswith(':'):
                dep = '//' + node['package'] + dep
            dep = canonical(dep)
            if dep not in nodes:
                raise ValueError('Unavailable runfile: ' + dep)
            data.append((dep, nodes[dep], None))
        for p in srcs:
            if not (source / p).is_file():
                raise ValueError('Unavailable source: ' + p)
        return srcs, libraries, data

    def objects_for(srcs):
        names = []
        for p in sorted(srcs):
            obj = 'gv_' + hashlib.sha256(p.encode()).hexdigest()[:16]
            if p not in objects:
                objects[p] = obj
                lines.append('add_library(' + obj + ' OBJECT "${GVISOR_SOURCE}/' + p + '")')
                if p == 'test/syscalls/linux/sticky.cc':
                    # This upstream test intentionally omits an unused O_CREAT
                    # mode. Ubuntu's default fortify rejects the errno probe.
                    lines.append('target_compile_options('+obj+' PRIVATE -U_FORTIFY_SOURCE)')
            names.append('$<TARGET_OBJECTS:' + obj + '>')
        return names

    def executable(label, target, selected):
        srcs, libraries, data = resolve(label)
        direct = value(nodes[label]['fields'].get('srcs', ast.List(elts=[])))
        if not any(p.endswith(('.cc', '.c', '.S')) for p in direct):
            raise ValueError('No upstream source for ARM64')
        needs_main = 'test/util/test_main.cc' in srcs
        srcs.discard('test/util/test_main.cc')
        lines.append('add_executable(' + target + ' ' + ' '.join(objects_for(srcs)) + ')')
        if needs_main:
            lines.append('target_link_libraries('+target+' PRIVATE gvisor_test_main)')
        lines.append('target_link_options(' + target + ' PRIVATE -static -Wl,--gc-sections)')
        lines.append('target_link_libraries(' + target + ' PRIVATE GTest::gmock GTest::gtest benchmark absl::flags_parse absl::str_format absl::strings absl::synchronization absl::time pthread dl rt)')
        for lib in sorted(libraries):
            lines.extend(['if(TARGET ' + lib + ')', '  target_link_libraries(' + target + ' PRIVATE ' + lib + ')', 'endif()'])
        for dep, node, fields in data:
            helpers[dep] = node
        return dict(name=target.removesuffix('_test'), target=target, sources=sorted(srcs), libraries=sorted(libraries), data=sorted(set(dep for dep, _, _ in data)))

    for label, node in nodes.items():
        if node['package'] != PACKAGES[0] or node['kind'] != 'cc_binary' or not node['name'].endswith('_test'):
            continue
        checkpoint = len(lines)
        old_objects, old_helpers = dict(objects), dict(helpers)
        try:
            suites.append(executable(label, node['name'], True))
        except ValueError as error:
            del lines[checkpoint:]; objects = old_objects; helpers = old_helpers
            blocked.append(dict(name=node['name'].removesuffix('_test'), reason=str(error)))
    assets = []
    pending = list(helpers)
    done = set()
    while pending:
        label = pending.pop()
        if label in done:
            continue
        done.add(label)
        node = nodes[label]
        if node['kind'] == 'sh_binary':
            srcs = value(node['fields']['srcs'])
            if len(srcs) != 1:
                raise ValueError('Expected one shell runfile')
            assets.append(dict(path=node['package']+'/'+node['name'], source=node['package']+'/'+srcs[0]))
        elif node['kind'] == 'cc_binary':
            executable(label, node['name'], False)
            assets.append(dict(path=node['package']+'/'+node['name'], target=node['name']))
        elif node['kind'] == 'genrule' and node['package'] == 'test/syscalls/linux/rseq' and node['name'] == 'rseq_binary':
            inputs = value(node['fields']['srcs'])
            required = {'critical.h', 'critical_amd64.S', 'critical_arm64.S', 'rseq.cc',
                        'syscalls.h', 'start_amd64.S', 'start_arm64.S', 'test.h', 'types.h', 'uapi.h'}
            if set(inputs) != required:
                raise ValueError('Unexpected pinned rseq freestanding inputs')
            for name in inputs:
                if not (source / node['package'] / name).is_file():
                    raise ValueError('Unavailable rseq source: ' + name)
            prefix = '${GVISOR_SOURCE}/' + node['package'] + '/'
            target = 'gvisor_rseq_nolibc'
            output = '${CMAKE_CURRENT_BINARY_DIR}/' + target
            # This is the reviewed upstream genrule's ARM64 command, using
            # the selected C++ toolchain. No test/main/allocator/libc is linked.
            lines.extend([
                'add_custom_command(OUTPUT "' + output + '"',
                '  COMMAND "${CMAKE_CXX_COMPILER}" "-I${GVISOR_SOURCE}" -Wall -Werror -O2 -std=c++17 -static -nostdlib -ffreestanding -fno-exceptions -fno-pie -no-pie',
                '    "' + prefix + 'critical_arm64.S" "' + prefix + 'start_arm64.S" "' + prefix + 'rseq.cc" -o "' + output + '"',
                '  DEPENDS ' + ' '.join('"' + prefix + name + '"' for name in sorted(inputs)),
                '  VERBATIM)',
                'add_custom_target(' + target + '_build DEPENDS "' + output + '")',
            ])
            assets.append(dict(path=node['package']+'/rseq', target=target,
                               build_target=target+'_build', freestanding=True,
                               sources=[node['package']+'/'+name for name in sorted(inputs)]))
        else:
            raise ValueError('Unsupported runfile kind: '+label)
        pending.extend(set(helpers)-done)
    manifest = dict(schema_version=1, suites=suites, blocked=blocked, runfiles=assets, compatibility_compile_flags={'test/syscalls/linux/sticky.cc':['-U_FORTIFY_SOURCE']}, library_link_semantics='test_main uses normal lazy static archive extraction; test registration libraries retain their original alwayslink objects')
    destination.mkdir(parents=True, exist_ok=True)
    (destination/'expanded.cmake').write_text('\n'.join(lines)+'\n')
    (destination/'expanded.json').write_text(json.dumps(manifest, indent=2)+'\n')
    return manifest


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    manifest = generate(args.source, args.output)
    print('Buildable groups:', len(manifest['suites']), 'Blocked:', len(manifest['blocked']))
