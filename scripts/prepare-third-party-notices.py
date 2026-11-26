#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Render reviewed dependency records and full notices. Requires Python 3.9+.

No downloads. After changing a lockfile, review new packages and add their exact
license texts and origins to third-party/licenses.json, then run this command.
--check verifies inputs, original text hashes and all generated outputs.
"""
import argparse
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BEGIN = '<!-- BEGIN GENERATED RUST DEPENDENCIES -->'
END = '<!-- END GENERATED RUST DEPENDENCIES -->'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def locked_packages(path):
    # Cargo emits one [[package]] block with JSON-compatible quoted scalar
    # identities. Read only those fields; dependencies/features are not needed
    # for a complete lockfile inventory. This also works on Apple's Python 3.9.
    records = []
    current = None
    fields = {'name', 'version', 'source', 'checksum'}
    for line in path.read_text().splitlines():
        line = line.strip()
        if line.startswith('['):
            if current is not None:
                records.append(current)
            current = {} if line == '[[package]]' else None
        elif current is not None and '=' in line:
            name, value = line.split('=', 1)
            if name.strip() in fields:
                current[name.strip()] = json.loads(value.strip())
    if current is not None:
        records.append(current)
    if not records or any('name' not in p or 'version' not in p for p in records):
        raise ValueError('Unsupported Cargo.lock package format: ' + str(path))
    return records


def render(root, check=False):
    catalog = json.loads((root / 'third-party/licenses.json').read_text())
    records = {(p['name'], p['version'], p['source']): p for p in catalog['packages']}
    active = {}
    inputs = {}
    for filename in catalog['lockfiles']:
        path = root / filename
        inputs[filename] = digest(path.read_bytes())
        for package in locked_packages(path):
            source = package.get('source', 'vendored-path')
            key = (package['name'], package['version'], source)
            if not package.get('source') and package['name'] in catalog['first_party_names']:
                continue
            if key not in records:
                raise ValueError('Unreviewed dependency: ' + repr(key) + ' in ' + filename)
            record = active.setdefault(key, dict(records[key], lockfiles=[]))
            record['lockfiles'].append(filename)
            if package.get('checksum') and package['checksum'] != record.get('checksum'):
                raise ValueError('Source checksum differs from reviewed package: ' + repr(key))
    for filename in catalog.get('additional_inputs', []):
        inputs[filename] = digest((root / filename).read_bytes())
    for record in active.values():
        for evidence in record['license_texts']:
            data = catalog['texts'][evidence['sha256']]['text'].encode('utf-8')
            if evidence.get('local_path') and digest((root / evidence['local_path']).read_bytes()) != evidence['sha256']:
                raise ValueError('Vendored license differs from reviewed source: ' + evidence['local_path'])
            if digest(data) != evidence['sha256']:
                raise ValueError('Changed original license text: ' + record['name'])
    parts = ['## Rust dependencies', '',
             'Generated from the committed lockfiles. This is the complete locked closure,',
             'including optional, build, test and other-target packages; it is not a claim',
             'that every entry is linked into each product. Project-owned packages are excluded.', '',
             '| Package | Version | Declared license | Selected license | Scope |',
             '| --- | --- | --- | --- | --- |']
    ordered = [active[k] for k in sorted(active)]
    for record in ordered:
        scope = 'Main' if 'Cargo.lock' in record['lockfiles'] else 'Auxiliary only'
        parts.append('| {name} | {version} | {declared_license} | {selected_license} | '.format(**record) + scope + ' |')
    parts += ['', 'Auxiliary lockfiles: ' + (', '.join('`' + p + '`' for p in catalog['lockfiles'] if p != 'Cargo.lock') or 'none') + '.', '']
    table = '\n'.join(parts)
    doc = root / 'docs/security/dependencies.md'
    contents = doc.read_text()
    if contents.count(BEGIN) != 1 or contents.count(END) != 1:
        raise ValueError('Dependency documentation must contain exactly one generated block')
    contents = contents.split(BEGIN)[0] + BEGIN + '\n\n' + table + '\n' + END + contents.split(END)[1]
    notices = ['Third-party Rust dependency notices', '',
               'These components retain their original terms and copyrights.',
               'The selected OR branch is identified per package; AND terms are retained.',
               'Complete original license/NOTICE files, including alternative branches, follow.',
               'Build/test/optional/other-target dependencies are included for completeness.',
               'Swift, native and guest components have additional notices documented in',
               'docs/security/dependencies.md; this file does not replace them.', '']
    used = {}
    for record in ordered:
        notices += [record['name'] + ' ' + record['version'],
                    'Source: ' + record['upstream'],
                    'Declared: ' + record['declared_license'],
                    'Selected: ' + record['selected_license']]
        for evidence in record['license_texts']:
            sha = evidence['sha256']
            used.setdefault(sha, []).append(record['name'] + ' ' + record['version'])
            notices.append('Original notice: sha256:' + sha + ' (' + evidence['origin'] + ')')
        notices.append('')
    for sha, packages in sorted(used.items()):
        notices += ['===== sha256:' + sha + ' =====',
                    'Applies to: ' + ', '.join(sorted(set(packages))), '',
                    catalog['texts'][sha]['text'], '']
    notice_bytes = ('\n'.join(notices).rstrip() + '\n').encode('utf-8')
    outputs = {doc: contents.encode('utf-8'), root / 'THIRD_PARTY_NOTICES.txt': notice_bytes,
               root / 'third-party/inputs.json': (json.dumps(inputs, indent=2, sort_keys=True) + '\n').encode('utf-8')}
    for filename in catalog.get('notice_copies', []):
        outputs[root / filename] = notice_bytes
    for path, data in outputs.items():
        if check:
            if not path.is_file() or path.read_bytes() != data:
                raise ValueError('Stale generated dependency file: ' + str(path.relative_to(root)))
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
    print(('Verified' if check else 'Generated') + f' {len(ordered)} reviewed Rust dependencies and {len(used)} original notice texts')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    try:
        render(ROOT, args.check)
    except (OSError, ValueError, KeyError) as error:
        parser.exit(1, str(error) + '\n')
