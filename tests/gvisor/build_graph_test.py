# SPDX-License-Identifier: GPL-3.0-or-later
"""Dependency coverage for the original freestanding rseq runfile."""
from pathlib import Path
import tempfile
import unittest

from build_graph import generate


class RseqRunfileTests(unittest.TestCase):
    def test_package_default_output_keeps_freestanding_link_and_original_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'source'
            linux = source / 'test/syscalls/linux'
            util = source / 'test/util'
            rseq = linux / 'rseq'
            for path in (linux, util, rseq):
                path.mkdir(parents=True, exist_ok=True)
            (util / 'BUILD').write_text('')
            (linux / 'BUILD').write_text('''
cc_binary(name="rseq_test", srcs=["rseq.cc"],
          deps=["//test/syscalls/linux/rseq:lib"],
          data=["//test/syscalls/linux/rseq"])
''')
            inputs = ['critical.h', 'critical_amd64.S', 'critical_arm64.S', 'rseq.cc',
                      'syscalls.h', 'start_amd64.S', 'start_arm64.S', 'test.h', 'types.h', 'uapi.h']
            (rseq / 'BUILD').write_text(
                'cc_library(name="lib", hdrs=["test.h", "uapi.h"])\n'
                f'genrule(name="rseq_binary", srcs={inputs!r}, outs=["rseq"])\n')
            (linux / 'rseq.cc').write_text('// original test source\n')
            for name in inputs:
                (rseq / name).write_text('// original freestanding input\n')
            before = {str(path.relative_to(source)): path.read_bytes()
                      for path in source.rglob('*') if path.is_file()}
            manifest = generate(source, root / 'graph')
            self.assertEqual(manifest['blocked'], [])
            self.assertEqual([suite['name'] for suite in manifest['suites']], ['rseq'])
            asset, = manifest['runfiles']
            self.assertEqual(asset['path'], 'test/syscalls/linux/rseq/rseq')
            self.assertTrue(asset['freestanding'])
            cmake = (root / 'graph/expanded.cmake').read_text()
            command = next(line for line in cmake.splitlines() if 'COMMAND ' in line)
            self.assertIn('-nostdlib', command)
            self.assertIn('-ffreestanding', command)
            self.assertIn('-fno-exceptions', command)
            self.assertNotIn('gvisor_test_main', command)
            self.assertIn('critical_arm64.S', cmake)
            self.assertIn('start_arm64.S', cmake)
            self.assertEqual(before, {str(path.relative_to(source)): path.read_bytes()
                                     for path in source.rglob('*') if path.is_file()})


if __name__ == '__main__':
    unittest.main()
