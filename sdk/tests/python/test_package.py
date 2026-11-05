"""Build and install actual reproducible wheel bytes in a clean consumer."""
import hashlib
import importlib.metadata
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[3]

def build_wheel(source, output):
    env = dict(os.environ, SOURCE_DATE_EPOCH='1700000000', PYTHONHASHSEED='0')
    subprocess.run([sys.executable, '-m', 'build', '--wheel', '--no-isolation', '--outdir', str(output), str(source)], env=env, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return next(output.glob('*.whl'))

class PackageTests(unittest.TestCase):
    def test_generated_public_type_annotations_resolve(self):
        import typing
        from positron_sdk import types
        for name, value in vars(types).items():
            if typing.is_typeddict(value):
                with self.subTest(name=name):
                    typing.get_type_hints(value, vars(types))

    def test_clean_package_install_rebuild_metadata_and_example(self):
        self.assertEqual(importlib.metadata.version('setuptools'), '80.9.0')
        with tempfile.TemporaryDirectory(prefix='positron-python-package-') as temporary:
            temporary = pathlib.Path(temporary)
            source = temporary / 'source'
            shutil.copytree(ROOT / 'sdk/python', source, ignore=shutil.ignore_patterns('__pycache__', 'build', 'dist', '*.egg-info'))
            first, second = build_wheel(source, temporary / 'first'), build_wheel(source, temporary / 'second')
            self.assertEqual(first.read_bytes(), second.read_bytes())
            with zipfile.ZipFile(first) as wheel:
                self.assertIn('positron_sdk/py.typed', wheel.namelist())
                release = json.loads(wheel.read('positron_sdk/release.json'))
                self.assertEqual(release['schema_digest'], hashlib.sha256(wheel.read('positron_sdk/api/positron.proto')).hexdigest())
                metadata = wheel.read(next(name for name in wheel.namelist() if name.endswith('/METADATA'))).decode()
                self.assertIn('Name: positron-sdk\n', metadata)
                self.assertIn('License-Expression: MIT\n', metadata)
                self.assertNotIn('Requires-Dist:', metadata)
            consumer = temporary / 'consumer'
            subprocess.run([sys.executable, '-m', 'venv', str(consumer)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            executable = consumer / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
            env = {key: value for key, value in os.environ.items() if key != 'PYTHONPATH'}
            subprocess.run([str(executable), '-m', 'pip', 'install', '--no-deps', '--no-index', str(first)], env=env, cwd=temporary, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            code = "from positron_sdk import PositronClient, SCHEMA_DIGEST; from positron_sdk.types import LogQueryRequest; import runpy; runpy.run_path('example.py', run_name='example'); print(SCHEMA_DIGEST)"
            shutil.copyfile(source / 'examples/query.py', temporary / 'example.py')
            result = subprocess.run([str(executable), '-c', code], cwd=temporary, env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), release['schema_digest'])
