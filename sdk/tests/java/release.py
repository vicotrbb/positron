"""Build actual independent Maven payloads for the existing Release Trust tests."""
import pathlib
import shutil
import sys
from test_package import ROOT, build

output = pathlib.Path(sys.argv[1])
source_commit = sys.argv[2]
for name in ('first', 'second'):
    source = output / name
    shutil.copytree(ROOT / 'sdk/java', source, ignore=shutil.ignore_patterns('target'))
    build(source, '1.0.0', source_commit)
    destination = output / ('payload-' + name)
    destination.mkdir()
    for artifact in source.glob('target/*.jar'):
        shutil.copyfile(artifact, destination / artifact.name)
    shutil.copyfile(source / 'pom.xml', destination / 'sdk-1.0.0.pom')
