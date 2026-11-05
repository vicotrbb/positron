"""Install the actual generated Maven package before candidate-server conformance."""
import pathlib
import shutil
import sys
import tempfile
from test_package import ROOT, JAVA_HOME, build, consumer, run

with tempfile.TemporaryDirectory(dir=ROOT / 'target', prefix='java-sdk-live-') as temporary:
    directory = pathlib.Path(temporary)
    source = directory / 'source'
    shutil.copytree(ROOT / 'sdk/java', source, ignore=shutil.ignore_patterns('target'))
    build(source)
    classpath = consumer(directory, source, directory / 'clean-m2')
    result = run([JAVA_HOME / 'bin/java', '-Xmx256m', '-XX:ActiveProcessorCount=2', '-cp', classpath, 'Live'], input=sys.stdin.read())
    print(result.stdout, end='')
