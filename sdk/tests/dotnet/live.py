"""Install the real generated NuGet package before candidate-server conformance."""
import pathlib
import shutil
import sys
import tempfile
from test_package import ROOT,DOTNET,build,consumer,run
with tempfile.TemporaryDirectory(dir=ROOT/'target',prefix='dotnet-sdk-live-') as temporary:
    directory=pathlib.Path(temporary);source=directory/'source'
    shutil.copytree(ROOT/'sdk/dotnet',source,ignore=shutil.ignore_patterns('bin','obj'))
    package=build(source);dll=consumer(directory,package)
    print(run([DOTNET,dll,'live'],input=sys.stdin.read()).stdout,end='')
