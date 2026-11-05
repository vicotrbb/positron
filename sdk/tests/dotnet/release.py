"""Produce two independent unsigned native payloads for Release Trust tests."""
import pathlib
import shutil
import sys
from test_package import ROOT,build
out=pathlib.Path(sys.argv[1]);commit=sys.argv[2]
for label in ('first','second'):
    source=out/('dotnet-'+label)
    shutil.copytree(ROOT/'sdk/dotnet',source,ignore=shutil.ignore_patterns('obj','bin'))
    package=build(source,'1.0.0',commit)
    directory=out/('dotnet-payload-'+label);directory.mkdir()
    shutil.copyfile(package,directory/'Positron.SDK.1.0.0.nupkg')
    shutil.copyfile(package.parent/'Positron.SDK.1.0.0.snupkg',directory/'Positron.SDK.1.0.0.snupkg')

import zipfile
first=out/'dotnet-payload-first/Positron.SDK.1.0.0.nupkg'
second=out/'dotnet-payload-second/Positron.SDK.1.0.0.nupkg'
if first.read_bytes()!=second.read_bytes():
    with zipfile.ZipFile(first) as a,zipfile.ZipFile(second) as b:
        for name in a.namelist():
            if name not in b.namelist() or a.read(name)!=b.read(name):
                print('Different NuGet member: '+name,file=sys.stderr)
                if name.endswith('.nuspec'):print(a.read(name),b.read(name),file=sys.stderr)
    raise AssertionError('Independent NuGet payload differs')
