"""Create deterministic unsigned NuGet payloads before any signing or provenance.

NuGet's pack task assigns random OPC relationship IDs and wall-clock ZIP times.
Normalize only that container metadata; compiled binaries and source stay intact.
Never run this on an already signed package.
"""
import argparse
import json
import os
import subprocess
import pathlib
import re
import sys
import zipfile

def normalize(path):
    with zipfile.ZipFile(path) as archive:
        files={name:archive.read(name) for name in archive.namelist()}
    if '.signature.p7s' in files:
        raise ValueError('Refusing to rewrite a signed NuGet package')
    core=[name for name in files if name.endswith('.psmdcp')]
    if len(core)!=1:
        raise ValueError('Expected one NuGet core properties member')
    stable='package/services/metadata/core-properties/00000000000000000000000000000000.psmdcp'
    files[stable]=files.pop(core[0])
    rels=files['_rels/.rels'].decode().replace(core[0],stable)
    counter=iter(range(1,16))
    files['_rels/.rels']=re.sub(r'Id="[^"]+"',lambda _:f'Id="R{next(counter):016X}"',rels).encode()
    temporary=path.with_suffix(path.suffix+'.tmp')
    with zipfile.ZipFile(temporary,'w',compression=zipfile.ZIP_STORED) as archive:
        for name,data in sorted(files.items()):
            info=zipfile.ZipInfo(name,(2000,1,1,0,0,0));info.compress_type=zipfile.ZIP_STORED;info.external_attr=0o100644<<16
            archive.writestr(info,data)
    temporary.replace(path)

def build(dotnet,version,source_commit):
    source=pathlib.Path(__file__).resolve().parent
    if not re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)',version):
        raise ValueError('Expected a stable package version')
    if not re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}',source_commit) or set(source_commit)=={'0'}:
        raise ValueError('Expected a source commit')
    actual=subprocess.check_output([dotnet,'--version'],cwd=source,text=True).strip()
    if actual!='8.0.427':
        raise ValueError('Expected pinned .NET SDK 8.0.427')
    metadata=source/'release.json';release=json.loads(metadata.read_text());release.update(version=version,source_commit=source_commit)
    metadata.write_text(json.dumps(release,separators=(',',':')))
    subprocess.run([dotnet,'pack',str(source),'-c','Release','--disable-build-servers','-m:1','-p:Version='+version,'-p:PathMap='+str(source)+'=/_/src','-p:RepositoryCommit='+source_commit],cwd=source,check=True)
    for archive in (source/'bin/Release').glob('*.*nupkg'):
        normalize(archive)

if __name__=='__main__':
    if '--build' in sys.argv:
        parser=argparse.ArgumentParser();parser.add_argument('--build',action='store_true');parser.add_argument('--dotnet',default='dotnet');parser.add_argument('--version',required=True);parser.add_argument('--source-commit',required=True)
        args=parser.parse_args();build(args.dotnet,args.version,args.source_commit)
    else:
        for argument in sys.argv[1:]:normalize(pathlib.Path(argument))
