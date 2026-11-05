"""Build twice and exercise an installed NuGet consumer at public seams."""
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest
import zipfile
ROOT = pathlib.Path(__file__).resolve().parents[3]
DOTNET = ROOT/'target/dotnet-sdk-tools/8.0.427/dotnet'
ENV = dict(os.environ,DOTNET_ROOT=str(DOTNET.parent),DOTNET_CLI_HOME=str(ROOT/'target/dotnet-home'),NUGET_PACKAGES=str(ROOT/'target/dotnet-nuget'),DOTNET_PROCESSOR_COUNT='2',DOTNET_NOLOGO='1',DOTNET_SKIP_FIRST_TIME_EXPERIENCE='1',DOTNET_CLI_TELEMETRY_OPTOUT='1')
def run(command,**kwargs):
    result=subprocess.run([str(v) for v in command],env=ENV,capture_output=True,text=True,**kwargs)
    if result.returncode:raise AssertionError(result.stdout+'\n'+result.stderr)
    return result

def build(source,version='0.0.0',commit=None):
    source=source.resolve()
    run(['python3',source/'pack.py','--build','--dotnet',DOTNET,'--version',version,'--source-commit',commit or '55'*20],cwd=source)
    return source/f'bin/Release/Positron.SDK.{version}.nupkg'

def consumer(directory,package,version='0.0.0'):
    source=directory/'consumer';source.mkdir()
    config=source/'NuGet.Config';config.write_text('<configuration><packageSources><clear/><add key="local" value="'+str(package.parent)+'"/></packageSources></configuration>')
    (source/'Consumer.csproj').write_text('<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net8.0</TargetFramework><ImplicitUsings>enable</ImplicitUsings></PropertyGroup><ItemGroup><PackageReference Include="Positron.SDK" Version="'+version+'"/></ItemGroup></Project>')
    shutil.copyfile(ROOT/'sdk/tests/dotnet/Program.cs',source/'Program.cs')
    example=(ROOT/'sdk/dotnet.md').read_text().split('```csharp\n',1)[1].split('```',1)[0]
    imports,body=example.split('using var',1)
    (source/'Documentation.cs').write_text(imports+'\nstatic class Documentation { public static async System.Threading.Tasks.Task Run() { using var'+body+'\n} }')
    clean=directory/'clean-packages'
    run([DOTNET,'restore',source,'--configfile',config,'--packages',clean,'--disable-build-servers'],cwd=source)
    run([DOTNET,'build',source,'-c','Release','--no-restore','--disable-build-servers','-m:1'],cwd=source)
    assert (clean/'positron.sdk'/version/f'positron.sdk.{version}.nupkg').is_file()
    return source/'bin/Release/net8.0/Consumer.dll'
class PackageTests(unittest.TestCase):
    def test_clean_generated_package(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'target',prefix='dotnet-sdk-package-') as temporary:
            directory=pathlib.Path(temporary);first=directory/'first';second=directory/'second'
            run(['cargo','run','--locked','-p','positron-api','--example','generate_dotnet_sdk','--',first],cwd=ROOT)
            for expected in (ROOT/'sdk/dotnet').rglob('*'):
                if expected.is_file() and not {'bin','obj'}.intersection(expected.relative_to(ROOT/'sdk/dotnet').parts):
                    self.assertEqual(expected.read_bytes(),(first/expected.relative_to(ROOT/'sdk/dotnet')).read_bytes(),str(expected))
            shutil.copytree(first,second);actual=build(first);rebuilt=build(second)
            self.assertEqual(actual.read_bytes(),rebuilt.read_bytes())
            for suffix in ('.snupkg',):self.assertEqual((actual.parent/('Positron.SDK.0.0.0'+suffix)).read_bytes(),(rebuilt.parent/('Positron.SDK.0.0.0'+suffix)).read_bytes())
            dll=consumer(directory,actual)
            print(run([DOTNET,dll,ROOT/'api/positron/v1']).stdout)
            signed=directory/'signed.nupkg';shutil.copyfile(actual,signed)
            with zipfile.ZipFile(signed,'a') as archive:archive.writestr('.signature.p7s',b'private signature refusal fixture')
            original=signed.read_bytes()
            with self.assertRaises(AssertionError):run(['python3',first/'pack.py',signed])
            self.assertEqual(original,signed.read_bytes())
if __name__=='__main__':unittest.main()
