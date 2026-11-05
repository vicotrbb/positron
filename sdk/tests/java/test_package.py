"""Build reproducible JVM JARs and exercise a clean Maven consumer installation."""
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[3]
JAVA_HOME = pathlib.Path(os.environ.get('JAVA_HOME', ROOT / 'target/java-sdk-tools/jdk-21.0.9+10/Contents/Home'))
MVN = os.environ.get('POSITRON_MAVEN', str(ROOT / 'target/java-sdk-tools/apache-maven-3.9.11/bin/mvn'))
M2 = pathlib.Path(os.environ.get('POSITRON_MAVEN_REPO', ROOT / 'target/java-sdk-m2'))
ENV = dict(os.environ, JAVA_HOME=str(JAVA_HOME), MAVEN_OPTS='-Xmx512m -XX:ActiveProcessorCount=2')

def run(command, **kwargs):
    result = subprocess.run([str(v) for v in command], env=ENV, capture_output=True, text=True, **kwargs)
    if result.returncode:
        raise AssertionError(f'{command[0]} failed ({result.returncode})\n{result.stdout}\n{result.stderr}')
    return result

def maven(source, *arguments, repository=M2):
    return run([MVN, '-B', '-ntp', '-Dmaven.repo.local=' + str(repository), '-f', source / 'pom.xml', *arguments])

def build(source, version=None, source_commit=None):
    if version:
        pom = source / 'pom.xml'
        pom.write_text(pom.read_text().replace('<version>0.0.0</version>', f'<version>{version}</version>', 1))
        metadata = source / 'src/main/resources/dev/positron/release.json'
        release = json.loads(metadata.read_text())
        release.update(version=version, source_commit=source_commit or '55' * 20)
        metadata.write_text(json.dumps(release, separators=(',', ':')))
    maven(source, 'package')
    version = version or '0.0.0'
    return {suffix: (source / f'target/sdk-{version}{suffix}').read_bytes() for suffix in ('.jar', '-sources.jar', '-javadoc.jar')}


def consumer(directory, source, repository):
    maven(source, 'install', repository=repository)
    consumer = directory / 'consumer'
    (consumer / 'src/main/java').mkdir(parents=True)
    for java in (ROOT / 'sdk/tests/java').glob('*.java'):
        shutil.copyfile(java, consumer / 'src/main/java' / java.name)
    shutil.copyfile(source / 'examples/Example.java', consumer / 'src/main/java/Example.java')
    (consumer / 'pom.xml').write_text('''<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion><groupId>test</groupId><artifactId>consumer</artifactId><version>1</version><properties><maven.compiler.release>21</maven.compiler.release><project.build.sourceEncoding>UTF-8</project.build.sourceEncoding></properties><dependencies><dependency><groupId>dev.positron</groupId><artifactId>sdk</artifactId><version>0.0.0</version></dependency></dependencies><build><plugins><plugin><groupId>org.apache.maven.plugins</groupId><artifactId>maven-resources-plugin</artifactId><version>3.3.1</version></plugin><plugin><groupId>org.apache.maven.plugins</groupId><artifactId>maven-compiler-plugin</artifactId><version>3.14.1</version></plugin></plugins></build></project>''')
    maven(consumer, 'compile', 'org.apache.maven.plugins:maven-dependency-plugin:3.8.1:build-classpath', '-Dmdep.outputFile=' + str(consumer / 'classpath'), repository=repository)
    classpath = str(consumer / 'target/classes') + os.pathsep + (consumer / 'classpath').read_text().strip()
    for dependency in json.loads((source / 'src/main/resources/dev/positron/dependencies.json').read_text()):
        path = repository / dependency['group'].replace('.', '/') / dependency['name'] / dependency['version'] / f"{dependency['name']}-{dependency['version']}.jar"
        assert hashlib.sha256(path.read_bytes()).hexdigest() == dependency['sha256'], dependency['name']
    # The SDK must resolve from this clean Maven repository, never its source classes.
    assert str(repository / 'dev/positron/sdk/0.0.0/sdk-0.0.0.jar') in classpath
    assert str(source) not in classpath
    return classpath

class PackageTests(unittest.TestCase):
    def test_clean_generation_package_install_reproducibility_and_conformance(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'target', prefix='java-sdk-package-') as output:
            output = pathlib.Path(output)
            first, second = output / 'first', output / 'second'
            run(['cargo', 'run', '--locked', '-p', 'positron-api', '--example', 'generate_java_sdk', '--', first], cwd=ROOT)
            for expected in (ROOT / 'sdk/java').rglob('*'):
                if expected.is_file() and 'target' not in expected.relative_to(ROOT / 'sdk/java').parts:
                    self.assertEqual(expected.read_bytes(), (first / expected.relative_to(ROOT / 'sdk/java')).read_bytes(), str(expected))
            shutil.copytree(first, second)
            actual, rebuilt = build(first), build(second)
            self.assertEqual(actual, rebuilt)
            with zipfile.ZipFile(first / 'target/sdk-0.0.0.jar') as jar:
                release = json.loads(jar.read('dev/positron/release.json'))
                self.assertEqual(release['schema_digest'], hashlib.sha256(jar.read('dev/positron/api/positron.proto')).hexdigest())
                self.assertIn(b'Automatic-Module-Name: dev.positron.sdk', jar.read('META-INF/MANIFEST.MF'))
                self.assertIn(b'MIT License', jar.read('dev/positron/LICENSE'))
            repository = output / 'clean-m2'
            classpath = consumer(output, first, repository)
            keystore=output / 'tls.p12'
            run([JAVA_HOME / 'bin/keytool', '-genkeypair', '-alias', 'test', '-keyalg', 'RSA', '-keysize', '2048', '-validity', '1', '-storetype', 'PKCS12', '-keystore', keystore, '-storepass', 'test-only', '-dname', 'CN=localhost'])
            for test in ('Goldens', 'Delivery', 'Transport', 'Refusals', 'Example'):
                with self.subTest(test=test):
                    arguments = [] if test == 'Example' else [ROOT / 'api/positron/v1', keystore]
                    result = run([JAVA_HOME / 'bin/java', '-Xmx256m', '-XX:ActiveProcessorCount=2', '-cp', classpath, test, *arguments])
                    self.assertTrue(result.stdout.strip())

if __name__ == '__main__':
    unittest.main()
