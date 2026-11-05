package sdk_test

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	positron "github.com/vicotrbb/positron/sdk/go"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const modulePath = "github.com/vicotrbb/positron/sdk/go"

func moduleArchive(t *testing.T) []byte {
	t.Helper()
	var buffer bytes.Buffer
	archive := zip.NewWriter(&buffer)
	err := filepath.WalkDir("../../go", func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel("../../go", path)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if relative == "release.json" {
			var metadata map[string]any
			if err = json.Unmarshal(data, &metadata); err != nil {
				return err
			}
			metadata["version"] = "1.0.0"
			metadata["source_commit"] = strings.Repeat("1", 40)
			data, err = json.Marshal(metadata)
			if err != nil {
				return err
			}
		}
		writer, err := archive.CreateHeader(&zip.FileHeader{Name: modulePath + "@v1.0.0/" + filepath.ToSlash(relative), Method: zip.Store})
		if err != nil {
			return err
		}
		_, err = writer.Write(data)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = archive.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}
func TestActualModuleInstallAndReproducibility(t *testing.T) {
	first, second := moduleArchive(t), moduleArchive(t)
	if !bytes.Equal(first, second) {
		t.Fatal("module ZIP is not reproducible")
	}
	root := t.TempDir()
	proxy := filepath.Join(root, "proxy", filepath.FromSlash(modulePath), "@v")
	if err := os.MkdirAll(proxy, 0700); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"v1.0.0.zip": first, "v1.0.0.mod": []byte("module " + modulePath + "\n\ngo 1.24.0\n"), "v1.0.0.info": []byte(`{"Version":"v1.0.0","Time":"2023-11-14T22:13:20Z"}`), "list": []byte("v1.0.0\n")} {
		if err := os.WriteFile(filepath.Join(proxy, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	consumer := filepath.Join(root, "consumer")
	if err := os.Mkdir(consumer, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(consumer, "go.mod"), []byte("module consumer\n\ngo 1.24.0\n\nrequire "+modulePath+" v1.0.0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(consumer, "main_test.go"), []byte("package consumer\nimport(\"testing\"; sdk \""+modulePath+"\")\nfunc TestInstalled(t *testing.T){if sdk.APIVersion!=\"positron.v1\"{t.Fatal(\"identity\")}; if _,err:=sdk.NewClient(\"https://localhost\",false);err!=nil{t.Fatal(err)}}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(), "GOPROXY=file://"+filepath.Join(root, "proxy"), "GOSUMDB=off", "GOMODCACHE="+filepath.Join(root, "modcache"), "GOMAXPROCS=2", "GOTOOLCHAIN=local", "GOFLAGS=-mod=mod -modcacherw")
	for _, args := range [][]string{{"mod", "download", "-json", modulePath + "@v1.0.0"}, {"test", "-p", "1", "./..."}, {"doc", modulePath + ".Client"}, {"build", "-p", "1", modulePath + "/examples/query"}} {
		command := exec.Command("go", args...)
		command.Dir = consumer
		command.Env = env
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("installed module %v: %v\n%s", args, err, output)
		}
	}
}
func FuzzPublicDecode(f *testing.F) {
	f.Add("LogQueryValue", []byte(`{"textValue":"example"}`))
	f.Add("LogQueryCell", []byte(`{"unsignedInteger":"18446744073709551615"}`))
	f.Add("CapabilityRequest", []byte(`{"api_major":1e1000000000}`))
	f.Add("LogQueryValue", []byte(`{"textValue":"\ud800"}`))
	f.Add("LogQueryValue", []byte(`{"\udfff":"value"}`))
	f.Fuzz(func(t *testing.T, name string, data []byte) {
		if len(data) > 262145 {
			return
		}
		_, _ = positron.Decode(name, data)
		_, _ = positron.DecodeQuery(data, "session")
		_ = positron.QueryError(503, data, false)
	})
}
