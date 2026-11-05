package sdk_test

import (
	"encoding/json"
	"errors"
	positron "github.com/vicotrbb/positron/sdk/go"
	"os"
	"testing"
)

func TestCanonicalPublicValues(t *testing.T) {
	if positron.APIVersion != "positron.v1" || len(positron.SchemaDigest) != 64 {
		t.Fatal("missing canonical identity")
	}
	var request positron.LogQueryRequest
	if err := json.Unmarshal([]byte(`{"pipeline":"pipeline:v1 logs","budget":{"scannedBytes":"18446744073709551615"}}`), &request); err != nil {
		t.Fatal(err)
	}
	if _, err := positron.Decode("LogQueryRequest", []byte(`{"pipeline":"first","pipeline":"second"}`)); err == nil {
		t.Fatal("duplicate property accepted")
	}
}

type golden struct {
	Representations []struct {
		ID        string `json:"id"`
		Type      string `json:"type"`
		Input     string `json:"input"`
		Accepted  bool   `json:"accepted"`
		Canonical any    `json:"canonical"`
	} `json:"representations"`
	Responses []struct {
		ID       string          `json:"id"`
		Input    json.RawMessage `json:"input"`
		Accepted bool            `json:"accepted"`
		Mode     string          `json:"mode"`
	} `json:"responses"`
	Errors []struct {
		ID           string          `json:"id"`
		Status       int             `json:"status"`
		Input        json.RawMessage `json:"input"`
		Cancellation bool            `json:"cancellation"`
		Failure      string          `json:"failure"`
		Retry        string          `json:"retryClass"`
		Completion   string          `json:"completionState"`
	} `json:"errors"`
}

func fixtures(t *testing.T) golden {
	t.Helper()
	data, err := os.ReadFile("../../go/api/query-golden-fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var result golden
	if err = json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	return result
}
func TestCrossLanguageGoldens(t *testing.T) {
	f := fixtures(t)
	for _, c := range f.Representations {
		t.Run(c.ID, func(t *testing.T) {
			value, err := positron.Decode(c.Type, []byte(c.Input))
			if (err == nil) != c.Accepted {
				t.Fatalf("accepted=%v error=%v", c.Accepted, err)
			}
			if c.Accepted {
				a, _ := json.Marshal(value)
				b, _ := json.Marshal(c.Canonical)
				if string(a) != string(b) {
					t.Fatal("canonical representation differs")
				}
			}
		})
	}
	for _, c := range f.Responses {
		t.Run(c.ID, func(t *testing.T) {
			mode := c.Mode
			if mode == "" {
				mode = "execute"
			}
			_, err := positron.DecodeQuery(c.Input, mode)
			if (err == nil) != c.Accepted {
				t.Fatalf("accepted=%v error=%v", c.Accepted, err)
			}
		})
	}
	for _, c := range f.Errors {
		t.Run(c.ID, func(t *testing.T) {
			err := positron.QueryError(c.Status, c.Input, c.Cancellation)
			var failure *positron.ClientError
			if !errors.As(err, &failure) || failure.Failure != c.Failure || failure.RetryClass != c.Retry || failure.CompletionState != c.Completion {
				t.Fatalf("policy differs: %+v", failure)
			}
		})
	}
}

func TestUnicodeSurrogateParity(t *testing.T) {
	for _, input := range []string{`{"textValue":"\ud800"}`, `{"textValue":"\udfff"}`, `{"\ud800":"value"}`, `{"\udfff":"value"}`, `{"textValue":"\ud800\u0041"}`} {
		if _, err := positron.Decode("LogQueryValue", []byte(input)); err == nil {
			t.Fatalf("unpaired surrogate accepted: %s", input)
		}
	}
	for _, input := range []string{`{"textValue":"\ud83d\ude00"}`, `{"textValue":"�"}`, `{"textValue":"\ufffd"}`, `{"textValue":"\\ud800"}`} {
		if _, err := positron.Decode("LogQueryValue", []byte(input)); err != nil {
			t.Fatalf("valid Unicode rejected: %s", input)
		}
	}
}
