package sdk_test

import (
	"context"
	"errors"
	"fmt"
	positron "github.com/vicotrbb/positron/sdk/go"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTransportRefusalAndAmbiguity(t *testing.T) {
	for _, endpoint := range []string{"http://localhost", "https://secret@localhost", "https://localhost/?secret=value", "https://localhost/path", "https://localhost/#secret"} {
		if _, err := positron.NewClient(endpoint, false); err == nil {
			t.Fatal("unsafe endpoint accepted")
		}
	}
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"api_major":1,"schema_digest":"`+positron.SchemaDigest+`","availability":1,"refusal":null,"deprecation":0,"capability":0}`)
	}))
	defer server.Close()
	client, err := positron.NewClient(server.URL, true)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var output map[string]any
	if err = client.Call(context.Background(), "positron.v1.CapabilityService/Negotiate", map[string]any{"api_major": 1}, "private-secret\n", &output); err == nil {
		t.Fatal("credential injection accepted")
	}
	if requests != 0 {
		t.Fatal("unsafe credential sent")
	}
	if err = client.Call(context.Background(), "positron.v1.CapabilityService/Negotiate", map[string]any{"api_major": 1}, "private-secret", &output); err != nil {
		t.Fatal(err)
	}
}
func TestTransportBoundsPrematureEOFRedirectAndTLS(t *testing.T) {
	for _, mode := range []string{"deadline", "truncated", "oversize", "redirect"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				switch mode {
				case "deadline":
					select {
					case <-r.Context().Done():
					case <-time.After(time.Second):
					}
				case "truncated":
					w.Header().Set("Content-Length", "1024")
					fmt.Fprint(w, `{}`)
				case "oversize":
					fmt.Fprint(w, strings.Repeat(" ", 262145))
				case "redirect":
					w.Header().Set("Location", "https://external.invalid")
					w.WriteHeader(307)
				}
			}))
			defer server.Close()
			client, err := positron.NewClient(server.URL, true)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
			defer cancel()
			var out map[string]any
			err = client.Call(ctx, "positron.v1.CapabilityService/Negotiate", map[string]any{"api_major": 1}, "private-secret", &out)
			if err == nil {
				t.Fatal("invalid response accepted")
			}
			if strings.Contains(err.Error(), "private-secret") {
				t.Fatal("secret in diagnostics")
			}
			if calls != 1 {
				t.Fatalf("effect retried %d", calls)
			}
			if mode != "redirect" {
				var failure *positron.ClientError
				if !errors.As(err, &failure) || failure.RetryClass != "RETRY_CLASS_NEVER" || failure.CompletionState != "COMPLETION_STATE_AMBIGUOUS" {
					t.Fatal("lost ambiguity")
				}
			}
		})
	}
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer tlsServer.Close()
	client, err := positron.NewClient(tlsServer.URL, false)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var out map[string]any
	if client.Call(context.Background(), "positron.v1.CapabilityService/Negotiate", map[string]any{"api_major": 1}, "", &out) == nil {
		t.Fatal("untrusted TLS accepted")
	}
}
func TestDeliveryReceiptsPreserveStateOnRefusal(t *testing.T) {
	fixture := fixtures(t)
	response := func(id string) map[string]any {
		for _, value := range fixture.Responses {
			if value.ID == id {
				mode := value.Mode
				if mode == "" {
					mode = "execute"
				}
				result, err := positron.DecodeQuery(value.Input, mode)
				if err != nil {
					t.Fatal(err)
				}
				return result
			}
		}
		t.Fatal("missing response")
		return nil
	}
	tracker, _ := positron.NewBatchTracker("tail")
	first := response("tail-single-incomplete")
	if tracker.Acknowledgement() != nil {
		t.Fatal("premature receipt")
	}
	batches, err := tracker.Filter(first)
	if err != nil || len(batches) != 1 {
		t.Fatal(err)
	}
	if batches, err = tracker.Filter(first); err != nil || len(batches) != 0 {
		t.Fatal("repeat exposed")
	}
	receipt := tracker.Acknowledgement()
	if receipt["sequence"] != "0" {
		t.Fatal("receipt precision")
	}
	next := response("tail-next-incomplete")
	changed := response("tail-next-incomplete")
	events := changed["events"].([]any)
	events[1].(map[string]any)["batch"].(map[string]any)["sequence"] = "4"
	if _, err = tracker.Filter(changed); err == nil {
		t.Fatal("gap accepted")
	}
	if batches, err = tracker.Filter(next); err != nil || len(batches) != 1 {
		t.Fatal("invalid page advanced state")
	}
	if _, err = tracker.Filter(first); err == nil {
		t.Fatal("old page accepted")
	}
	completed, _ := positron.NewBatchTracker("session")
	page := response("one-batch-complete")
	if _, err = completed.Filter(page); err != nil {
		t.Fatal(err)
	}
	mutated := response("one-batch-complete")
	values := mutated["events"].([]any)[1].(map[string]any)["batch"].(map[string]any)["rows"].([]any)[0].(map[string]any)["cells"].([]any)[0].(map[string]any)["nativeValue"].(map[string]any)
	values["textValue"] = "changed"
	if _, err = completed.Filter(mutated); err == nil {
		t.Fatal("changed repeated content accepted")
	}
	if _, err = completed.Filter(page); err != nil {
		t.Fatal("failure advanced state")
	}
}

func TestCapabilityNegotiationRefusesOlderServerBeforeAddedEffects(t *testing.T) {
	query := map[string]any{"pipeline": "pipeline:v1 logs", "budget": map[string]any{"scannedBytes": "1", "decodedRecords": "1", "outputRows": "1", "outputBytes": "1", "memoryBytes": "1", "cpuWorkUnits": "1", "wallSeconds": "1", "maximumTimeRangeNanoseconds": "1"}}
	negotiations, effects := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/capabilities:negotiate" {
			effects++
			w.WriteHeader(500)
			return
		}
		negotiations++
		fmt.Fprintf(w, `{"api_major":1,"schema_digest":%q,"availability":3,"refusal":null,"deprecation":0,"capability":4}`, positron.SchemaDigest)
	}))
	defer server.Close()
	client, err := positron.NewClient(server.URL, true)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	for attempt := 0; attempt < 2; attempt++ {
		var result any
		err = client.Call(context.Background(), "positron.v1.LogQueryService/Session", map[string]any{"execute": query, "batchLimit": 1}, "key", &result)
		var failure *positron.ClientError
		if !errors.As(err, &failure) || failure.Failure != "UnsupportedFeature" || failure.RetryClass != "RETRY_CLASS_NEVER" || failure.CompletionState != "COMPLETION_STATE_REJECTED" {
			t.Fatalf("missing stable unsupported detail: %v", err)
		}
	}
	if negotiations != 2 || effects != 0 {
		t.Fatal("stale capabilities or unsupported effect sent")
	}
}

func TestAdministrationPreservesCanonicalErrorTruth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(409)
		fmt.Fprint(w, `{"code":1,"retry_class":1,"completion_state":1,"source":1,"safe_detail":1}`)
	}))
	defer server.Close()
	client, err := positron.NewClient(server.URL, true)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var result any
	err = client.Call(context.Background(), "positron.v1.TenantService/List", positron.TenantListRequest{}, "key", &result)
	var failure *positron.ClientError
	if !errors.As(err, &failure) || failure.Failure != "PUBLIC_ERROR_CODE_UNSUPPORTED_API_VERSION" {
		t.Fatalf("administration discarded stable code: %v", err)
	}
}

func TestExecuteTransportHasFiveSecondCeiling(t *testing.T) {
	query := map[string]any{"pipeline": "pipeline:v1 logs", "budget": map[string]any{"scannedBytes": "1", "decodedRecords": "1", "outputRows": "1", "outputBytes": "1", "memoryBytes": "1", "cpuWorkUnits": "1", "wallSeconds": "5", "maximumTimeRangeNanoseconds": "1"}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(6 * time.Second):
			w.WriteHeader(503)
		}
	}))
	defer server.Close()
	client, err := positron.NewClient(server.URL, true)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	for _, shorter := range []bool{false, true} {
		ctx := context.Background()
		cancel := func() {}
		maximum := 5700 * time.Millisecond
		if shorter {
			ctx, cancel = context.WithTimeout(ctx, 25*time.Millisecond)
			maximum = 500 * time.Millisecond
		}
		start := time.Now()
		var result any
		err = client.Call(ctx, "positron.v1.LogQueryService/Execute", query, "key", &result)
		cancel()
		elapsed := time.Since(start)
		var failure *positron.ClientError
		if !errors.As(err, &failure) || failure.CompletionState != "COMPLETION_STATE_AMBIGUOUS" || failure.RetryClass != "RETRY_CLASS_NEVER" {
			t.Fatal("deadline lost ambiguity")
		}
		if elapsed > maximum {
			t.Fatalf("Execute exceeded its transport ceiling: %v", elapsed)
		}
	}
}

func TestSessionKeepsItsSeparateTransportWindow(t *testing.T) {
	query := map[string]any{"pipeline": "pipeline:v1 logs", "budget": map[string]any{"scannedBytes": "1", "decodedRecords": "1", "outputRows": "1", "outputBytes": "1", "memoryBytes": "1", "cpuWorkUnits": "1", "wallSeconds": "5", "maximumTimeRangeNanoseconds": "1"}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/capabilities:negotiate" {
			fmt.Fprintf(w, `{"api_major":1,"schema_digest":%q,"availability":1,"refusal":null,"deprecation":0,"capability":4}`, positron.SchemaDigest)
			return
		}
		select {
		case <-r.Context().Done():
		case <-time.After(5200 * time.Millisecond):
			w.WriteHeader(503)
		}
	}))
	defer server.Close()
	client, err := positron.NewClient(server.URL, true)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	start := time.Now()
	var result any
	err = client.Call(ctx, "positron.v1.LogQueryService/Session", map[string]any{"execute": query, "batchLimit": 1}, "key", &result)
	if err == nil {
		t.Fatal("stalled refusal accepted")
	}
	if time.Since(start) < 5100*time.Millisecond {
		t.Fatal("finite Execute ceiling leaked into Session")
	}
}

func TestInvalidOriginalRequestTextIsNeverSent(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		fmt.Fprint(w, `{"tenants":[],"continuation":null}`)
	}))
	defer server.Close()
	client, err := positron.NewClient(server.URL, true)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	invalid := string([]byte{0xff})
	value := func(text string) *string { return &text }
	request := positron.LogQueryRequest{Pipeline: &invalid, Budget: &positron.LogQueryBudget{
		ScannedBytes: value("1"), DecodedRecords: value("1"), OutputRows: value("1"), OutputBytes: value("1"), MemoryBytes: value("1"), CpuWorkUnits: value("1"), WallSeconds: value("1"), MaximumTimeRangeNanoseconds: value("1"),
	}}
	_, err = client.LogQueryExecute(context.Background(), request, "key")
	if !errors.Is(err, positron.ErrWire) || calls != 0 {
		t.Fatal("invalid request text reached transport")
	}
}
