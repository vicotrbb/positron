package sdk_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	positron "github.com/vicotrbb/positron/sdk/go"
)

// Exercise native refusals through the public transport, reusing one server and
// client per fuzz worker rather than allocating sockets for every mutation.
func FuzzNativeAdministrationRefusal(f *testing.F) {
	for _, seed := range []struct {
		status uint16
		body   string
	}{
		{401, `{"code":"authentication_rejected"}`},
		{409, `{"code":"idempotency_conflict"}`},
		{409, `{"code":"stale_display_generation"}`},
		{400, `{"code":"invalid_request","retryClass":1,"completionState":1,"source":1,"safeDetail":1}`},
		{409, `{"code":1,"retry_class":1,"completion_state":1,"source":1,"safe_detail":1}`},
		{401, `{"code":"authentication_rejected","retryClass":1,"completionState":2}`},
		{401, `{"code":"authentication_rejected","code":"authentication_rejected"}`},
		{401, `{"code":"authentication_rejected","retryClass":1,"retry_class":1,"completionState":1}`},
		{401, `{"code":"private-secret"}`},
		{401, `{"code":"authentication_rejected","unknown":"private-secret"}`},
		{401, `{`},
		{401, `{"code":"authentication_rejected"}` + strings.Repeat(" ", 1024)},
	} {
		f.Add(seed.status, []byte(seed.body))
	}
	var mu sync.Mutex
	var status, attempts int
	var body []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		currentStatus, currentBody := status, body
		attempts++
		mu.Unlock()
		w.WriteHeader(currentStatus)
		_, _ = w.Write(currentBody)
	}))
	defer server.Close()
	client, err := positron.NewClient(server.URL, true)
	if err != nil {
		f.Fatal(err)
	}
	defer client.Close()
	request := positron.TenantDisplayNameUpdateRequest{Tenant: "00000000-0000-0000-0000-000000000001", DisplayName: "fuzz", ExpectedDisplayGeneration: 1, IdempotencyKey: "00000000-0000-0000-0000-000000000002"}
	f.Fuzz(func(t *testing.T, rawStatus uint16, data []byte) {
		if len(data) > 2048 {
			return
		}
		responseStatus := 400 + int(rawStatus)%200
		mu.Lock()
		status, body, attempts = responseStatus, data, 0
		mu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		var output any
		err := client.Call(ctx, "positron.v1.TenantService/UpdateDisplayName", request, "private-secret", &output)
		mu.Lock()
		calls := attempts
		mu.Unlock()
		if calls != 1 {
			t.Fatalf("expected one attempt, got %d", calls)
		}
		var failure *positron.ClientError
		if !errors.As(err, &failure) {
			t.Fatalf("non-success response lost bounded refusal: %T", err)
		}
		if len(err.Error()) > 160 || strings.Contains(err.Error(), "private-secret") {
			t.Fatal("unsafe error diagnostics")
		}
		for _, known := range []struct {
			status int
			code   string
		}{{401, "authentication_rejected"}, {409, "stale_display_generation"}, {409, "idempotency_conflict"}} {
			if responseStatus == known.status && bytes.Equal(data, []byte(`{"code":"`+known.code+`"}`)) {
				if failure.Code != known.code || failure.RetryClass != "RETRY_CLASS_NEVER" || failure.CompletionState != "COMPLETION_STATE_AMBIGUOUS" {
					t.Fatal("native refusal lost identity or invented certainty")
				}
			}
		}
		if failure.Failure == "Transport" {
			if failure.RetryClass != "RETRY_CLASS_NEVER" || failure.CompletionState != "COMPLETION_STATE_AMBIGUOUS" {
				t.Fatal("transport failure invented certainty")
			}
			return
		}
		if failure.Status != responseStatus || failure.Code != failure.Failure {
			t.Fatal("lost refusal identity")
		}
		if len(data) > 1024 {
			t.Fatal("oversized refusal accepted")
		}
		if failure.CompletionState == "COMPLETION_STATE_AMBIGUOUS" && failure.RetryClass != "RETRY_CLASS_NEVER" {
			t.Fatal("ambiguous failure permits retry")
		}
		if !strings.HasPrefix(failure.Code, "PUBLIC_ERROR_CODE_") {
			allowed := map[int][]string{400: {"invalid_request"}, 401: {"authentication_rejected"}, 409: {"stale_display_generation", "idempotency_conflict"}, 503: {"administration_unavailable"}}
			declared := false
			for _, code := range allowed[responseStatus] {
				declared = declared || failure.Code == code
			}
			if !declared {
				t.Fatalf("undeclared refusal identity: %q", failure.Code)
			}
		}
	})
}
