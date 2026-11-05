package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	positron "github.com/vicotrbb/positron/sdk/go"
	"os"
	"time"
)

func pointer[T any](value T) *T { return &value }
func require(ok bool) error {
	if !ok {
		return errors.New("conformance outcome differs")
	}
	return nil
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "Go live conformance failed")
		os.Exit(1)
	}
	fmt.Println("Go live conformance passed")
}
func run() error {
	var args struct {
		Endpoint string `json:"endpoint"`
		Bearer   string `json:"bearer"`
		Admin    string `json:"admin"`
	}
	if err := json.NewDecoder(os.Stdin).Decode(&args); err != nil {
		return err
	}
	client, err := positron.NewClient(args.Endpoint, true)
	if err != nil {
		return err
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	capability, err := client.CapabilityNegotiate(ctx, positron.CapabilityRequest{ApiMajor: pointer(int64(1))}, "")
	if err != nil {
		return err
	}
	if err = require(capability.ApiMajor != nil && *capability.ApiMajor == 1); err != nil {
		return err
	}
	query := positron.LogQueryRequest{Pipeline: pointer("pipeline:v1 logs | range query_time 0 100 | project commit_position | limit 2"), Budget: &positron.LogQueryBudget{ScannedBytes: pointer("1048576"), DecodedRecords: pointer("16"), OutputRows: pointer("16"), OutputBytes: pointer("16384"), MemoryBytes: pointer("1048576"), CpuWorkUnits: pointer("16"), WallSeconds: pointer("5"), MaximumTimeRangeNanoseconds: pointer("100")}}
	admitted := func(call func() (positron.LogQueryResponse, error)) (map[string]any, error) {
		for attempt := 0; attempt < 5; attempt++ {
			response, err := call()
			if err == nil {
				data, err := json.Marshal(response)
				if err != nil {
					return nil, err
				}
				return positron.Decode("LogQueryResponse", data)
			}
			var failure *positron.ClientError
			if !errors.As(err, &failure) || failure.Failure != "CapacityUnavailable" {
				return nil, err
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Second):
			}
		}
		return nil, errors.New("admission exhausted")
	}
	first, err := admitted(func() (positron.LogQueryResponse, error) { return client.LogQueryExecute(ctx, query, args.Bearer) })
	if err != nil {
		return err
	}
	tracker, _ := positron.NewBatchTracker("session")
	batches, err := tracker.Filter(first)
	if err != nil || len(batches) != 1 {
		return errors.New("execute differs")
	}
	page, err := admitted(func() (positron.LogQueryResponse, error) {
		return client.LogQuerySession(ctx, positron.LogQuerySessionRequest{Execute: &query, BatchLimit: pointer(int64(1))}, args.Bearer)
	})
	if err != nil {
		return err
	}
	tracker, _ = positron.NewBatchTracker("session")
	if _, err = tracker.Filter(page); err != nil {
		return err
	}
	events := page["events"].([]any)
	terminal := events[len(events)-1].(map[string]any)["terminal"].(map[string]any)
	state, err := positron.TerminalStatus(terminal)
	if err != nil || state != "continued" {
		return errors.New("missing continuation")
	}
	resume := terminal["continuationCursor"].(string)
	second, err := admitted(func() (positron.LogQueryResponse, error) {
		return client.LogQuerySession(ctx, positron.LogQuerySessionRequest{Resume: &resume, BatchLimit: pointer(int64(1))}, args.Bearer)
	})
	if err != nil {
		return err
	}
	if _, err = tracker.Filter(second); err != nil {
		return err
	}
	cursor := events[0].(map[string]any)["header"].(map[string]any)["initialCursor"].(string)
	page, err = admitted(func() (positron.LogQueryResponse, error) {
		return client.LogQuerySession(ctx, positron.LogQuerySessionRequest{Execute: &query, BatchLimit: pointer(int64(1))}, args.Bearer)
	})
	if err != nil {
		return err
	}
	cursor = page["events"].([]any)[0].(map[string]any)["header"].(map[string]any)["initialCursor"].(string)
	cancelled, err := client.LogQueryCancel(ctx, positron.LogQueryCancelRequest{Query: &cursor}, args.Bearer)
	if err != nil {
		return err
	}
	if err = require(cancelled.Cancelled != nil && *cancelled.Cancelled); err != nil {
		return err
	}
	query.Pipeline = pointer("pipeline:v1 logs | range query_time 0 100 | project commit_position | limit all")
	query.Budget.WallSeconds = pointer("60")
	tail, err := admitted(func() (positron.LogQueryResponse, error) {
		return client.LogQuerySession(ctx, positron.LogQuerySessionRequest{Tail: &positron.LogQueryTailRequest{Query: &query}, BatchLimit: pointer(int64(1))}, args.Bearer)
	})
	if err != nil {
		return err
	}
	tracker, _ = positron.NewBatchTracker("tail")
	if _, err = tracker.Filter(tail); err != nil {
		return err
	}
	events = tail["events"].([]any)
	terminal = events[len(events)-1].(map[string]any)["terminal"].(map[string]any)
	cursor = terminal["continuationCursor"].(string)
	if _, err = client.LogQueryCancel(ctx, positron.LogQueryCancelRequest{Tail: &cursor}, args.Bearer); err != nil {
		return err
	}
	query.Budget.WallSeconds = pointer("5")
	_, err = client.LogQueryExecute(ctx, query, "invalid")
	var failure *positron.ClientError
	if !errors.As(err, &failure) || failure.Failure != "AuthenticationRejected" || failure.CompletionState != "COMPLETION_STATE_REJECTED" {
		return errors.New("authentication outcome differs")
	}
	_, err = client.TenantList(ctx, positron.TenantListRequest{}, args.Admin)
	return err
}
