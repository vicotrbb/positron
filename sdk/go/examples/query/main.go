package main

import (
	"context"
	"fmt"
	positron "github.com/vicotrbb/positron/sdk/go"
	"os"
	"time"
)

func main() {
	client, err := positron.NewClient(os.Getenv("POSITRON_ENDPOINT"), false)
	if err != nil {
		fmt.Fprintln(os.Stderr, "invalid endpoint")
		os.Exit(1)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	major := int64(1)
	result, err := client.CapabilityNegotiate(ctx, positron.CapabilityRequest{ApiMajor: &major}, os.Getenv("POSITRON_BEARER"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "capability request failed")
		os.Exit(1)
	}
	fmt.Println(result.ApiMajor)
}
