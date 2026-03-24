package illumio

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func TestGetTrafficFlowsDatabaseMetrics(t *testing.T) {
	t.Parallel()

	client := NewClient("https://pce.example.com", "1", "key", "secret")
	client.HTTP.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != "https://pce.example.com/api/v2/orgs/1/traffic_flows/database_metrics" {
			t.Fatalf("unexpected URL %q", req.URL.String())
		}

		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body: io.NopCloser(strings.NewReader(`{
				"flows_days": 35,
				"flows_oldest_day": "2026-02-17",
				"server": {
					"num_flows_days": 35,
					"num_flows_days_limit": 90,
					"flows_oldest_day": "2026-02-17",
					"num_daily_tables": 35,
					"num_weekly_tables": 5
				},
				"updated_at": "2026-03-23T16:20:00Z"
			}`)),
		}, nil
	})

	metrics, err := client.GetTrafficFlowsDatabaseMetrics(context.Background())
	if err != nil {
		t.Fatalf("GetTrafficFlowsDatabaseMetrics() error = %v", err)
	}

	if metrics.Server.NumFlowsDays != 35 {
		t.Fatalf("server.num_flows_days = %d, want 35", metrics.Server.NumFlowsDays)
	}
	if metrics.Server.FlowsOldestDay != "2026-02-17" {
		t.Fatalf("server.flows_oldest_day = %q, want 2026-02-17", metrics.Server.FlowsOldestDay)
	}
	if metrics.UpdatedAt != "2026-03-23T16:20:00Z" {
		t.Fatalf("updated_at = %q, want 2026-03-23T16:20:00Z", metrics.UpdatedAt)
	}
}
