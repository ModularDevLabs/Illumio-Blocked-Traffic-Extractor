package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestTemplateToConfigPreservesTrafficScopeAndServiceExclusions(t *testing.T) {
	t.Parallel()
	template := ReportTemplate{
		Name: "All Traffic", ProfileName: "prod", Services: "HTTPS, TCP:8443",
		ExcludeServices: "TCP:9300, DNS", TrafficScope: trafficScopeAll,
	}
	cfg := templateToConfig(template, "run-123", time.Date(2026, time.September, 2, 12, 0, 0, 0, time.UTC))
	if cfg.Services != template.Services || cfg.ExcludeServices != template.ExcludeServices {
		t.Fatalf("service filters = include %q exclude %q", cfg.Services, cfg.ExcludeServices)
	}
	if cfg.TrafficScope != trafficScopeAll {
		t.Fatalf("traffic scope = %q, want %q", cfg.TrafficScope, trafficScopeAll)
	}
}

func TestPartialRunRetainsArtifactWithoutSuccessMetrics(t *testing.T) {
	artifact := filepath.Join(t.TempDir(), "traffic_PARTIAL.csv")
	if err := os.WriteFile(artifact, []byte("header\npartial\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest := extractionManifestPath(artifact)
	if err := os.WriteFile(manifest, []byte(`{"partial":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	manager := &AutomationManager{storePath: filepath.Join(t.TempDir(), "automation.json"), data: automationStoreData{
		Version: automationStoreVersion,
		Templates: map[string]ReportTemplate{"tpl": {
			ID: "tpl", Name: "Scheduled Traffic",
		}},
		Destinations: map[string]DeliveryDestination{},
		Runs: []AutomationRun{{
			ID: "run-partial", TemplateID: "tpl", Status: "running",
			Metrics: RunMetrics{TotalFlows: 999, PreviousCompletedRunID: "must-be-cleared"},
		}},
	}}
	manager.finishPartialRun(context.Background(), "run-partial", artifact, errors.New("2 query chunks did not complete"))

	run := manager.data.Runs[0]
	if run.Status != "partial" || run.ArtifactPath != artifact || run.Error != "2 query chunks did not complete" {
		t.Fatalf("partial run = %#v", run)
	}
	if !reflect.DeepEqual(run.Metrics, RunMetrics{}) {
		t.Fatalf("partial metrics must not be used as a complete baseline: %#v", run.Metrics)
	}
	if run.DeliverySkipped != "successful delivery skipped because extraction output is partial" {
		t.Fatalf("delivery skip reason = %q", run.DeliverySkipped)
	}
	if !reflect.DeepEqual(run.AdditionalArtifactPaths, []string{manifest}) {
		t.Fatalf("partial companion artifacts = %#v, want coverage manifest", run.AdditionalArtifactPaths)
	}
}

func TestReportGenerationFailureRetainsCSVArtifact(t *testing.T) {
	artifact := filepath.Join(t.TempDir(), "traffic.csv")
	if err := os.WriteFile(artifact, []byte("header\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest := extractionManifestPath(artifact)
	if err := os.WriteFile(manifest, []byte(`{"partial":false}`), 0o600); err != nil {
		t.Fatal(err)
	}
	manager := &AutomationManager{storePath: filepath.Join(t.TempDir(), "automation.json"), data: automationStoreData{
		Version:      automationStoreVersion,
		Templates:    map[string]ReportTemplate{"tpl": {ID: "tpl", Name: "Report"}},
		Destinations: map[string]DeliveryDestination{},
		Runs:         []AutomationRun{{ID: "run-report-failed", TemplateID: "tpl", Status: "running", Metrics: RunMetrics{TotalFlows: 42}}},
	}}
	manager.finishFailedRunWithArtifact(context.Background(), "run-report-failed", artifact, errors.New("render executive PDF"))
	run := manager.data.Runs[0]
	if run.Status != "failed" || run.ArtifactPath != artifact || run.Error != "render executive PDF" {
		t.Fatalf("failed report run = %#v", run)
	}
	if !reflect.DeepEqual(run.Metrics, RunMetrics{}) || !reflect.DeepEqual(run.AdditionalArtifactPaths, []string{manifest}) {
		t.Fatalf("failed report run must not publish success metrics/reports: %#v", run)
	}
}

func TestPartialRunIsNotUsedAsMetricsBaseline(t *testing.T) {
	t.Parallel()
	manager := &AutomationManager{data: automationStoreData{Runs: []AutomationRun{
		{ID: "partial", TemplateID: "tpl", Status: "partial", Metrics: RunMetrics{TotalFlows: 1000}},
		{ID: "complete", TemplateID: "tpl", Status: "completed", Metrics: RunMetrics{TotalFlows: 10}},
	}}}
	metrics := manager.calculateMetrics("tpl", "new", []PortProtocolSummary{{Protocol: "TCP", Port: 443, FlowCount: 15}}, AnalyticsInsights{})
	if metrics.PreviousCompletedRunID != "complete" || metrics.FlowChangePercent != 50 {
		t.Fatalf("metrics used an incomplete baseline: %#v", metrics)
	}
}

func TestRetentionIncludesPartialAndFailedRunsAndRemovesTrackedManifests(t *testing.T) {
	t.Parallel()
	output := t.TempDir()
	newestPartial := filepath.Join(output, "newest_PARTIAL.csv")
	newestManifest := extractionManifestPath(newestPartial)
	oldFailed := filepath.Join(output, "old.csv")
	oldManifest := extractionManifestPath(oldFailed)
	for _, path := range []string{newestPartial, newestManifest, oldFailed, oldManifest} {
		if err := os.WriteFile(path, []byte("data"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	manager := &AutomationManager{data: automationStoreData{Runs: []AutomationRun{
		{ID: "new", TemplateID: "tpl", Status: "partial", ArtifactPath: newestPartial, AdditionalArtifactPaths: []string{newestManifest}},
		{ID: "old", TemplateID: "tpl", Status: "failed", ArtifactPath: oldFailed, AdditionalArtifactPaths: []string{oldManifest}},
	}}}
	manager.applyRetention(ReportTemplate{ID: "tpl", SavePath: output, RetentionCount: 1})
	for _, path := range []string{newestPartial, newestManifest} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("newest retained artifact %s should remain: %v", path, err)
		}
	}
	for _, path := range []string{oldFailed, oldManifest} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("expired retained artifact %s should be removed, stat error = %v", path, err)
		}
	}
}

func TestPartialAutomationArtifactAndCoverageAreDownloadable(t *testing.T) {
	artifact := filepath.Join(t.TempDir(), "traffic_PARTIAL.csv")
	want := "header\npartial\n"
	if err := os.WriteFile(artifact, []byte(want), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest := extractionManifestPath(artifact)
	manifestData := `{"partial":true}`
	if err := os.WriteFile(manifest, []byte(manifestData), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := automation
	automation = &AutomationManager{data: automationStoreData{
		Templates: map[string]ReportTemplate{}, Destinations: map[string]DeliveryDestination{},
		Runs: []AutomationRun{{ID: "run-partial", Status: "partial", ArtifactPath: artifact, AdditionalArtifactPaths: []string{manifest}, Error: "incomplete extraction"}},
	}}
	t.Cleanup(func() { automation = previous })

	recorder := httptest.NewRecorder()
	handleAutomationRunArtifact(recorder, httptest.NewRequest(http.MethodGet, "/api/automation/runs/artifact?id=run-partial&kind=csv", nil))
	if recorder.Code != http.StatusOK || recorder.Body.String() != want {
		t.Fatalf("partial artifact response = %d %q", recorder.Code, recorder.Body.String())
	}
	coverageRecorder := httptest.NewRecorder()
	handleAutomationRunArtifact(coverageRecorder, httptest.NewRequest(http.MethodGet, "/api/automation/runs/artifact?id=run-partial&kind=coverage", nil))
	if coverageRecorder.Code != http.StatusOK || coverageRecorder.Body.String() != manifestData {
		t.Fatalf("coverage artifact response = %d %q", coverageRecorder.Code, coverageRecorder.Body.String())
	}
	if got := coverageRecorder.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
		t.Fatalf("coverage Content-Type = %q", got)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	run, err := waitForAutomationRun(ctx, "run-partial")
	if err == nil || run.Status != "partial" || !strings.Contains(err.Error(), "incomplete extraction") {
		t.Fatalf("partial terminal result = run %#v, err %v", run, err)
	}
}

func TestBuildEmailMessageRejectsHeaderInjection(t *testing.T) {
	t.Parallel()
	_, err := buildEmailMessage(
		DeliveryDestination{SMTPFrom: "sender@example.com", SMTPTo: []string{"recipient@example.com"}},
		deliveryMessage{Title: "Report\r\nBcc: attacker@example.com", Text: "body"},
	)
	if err == nil || !strings.Contains(err.Error(), "single-line") {
		t.Fatalf("email header injection error = %v", err)
	}
}

func TestNormalizeSFTPRemoteDirectoryRejectsTraversal(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"", ".", "../reports", "reports/../../secrets", "reports\\windows"} {
		if _, err := normalizeSFTPRemoteDirectory(value); err == nil {
			t.Fatalf("normalizeSFTPRemoteDirectory(%q) should fail", value)
		}
	}
	if got, err := normalizeSFTPRemoteDirectory("/reports/monthly"); err != nil || got != "/reports/monthly" {
		t.Fatalf("normalized SFTP directory = %q, %v", got, err)
	}
}
