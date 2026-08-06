package main

import (
	"strings"
	"testing"
	"time"
)

func TestNormalizeCoverageFindsMissingMonthsAndOverlaps(t *testing.T) {
	t.Parallel()
	coverage := normalizeCoverage(DatasetCoverage{Source: "csv_import", Files: []DatasetFileCoverage{
		{Name: "january.csv", FirstDetected: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), LastDetected: time.Date(2026, 1, 31, 23, 0, 0, 0, time.UTC), Months: []string{"2026-01"}},
		{Name: "march-a.csv", FirstDetected: time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), LastDetected: time.Date(2026, 3, 20, 0, 0, 0, 0, time.UTC), Months: []string{"2026-03"}},
		{Name: "march-b.csv", FirstDetected: time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC), LastDetected: time.Date(2026, 3, 31, 0, 0, 0, 0, time.UTC), Months: []string{"2026-03"}},
	}})
	if len(coverage.MissingMonths) != 1 || coverage.MissingMonths[0] != "2026-02" {
		t.Fatalf("missing months = %#v", coverage.MissingMonths)
	}
	if len(coverage.Overlaps) != 1 || coverage.Overlaps[0].FirstFile != "march-a.csv" || coverage.Overlaps[0].SecondFile != "march-b.csv" {
		t.Fatalf("overlaps = %#v", coverage.Overlaps)
	}
	if len(coverage.Warnings) < 2 {
		t.Fatalf("coverage warnings = %#v", coverage.Warnings)
	}
}

func TestDetailedCSVImportBuildsCoverageAndRelationshipTrends(t *testing.T) {
	t.Parallel()
	header := "Source IP,Destination IP,Port,Protocol,Flows,Src Env,Dst Env,Src App,Dst App,First Detected,Last Detected"
	january := strings.Join([]string{header, "10.0.0.1,10.0.0.2,443,TCP,3,Prod,Shared,Web,API,2026-01-02 01:00:00,2026-01-29 22:00:00"}, "\n")
	march := strings.Join([]string{header, "10.0.0.3,198.51.100.5,445,TCP,7,Prod,External/Unmanaged,Web,External/Unmanaged,2026-03-03 01:00:00,2026-03-28 22:00:00"}, "\n")
	dataset, err := parseCSVAnalyticsInputsDetailed([]csvAnalyticsInput{{Name: "jan.csv", Reader: strings.NewReader(january)}, {Name: "mar.csv", Reader: strings.NewReader(march)}}, "env", "app")
	if err != nil {
		t.Fatalf("parseCSVAnalyticsInputsDetailed: %v", err)
	}
	if len(dataset.Coverage.MissingMonths) != 1 || dataset.Coverage.MissingMonths[0] != "2026-02" {
		t.Fatalf("coverage = %#v", dataset.Coverage)
	}
	if len(dataset.Insights.MonthlyRelationships) != 2 {
		t.Fatalf("monthly relationships = %#v", dataset.Insights.MonthlyRelationships)
	}
	if len(dataset.Insights.MonthlyExternalDestinations) != 1 || dataset.Insights.MonthlyExternalDestinations[0].Destination != "198.51.100.5" {
		t.Fatalf("monthly external destinations = %#v", dataset.Insights.MonthlyExternalDestinations)
	}
}
