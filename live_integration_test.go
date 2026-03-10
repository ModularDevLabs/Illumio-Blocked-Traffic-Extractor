package main

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"illumio-traffic-tool-v2/illumio"
)

func loadLiveTestProfile(t *testing.T) PCEProfile {
	t.Helper()

	if os.Getenv("RUN_LIVE_PCE_TESTS") != "1" {
		t.Skip("set RUN_LIVE_PCE_TESTS=1 to run live PCE smoke tests")
	}

	profilePath := os.Getenv("PCE_PROFILE_PATH")
	if strings.TrimSpace(profilePath) == "" {
		profilePath = "pce_profiles.json"
	}

	data, err := os.ReadFile(profilePath)
	if err != nil {
		t.Fatalf("read profile file %q: %v", profilePath, err)
	}

	var profiles map[string]PCEProfile
	if err := json.Unmarshal(data, &profiles); err != nil {
		t.Fatalf("decode profile file %q: %v", profilePath, err)
	}

	if len(profiles) == 0 {
		t.Fatalf("no profiles found in %q", profilePath)
	}

	if profileName := strings.TrimSpace(os.Getenv("PCE_PROFILE_NAME")); profileName != "" {
		profile, ok := profiles[profileName]
		if !ok {
			t.Fatalf("profile %q not found in %q", profileName, profilePath)
		}
		return profile
	}

	for _, profile := range profiles {
		return profile
	}

	t.Fatalf("no usable profiles found in %q", profilePath)
	return PCEProfile{}
}

func TestLivePCEConnectionAndDirectServiceQuery(t *testing.T) {
	profile := loadLiveTestProfile(t)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	client := illumio.NewClient(profile.PCEURL, profile.OrgID, profile.APIKey, profile.APISecret)

	labels, err := client.GetLabels(ctx)
	if err != nil {
		t.Fatalf("GetLabels failed: %v", err)
	}
	if len(labels) == 0 {
		t.Fatal("GetLabels returned no labels")
	}

	services, err := client.GetServices(ctx)
	if err != nil {
		t.Fatalf("GetServices failed: %v", err)
	}
	if len(services) == 0 {
		t.Fatal("GetServices returned no services")
	}

	var namedServiceIncludes []interface{}
	for _, service := range services {
		for _, port := range service.ServicePorts {
			if port.Port > 0 && (port.Proto == 6 || port.Proto == 17) {
				namedServiceIncludes = serviceEntriesFromService(illumio.Service{
					Name:         service.Name,
					ServicePorts: []illumio.ServicePort{port},
				})
				break
			}
		}
		if len(namedServiceIncludes) > 0 {
			break
		}
	}
	if len(namedServiceIncludes) == 0 {
		t.Fatal("GetServices returned no Explorer-compatible named service entries")
	}

	now := time.Now().UTC()
	serviceIncludes := append([]interface{}{}, namedServiceIncludes[0])
	serviceIncludes = append(serviceIncludes,
		illumio.PortProtoService{Port: 445, Proto: 6},
		illumio.PortProtoService{Port: 5355, Proto: 17},
	)
	req := illumio.AsyncQueryRequest{
		Sources: illumio.IncludeExclude{
			Include: [][]illumio.LabelRef{},
			Exclude: []illumio.LabelRef{},
		},
		Destinations: illumio.IncludeExclude{
			Include: [][]illumio.LabelRef{},
			Exclude: []illumio.LabelRef{},
		},
		Services: illumio.ServiceFilter{
			Include: serviceIncludes,
			Exclude: []interface{}{},
		},
		StartDate:  now.Add(-24 * time.Hour).Format("2006-01-02T00:00:00Z"),
		EndDate:    now.Format("2006-01-02T00:00:00Z"),
		MaxResults: 200000,
	}

	flows, err := client.FetchDayOfTraffic(ctx, req, func(string) {})
	if err != nil {
		t.Fatalf("FetchDayOfTraffic with named and direct services failed: %v", err)
	}

	if flows == nil {
		t.Fatal("FetchDayOfTraffic returned nil flow slice")
	}
}
