package main

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"illumio-traffic-tool-v2/illumio"
)

func TestParseDirectService(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		input  string
		want   illumio.PortProtoService
		wantOK bool
	}{
		{
			name:   "tcp single port",
			input:  "TCP:445",
			want:   illumio.PortProtoService{Port: 445, Proto: 6},
			wantOK: true,
		},
		{
			name:   "udp single port with spaces",
			input:  " UDP : 5355 ",
			want:   illumio.PortProtoService{Port: 5355, Proto: 17},
			wantOK: true,
		},
		{
			name:   "numeric proto range",
			input:  "47:1024-2048",
			want:   illumio.PortProtoService{Port: 1024, ToPort: 2048, Proto: 47},
			wantOK: true,
		},
		{
			name:   "igmp proto",
			input:  "IGMP:2",
			want:   illumio.PortProtoService{Port: 2, Proto: 2},
			wantOK: true,
		},
		{
			name:   "missing port",
			input:  "TCP:",
			wantOK: false,
		},
		{
			name:   "invalid proto",
			input:  "BOGUS:445",
			wantOK: false,
		},
		{
			name:   "invalid range",
			input:  "TCP:200-100",
			wantOK: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, ok := parseDirectService(tt.input)
			if ok != tt.wantOK {
				t.Fatalf("parseDirectService(%q) ok = %v, want %v", tt.input, ok, tt.wantOK)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("parseDirectService(%q) = %#v, want %#v", tt.input, got, tt.want)
			}
		})
	}
}

func TestBuildServiceIncludeEntries(t *testing.T) {
	t.Parallel()

	serviceMap := map[string][]interface{}{
		"SSH": {
			illumio.PortProtoService{Port: 22, Proto: 6},
		},
	}

	got, warnings := buildServiceIncludeEntries("SSH, TCP:445, UDP:5355, Unknown Service", serviceMap)
	if len(warnings) != 1 || warnings[0] != "Unknown Service" {
		t.Fatalf("buildServiceIncludeEntries warnings = %#v, want only Unknown Service", warnings)
	}

	if len(got) != 3 {
		t.Fatalf("buildServiceIncludeEntries returned %d entries, want 3", len(got))
	}

	serviceRef, ok := got[0].(illumio.PortProtoService)
	if !ok || serviceRef != (illumio.PortProtoService{Port: 22, Proto: 6}) {
		t.Fatalf("first include = %#v, want expanded service entry for SSH", got[0])
	}

	tcpRef, ok := got[1].(illumio.PortProtoService)
	if !ok || tcpRef != (illumio.PortProtoService{Port: 445, Proto: 6}) {
		t.Fatalf("second include = %#v, want TCP:445", got[1])
	}

	udpRef, ok := got[2].(illumio.PortProtoService)
	if !ok || udpRef != (illumio.PortProtoService{Port: 5355, Proto: 17}) {
		t.Fatalf("third include = %#v, want UDP:5355", got[2])
	}
}

func TestServiceEntriesFromService(t *testing.T) {
	t.Parallel()

	icmpType := 8
	icmpCode := 0
	service := illumio.Service{
		Name: "Complex Service",
		ServicePorts: []illumio.ServicePort{
			{Port: 443, Proto: 6},
			{Proto: 1, ICMPType: &icmpType, ICMPCode: &icmpCode},
		},
	}

	got := serviceEntriesFromService(service)
	if len(got) != 2 {
		t.Fatalf("serviceEntriesFromService returned %d entries, want 2", len(got))
	}

	first, ok := got[0].(illumio.PortProtoService)
	if !ok || first.Port != 443 || first.Proto != 6 {
		t.Fatalf("first expanded entry = %#v", got[0])
	}

	second, ok := got[1].(illumio.PortProtoService)
	if !ok || second.Proto != 1 || second.ICMPType == nil || *second.ICMPType != icmpType {
		t.Fatalf("second expanded entry = %#v", got[1])
	}
}

func TestParseSelectorRejectsUnknownNonIP(t *testing.T) {
	t.Parallel()

	_, ok := parseSelector("A-RXCONNECT", map[string]string{}, map[string]string{}, map[string]string{}, map[string]string{}, map[string]string{}, map[string]string{})
	if ok {
		t.Fatal("parseSelector should reject unknown non-IP tokens")
	}

	ref, ok := parseSelector("10.10.10.10", map[string]string{}, map[string]string{}, map[string]string{}, map[string]string{}, map[string]string{}, map[string]string{})
	if !ok {
		t.Fatal("parseSelector should accept valid IP addresses")
	}
	if ref.IPAddress != "10.10.10.10" {
		t.Fatalf("parseSelector returned %#v, want IPAddress 10.10.10.10", ref)
	}
}

func TestExtractionDateRange(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.March, 10, 12, 0, 0, 0, time.UTC)

	t.Run("explicit inclusive range", func(t *testing.T) {
		t.Parallel()

		cfg := Config{StartDate: "2026-02-01", EndDate: "2026-02-28", Days: 90}
		start, end, days, err := extractionDateRange(cfg, now)
		if err != nil {
			t.Fatalf("extractionDateRange returned error: %v", err)
		}
		if got, want := start.Format("2006-01-02"), "2026-02-01"; got != want {
			t.Fatalf("start = %s, want %s", got, want)
		}
		if got, want := end.Format("2006-01-02"), "2026-02-28"; got != want {
			t.Fatalf("end = %s, want %s", got, want)
		}
		if days != 28 {
			t.Fatalf("days = %d, want 28", days)
		}
	})

	t.Run("trailing days defaults to yesterday", func(t *testing.T) {
		t.Parallel()

		cfg := Config{Days: 7}
		start, end, days, err := extractionDateRange(cfg, now)
		if err != nil {
			t.Fatalf("extractionDateRange returned error: %v", err)
		}
		if got, want := end.Format("2006-01-02"), "2026-03-09"; got != want {
			t.Fatalf("end = %s, want %s", got, want)
		}
		if got, want := start.Format("2006-01-02"), "2026-03-03"; got != want {
			t.Fatalf("start = %s, want %s", got, want)
		}
		if days != 7 {
			t.Fatalf("days = %d, want 7", days)
		}
	})

	t.Run("requires both explicit dates", func(t *testing.T) {
		t.Parallel()

		_, _, _, err := extractionDateRange(Config{StartDate: "2026-02-01"}, now)
		if err == nil {
			t.Fatal("expected error when only one explicit date is provided")
		}
	})
}

func TestMonthlyPortProtocolFromRecordsTracksActiveConnectionsAcrossMonths(t *testing.T) {
	t.Parallel()

	records := []AnalyticsRecord{
		{
			Protocol:  "TCP",
			Port:      5985,
			Month:     "2026-01",
			FlowCount: 90,
			FirstSeen: time.Date(2026, time.January, 15, 0, 0, 0, 0, time.UTC),
			LastSeen:  time.Date(2026, time.March, 3, 0, 0, 0, 0, time.UTC),
		},
	}

	got := monthlyPortProtocolFromRecords(records)
	if len(got) != 3 {
		t.Fatalf("monthlyPortProtocolFromRecords returned %d rows, want 3", len(got))
	}

	byMonth := map[string]MonthlyPortProtocolSummary{}
	for _, row := range got {
		byMonth[row.Month] = row
	}

	if byMonth["2026-01"].FlowCount != 90 || byMonth["2026-01"].UniqueConnections != 1 || byMonth["2026-01"].ActiveConnections != 1 {
		t.Fatalf("january row = %#v, want flow 90 unique 1 active 1", byMonth["2026-01"])
	}
	if byMonth["2026-02"].FlowCount != 0 || byMonth["2026-02"].UniqueConnections != 0 || byMonth["2026-02"].ActiveConnections != 1 {
		t.Fatalf("february row = %#v, want flow 0 unique 0 active 1", byMonth["2026-02"])
	}
	if byMonth["2026-03"].FlowCount != 0 || byMonth["2026-03"].UniqueConnections != 0 || byMonth["2026-03"].ActiveConnections != 1 {
		t.Fatalf("march row = %#v, want flow 0 unique 0 active 1", byMonth["2026-03"])
	}
}

func TestSameOriginRequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		host    string
		origin  string
		referer string
		want    bool
	}{
		{name: "no headers allowed", host: "localhost:8080", want: true},
		{name: "matching origin allowed", host: "localhost:8080", origin: "http://localhost:8080", want: true},
		{name: "matching referer allowed", host: "localhost:8080", referer: "http://localhost:8080/summary", want: true},
		{name: "mismatched origin rejected", host: "localhost:8080", origin: "http://evil.example", want: false},
		{name: "mismatched referer rejected", host: "localhost:8080", referer: "http://evil.example/form", want: false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodPost, "http://"+tt.host+"/api/start", nil)
			req.Host = tt.host
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			if tt.referer != "" {
				req.Header.Set("Referer", tt.referer)
			}

			if got := sameOriginRequest(req); got != tt.want {
				t.Fatalf("sameOriginRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}
