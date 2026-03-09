package main

import (
	"reflect"
	"testing"

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

	serviceMap := map[string]string{
		"SSH": "/orgs/1/sec_policy/active/services/1",
	}

	got, warnings := buildServiceIncludeEntries("SSH, TCP:445, UDP:5355, Unknown Service", serviceMap)
	if len(warnings) != 1 || warnings[0] != "Unknown Service" {
		t.Fatalf("buildServiceIncludeEntries warnings = %#v, want only Unknown Service", warnings)
	}

	if len(got) != 3 {
		t.Fatalf("buildServiceIncludeEntries returned %d entries, want 3", len(got))
	}

	serviceRef, ok := got[0].(illumio.ServiceRef)
	if !ok || serviceRef.Href != serviceMap["SSH"] {
		t.Fatalf("first include = %#v, want ServiceRef for SSH", got[0])
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
