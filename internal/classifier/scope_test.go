package classifier

import (
	"net/netip"
	"testing"

	"ip-intelligence-service/internal/model"
)

func TestClassifyScope(t *testing.T) {
	tests := []struct {
		ip        string
		want      model.IPScopeType
		reachable bool
	}{
		{"8.8.8.8", model.ScopePublic, true},
		{"10.0.0.1", model.ScopePrivate, false},
		{"100.64.0.1", model.ScopeCGNAT, false},
		{"127.0.0.1", model.ScopeLoopback, false},
		{"169.254.1.1", model.ScopeLinkLocal, false},
		{"192.0.2.1", model.ScopeDocumentation, false},
		{"198.18.0.1", model.ScopeBenchmark, false},
		{"255.255.255.255", model.ScopeBroadcast, false},
		{"::", model.ScopeUnspecified, false},
		{"fc00::1", model.ScopePrivate, false},
		{"fe80::1", model.ScopeLinkLocal, false},
		{"2001:db8::1", model.ScopeDocumentation, false},
		{"2001:4860:4860::8888", model.ScopePublic, true},
	}
	for _, test := range tests {
		t.Run(test.ip, func(t *testing.T) {
			got := ClassifyScope(netip.MustParseAddr(test.ip))
			if got.Type != test.want || got.GloballyReachable != test.reachable {
				t.Fatalf("got %+v, want type=%s reachable=%t", got, test.want, test.reachable)
			}
		})
	}
}
