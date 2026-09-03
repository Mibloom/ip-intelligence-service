package classifier

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"ip-intelligence-service/internal/model"
)

func TestThreatClassifiesCIDRAndASN(t *testing.T) {
	dataset := ThreatDataset{
		GeneratedAt: "2026-09-03T08:00:00Z",
		UpdatedAt:   "2026-09-03T07:00:00Z",
		Attribution: "(c) 2026 The Spamhaus Project SLU",
		Terms:       "https://www.spamhaus.org/drop/terms/",
		Sources: []ThreatSource{{
			ID: "SPAMHAUS_DROP_V4", Name: "Spamhaus DROP IPv4", URL: "https://example.test/drop", UpdatedAt: "2026-09-03T07:00:00Z", Records: 1,
		}},
		Prefixes: []ThreatPrefixRule{{Prefix: "1.10.16.0/20", Source: "SPAMHAUS_DROP_V4", References: []string{"SBL256894"}}},
		ASNs:     []ThreatASNRule{{ASN: 64512, Source: "SPAMHAUS_ASN_DROP"}},
	}
	path := filepath.Join(t.TempDir(), "threat.json")
	data, err := json.Marshal(dataset)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}

	threat, err := LoadThreat(path)
	if err != nil {
		t.Fatal(err)
	}
	result := threat.Classify(netip.MustParseAddr("1.10.20.1"), 64512)
	if !result.Listed || result.Status != model.StatusKnown || result.Level != model.ThreatLevelHigh || len(result.Matches) != 2 {
		t.Fatalf("unexpected threat result: %+v", result)
	}
	if result.Matches[0].Kind != "CIDR" || len(result.Matches[0].References) != 1 || result.Matches[0].References[0] != "SBL256894" || result.Matches[1].Kind != "ASN" {
		t.Fatalf("unexpected matches: %+v", result.Matches)
	}
}

func TestThreatNoMatchDoesNotClaimSafety(t *testing.T) {
	dataset := ThreatDataset{
		GeneratedAt: "2026-09-03T08:00:00Z",
		UpdatedAt:   "2026-09-03T07:00:00Z",
		Sources: []ThreatSource{{
			ID: "SPAMHAUS_DROP_V4", Name: "Spamhaus DROP IPv4", URL: "https://example.test/drop", UpdatedAt: "2026-09-03T07:00:00Z", Records: 1,
		}},
		Prefixes: []ThreatPrefixRule{{Prefix: "1.10.16.0/20", Source: "SPAMHAUS_DROP_V4"}},
	}
	path := filepath.Join(t.TempDir(), "threat.json")
	data, _ := json.Marshal(dataset)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	threat, err := LoadThreat(path)
	if err != nil {
		t.Fatal(err)
	}
	result := threat.Classify(netip.MustParseAddr("8.8.8.8"), 15169)
	if result.Listed || result.Status != model.StatusKnown || result.Level != model.ThreatLevelNone || result.Confidence != model.ThreatConfidenceNone {
		t.Fatalf("unexpected non-match result: %+v", result)
	}
}

func TestThreatMissingDatasetIsUnknown(t *testing.T) {
	threat, err := LoadThreat(filepath.Join(t.TempDir(), "missing.json"))
	if err != nil {
		t.Fatal(err)
	}
	result := threat.Classify(netip.MustParseAddr("8.8.8.8"), 15169)
	if result.Status != model.StatusUnknown || result.Level != model.ThreatLevelUnknown || result.Confidence != model.ThreatConfidenceUnknown {
		t.Fatalf("unexpected unavailable result: %+v", result)
	}
}
