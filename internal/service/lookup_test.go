package service

import (
	"errors"
	"net/netip"
	"testing"

	"ip-intelligence-service/internal/classifier"
	"ip-intelligence-service/internal/geoip"
	"ip-intelligence-service/internal/model"
)

type fakeGeoIP struct {
	result geoip.Result
	err    error
}

type fakeThreat struct {
	result    model.ThreatInfo
	readiness classifier.ThreatReadiness
}

func (f fakeThreat) Ready() classifier.ThreatReadiness { return f.readiness }

func (f fakeThreat) Classify(netip.Addr, uint32) model.ThreatInfo { return f.result }

func (f fakeGeoIP) Ready() geoip.Readiness {
	return geoip.Readiness{CountryDB: f.err == nil, ASNDB: f.err == nil}
}

func (f fakeGeoIP) Lookup(netip.Addr) (geoip.Result, error) {
	return f.result, f.err
}

func TestLookup(t *testing.T) {
	geo := fakeGeoIP{result: geoip.Result{
		Country:   model.CountryInfo{Code: "CN", Status: model.StatusKnown, MainlandChina: true, Source: "DBIP_LITE"},
		ASN:       37963,
		ASNName:   "Alibaba",
		ASNStatus: model.StatusKnown,
		ASNSource: "DBIP_LITE",
		Agreement: model.AgreementInfo{Country: model.AgreementAgree, ASN: model.AgreementDisagree},
	}}
	lookup := New(geo, classifier.New(map[uint32]string{37963: "ALIYUN"}), fakeThreat{
		readiness: classifier.ThreatReadiness{Loaded: true},
		result: model.ThreatInfo{
			Status:     model.StatusKnown,
			Level:      model.ThreatLevelHigh,
			Confidence: model.ThreatConfidenceHigh,
			Listed:     true,
			Categories: []string{classifier.ThreatCategoryCybercrimeNetwork},
			Matches:    []model.ThreatMatch{{Source: "SPAMHAUS_ASN_DROP", Kind: "ASN", Value: "AS37963"}},
		},
	})

	profile, err := lookup.Lookup("::ffff:223.5.5.5")
	if err != nil {
		t.Fatal(err)
	}
	if profile.IP != "223.5.5.5" || !profile.Country.MainlandChina {
		t.Fatalf("unexpected profile: %+v", profile)
	}
	if profile.Network.Type != model.NetworkHosting || profile.Cloud.Provider != "ALIYUN" {
		t.Fatalf("unexpected cloud result: %+v", profile)
	}
	if profile.Network.Status != model.StatusKnown || profile.Cloud.Confidence != model.ConfidenceMedium {
		t.Fatalf("unexpected status result: %+v", profile)
	}
	if profile.Scope.Type != model.ScopePublic || !profile.Scope.GloballyReachable {
		t.Fatalf("unexpected IP scope: %+v", profile.Scope)
	}
	if profile.Agreement.ASN != model.AgreementDisagree {
		t.Fatalf("unexpected agreement: %+v", profile.Agreement)
	}
	if !profile.Threat.Listed || profile.Threat.Level != model.ThreatLevelHigh {
		t.Fatalf("unexpected threat result: %+v", profile.Threat)
	}
}

func TestLookupRejectsInvalidIP(t *testing.T) {
	lookup := New(fakeGeoIP{}, classifier.New(nil), fakeThreat{})
	_, err := lookup.Lookup("not-an-ip")
	if !errors.Is(err, ErrInvalidIP) {
		t.Fatalf("got %v, want ErrInvalidIP", err)
	}
}

func TestLookupPreservesUnknownStatus(t *testing.T) {
	lookup := New(fakeGeoIP{result: geoip.Result{
		Country:   model.CountryInfo{Status: model.StatusUnknown},
		ASNStatus: model.StatusUnknown,
		Agreement: model.AgreementInfo{Country: model.AgreementInsufficient, ASN: model.AgreementInsufficient},
	}}, classifier.New(nil), fakeThreat{result: model.ThreatInfo{
		Status:     model.StatusUnknown,
		Level:      model.ThreatLevelUnknown,
		Confidence: model.ThreatConfidenceUnknown,
		Categories: []string{},
		Matches:    []model.ThreatMatch{},
	}})

	profile, err := lookup.Lookup("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if profile.Country.Status != model.StatusUnknown || profile.Network.Status != model.StatusUnknown {
		t.Fatalf("unknown status was lost: %+v", profile)
	}
	if profile.Cloud.Cloud || profile.Cloud.Confidence != model.ConfidenceLow || profile.Cloud.Source != "NONE" {
		t.Fatalf("unexpected unknown cloud result: %+v", profile.Cloud)
	}
	if profile.Scope.Type != model.ScopeLoopback || profile.Scope.GloballyReachable {
		t.Fatalf("unexpected loopback scope: %+v", profile.Scope)
	}
	if profile.Threat.Status != model.StatusUnknown {
		t.Fatalf("unexpected threat status: %+v", profile.Threat)
	}
}
