package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"ip-intelligence-service/internal/geoip"
	"ip-intelligence-service/internal/model"
	"ip-intelligence-service/internal/service"
)

type fakeService struct {
	readiness service.Readiness
	profile   model.IPProfile
	err       error
}

func (f fakeService) Ready() service.Readiness { return f.readiness }

func (f fakeService) Lookup(string) (model.IPProfile, error) { return f.profile, f.err }

func TestHealth(t *testing.T) {
	recorder := httptest.NewRecorder()
	NewHandler(fakeService{}).Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/health", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("got status %d", recorder.Code)
	}
}

func TestReadyUnavailable(t *testing.T) {
	recorder := httptest.NewRecorder()
	NewHandler(fakeService{}).Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/ready", nil))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("got status %d", recorder.Code)
	}
}

func TestInvalidIP(t *testing.T) {
	recorder := httptest.NewRecorder()
	handler := NewHandler(fakeService{
		readiness: service.Readiness{CountryDB: true, ASNDB: true, ThreatData: true},
		err:       service.ErrInvalidIP,
	})
	handler.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v1/lookup/nope", nil))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("got status %d", recorder.Code)
	}
	var response errorResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Code != "INVALID_IP" {
		t.Fatalf("got response %+v", response)
	}
}

func TestLookupNotReady(t *testing.T) {
	recorder := httptest.NewRecorder()
	handler := NewHandler(fakeService{err: geoip.ErrNotReady})
	handler.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v1/lookup/8.8.8.8", nil))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("got status %d", recorder.Code)
	}
}

func TestMetricsCountsUnknownAndCloudSource(t *testing.T) {
	handler := NewHandler(fakeService{profile: model.IPProfile{
		Scope:   model.ScopeInfo{Type: model.ScopeLoopback, GloballyReachable: false},
		Country: model.CountryInfo{Status: model.StatusUnknown},
		Network: model.NetworkInfo{Status: model.StatusUnknown},
		Cloud:   model.CloudInfo{Cloud: false, Confidence: model.ConfidenceLow, Source: "NONE"},
		Threat: model.ThreatInfo{
			Status:     model.StatusKnown,
			Level:      model.ThreatLevelNone,
			Confidence: model.ThreatConfidenceNone,
			Categories: []string{},
			Matches:    []model.ThreatMatch{},
		},
		Agreement: model.AgreementInfo{Country: model.AgreementDisagree, ASN: model.AgreementDisagree},
	}})
	handler.Routes().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/v1/lookup/127.0.0.1", nil))
	recorder := httptest.NewRecorder()
	handler.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("got status %d", recorder.Code)
	}
	for _, expected := range []string{
		"ip_intelligence_lookups_total 1",
		"ip_intelligence_country_unknown_total 1",
		"ip_intelligence_asn_unknown_total 1",
		"ip_intelligence_cloud_no_match_total 1",
		"ip_intelligence_country_source_conflicts_total 1",
		"ip_intelligence_asn_source_conflicts_total 1",
		"ip_intelligence_non_public_total 1",
		"ip_intelligence_threat_not_listed_total 1",
	} {
		if !strings.Contains(recorder.Body.String(), expected) {
			t.Fatalf("metrics missing %q:\n%s", expected, recorder.Body.String())
		}
	}
}

func TestMetricsCountsThreatMatches(t *testing.T) {
	handler := NewHandler(fakeService{profile: model.IPProfile{
		Threat: model.ThreatInfo{
			Status:     model.StatusKnown,
			Listed:     true,
			Level:      model.ThreatLevelHigh,
			Confidence: model.ThreatConfidenceHigh,
			Matches: []model.ThreatMatch{
				{Kind: "CIDR"},
				{Kind: "ASN"},
			},
		},
	}})
	handler.Routes().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/v1/lookup/1.2.3.4", nil))
	recorder := httptest.NewRecorder()
	handler.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	for _, expected := range []string{
		"ip_intelligence_threat_cidr_matches_total 1",
		"ip_intelligence_threat_asn_matches_total 1",
	} {
		if !strings.Contains(recorder.Body.String(), expected) {
			t.Fatalf("metrics missing %q:\n%s", expected, recorder.Body.String())
		}
	}
}
