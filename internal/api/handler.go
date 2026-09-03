package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync/atomic"

	"ip-intelligence-service/internal/geoip"
	"ip-intelligence-service/internal/model"
	"ip-intelligence-service/internal/service"
)

type LookupService interface {
	Ready() service.Readiness
	Lookup(string) (model.IPProfile, error)
}

type Handler struct {
	service LookupService
	metrics metrics
}

type metrics struct {
	lookups         uint64
	invalid         uint64
	failures        uint64
	countryUnknown  uint64
	asnUnknown      uint64
	cloudCIDR       uint64
	cloudASN        uint64
	cloudNoMatch    uint64
	countryConflict uint64
	asnConflict     uint64
	nonPublic       uint64
	threatCIDR      uint64
	threatASN       uint64
	threatNotListed uint64
	threatUnknown   uint64
}

type errorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func NewHandler(service LookupService) *Handler {
	return &Handler{service: service}
}

func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", h.health)
	mux.HandleFunc("/ready", h.ready)
	mux.HandleFunc("/metrics", h.writeMetrics)
	mux.HandleFunc("/v1/lookup/", h.lookup)
	mux.HandleFunc("/v1/lookup", h.lookupWithoutIP)
	return recoverPanic(mux)
}

func (h *Handler) health(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "UP"})
}

func (h *Handler) ready(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	ready := h.service.Ready()
	status := http.StatusOK
	state := "READY"
	if !ready.Ready() {
		status = http.StatusServiceUnavailable
		state = "NOT_READY"
	} else if !ready.ThreatData {
		state = "DEGRADED"
	}
	writeJSON(w, status, struct {
		Status            string             `json:"status"`
		CountryDB         bool               `json:"countryDb"`
		ASNDB             bool               `json:"asnDb"`
		CountrySources    []model.DataSource `json:"countrySources,omitempty"`
		ASNSources        []model.DataSource `json:"asnSources,omitempty"`
		ThreatData        bool               `json:"threatData"`
		ThreatUpdatedAt   string             `json:"threatUpdatedAt,omitempty"`
		ThreatAttribution string             `json:"threatAttribution,omitempty"`
		ThreatTerms       string             `json:"threatTerms,omitempty"`
		ThreatSources     []model.DataSource `json:"threatSources,omitempty"`
	}{
		state,
		ready.CountryDB,
		ready.ASNDB,
		ready.CountrySources,
		ready.ASNSources,
		ready.ThreatData,
		ready.ThreatUpdatedAt,
		ready.ThreatAttribution,
		ready.ThreatTerms,
		ready.ThreatSources,
	})
}

func (h *Handler) lookupWithoutIP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/v1/lookup" {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "route not found")
		return
	}
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	atomic.AddUint64(&h.metrics.lookups, 1)
	atomic.AddUint64(&h.metrics.invalid, 1)
	writeError(w, http.StatusBadRequest, "INVALID_IP", "IP address is required")
}

func (h *Handler) lookup(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	atomic.AddUint64(&h.metrics.lookups, 1)
	rawIP := strings.TrimPrefix(r.URL.Path, "/v1/lookup/")
	if rawIP == "" || strings.Contains(rawIP, "/") {
		atomic.AddUint64(&h.metrics.invalid, 1)
		writeError(w, http.StatusBadRequest, "INVALID_IP", "invalid IP address")
		return
	}

	profile, err := h.service.Lookup(rawIP)
	switch {
	case err == nil:
		h.recordProfile(profile)
		writeJSON(w, http.StatusOK, profile)
	case errors.Is(err, service.ErrInvalidIP):
		atomic.AddUint64(&h.metrics.invalid, 1)
		writeError(w, http.StatusBadRequest, "INVALID_IP", "invalid IP address")
	case errors.Is(err, geoip.ErrNotReady):
		atomic.AddUint64(&h.metrics.failures, 1)
		writeError(w, http.StatusServiceUnavailable, "SERVICE_NOT_READY", "GeoIP databases are not ready")
	default:
		atomic.AddUint64(&h.metrics.failures, 1)
		log.Printf("lookup %q failed: %v", rawIP, err)
		writeError(w, http.StatusInternalServerError, "LOOKUP_FAILED", "IP lookup failed")
	}
}

func (h *Handler) recordProfile(profile model.IPProfile) {
	if profile.Country.Status == model.StatusUnknown {
		atomic.AddUint64(&h.metrics.countryUnknown, 1)
	}
	if profile.Network.Status == model.StatusUnknown {
		atomic.AddUint64(&h.metrics.asnUnknown, 1)
	}
	if profile.Agreement.Country == model.AgreementDisagree {
		atomic.AddUint64(&h.metrics.countryConflict, 1)
	}
	if profile.Agreement.ASN == model.AgreementDisagree {
		atomic.AddUint64(&h.metrics.asnConflict, 1)
	}
	if !profile.Scope.GloballyReachable {
		atomic.AddUint64(&h.metrics.nonPublic, 1)
	}
	switch profile.Cloud.Source {
	case "CIDR":
		atomic.AddUint64(&h.metrics.cloudCIDR, 1)
	case "ASN":
		atomic.AddUint64(&h.metrics.cloudASN, 1)
	default:
		atomic.AddUint64(&h.metrics.cloudNoMatch, 1)
	}
	if profile.Threat.Status == model.StatusUnknown {
		atomic.AddUint64(&h.metrics.threatUnknown, 1)
	} else if !profile.Threat.Listed {
		atomic.AddUint64(&h.metrics.threatNotListed, 1)
	}
	for _, match := range profile.Threat.Matches {
		switch match.Kind {
		case "CIDR":
			atomic.AddUint64(&h.metrics.threatCIDR, 1)
		case "ASN":
			atomic.AddUint64(&h.metrics.threatASN, 1)
		}
	}
}

func (h *Handler) writeMetrics(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	values := []struct {
		name  string
		value uint64
	}{
		{"ip_intelligence_lookups_total", atomic.LoadUint64(&h.metrics.lookups)},
		{"ip_intelligence_invalid_ip_total", atomic.LoadUint64(&h.metrics.invalid)},
		{"ip_intelligence_lookup_failures_total", atomic.LoadUint64(&h.metrics.failures)},
		{"ip_intelligence_country_unknown_total", atomic.LoadUint64(&h.metrics.countryUnknown)},
		{"ip_intelligence_asn_unknown_total", atomic.LoadUint64(&h.metrics.asnUnknown)},
		{"ip_intelligence_cloud_cidr_matches_total", atomic.LoadUint64(&h.metrics.cloudCIDR)},
		{"ip_intelligence_cloud_asn_matches_total", atomic.LoadUint64(&h.metrics.cloudASN)},
		{"ip_intelligence_cloud_no_match_total", atomic.LoadUint64(&h.metrics.cloudNoMatch)},
		{"ip_intelligence_country_source_conflicts_total", atomic.LoadUint64(&h.metrics.countryConflict)},
		{"ip_intelligence_asn_source_conflicts_total", atomic.LoadUint64(&h.metrics.asnConflict)},
		{"ip_intelligence_non_public_total", atomic.LoadUint64(&h.metrics.nonPublic)},
		{"ip_intelligence_threat_cidr_matches_total", atomic.LoadUint64(&h.metrics.threatCIDR)},
		{"ip_intelligence_threat_asn_matches_total", atomic.LoadUint64(&h.metrics.threatASN)},
		{"ip_intelligence_threat_not_listed_total", atomic.LoadUint64(&h.metrics.threatNotListed)},
		{"ip_intelligence_threat_unknown_total", atomic.LoadUint64(&h.metrics.threatUnknown)},
	}
	for _, value := range values {
		_, _ = fmt.Fprintf(w, "%s %d\n", value.name, value.value)
	}
}

func requireMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method == method {
		return true
	}
	w.Header().Set("Allow", method)
	writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed")
	return false
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, errorResponse{Code: code, Message: message})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		log.Printf("write JSON response: %v", err)
	}
}

func recoverPanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				log.Printf("panic serving request: %v", recovered)
				writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}
