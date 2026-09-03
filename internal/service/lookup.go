package service

import (
	"errors"
	"net/netip"

	"ip-intelligence-service/internal/classifier"
	"ip-intelligence-service/internal/geoip"
	"ip-intelligence-service/internal/model"
)

var ErrInvalidIP = errors.New("invalid IP address")

type GeoIP interface {
	Ready() geoip.Readiness
	Lookup(netip.Addr) (geoip.Result, error)
}

type CloudClassifier interface {
	Classify(netip.Addr, uint32) model.CloudInfo
}

type ThreatClassifier interface {
	Ready() classifier.ThreatReadiness
	Classify(netip.Addr, uint32) model.ThreatInfo
}

type Readiness struct {
	CountryDB         bool               `json:"countryDb"`
	ASNDB             bool               `json:"asnDb"`
	CountrySources    []model.DataSource `json:"countrySources,omitempty"`
	ASNSources        []model.DataSource `json:"asnSources,omitempty"`
	ThreatData        bool               `json:"threatData"`
	ThreatUpdatedAt   string             `json:"threatUpdatedAt,omitempty"`
	ThreatAttribution string             `json:"threatAttribution,omitempty"`
	ThreatTerms       string             `json:"threatTerms,omitempty"`
	ThreatSources     []model.DataSource `json:"threatSources,omitempty"`
}

func (r Readiness) Ready() bool {
	return r.CountryDB && r.ASNDB
}

type Lookup struct {
	geoIP            GeoIP
	cloudClassifier  CloudClassifier
	threatClassifier ThreatClassifier
}

func New(geoIP GeoIP, cloudClassifier CloudClassifier, threatClassifier ThreatClassifier) *Lookup {
	return &Lookup{geoIP: geoIP, cloudClassifier: cloudClassifier, threatClassifier: threatClassifier}
}

func (s *Lookup) Ready() Readiness {
	geo := s.geoIP.Ready()
	threat := s.threatClassifier.Ready()
	return Readiness{
		CountryDB:         geo.CountryDB,
		ASNDB:             geo.ASNDB,
		CountrySources:    geo.CountrySources,
		ASNSources:        geo.ASNSources,
		ThreatData:        threat.Loaded,
		ThreatUpdatedAt:   threat.UpdatedAt,
		ThreatAttribution: threat.Attribution,
		ThreatTerms:       threat.Terms,
		ThreatSources:     threat.Sources,
	}
}

func (s *Lookup) Lookup(rawIP string) (model.IPProfile, error) {
	addr, err := netip.ParseAddr(rawIP)
	if err != nil || addr.Zone() != "" {
		return model.IPProfile{}, ErrInvalidIP
	}
	addr = addr.Unmap()

	geoResult, err := s.geoIP.Lookup(addr)
	if err != nil {
		return model.IPProfile{}, err
	}

	cloud := s.cloudClassifier.Classify(addr, geoResult.ASN)
	threat := s.threatClassifier.Classify(addr, geoResult.ASN)
	networkType := model.NetworkUnknown
	if cloud.Cloud {
		networkType = model.NetworkHosting
	}

	return model.IPProfile{
		IP:      addr.String(),
		Scope:   classifier.ClassifyScope(addr),
		Country: geoResult.Country,
		Network: model.NetworkInfo{
			ASN:    geoResult.ASN,
			Name:   geoResult.ASNName,
			Type:   networkType,
			Status: geoResult.ASNStatus,
			Source: geoResult.ASNSource,
		},
		Cloud:     cloud,
		Threat:    threat,
		Agreement: geoResult.Agreement,
	}, nil
}
