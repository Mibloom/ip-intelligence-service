package classifier

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"ip-intelligence-service/internal/model"
)

const ThreatCategoryCybercrimeNetwork = "CYBERCRIME_NETWORK"

type ThreatDataset struct {
	GeneratedAt string             `json:"generatedAt"`
	UpdatedAt   string             `json:"updatedAt"`
	Attribution string             `json:"attribution"`
	Terms       string             `json:"terms"`
	Sources     []ThreatSource     `json:"sources"`
	Prefixes    []ThreatPrefixRule `json:"prefixes"`
	ASNs        []ThreatASNRule    `json:"asns"`
}

type ThreatSource struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	URL       string `json:"url"`
	UpdatedAt string `json:"updatedAt"`
	Records   int    `json:"records"`
}

type ThreatPrefixRule struct {
	Prefix     string   `json:"prefix"`
	Source     string   `json:"source"`
	References []string `json:"references,omitempty"`
}

type ThreatASNRule struct {
	ASN    uint32 `json:"asn"`
	Source string `json:"source"`
}

type ThreatReadiness struct {
	Loaded      bool
	UpdatedAt   string
	Attribution string
	Terms       string
	Sources     []model.DataSource
}

type Threat struct {
	prefixes  map[netip.Prefix]model.ThreatMatch
	asns      map[uint32]model.ThreatMatch
	readiness ThreatReadiness
}

func LoadThreat(path string) (*Threat, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return unavailableThreat(), nil
	}
	if err != nil {
		return nil, err
	}

	var dataset ThreatDataset
	if err := json.Unmarshal(data, &dataset); err != nil {
		return nil, fmt.Errorf("decode threat rules: %w", err)
	}
	if len(dataset.Sources) == 0 || (len(dataset.Prefixes) == 0 && len(dataset.ASNs) == 0) {
		return nil, fmt.Errorf("threat rules are empty")
	}
	if _, err := time.Parse(time.RFC3339, dataset.UpdatedAt); err != nil {
		return nil, fmt.Errorf("invalid threat update time %q: %w", dataset.UpdatedAt, err)
	}

	threat := unavailableThreat()
	for _, rule := range dataset.Prefixes {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(rule.Prefix))
		if err != nil {
			return nil, fmt.Errorf("invalid threat prefix %q: %w", rule.Prefix, err)
		}
		source := strings.TrimSpace(rule.Source)
		if source == "" {
			return nil, fmt.Errorf("threat prefix %s has empty source", rule.Prefix)
		}
		prefix = prefix.Masked()
		threat.prefixes[prefix] = model.ThreatMatch{
			Source:     source,
			Kind:       "CIDR",
			Value:      prefix.String(),
			References: append([]string(nil), rule.References...),
		}
	}
	for _, rule := range dataset.ASNs {
		if rule.ASN == 0 || strings.TrimSpace(rule.Source) == "" {
			return nil, fmt.Errorf("invalid threat ASN rule for AS%d", rule.ASN)
		}
		threat.asns[rule.ASN] = model.ThreatMatch{
			Source: rule.Source,
			Kind:   "ASN",
			Value:  fmt.Sprintf("AS%d", rule.ASN),
		}
	}

	sources := make([]model.DataSource, 0, len(dataset.Sources))
	for _, source := range dataset.Sources {
		if source.ID == "" || source.Name == "" || source.URL == "" || source.UpdatedAt == "" {
			return nil, fmt.Errorf("invalid threat source metadata")
		}
		sources = append(sources, model.DataSource{
			ID:        source.ID,
			Name:      source.Name,
			URL:       source.URL,
			BuildTime: source.UpdatedAt,
		})
	}
	threat.readiness = ThreatReadiness{
		Loaded:      true,
		UpdatedAt:   dataset.UpdatedAt,
		Attribution: dataset.Attribution,
		Terms:       dataset.Terms,
		Sources:     sources,
	}
	return threat, nil
}

func unavailableThreat() *Threat {
	return &Threat{
		prefixes: make(map[netip.Prefix]model.ThreatMatch),
		asns:     make(map[uint32]model.ThreatMatch),
	}
}

func (t *Threat) Ready() ThreatReadiness {
	return t.readiness
}

func (t *Threat) Classify(addr netip.Addr, asn uint32) model.ThreatInfo {
	matches := make([]model.ThreatMatch, 0, 2)
	if !t.readiness.Loaded {
		return model.ThreatInfo{
			Status:     model.StatusUnknown,
			Level:      model.ThreatLevelUnknown,
			Confidence: model.ThreatConfidenceUnknown,
			Categories: []string{},
			Matches:    matches,
		}
	}

	if match, ok := t.matchPrefix(addr); ok {
		matches = append(matches, match)
	}
	if match, ok := t.asns[asn]; ok {
		matches = append(matches, match)
	}
	if len(matches) == 0 {
		return model.ThreatInfo{
			Status:     model.StatusKnown,
			Level:      model.ThreatLevelNone,
			Confidence: model.ThreatConfidenceNone,
			Categories: []string{},
			Matches:    matches,
		}
	}
	return model.ThreatInfo{
		Status:     model.StatusKnown,
		Listed:     true,
		Level:      model.ThreatLevelHigh,
		Confidence: model.ThreatConfidenceHigh,
		Categories: []string{ThreatCategoryCybercrimeNetwork},
		Matches:    matches,
	}
}

func (t *Threat) matchPrefix(addr netip.Addr) (model.ThreatMatch, bool) {
	addr = addr.Unmap()
	bits := 128
	if addr.Is4() {
		bits = 32
	}
	for prefixBits := bits; prefixBits >= 0; prefixBits-- {
		prefix, err := addr.Prefix(prefixBits)
		if err != nil {
			return model.ThreatMatch{}, false
		}
		if match, ok := t.prefixes[prefix]; ok {
			return match, true
		}
	}
	return model.ThreatMatch{}, false
}
