package classifier

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"ip-intelligence-service/internal/model"
)

type CIDRRule struct {
	Prefix   string `json:"prefix"`
	Provider string `json:"provider"`
	Source   string `json:"source"`
}

type cidrMatch struct {
	provider string
	source   string
}

type Cloud struct {
	providers map[uint32]string
	prefixes  map[netip.Prefix]cidrMatch
}

func Load(path string) (*Cloud, error) {
	return LoadWithCIDRs(path, "")
}

func LoadWithCIDRs(asnPath, cidrPath string) (*Cloud, error) {
	providers, err := loadASNs(asnPath)
	if err != nil {
		return nil, err
	}
	prefixes, err := loadCIDRs(cidrPath)
	if err != nil {
		return nil, err
	}
	return &Cloud{providers: providers, prefixes: prefixes}, nil
}

func New(rules map[uint32]string) *Cloud {
	providers := make(map[uint32]string, len(rules))
	for asn, provider := range rules {
		providers[asn] = strings.ToUpper(strings.TrimSpace(provider))
	}
	return &Cloud{providers: providers, prefixes: make(map[netip.Prefix]cidrMatch)}
}

func NewWithCIDRs(rules map[uint32]string, cidrs []CIDRRule) (*Cloud, error) {
	cloud := New(rules)
	for _, rule := range cidrs {
		prefix, err := netip.ParsePrefix(rule.Prefix)
		if err != nil {
			return nil, fmt.Errorf("invalid cloud prefix %q: %w", rule.Prefix, err)
		}
		provider := strings.ToUpper(strings.TrimSpace(rule.Provider))
		source := strings.TrimSpace(rule.Source)
		if provider == "" || source == "" {
			return nil, fmt.Errorf("cloud prefix %s has empty provider or source", rule.Prefix)
		}
		cloud.prefixes[prefix.Masked()] = cidrMatch{provider: provider, source: source}
	}
	return cloud, nil
}

func (c *Cloud) Classify(addr netip.Addr, asn uint32) model.CloudInfo {
	if match, ok := c.matchPrefix(addr); ok {
		return model.CloudInfo{
			Cloud:      true,
			Provider:   match.provider,
			Confidence: model.ConfidenceHigh,
			Source:     "CIDR",
			Rule:       match.source,
		}
	}
	if provider, ok := c.providers[asn]; ok {
		return model.CloudInfo{
			Cloud:      true,
			Provider:   provider,
			Confidence: model.ConfidenceMedium,
			Source:     "ASN",
		}
	}
	return model.CloudInfo{Cloud: false, Confidence: model.ConfidenceLow, Source: "NONE"}
}

func (c *Cloud) matchPrefix(addr netip.Addr) (cidrMatch, bool) {
	addr = addr.Unmap()
	bits := 128
	if addr.Is4() {
		bits = 32
	}
	for prefixBits := bits; prefixBits >= 0; prefixBits-- {
		prefix, err := addr.Prefix(prefixBits)
		if err != nil {
			return cidrMatch{}, false
		}
		if match, ok := c.prefixes[prefix]; ok {
			return match, true
		}
	}
	return cidrMatch{}, false
}

func loadASNs(path string) (map[uint32]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw map[string]string
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("decode ASN rules: %w", err)
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("ASN rules are empty")
	}

	providers := make(map[uint32]string, len(raw))
	for rawASN, rawProvider := range raw {
		asn, err := strconv.ParseUint(rawASN, 10, 32)
		if err != nil || asn == 0 {
			return nil, fmt.Errorf("invalid ASN %q", rawASN)
		}
		provider := strings.ToUpper(strings.TrimSpace(rawProvider))
		if provider == "" {
			return nil, fmt.Errorf("provider for ASN %s is empty", rawASN)
		}
		providers[uint32(asn)] = provider
	}
	return providers, nil
}

func loadCIDRs(path string) (map[netip.Prefix]cidrMatch, error) {
	prefixes := make(map[netip.Prefix]cidrMatch)
	if path == "" {
		return prefixes, nil
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return prefixes, nil
	}
	if err != nil {
		return nil, err
	}
	var rules []CIDRRule
	if err := json.Unmarshal(data, &rules); err != nil {
		return nil, fmt.Errorf("decode CIDR rules: %w", err)
	}
	for _, rule := range rules {
		prefix, err := netip.ParsePrefix(rule.Prefix)
		if err != nil {
			return nil, fmt.Errorf("invalid cloud prefix %q: %w", rule.Prefix, err)
		}
		provider := strings.ToUpper(strings.TrimSpace(rule.Provider))
		source := strings.TrimSpace(rule.Source)
		if provider == "" || source == "" {
			return nil, fmt.Errorf("cloud prefix %s has empty provider or source", rule.Prefix)
		}
		prefixes[prefix.Masked()] = cidrMatch{provider: provider, source: source}
	}
	return prefixes, nil
}
