package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"ip-intelligence-service/internal/classifier"
)

const (
	dropV4URL  = "https://www.spamhaus.org/drop/drop_v4.json"
	dropV6URL  = "https://www.spamhaus.org/drop/drop_v6.json"
	asnDropURL = "https://www.spamhaus.org/drop/asndrop.json"
)

type feedKind int

const (
	prefixFeed feedKind = iota
	asnFeed
)

type feedConfig struct {
	id   string
	name string
	url  string
	kind feedKind
}

type feedRecord struct {
	Type      string `json:"type"`
	CIDR      string `json:"cidr"`
	SBLID     string `json:"sblid"`
	ASN       uint32 `json:"asn"`
	Timestamp int64  `json:"timestamp"`
	Records   int    `json:"records"`
	Copyright string `json:"copyright"`
	Terms     string `json:"terms"`
}

type parsedFeed struct {
	source      classifier.ThreatSource
	prefixRules []classifier.ThreatPrefixRule
	asnRules    []classifier.ThreatASNRule
	attribution string
	terms       string
	updatedAt   time.Time
}

func main() {
	output := flag.String("output", "data/rules/threat.json", "output JSON path")
	flag.Parse()

	client := &http.Client{Timeout: 30 * time.Second}
	dataset, err := collect(client)
	if err != nil {
		log.Fatal(err)
	}
	if err := writeDataset(*output, dataset); err != nil {
		log.Fatal(err)
	}
	log.Printf("wrote %d Spamhaus prefixes and %d ASNs to %s", len(dataset.Prefixes), len(dataset.ASNs), *output)
}

func collect(client *http.Client) (classifier.ThreatDataset, error) {
	configs := []feedConfig{
		{"SPAMHAUS_DROP_V4", "Spamhaus DROP IPv4", dropV4URL, prefixFeed},
		{"SPAMHAUS_DROP_V6", "Spamhaus DROP IPv6", dropV6URL, prefixFeed},
		{"SPAMHAUS_ASN_DROP", "Spamhaus ASN-DROP", asnDropURL, asnFeed},
	}

	dataset := classifier.ThreatDataset{GeneratedAt: time.Now().UTC().Format(time.RFC3339)}
	var newest time.Time
	for _, config := range configs {
		feed, err := fetchFeed(client, config)
		if err != nil {
			return classifier.ThreatDataset{}, fmt.Errorf("%s: %w", config.id, err)
		}
		if dataset.Attribution != "" && dataset.Attribution != feed.attribution {
			return classifier.ThreatDataset{}, fmt.Errorf("source attribution mismatch")
		}
		if dataset.Terms != "" && dataset.Terms != feed.terms {
			return classifier.ThreatDataset{}, fmt.Errorf("source terms mismatch")
		}
		dataset.Attribution = feed.attribution
		dataset.Terms = feed.terms
		dataset.Sources = append(dataset.Sources, feed.source)
		dataset.Prefixes = append(dataset.Prefixes, feed.prefixRules...)
		dataset.ASNs = append(dataset.ASNs, feed.asnRules...)
		if feed.updatedAt.After(newest) {
			newest = feed.updatedAt
		}
	}
	if newest.IsZero() {
		return classifier.ThreatDataset{}, fmt.Errorf("sources have no update timestamp")
	}
	dataset.UpdatedAt = newest.Format(time.RFC3339)

	if err := normalize(&dataset); err != nil {
		return classifier.ThreatDataset{}, err
	}
	return dataset, nil
}

func fetchFeed(client *http.Client, config feedConfig) (parsedFeed, error) {
	request, err := http.NewRequest(http.MethodGet, config.url, nil)
	if err != nil {
		return parsedFeed{}, err
	}
	request.Header.Set("User-Agent", "ip-intelligence-service/1.0")
	response, err := client.Do(request)
	if err != nil {
		return parsedFeed{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return parsedFeed{}, fmt.Errorf("GET %s returned %s", config.url, response.Status)
	}
	return parseFeed(io.LimitReader(response.Body, 16<<20), config)
}

func parseFeed(reader io.Reader, config feedConfig) (parsedFeed, error) {
	result := parsedFeed{}
	metadataFound := false
	recordCount := 0
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var record feedRecord
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			return parsedFeed{}, fmt.Errorf("decode record %d: %w", recordCount+1, err)
		}
		if record.Type == "metadata" {
			if metadataFound {
				return parsedFeed{}, fmt.Errorf("duplicate metadata record")
			}
			if record.Timestamp <= 0 || record.Records < 1 || record.Copyright == "" || record.Terms == "" {
				return parsedFeed{}, fmt.Errorf("incomplete metadata record")
			}
			metadataFound = true
			result.updatedAt = time.Unix(record.Timestamp, 0).UTC()
			result.attribution = record.Copyright
			result.terms = record.Terms
			result.source = classifier.ThreatSource{
				ID:        config.id,
				Name:      config.name,
				URL:       config.url,
				UpdatedAt: result.updatedAt.Format(time.RFC3339),
				Records:   record.Records,
			}
			continue
		}

		recordCount++
		switch config.kind {
		case prefixFeed:
			prefix, err := netip.ParsePrefix(record.CIDR)
			if err != nil {
				return parsedFeed{}, fmt.Errorf("invalid prefix %q: %w", record.CIDR, err)
			}
			references := []string{}
			if reference := strings.TrimSpace(record.SBLID); reference != "" {
				references = append(references, reference)
			}
			result.prefixRules = append(result.prefixRules, classifier.ThreatPrefixRule{
				Prefix:     prefix.Masked().String(),
				Source:     config.id,
				References: references,
			})
		case asnFeed:
			if record.ASN == 0 {
				return parsedFeed{}, fmt.Errorf("invalid ASN record")
			}
			result.asnRules = append(result.asnRules, classifier.ThreatASNRule{ASN: record.ASN, Source: config.id})
		}
	}
	if err := scanner.Err(); err != nil {
		return parsedFeed{}, err
	}
	if !metadataFound {
		return parsedFeed{}, fmt.Errorf("metadata record is missing")
	}
	if result.source.Records != recordCount {
		return parsedFeed{}, fmt.Errorf("metadata says %d records, decoded %d", result.source.Records, recordCount)
	}
	return result, nil
}

func normalize(dataset *classifier.ThreatDataset) error {
	prefixes := make(map[netip.Prefix]classifier.ThreatPrefixRule, len(dataset.Prefixes))
	for _, rule := range dataset.Prefixes {
		prefix := netip.MustParsePrefix(rule.Prefix).Masked()
		if existing, ok := prefixes[prefix]; ok {
			if existing.Source != rule.Source {
				return fmt.Errorf("conflicting threat prefix %s", prefix)
			}
			existing.References = mergeStrings(existing.References, rule.References)
			prefixes[prefix] = existing
			continue
		}
		rule.References = mergeStrings(nil, rule.References)
		prefixes[prefix] = rule
	}
	dataset.Prefixes = dataset.Prefixes[:0]
	for _, rule := range prefixes {
		dataset.Prefixes = append(dataset.Prefixes, rule)
	}
	sort.Slice(dataset.Prefixes, func(i, j int) bool {
		left := netip.MustParsePrefix(dataset.Prefixes[i].Prefix)
		right := netip.MustParsePrefix(dataset.Prefixes[j].Prefix)
		if comparison := left.Addr().Compare(right.Addr()); comparison != 0 {
			return comparison < 0
		}
		return left.Bits() < right.Bits()
	})

	asns := make(map[uint32]classifier.ThreatASNRule, len(dataset.ASNs))
	for _, rule := range dataset.ASNs {
		if existing, ok := asns[rule.ASN]; ok && existing.Source != rule.Source {
			return fmt.Errorf("conflicting threat ASN %d", rule.ASN)
		}
		asns[rule.ASN] = rule
	}
	dataset.ASNs = dataset.ASNs[:0]
	for _, rule := range asns {
		dataset.ASNs = append(dataset.ASNs, rule)
	}
	sort.Slice(dataset.ASNs, func(i, j int) bool { return dataset.ASNs[i].ASN < dataset.ASNs[j].ASN })
	return nil
}

func mergeStrings(existing, additions []string) []string {
	unique := make(map[string]struct{}, len(existing)+len(additions))
	for _, value := range append(existing, additions...) {
		value = strings.TrimSpace(value)
		if value != "" {
			unique[value] = struct{}{}
		}
	}
	merged := make([]string, 0, len(unique))
	for value := range unique {
		merged = append(merged, value)
	}
	sort.Strings(merged)
	return merged
}

func writeDataset(path string, dataset classifier.ThreatDataset) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".threat-*.json")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)

	encoder := json.NewEncoder(temporary)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(dataset); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Chmod(0644); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}
