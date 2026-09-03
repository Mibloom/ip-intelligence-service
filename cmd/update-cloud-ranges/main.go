package main

import (
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
)

const (
	awsURL          = "https://ip-ranges.amazonaws.com/ip-ranges.json"
	googleCloudURL  = "https://www.gstatic.com/ipranges/cloud.json"
	cloudflareV4URL = "https://www.cloudflare.com/ips-v4"
	cloudflareV6URL = "https://www.cloudflare.com/ips-v6"
	oracleCloudURL  = "https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json"
)

type rule struct {
	Prefix   string `json:"prefix"`
	Provider string `json:"provider"`
	Source   string `json:"source"`
}

type awsRanges struct {
	Prefixes []struct {
		Prefix string `json:"ip_prefix"`
	} `json:"prefixes"`
	IPv6Prefixes []struct {
		Prefix string `json:"ipv6_prefix"`
	} `json:"ipv6_prefixes"`
}

type googleRanges struct {
	Prefixes []struct {
		IPv4 string `json:"ipv4Prefix"`
		IPv6 string `json:"ipv6Prefix"`
	} `json:"prefixes"`
}

type oracleRanges struct {
	Regions []struct {
		CIDRs []struct {
			CIDR string `json:"cidr"`
		} `json:"cidrs"`
	} `json:"regions"`
}

func main() {
	output := flag.String("output", "data/rules/cloud-cidr.json", "output JSON path")
	flag.Parse()

	client := &http.Client{Timeout: 30 * time.Second}
	rules, err := collect(client)
	if err != nil {
		log.Fatal(err)
	}
	if err := writeRules(*output, rules); err != nil {
		log.Fatal(err)
	}
	log.Printf("wrote %d official cloud CIDR rules to %s", len(rules), *output)
}

func collect(client *http.Client) ([]rule, error) {
	collected := make([]rule, 0, 10000)

	var aws awsRanges
	if err := fetchJSON(client, awsURL, &aws); err != nil {
		return nil, fmt.Errorf("AWS ranges: %w", err)
	}
	for _, prefix := range aws.Prefixes {
		collected = append(collected, rule{prefix.Prefix, "AWS", "AWS_IP_RANGES"})
	}
	for _, prefix := range aws.IPv6Prefixes {
		collected = append(collected, rule{prefix.Prefix, "AWS", "AWS_IP_RANGES"})
	}

	var google googleRanges
	if err := fetchJSON(client, googleCloudURL, &google); err != nil {
		return nil, fmt.Errorf("Google Cloud ranges: %w", err)
	}
	for _, prefix := range google.Prefixes {
		value := prefix.IPv4
		if value == "" {
			value = prefix.IPv6
		}
		collected = append(collected, rule{value, "GOOGLE_CLOUD", "GOOGLE_CLOUD_IP_RANGES"})
	}

	for _, source := range []struct {
		url  string
		name string
	}{{cloudflareV4URL, "CLOUDFLARE_IP_RANGES"}, {cloudflareV6URL, "CLOUDFLARE_IP_RANGES"}} {
		prefixes, err := fetchLines(client, source.url)
		if err != nil {
			return nil, fmt.Errorf("Cloudflare ranges: %w", err)
		}
		for _, prefix := range prefixes {
			collected = append(collected, rule{prefix, "CLOUDFLARE", source.name})
		}
	}

	var oracle oracleRanges
	if err := fetchJSON(client, oracleCloudURL, &oracle); err != nil {
		return nil, fmt.Errorf("Oracle Cloud ranges: %w", err)
	}
	for _, region := range oracle.Regions {
		for _, prefix := range region.CIDRs {
			collected = append(collected, rule{prefix.CIDR, "ORACLE_CLOUD", "ORACLE_CLOUD_IP_RANGES"})
		}
	}

	return normalize(collected)
}

func normalize(rules []rule) ([]rule, error) {
	unique := make(map[netip.Prefix]rule, len(rules))
	for _, current := range rules {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(current.Prefix))
		if err != nil {
			return nil, fmt.Errorf("invalid prefix %q from %s: %w", current.Prefix, current.Source, err)
		}
		prefix = prefix.Masked()
		current.Prefix = prefix.String()
		if existing, ok := unique[prefix]; ok && existing.Provider != current.Provider {
			return nil, fmt.Errorf("prefix %s belongs to both %s and %s", prefix, existing.Provider, current.Provider)
		}
		unique[prefix] = current
	}

	result := make([]rule, 0, len(unique))
	for _, current := range unique {
		result = append(result, current)
	}
	sort.Slice(result, func(i, j int) bool {
		left := netip.MustParsePrefix(result[i].Prefix)
		right := netip.MustParsePrefix(result[j].Prefix)
		if comparison := left.Addr().Compare(right.Addr()); comparison != 0 {
			return comparison < 0
		}
		return left.Bits() < right.Bits()
	})
	return result, nil
}

func fetchJSON(client *http.Client, url string, target any) error {
	response, err := get(client, url)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	return json.NewDecoder(io.LimitReader(response.Body, 64<<20)).Decode(target)
}

func fetchLines(client *http.Client, url string) ([]string, error) {
	response, err := get(client, url)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var lines []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines, nil
}

func get(client *http.Client, url string) (*http.Response, error) {
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", "ip-intelligence-service/1.0")
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		return nil, fmt.Errorf("GET %s returned %s", url, response.Status)
	}
	return response, nil
}

func writeRules(path string, rules []rule) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".cloud-cidr-*.json")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)

	encoder := json.NewEncoder(temporary)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(rules); err != nil {
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
