package main

import (
	"strings"
	"testing"
)

func TestParsePrefixFeed(t *testing.T) {
	input := strings.Join([]string{
		`{"cidr":"1.10.16.0/20","sblid":"SBL256894","rir":"apnic"}`,
		`{"type":"metadata","timestamp":1788421442,"size":100,"records":1,"copyright":"(c) 2026 The Spamhaus Project SLU","terms":"https://www.spamhaus.org/drop/terms/"}`,
	}, "\n")
	feed, err := parseFeed(strings.NewReader(input), feedConfig{"SPAMHAUS_DROP_V4", "Spamhaus DROP IPv4", "https://example.test/drop", prefixFeed})
	if err != nil {
		t.Fatal(err)
	}
	if len(feed.prefixRules) != 1 || len(feed.prefixRules[0].References) != 1 || feed.prefixRules[0].References[0] != "SBL256894" || feed.source.Records != 1 {
		t.Fatalf("unexpected feed: %+v", feed)
	}
}

func TestParseFeedRejectsRecordCountMismatch(t *testing.T) {
	input := strings.Join([]string{
		`{"asn":245}`,
		`{"type":"metadata","timestamp":1788421442,"records":2,"copyright":"copyright","terms":"https://example.test/terms"}`,
	}, "\n")
	_, err := parseFeed(strings.NewReader(input), feedConfig{"SPAMHAUS_ASN_DROP", "Spamhaus ASN-DROP", "https://example.test/asn", asnFeed})
	if err == nil || !strings.Contains(err.Error(), "metadata says 2 records, decoded 1") {
		t.Fatalf("unexpected error: %v", err)
	}
}
