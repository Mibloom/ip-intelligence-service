package main

import "testing"

func TestNormalizeMasksAndDeduplicates(t *testing.T) {
	rules, err := normalize([]rule{
		{Prefix: "10.0.0.1/24", Provider: "AWS", Source: "AWS_IP_RANGES"},
		{Prefix: "10.0.0.0/24", Provider: "AWS", Source: "AWS_IP_RANGES"},
		{Prefix: "2001:db8::1/48", Provider: "GOOGLE_CLOUD", Source: "GOOGLE_CLOUD_IP_RANGES"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 {
		t.Fatalf("got %d rules, want 2", len(rules))
	}
	if rules[0].Prefix != "10.0.0.0/24" || rules[1].Prefix != "2001:db8::/48" {
		t.Fatalf("unexpected normalized rules: %+v", rules)
	}
}
