package classifier

import (
	"net/netip"
	"testing"
)

func TestClassify(t *testing.T) {
	classifier := New(map[uint32]string{37963: "aliyun"})

	cloud := classifier.Classify(netip.MustParseAddr("223.5.5.5"), 37963)
	if !cloud.Cloud || cloud.Provider != "ALIYUN" || cloud.Source != "ASN" || cloud.Confidence != "MEDIUM" {
		t.Fatalf("unexpected cloud classification: %+v", cloud)
	}

	notCloud := classifier.Classify(netip.MustParseAddr("1.2.3.4"), 4134)
	if notCloud.Cloud || notCloud.Provider != "" || notCloud.Confidence != "LOW" {
		t.Fatalf("unexpected non-cloud classification: %+v", notCloud)
	}
}

func TestCIDRTakesPriorityOverASN(t *testing.T) {
	classifier, err := NewWithCIDRs(
		map[uint32]string{16509: "AWS"},
		[]CIDRRule{{Prefix: "34.80.0.0/15", Provider: "GOOGLE_CLOUD", Source: "GOOGLE_CLOUD_IP_RANGES"}},
	)
	if err != nil {
		t.Fatal(err)
	}

	cloud := classifier.Classify(netip.MustParseAddr("34.80.1.2"), 16509)
	if cloud.Provider != "GOOGLE_CLOUD" || cloud.Source != "CIDR" || cloud.Confidence != "HIGH" {
		t.Fatalf("unexpected CIDR classification: %+v", cloud)
	}
}
