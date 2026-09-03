package geoip

import (
	"testing"

	"ip-intelligence-service/internal/model"
)

func TestAgreement(t *testing.T) {
	tests := []struct {
		name   string
		values []string
		want   model.AgreementStatus
	}{
		{"no values", nil, model.AgreementInsufficient},
		{"one value", []string{"CN"}, model.AgreementInsufficient},
		{"same", []string{"CN", "CN"}, model.AgreementAgree},
		{"different", []string{"CN", "US"}, model.AgreementDisagree},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := agreement(test.values); got != test.want {
				t.Fatalf("got %s, want %s", got, test.want)
			}
		})
	}
}
