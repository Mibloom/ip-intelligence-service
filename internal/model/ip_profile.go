package model

type NetworkType string
type LookupStatus string
type Confidence string
type AgreementStatus string
type IPScopeType string
type ThreatLevel string
type ThreatConfidence string

const (
	NetworkHosting NetworkType = "HOSTING"
	NetworkUnknown NetworkType = "UNKNOWN"

	StatusKnown   LookupStatus = "KNOWN"
	StatusUnknown LookupStatus = "UNKNOWN"

	ConfidenceHigh   Confidence = "HIGH"
	ConfidenceMedium Confidence = "MEDIUM"
	ConfidenceLow    Confidence = "LOW"

	AgreementAgree        AgreementStatus = "AGREE"
	AgreementDisagree     AgreementStatus = "DISAGREE"
	AgreementInsufficient AgreementStatus = "INSUFFICIENT_DATA"

	ScopePublic        IPScopeType = "PUBLIC"
	ScopePrivate       IPScopeType = "PRIVATE"
	ScopeLoopback      IPScopeType = "LOOPBACK"
	ScopeLinkLocal     IPScopeType = "LINK_LOCAL"
	ScopeCGNAT         IPScopeType = "CGNAT"
	ScopeMulticast     IPScopeType = "MULTICAST"
	ScopeDocumentation IPScopeType = "DOCUMENTATION"
	ScopeBenchmark     IPScopeType = "BENCHMARK"
	ScopeBroadcast     IPScopeType = "BROADCAST"
	ScopeUnspecified   IPScopeType = "UNSPECIFIED"
	ScopeReserved      IPScopeType = "RESERVED"

	ThreatLevelHigh    ThreatLevel = "HIGH"
	ThreatLevelNone    ThreatLevel = "NONE"
	ThreatLevelUnknown ThreatLevel = "UNKNOWN"

	ThreatConfidenceHigh    ThreatConfidence = "HIGH"
	ThreatConfidenceNone    ThreatConfidence = "NONE"
	ThreatConfidenceUnknown ThreatConfidence = "UNKNOWN"
)

type CountryInfo struct {
	Code          string       `json:"code"`
	Status        LookupStatus `json:"status"`
	MainlandChina bool         `json:"mainlandChina"`
	Source        string       `json:"source,omitempty"`
}

type NetworkInfo struct {
	ASN    uint32       `json:"asn"`
	Name   string       `json:"name"`
	Type   NetworkType  `json:"type"`
	Status LookupStatus `json:"status"`
	Source string       `json:"source,omitempty"`
}

type CloudInfo struct {
	Cloud      bool       `json:"cloud"`
	Provider   string     `json:"provider,omitempty"`
	Confidence Confidence `json:"confidence"`
	Source     string     `json:"source"`
	Rule       string     `json:"rule,omitempty"`
}

type DataSource struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	URL       string `json:"url,omitempty"`
	BuildTime string `json:"buildTime,omitempty"`
}

type ScopeInfo struct {
	Type              IPScopeType `json:"type"`
	GloballyReachable bool        `json:"globallyReachable"`
}

type AgreementInfo struct {
	Country AgreementStatus `json:"country"`
	ASN     AgreementStatus `json:"asn"`
}

type ThreatMatch struct {
	Source     string   `json:"source"`
	Kind       string   `json:"kind"`
	Value      string   `json:"value"`
	References []string `json:"references,omitempty"`
}

type ThreatInfo struct {
	Status     LookupStatus     `json:"status"`
	Listed     bool             `json:"listed"`
	Level      ThreatLevel      `json:"level"`
	Confidence ThreatConfidence `json:"confidence"`
	Categories []string         `json:"categories"`
	Matches    []ThreatMatch    `json:"matches"`
}

type IPProfile struct {
	IP        string        `json:"ip"`
	Scope     ScopeInfo     `json:"scope"`
	Country   CountryInfo   `json:"country"`
	Network   NetworkInfo   `json:"network"`
	Cloud     CloudInfo     `json:"cloud"`
	Threat    ThreatInfo    `json:"threat"`
	Agreement AgreementInfo `json:"agreement"`
}
