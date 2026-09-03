package geoip

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/oschwald/maxminddb-golang"

	"ip-intelligence-service/internal/model"
)

var ErrNotReady = errors.New("geoip database is not ready")

type SourceConfig struct {
	ID          string
	Name        string
	URL         string
	CountryPath string
	ASNPath     string
	Optional    bool
}

type Readiness struct {
	CountryDB      bool               `json:"countryDb"`
	ASNDB          bool               `json:"asnDb"`
	CountrySources []model.DataSource `json:"countrySources,omitempty"`
	ASNSources     []model.DataSource `json:"asnSources,omitempty"`
}

func (r Readiness) Ready() bool {
	return r.CountryDB && r.ASNDB
}

type Result struct {
	Country   model.CountryInfo
	ASN       uint32
	ASNName   string
	ASNStatus model.LookupStatus
	ASNSource string
	Agreement model.AgreementInfo
}

type database struct {
	reader *maxminddb.Reader
	source model.DataSource
}

type Provider struct {
	countryDBs []database
	asnDBs     []database
	loadErr    error
}

type countryRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

type asnRecord struct {
	ASN          uint32 `maxminddb:"autonomous_system_number"`
	Organization string `maxminddb:"autonomous_system_organization"`
}

func Open(countryPath, asnPath string) *Provider {
	return OpenSources([]SourceConfig{{
		ID:          "GEOIP_MMDB",
		Name:        "GeoIP MMDB",
		CountryPath: countryPath,
		ASNPath:     asnPath,
	}})
}

func OpenSources(configs []SourceConfig) *Provider {
	p := &Provider{}
	var loadErrors []error

	for _, config := range configs {
		countryDB, err := openDatabase(config.CountryPath, config, "country")
		if err != nil {
			loadErrors = append(loadErrors, err)
		} else if countryDB != nil {
			p.countryDBs = append(p.countryDBs, *countryDB)
		}

		asnDB, err := openDatabase(config.ASNPath, config, "ASN")
		if err != nil {
			loadErrors = append(loadErrors, err)
		} else if asnDB != nil {
			p.asnDBs = append(p.asnDBs, *asnDB)
		}
	}

	p.loadErr = joinErrors(loadErrors...)
	return p
}

func (p *Provider) Ready() Readiness {
	readiness := Readiness{
		CountryDB: len(p.countryDBs) > 0,
		ASNDB:     len(p.asnDBs) > 0,
	}
	for _, db := range p.countryDBs {
		readiness.CountrySources = append(readiness.CountrySources, db.source)
	}
	for _, db := range p.asnDBs {
		readiness.ASNSources = append(readiness.ASNSources, db.source)
	}
	return readiness
}

func (p *Provider) LoadError() error {
	return p.loadErr
}

func (p *Provider) Lookup(addr netip.Addr) (Result, error) {
	if !p.Ready().Ready() {
		return Result{}, ErrNotReady
	}

	ip := net.IP(addr.AsSlice())
	result := Result{
		Country:   model.CountryInfo{Status: model.StatusUnknown},
		ASNStatus: model.StatusUnknown,
		Agreement: model.AgreementInfo{
			Country: model.AgreementInsufficient,
			ASN:     model.AgreementInsufficient,
		},
	}

	var countryErrors []error
	var countryValues []string
	for _, db := range p.countryDBs {
		var record countryRecord
		if err := db.reader.Lookup(ip, &record); err != nil {
			countryErrors = append(countryErrors, fmt.Errorf("%s country lookup: %w", db.source.ID, err))
			continue
		}
		code := strings.ToUpper(record.Country.ISOCode)
		if code == "" {
			continue
		}
		countryValues = append(countryValues, code)
		if result.Country.Status == model.StatusUnknown {
			result.Country = model.CountryInfo{
				Code:          code,
				Status:        model.StatusKnown,
				MainlandChina: code == "CN",
				Source:        db.source.ID,
			}
		}
	}
	if result.Country.Status == model.StatusUnknown && len(countryErrors) == len(p.countryDBs) {
		return Result{}, joinErrors(countryErrors...)
	}
	result.Agreement.Country = agreement(countryValues)

	var asnErrors []error
	var asnValues []uint32
	for _, db := range p.asnDBs {
		var record asnRecord
		if err := db.reader.Lookup(ip, &record); err != nil {
			asnErrors = append(asnErrors, fmt.Errorf("%s ASN lookup: %w", db.source.ID, err))
			continue
		}
		if record.ASN == 0 {
			continue
		}
		asnValues = append(asnValues, record.ASN)
		if result.ASNStatus == model.StatusUnknown {
			result.ASN = record.ASN
			result.ASNName = record.Organization
			result.ASNStatus = model.StatusKnown
			result.ASNSource = db.source.ID
		}
	}
	if result.ASNStatus == model.StatusUnknown && len(asnErrors) == len(p.asnDBs) {
		return Result{}, joinErrors(asnErrors...)
	}
	result.Agreement.ASN = agreement(asnValues)
	return result, nil
}

func (p *Provider) Close() error {
	var closeErrors []error
	for _, db := range p.countryDBs {
		closeErrors = append(closeErrors, db.reader.Close())
	}
	for _, db := range p.asnDBs {
		closeErrors = append(closeErrors, db.reader.Close())
	}
	return joinErrors(closeErrors...)
}

func openDatabase(path string, config SourceConfig, kind string) (*database, error) {
	if path == "" {
		return nil, nil
	}
	reader, err := maxminddb.Open(path)
	if err != nil {
		if config.Optional && errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("%s %s database: %w", config.ID, kind, err)
	}
	return &database{
		reader: reader,
		source: model.DataSource{
			ID:        config.ID,
			Name:      config.Name,
			URL:       config.URL,
			BuildTime: time.Unix(int64(reader.Metadata.BuildEpoch), 0).UTC().Format(time.RFC3339),
		},
	}, nil
}

func joinErrors(errs ...error) error {
	messages := make([]string, 0, len(errs))
	for _, err := range errs {
		if err != nil {
			messages = append(messages, err.Error())
		}
	}
	if len(messages) == 0 {
		return nil
	}
	return errors.New(strings.Join(messages, "; "))
}

func agreement[T comparable](values []T) model.AgreementStatus {
	if len(values) < 2 {
		return model.AgreementInsufficient
	}
	first := values[0]
	for _, value := range values[1:] {
		if value != first {
			return model.AgreementDisagree
		}
	}
	return model.AgreementAgree
}
