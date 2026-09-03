package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ip-intelligence-service/internal/api"
	"ip-intelligence-service/internal/classifier"
	"ip-intelligence-service/internal/geoip"
	"ip-intelligence-service/internal/service"
)

const (
	defaultListenAddr       = ":8080"
	defaultCountryDB        = "/data/geoip/country.mmdb"
	defaultASNDB            = "/data/geoip/asn.mmdb"
	defaultMaxMindCountryDB = "/data/geoip/maxmind-country.mmdb"
	defaultMaxMindASNDB     = "/data/geoip/maxmind-asn.mmdb"
	defaultCloudRules       = "/data/rules/cloud-asn.json"
	defaultCloudCIDRs       = "/data/rules/cloud-cidr.json"
	defaultThreatRules      = "/data/rules/threat.json"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		if err := healthcheck(); err != nil {
			log.Print(err)
			os.Exit(1)
		}
		return
	}

	provider := geoip.OpenSources([]geoip.SourceConfig{
		{
			ID:          "MAXMIND_GEOLITE2",
			Name:        "MaxMind GeoLite2",
			URL:         "https://www.maxmind.com",
			CountryPath: env("MAXMIND_COUNTRY_DB_PATH", defaultMaxMindCountryDB),
			ASNPath:     env("MAXMIND_ASN_DB_PATH", defaultMaxMindASNDB),
			Optional:    true,
		},
		{
			ID:          "DBIP_LITE",
			Name:        "DB-IP Lite",
			URL:         "https://db-ip.com",
			CountryPath: env("COUNTRY_DB_PATH", defaultCountryDB),
			ASNPath:     env("ASN_DB_PATH", defaultASNDB),
		},
	})
	defer provider.Close()
	if err := provider.LoadError(); err != nil {
		log.Printf("geoip data is not ready: %v", err)
	}

	cloudClassifier, err := classifier.LoadWithCIDRs(
		env("CLOUD_ASN_RULES_PATH", defaultCloudRules),
		env("CLOUD_CIDR_RULES_PATH", defaultCloudCIDRs),
	)
	if err != nil {
		log.Fatalf("load cloud ASN rules: %v", err)
	}
	threatClassifier, err := classifier.LoadThreat(env("THREAT_RULES_PATH", defaultThreatRules))
	if err != nil {
		log.Fatalf("load threat rules: %v", err)
	}
	if !threatClassifier.Ready().Loaded {
		log.Printf("threat data is not ready; lookups will report threat.status=UNKNOWN")
	}

	lookupService := service.New(provider, cloudClassifier, threatClassifier)
	handler := api.NewHandler(lookupService)

	server := &http.Server{
		Addr:              env("LISTEN_ADDR", defaultListenAddr),
		Handler:           handler.Routes(),
		ReadHeaderTimeout: durationEnv("READ_HEADER_TIMEOUT", 5*time.Second),
		ReadTimeout:       durationEnv("READ_TIMEOUT", 10*time.Second),
		WriteTimeout:      durationEnv("WRITE_TIMEOUT", 10*time.Second),
		IdleTimeout:       durationEnv("IDLE_TIMEOUT", 60*time.Second),
	}

	serverErrors := make(chan error, 1)
	go func() {
		log.Printf("ip-intelligence listening on %s", server.Addr)
		serverErrors <- server.ListenAndServe()
	}()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-signals:
		log.Printf("received %s, shutting down", sig)
	case err := <-serverErrors:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("serve HTTP: %v", err)
		}
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Printf("graceful shutdown failed: %v", err)
	}
}

func healthcheck() error {
	port := env("HEALTHCHECK_PORT", "8080")
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://127.0.0.1:" + port + "/ready")
	if err != nil {
		return fmt.Errorf("ready request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ready returned %s", resp.Status)
	}
	return nil
}

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func durationEnv(name string, fallback time.Duration) time.Duration {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		log.Fatalf("invalid %s duration %q", name, value)
	}
	return duration
}
