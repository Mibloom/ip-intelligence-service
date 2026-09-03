# IP Intelligence Service

[简体中文](README.md) | [English](README.en.md)

A lightweight, read-only HTTP service for IP intelligence. It uses local MMDB
databases to identify country and ASN information, official cloud-provider CIDR
ranges plus maintainable ASN rules to recognize common cloud networks, and
Spamhaus DROP data to identify high-confidence malicious networks. Lookups do
not call third-party APIs.

## Capabilities and limitations

- IPv4 and IPv6
- Treats `CN` as mainland China; `HK`, `MO`, and `TW` are not treated as mainland China
- ASN and ASN organization name
- GeoLite2 as an optional primary source, with DB-IP Lite as the fallback for missing records
- Simultaneous MaxMind and DB-IP lookups with Country/ASN agreement reporting
- Classification of public, private, loopback, link-local, CGNAT, documentation, benchmark, multicast, and other address scopes
- Official cloud-provider CIDR matching first, with ASN-based inference as a secondary signal
- Independent `KNOWN` / `UNKNOWN` status for country and ASN, so unknown addresses are not treated as foreign addresses
- `HIGH` / `MEDIUM` / `LOW` confidence for cloud classification
- CIDR and ASN matching against Spamhaus DROP, DROPv6, and ASN-DROP, including the matching evidence
- Unmatched ASNs remain `UNKNOWN` instead of being labeled as residential or ISP networks without evidence
- No VPN, proxy, Tor, dynamic risk-score, or business-level blocking decisions

Cloud-IP classification is not absolute. An official CIDR match has `HIGH`
confidence, an ASN match has `MEDIUM` confidence, and an unmatched address
returns `cloud=false + LOW + NONE`. An unmatched result means that there is no
current evidence of cloud hosting; it does not prove that the address is not a
cloud IP. Small data centers, newly assigned provider ASNs, BYOIP, and shared
ASNs may cause false negatives or false positives. Consumers should use this as
a risk signal rather than as the sole basis for blocking.

Threat classification likewise reports only whether the address appears in the
currently loaded dataset. `threat.listed=false` means that the address is not in
the current Spamhaus DROP-family lists; it does not mean the address is safe.
`listed=true + level=HIGH + confidence=HIGH` can be used as a hard-block or
strong rate-limit signal, but production users should retain an allowlist and a
rollback switch. This service does not return `allow` or `block` decisions.

## Data

Geolocation sources are queried in this order:

1. [MaxMind GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/) Country / ASN, as the optional primary source.
2. [DB-IP Lite](https://db-ip.com) Country / ASN, as the default fallback under CC BY 4.0.

GeoLite2 requires a MaxMind Account ID and License Key. If GeoLite2 is not
installed, the service uses DB-IP directly without affecting readiness. The
source that actually supplied a result is returned in `country.source` and
`network.source`; loaded database versions are shown by `/ready`.

The cloud CIDR updater currently reads official public ranges from AWS, Google
Cloud, Cloudflare, and Oracle Cloud. Other providers are inferred from ASN rules
with lower confidence. Azure CIDRs and Tor exit nodes are not currently
integrated.

Threat data comes from the `drop_v4.json`, `drop_v6.json`, and `asndrop.json`
feeds published by [Spamhaus DROP](https://www.spamhaus.org/blocklists/do-not-route-or-peer/).
The updater validates each feed's metadata record count and preserves the
source URL, update time, copyright notice, and terms in the generated
`threat.json` file.

Download DB-IP, official cloud CIDRs, and Spamhaus threat data:

```bash
make data
```

If the current month's DB-IP data is not yet available, request the previous
month explicitly:

```bash
DBIP_RELEASE=2026-08 ./scripts/update-dbip.sh
```

Enable GeoLite2 as the primary source:

```bash
MAXMIND_ACCOUNT_ID=... MAXMIND_LICENSE_KEY=... make data-maxmind
```

Databases and generated cloud-CIDR and threat-data files are not committed to
Git. Update scripts validate downloads and replace target files atomically. The
container must be restarted after replacement to load the new data.

## Local development

```bash
make data
go test ./...
COUNTRY_DB_PATH="$PWD/data/geoip/country.mmdb" \
ASN_DB_PATH="$PWD/data/geoip/asn.mmdb" \
CLOUD_ASN_RULES_PATH="$PWD/data/rules/cloud-asn.json" \
CLOUD_CIDR_RULES_PATH="$PWD/data/rules/cloud-cidr.json" \
THREAT_RULES_PATH="$PWD/data/rules/threat.json" \
go run ./cmd/server
```

Docker:

```bash
make data
docker compose up -d --build
curl http://127.0.0.1:18080/ready
```

## API

Health and readiness:

```http
GET /health
GET /ready
```

Lookup:

```http
GET /v1/lookup/223.5.5.5
```

Example response:

```json
{
  "ip": "223.5.5.5",
  "scope": {
    "type": "PUBLIC",
    "globallyReachable": true
  },
  "country": {
    "code": "CN",
    "status": "KNOWN",
    "mainlandChina": true,
    "source": "MAXMIND_GEOLITE2"
  },
  "network": {
    "asn": 37963,
    "name": "Hangzhou Alibaba Advertising Co.,Ltd.",
    "type": "HOSTING",
    "status": "KNOWN",
    "source": "MAXMIND_GEOLITE2"
  },
  "cloud": {
    "cloud": true,
    "provider": "ALIYUN",
    "confidence": "MEDIUM",
    "source": "ASN"
  },
  "threat": {
    "status": "KNOWN",
    "listed": false,
    "level": "NONE",
    "confidence": "NONE",
    "categories": [],
    "matches": []
  },
  "agreement": {
    "country": "AGREE",
    "asn": "DISAGREE"
  }
}
```

An invalid IP returns HTTP 400:

```json
{"code":"INVALID_IP","message":"invalid IP address"}
```

If the GeoIP databases are not loaded, `/ready` and the lookup endpoint return
HTTP 503, while `/health` continues to report that the process is alive.
`/ready` also reports loaded sources and their build times. If threat data is
missing, GeoIP lookups remain available, `/ready.status` becomes `DEGRADED`, and
each lookup returns `threat.status=UNKNOWN` instead of pretending the address
was not listed.

Prometheus text metrics:

```http
GET /metrics
```

Metrics cover total lookups, invalid input, failures, unknown Country/ASN
results, non-public addresses, source conflicts, cloud CIDR/ASN classifications,
and threat CIDR/ASN matches, non-listed results, and unknown threat data.

## Configuration

| Environment variable | Default |
|---|---|
| `LISTEN_ADDR` | `:8080` |
| `COUNTRY_DB_PATH` | `/data/geoip/country.mmdb` |
| `ASN_DB_PATH` | `/data/geoip/asn.mmdb` |
| `MAXMIND_COUNTRY_DB_PATH` | `/data/geoip/maxmind-country.mmdb` |
| `MAXMIND_ASN_DB_PATH` | `/data/geoip/maxmind-asn.mmdb` |
| `CLOUD_ASN_RULES_PATH` | `/data/rules/cloud-asn.json` |
| `CLOUD_CIDR_RULES_PATH` | `/data/rules/cloud-cidr.json` |
| `THREAT_RULES_PATH` | `/data/rules/threat.json` |
| `READ_HEADER_TIMEOUT` | `5s` |
| `READ_TIMEOUT` | `10s` |
| `WRITE_TIMEOUT` | `10s` |
| `IDLE_TIMEOUT` | `60s` |

## Production deployment

The default Compose configuration binds the port only to the server loopback
interface instead of exposing it directly to the public network:

```bash
docker compose up -d --build
```

To make the service available to other containers, attach it to an existing
external network with a Compose override:

```yaml
services:
  ip-intelligence:
    networks:
      - app-network

networks:
  app-network:
    external: true
```

Containers on the same Docker network can use:

```text
http://ip-intelligence:8080
```

### Automatic updates

Production uses systemd timers:

- GeoLite2: check daily.
- Official AWS, Google Cloud, Cloudflare, and Oracle Cloud CIDRs: update daily.
- Spamhaus DROP, DROPv6, and ASN-DROP: update daily.
- DB-IP Lite fallback: update monthly on the third day of the month.

Install or update the timers:

```bash
install -m 0644 deploy/ip-intelligence-update@.service /etc/systemd/system/
install -m 0644 deploy/ip-intelligence-*-update.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now \
  ip-intelligence-cloud-update.timer \
  ip-intelligence-threat-update.timer \
  ip-intelligence-maxmind-update.timer \
  ip-intelligence-dbip-update.timer
```

Credentials are stored in `/etc/ip-intelligence/maxmind.env`, which must have
mode `0600`. A download or validation failure aborts the update while leaving
the running container and its currently loaded databases untouched. After a
successful update, the container is restarted and the updater waits for
`/ready` to recover.

## License and data attribution

The source code is licensed under the Apache License 2.0. GeoLite, DB-IP Lite,
Spamhaus DROP, and cloud-provider ranges remain subject to their respective data
licenses and terms; they are not covered by this project's software license.
Databases and generated intelligence snapshots are not committed to the
repository. See [NOTICE](NOTICE) for complete attribution.
