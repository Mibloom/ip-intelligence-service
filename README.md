# IP Intelligence Service

[简体中文](README.md) | [English](README.en.md)

一个轻量、只读的 IP 情报 HTTP 服务。服务用本地 MMDB 判断国家/地区和 ASN，用云厂商官方 CIDR 与可维护的 ASN 规则识别常见云网络，并用 Spamhaus DROP 数据识别高置信度恶意网络。查询过程不调用第三方 API。

## 能力与边界

- IPv4 / IPv6
- `CN` 视为中国大陆；`HK`、`MO`、`TW` 不视为中国大陆
- ASN 和 ASN 组织名
- GeoLite2 可作为主数据源，DB-IP Lite 在缺失记录时自动回退
- MaxMind 与 DB-IP 同时查询并返回 Country/ASN 一致性
- 公网、私网、回环、链路本地、CGNAT、文档、压测、组播等地址性质
- 云厂商官方 CIDR 优先匹配，ASN 作为次级推断
- 国家和 ASN 分别返回 `KNOWN` / `UNKNOWN`，不会把未知地址当成海外地址
- 云判断返回 `HIGH` / `MEDIUM` / `LOW` 置信度
- Spamhaus DROP、DROPv6 和 ASN-DROP 的 CIDR/ASN 匹配，返回命中事实和依据
- 未命中的 ASN 返回 `UNKNOWN`，不会武断地标成住宅/运营商网络
- 不包含 VPN、代理、Tor、动态风险评分或业务封禁决策

云 IP 识别本质上不是绝对事实。官方 CIDR 命中为 `HIGH`；ASN 命中为 `MEDIUM`；未命中返回 `cloud=false + LOW + NONE`，含义是“当前没有云证据”，不是“已经证明它不是云 IP”。小型 IDC、厂商新增 ASN、BYOIP 和共用 ASN 都可能造成漏判或误判。业务方应把结果作为风险信号，而不是唯一封禁依据。

威胁判断同样只陈述当前数据集是否命中。`threat.listed=false` 表示“不在当前 Spamhaus DROP 系列列表”，不表示该 IP 安全。`listed=true + level=HIGH + confidence=HIGH` 可作为硬拦截或强限流信号，但上线前仍应保留业务白名单和可回滚开关；本服务不返回 `allow` / `block` 决策。

## 数据

数据源按以下优先级查询：

1. [MaxMind GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/) Country / ASN（可选主数据源）。
2. [DB-IP Lite](https://db-ip.com) Country / ASN（默认回退，CC BY 4.0）。

GeoLite2 需要 MaxMind Account ID 和 License Key。未安装 GeoLite2 时服务会直接使用 DB-IP，不影响就绪状态；实际命中的数据源会分别写入 `country.source` 和 `network.source`，数据库版本在 `/ready` 中展示。

云 CIDR 更新器目前读取 AWS、Google Cloud、Cloudflare 和 Oracle Cloud 的官方公开地址范围。其他厂商通过 ASN 规则判断，置信度较低。Azure CIDR 和 Tor 出口节点尚未接入。

威胁数据来自 [Spamhaus DROP](https://www.spamhaus.org/blocklists/do-not-route-or-peer/) 的 `drop_v4.json`、`drop_v6.json` 和 `asndrop.json`。更新器校验每份文件的元数据记录数，并在生成的 `threat.json` 中保留源 URL、更新时间、版权归属与使用条款。

下载 DB-IP、官方云 CIDR 与 Spamhaus 威胁数据：

```bash
make data
```

若当月数据尚未发布，可指定上个月：

```bash
DBIP_RELEASE=2026-08 ./scripts/update-dbip.sh
```

启用 GeoLite2 主数据源：

```bash
MAXMIND_ACCOUNT_ID=... MAXMIND_LICENSE_KEY=... make data-maxmind
```

数据库和生成的云 CIDR、威胁数据文件不会提交进 Git。更新脚本校验下载内容并以重命名方式替换目标文件；替换后需要重启容器重新加载。

## 本地运行

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

Docker：

```bash
make data
docker compose up -d --build
curl http://127.0.0.1:18080/ready
```

## API

健康检查：

```http
GET /health
GET /ready
```

查询：

```http
GET /v1/lookup/223.5.5.5
```

示例响应：

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

非法 IP 返回 HTTP 400：

```json
{"code":"INVALID_IP","message":"invalid IP address"}
```

GeoIP 数据库未加载时，`/ready` 和查询接口返回 HTTP 503，进程本身仍可通过 `/health` 表明存活。`/ready` 同时返回当前已加载数据源及其构建时间。威胁数据缺失时 GeoIP 查询保持可用，`/ready.status` 为 `DEGRADED`，每次查询的 `threat.status` 为 `UNKNOWN`，不会伪装成未命中。

Prometheus 文本指标：

```http
GET /metrics
```

指标包括总查询量、非法输入、失败、Country/ASN 未知数、非公网地址数、数据源冲突数，云 CIDR/ASN 分类数量，以及威胁 CIDR/ASN 命中、未列入和数据未知数量。

## 配置

| 环境变量 | 默认值 |
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

## 生产部署

默认 Compose 配置只将端口绑定到服务器回环地址，不直接暴露到公网：

```bash
docker compose up -d --build
```

需要让其他容器访问时，可通过 Compose 覆盖文件将服务加入已有的外部网络：

```yaml
services:
  ip-intelligence:
    networks:
      - app-network

networks:
  app-network:
    external: true
```

同一 Docker 网络中的容器可通过以下地址访问：

```text
http://ip-intelligence:8080
```

### 自动更新

生产环境使用 systemd timer：

- GeoLite2：每天检查更新。
- AWS、Google Cloud、Cloudflare、Oracle Cloud 官方 CIDR：每天更新。
- Spamhaus DROP、DROPv6、ASN-DROP：每天更新。
- DB-IP Lite 回退库：每月 3 日更新。

安装或更新定时器：

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

凭证保存在 `/etc/ip-intelligence/maxmind.env`，权限必须是 `0600`。下载或校验失败时更新任务会退出，当前容器和已加载数据库保持不变；成功后容器重启并等待 `/ready` 恢复。

## 许可证与数据归属

本项目源代码使用 Apache License 2.0。GeoLite、DB-IP Lite、Spamhaus DROP
及云厂商地址范围适用各自的数据许可和使用条款，不属于本项目的软件许可。
数据库与生成的情报快照不会提交到代码仓库，完整归属说明见 [NOTICE](NOTICE)。
