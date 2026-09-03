package classifier

import (
	"net/netip"

	"ip-intelligence-service/internal/model"
)

var (
	cgnatPrefix             = netip.MustParsePrefix("100.64.0.0/10")
	ipv4Documentation       = mustPrefixes("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
	ipv6Documentation       = mustPrefixes("2001:db8::/32")
	benchmarkPrefixes       = mustPrefixes("198.18.0.0/15", "2001:2::/48")
	ipv4ReservedPrefixes    = mustPrefixes("0.0.0.0/8", "192.0.0.0/24", "240.0.0.0/4")
	ipv6ReservedPrefixes    = mustPrefixes("100::/64")
	globallyReachableV4IANA = map[netip.Addr]struct{}{
		netip.MustParseAddr("192.0.0.9"):  {},
		netip.MustParseAddr("192.0.0.10"): {},
	}
)

func ClassifyScope(addr netip.Addr) model.ScopeInfo {
	addr = addr.Unmap()
	if addr.IsUnspecified() {
		return scope(model.ScopeUnspecified)
	}
	if addr.IsLoopback() {
		return scope(model.ScopeLoopback)
	}
	if addr.IsPrivate() {
		return scope(model.ScopePrivate)
	}
	if addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() {
		return scope(model.ScopeLinkLocal)
	}
	if addr.IsMulticast() {
		return scope(model.ScopeMulticast)
	}
	if addr == netip.MustParseAddr("255.255.255.255") {
		return scope(model.ScopeBroadcast)
	}
	if addr.Is4() && cgnatPrefix.Contains(addr) {
		return scope(model.ScopeCGNAT)
	}
	if containsAny(ipv4Documentation, addr) || containsAny(ipv6Documentation, addr) {
		return scope(model.ScopeDocumentation)
	}
	if containsAny(benchmarkPrefixes, addr) {
		return scope(model.ScopeBenchmark)
	}
	if _, ok := globallyReachableV4IANA[addr]; ok {
		return model.ScopeInfo{Type: model.ScopePublic, GloballyReachable: true}
	}
	if containsAny(ipv4ReservedPrefixes, addr) || containsAny(ipv6ReservedPrefixes, addr) || !addr.IsGlobalUnicast() {
		return scope(model.ScopeReserved)
	}
	return model.ScopeInfo{Type: model.ScopePublic, GloballyReachable: true}
}

func scope(scopeType model.IPScopeType) model.ScopeInfo {
	return model.ScopeInfo{Type: scopeType, GloballyReachable: false}
}

func containsAny(prefixes []netip.Prefix, addr netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func mustPrefixes(raw ...string) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(raw))
	for _, value := range raw {
		prefixes = append(prefixes, netip.MustParsePrefix(value))
	}
	return prefixes
}
