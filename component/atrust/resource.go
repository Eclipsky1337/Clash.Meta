package atrust

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

type clientResource struct {
	Data struct {
		AppList struct {
			Data struct {
				AppInfo []struct {
					Apps []appResource
				}
				Config struct {
					NodeGroupConf struct {
						MajorNodeGroup struct {
							ID string
						}
						NodeGroupList []struct {
							AddressInfo []struct {
								Address string
								Type    string
							}
							ID string
						}
					}
				}
			}
		}
		SDPPolicy struct {
			Data struct {
				ClientOption struct {
					DNSOption struct {
						FirstDNS  string
						SecondDNS string
					}
					DNSOptionV2 struct {
						FirstDNS  string
						SecondDNS string
					}
				}
			}
		}
	}
}

type appResource struct {
	AppID     string            `json:"id"`
	GroupID   string            `json:"nodeGroupID"`
	Model     string            `json:"accessModel"`
	PreferL3  bool              `json:"enableTCPPrefL3"`
	Pretend   any               `json:"addrPretend"`
	Addresses []addressResource `json:"addressList"`
}

type addressResource struct {
	Proto     string   `json:"protocol"`
	PortRange string   `json:"port"`
	Target    string   `json:"host"`
	IPs       []string `json:"ip"`
}

type resourceIndex struct {
	ipResources []IPResource
	domains     []domainEntry
	dns         map[string][]netip.Addr
	dnsServers  []string
	nodeGroups  map[string]NodeGroup
	majorGroup  string
	snapshot    Snapshot
}

type domainEntry struct {
	Domain          string
	PortMin         int
	PortMax         int
	Protocol        string
	AppID           string
	NodeGroupID     string
	EnableTCPPrefL3 bool
	AddrPretend     bool
}

type NodeGroup struct {
	WAN []string
	LAN []string
}

func parseResource(data []byte, server string) (*resourceIndex, error) {
	var raw clientResource
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse aTrust client resource: %w", err)
	}
	index := &resourceIndex{
		dns:        map[string][]netip.Addr{},
		nodeGroups: map[string]NodeGroup{},
	}
	for _, app := range raw.Data.AppList.Data.AppInfo {
		for _, item := range app.Apps {
			if item.Model != "L3VPN" {
				continue
			}
			for _, address := range item.Addresses {
				if address.Proto != "tcp" && address.Proto != "udp" && address.Proto != "all" {
					continue
				}
				portMin, portMax, err := parsePortRange(address.PortRange)
				if err != nil {
					continue
				}
				host := strings.TrimSpace(address.Target)
				if host == "" {
					continue
				}
				entry := IPResource{
					PortMin:         portMin,
					PortMax:         portMax,
					Protocol:        address.Proto,
					AppID:           item.AppID,
					NodeGroupID:     item.GroupID,
					EnableTCPPrefL3: item.PreferL3,
				}
				switch {
				case parseHostRange(host, &entry):
					index.ipResources = append(index.ipResources, entry)
				case isDomainHost(host):
					domain := normalizeDomain(host)
					if domain == "" {
						continue
					}
					index.domains = append(index.domains, domainEntry{
						Domain:          domain,
						PortMin:         portMin,
						PortMax:         portMax,
						Protocol:        address.Proto,
						AppID:           item.AppID,
						NodeGroupID:     item.GroupID,
						EnableTCPPrefL3: item.PreferL3,
						AddrPretend:     addrPretend(item.Pretend),
					})
					for _, ipText := range address.IPs {
						ip, err := netip.ParseAddr(ipText)
						if err == nil && ip.Is4() {
							index.dns[domain] = append(index.dns[domain], ip)
							index.ipResources = append(index.ipResources, IPResource{
								IPMin:           ip,
								IPMax:           ip,
								PortMin:         portMin,
								PortMax:         portMax,
								Protocol:        address.Proto,
								AppID:           item.AppID,
								NodeGroupID:     item.GroupID,
								EnableTCPPrefL3: item.PreferL3,
							})
						}
					}
				}
			}
		}
	}
	index.nodeGroups, index.majorGroup = parseNodeGroups(raw, server)
	index.dnsServers = parseDNSServers(raw)
	index.snapshot = buildSnapshot(index)
	return index, nil
}

func parsePortRange(text string) (int, int, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return 0, 0, fmt.Errorf("empty port")
	}
	if strings.Contains(text, "-") {
		parts := strings.SplitN(text, "-", 2)
		minPort, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil {
			return 0, 0, err
		}
		maxPort, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil {
			return 0, 0, err
		}
		return minPort, maxPort, nil
	}
	port, err := strconv.Atoi(text)
	if err != nil {
		return 0, 0, err
	}
	return port, port, nil
}

func parseHostRange(host string, entry *IPResource) bool {
	if ip, err := netip.ParseAddr(host); err == nil {
		if !ip.Is4() {
			return false
		}
		entry.IPMin, entry.IPMax = ip, ip
		return true
	}
	if prefix, err := netip.ParsePrefix(host); err == nil {
		prefix = prefix.Masked()
		if !prefix.Addr().Is4() {
			return false
		}
		entry.IPMin = prefix.Addr()
		entry.IPMax = lastAddr(prefix)
		return true
	}
	if strings.Contains(host, "-") {
		parts := strings.SplitN(host, "-", 2)
		minIP, err1 := netip.ParseAddr(strings.TrimSpace(parts[0]))
		maxIP, err2 := netip.ParseAddr(strings.TrimSpace(parts[1]))
		if err1 == nil && err2 == nil && minIP.Is4() && maxIP.Is4() {
			entry.IPMin, entry.IPMax = minIP, maxIP
			return true
		}
	}
	return false
}

func lastAddr(prefix netip.Prefix) netip.Addr {
	addr := prefix.Addr().As4()
	bits := prefix.Bits()
	for i := bits; i < 32; i++ {
		addr[i/8] |= 1 << (7 - uint(i%8))
	}
	return netip.AddrFrom4(addr)
}

func isDomainHost(host string) bool {
	if _, err := netip.ParseAddr(host); err == nil {
		return false
	}
	if _, err := netip.ParsePrefix(host); err == nil {
		return false
	}
	return !strings.Contains(host, "/")
}

func normalizeDomain(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	host = strings.TrimPrefix(host, "*.")
	host = strings.TrimPrefix(host, ".")
	if host == "" || strings.ContainsAny(host, "* /") {
		return ""
	}
	return host
}

func addrPretend(value any) bool {
	if b, ok := value.(bool); ok {
		return b
	}
	return true
}

func parseNodeGroups(raw clientResource, server string) (map[string]NodeGroup, string) {
	conf := raw.Data.AppList.Data.Config.NodeGroupConf
	groups := make(map[string]NodeGroup, len(conf.NodeGroupList))
	for _, group := range conf.NodeGroupList {
		var parsed NodeGroup
		for _, info := range group.AddressInfo {
			address := info.Address
			if address == "{{sdpcHost}}" {
				address = server
			}
			if !strings.Contains(address, ":") {
				address += ":441"
			}
			switch strings.ToLower(info.Type) {
			case "wan":
				parsed.WAN = append(parsed.WAN, address)
			case "lan":
				parsed.LAN = append(parsed.LAN, address)
			}
		}
		groups[group.ID] = parsed
	}
	return groups, conf.MajorNodeGroup.ID
}

func parseDNSServers(raw clientResource) []string {
	option := raw.Data.SDPPolicy.Data.ClientOption.DNSOption
	if option.FirstDNS == "" {
		option = raw.Data.SDPPolicy.Data.ClientOption.DNSOptionV2
	}
	var servers []string
	for _, server := range []string{option.FirstDNS, option.SecondDNS} {
		if server != "" {
			servers = append(servers, server)
		}
	}
	return servers
}

func buildSnapshot(index *resourceIndex) Snapshot {
	domainSet := map[string]struct{}{}
	for _, entry := range index.domains {
		domainSet[entry.Domain] = struct{}{}
	}
	domains := make([]string, 0, len(domainSet))
	for domain := range domainSet {
		domains = append(domains, "+."+domain)
	}
	sort.Strings(domains)

	cidrSet := map[string]struct{}{}
	for _, resource := range index.ipResources {
		if resource.IPMin == resource.IPMax {
			cidrSet[resource.IPMin.String()+"/32"] = struct{}{}
			continue
		}
		prefixes := rangeToPrefixes(resource.IPMin, resource.IPMax)
		for _, prefix := range prefixes {
			cidrSet[prefix.String()] = struct{}{}
		}
	}
	cidrs := make([]string, 0, len(cidrSet))
	for cidr := range cidrSet {
		cidrs = append(cidrs, cidr)
	}
	sort.Strings(cidrs)
	return Snapshot{Domains: domains, CIDRs: cidrs}
}

func rangeToPrefixes(minIP, maxIP netip.Addr) []netip.Prefix {
	if !minIP.Is4() || !maxIP.Is4() || minIP.Compare(maxIP) > 0 {
		return nil
	}
	var prefixes []netip.Prefix
	current := minIP
	for current.Compare(maxIP) <= 0 {
		bits := 32
		for bits > 0 {
			candidate := netip.PrefixFrom(current, bits-1).Masked()
			if candidate.Addr() != current {
				break
			}
			if lastAddr(candidate).Compare(maxIP) > 0 {
				break
			}
			bits--
		}
		prefix := netip.PrefixFrom(current, bits).Masked()
		prefixes = append(prefixes, prefix)
		last := lastAddr(prefix)
		next, ok := nextAddr(last)
		if !ok {
			break
		}
		current = next
	}
	return prefixes
}

func nextAddr(addr netip.Addr) (netip.Addr, bool) {
	bytes := addr.As4()
	for i := 3; i >= 0; i-- {
		bytes[i]++
		if bytes[i] != 0 {
			return netip.AddrFrom4(bytes), true
		}
	}
	return netip.Addr{}, false
}

func (r *resourceIndex) matchDomain(host string, port int, protocol string) (domainEntry, bool) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	var best domainEntry
	found := false
	for _, entry := range r.domains {
		if host != entry.Domain && !strings.HasSuffix(host, "."+entry.Domain) {
			continue
		}
		if !portMatches(entry.PortMin, entry.PortMax, port) || !protocolMatches(entry.Protocol, protocol) {
			continue
		}
		if !found || len(entry.Domain) > len(best.Domain) {
			best = entry
			found = true
		}
	}
	return best, found
}

func (r *resourceIndex) matchIP(ip netip.Addr, port int, protocol string) (IPResource, bool) {
	if !ip.IsValid() {
		return IPResource{}, false
	}
	ip = ip.Unmap()
	var best IPResource
	found := false
	bestSpan := ^uint64(0)
	for _, resource := range r.ipResources {
		if ip.Compare(resource.IPMin) < 0 || ip.Compare(resource.IPMax) > 0 {
			continue
		}
		if !portMatches(resource.PortMin, resource.PortMax, port) || !protocolMatches(resource.Protocol, protocol) {
			continue
		}
		span := ipRangeSpan(resource)
		if !found || span <= bestSpan {
			best = resource
			bestSpan = span
			found = true
		}
	}
	return best, found
}

func ipRangeSpan(resource IPResource) uint64 {
	minBytes := resource.IPMin.As4()
	maxBytes := resource.IPMax.As4()
	minAddr := binary.BigEndian.Uint32(minBytes[:])
	maxAddr := binary.BigEndian.Uint32(maxBytes[:])
	return uint64(maxAddr - minAddr)
}

func portMatches(minPort, maxPort, port int) bool {
	if minPort == 0 && maxPort == 0 {
		return true
	}
	return port >= minPort && port <= maxPort
}

func protocolMatches(resource, actual string) bool {
	return resource == "all" || resource == actual
}
