package replace_ip

import (
	"net/netip"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
)

func init() {
	plugin.Register("replace-ip", setup)
}

func setup(c *caddy.Controller) error {
	c.Next()
	ips := make(map[netip.Addr]netip.Addr)

	for c.NextBlock() {
		for c.NextLine() {
			source, err := netip.ParseAddr(c.Val())

			if err != nil {
				return plugin.Error("replace-ip", err)
			}

			if !c.NextArg() {
				return plugin.Error("replace-ip", c.ArgErr())
			}

			destination, err := netip.ParseAddr(c.Val())

			if err != nil {
				return plugin.Error("replace-ip", err)
			}

			ips[source] = destination
		}
	}

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return ReplaceIp{Next: next, Ips: ips}
	})

	return nil
}
