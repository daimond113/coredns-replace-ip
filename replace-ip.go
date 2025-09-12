package replace_ip

import (
	"context"
	"fmt"
	"time"

	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/plugin/pkg/nonwriter"
	"github.com/coredns/coredns/plugin/pkg/response"

	"github.com/miekg/dns"

	"net/netip"
)

var log = clog.NewWithPlugin("replace-ip")

type ReplaceIp struct {
	Next plugin.Handler
	Ips  map[netip.Addr]netip.Addr
}

func (r ReplaceIp) Ready() bool { return true }

func (ri ReplaceIp) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	nw := nonwriter.New(w)

	rcode, err := plugin.NextOrFailure(ri.Name(), ri.Next, ctx, nw, r)
	if err != nil {
		return rcode, err
	}

	ty, _ := response.Typify(nw.Msg, time.Now().UTC())

	if ty != response.NoError {
		w.WriteMsg(nw.Msg)
		cl := response.Classify(ty)
		if cl == response.Denial || cl == response.Error || ty == response.Delegation {
			return 0, nil
		} else {
			return 0, plugin.Error("minimal", fmt.Errorf("unhandled response type %q for %q", ty, nw.Msg.Question[0].Name))
		}
	}

	d := nw.Msg.Copy()

	for _, rr := range d.Answer {
		if a, ok := rr.(*dns.A); ok {
			ip, _ := netip.AddrFromSlice(a.A)
			if replaced, found := ri.Ips[ip]; found {
				a.A = replaced.AsSlice()
			}
		} else if aaaa, ok := rr.(*dns.AAAA); ok {
			ip, _ := netip.AddrFromSlice(aaaa.AAAA)
			if replaced, found := ri.Ips[ip]; found {
				aaaa.AAAA = replaced.AsSlice()
			}
		}
	}

	w.WriteMsg(d)
	return 0, nil
}

func (r ReplaceIp) Name() string { return "replace-ip" }
