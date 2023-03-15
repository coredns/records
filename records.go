package records

import (
	"context"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/upstream"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
)

const maxCnameStackDepth = 10

// Records is the plugin handler.
type Records struct {
	origins  []string // for easy matching, these strings are the index in the map m.
	m        map[string][]dns.RR
	upstream *upstream.Upstream

	Next plugin.Handler
}

// ServeDNS implements the plugin.Handle interface.
func (re *Records) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}
	qname := state.Name()
	zone := plugin.Zones(re.origins).Matches(qname)
	if zone == "" {
		return plugin.NextOrFailure(re.Name(), re.Next, ctx, w, r)
	}

	// New we should have some data for this zone, as we just have a list of RR, iterate through them, find the qname
	// and see if the qtype exists. If so reply, if not do the normal DNS thing and return either NXDOMAIN or NODATA.
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	nxdomain := true
	// cnameMaybeUpstream tracks whether we are currently trying to resolve a CNAME. We always look for a match among
	// the records handled by this plugin first, then we go upstream. This is required to enforce stack depth and loop
	// detection.
	cnameMaybeUpstream := false
	var soa dns.RR
	cnameStack := make(map[string]struct{}, 0)

resolveLoop:
	for _, r := range re.m[zone] {
		if _, ok := cnameStack[qname]; ok {
			log.Errorf("detected loop in CNAME chain, name [%s] already processed", qname)
			goto servfail
		}
		if len(cnameStack) > maxCnameStackDepth {
			log.Errorf("maximum CNAME stack depth of %d exceeded", maxCnameStackDepth)
			goto servfail
		}

		if r.Header().Rrtype == dns.TypeSOA && soa == nil {
			soa = r
		}
		if r.Header().Name == qname {
			nxdomain = false
			if r.Header().Rrtype == state.QType() || r.Header().Rrtype == dns.TypeCNAME {
				m.Answer = append(m.Answer, r)
			}
			if r.Header().Rrtype == dns.TypeCNAME {
				cnameStack[qname] = struct{}{}
				qname = r.(*dns.CNAME).Target
				cnameMaybeUpstream = true
				// restart resolution with new query name
				goto resolveLoop
			} else {
				// If we found a match but the record type in the zone we control isn't
				// another CNAME, that means we have reached the end of our chain and we
				// don't need to go upstream.
				cnameMaybeUpstream = false
			}
		}
	}

	if cnameMaybeUpstream {
		// we've found a CNAME but it doesn't point to a record managed by this
		// plugin. In these cases we always restart with upstream.
		msgs, err := re.upstream.Lookup(ctx, state, qname, state.QType())
		if err == nil && len(msgs.Answer) > 0 {
			for _, ans := range msgs.Answer {
				m.Answer = append(m.Answer, ans)
			}
		}
	}

	// handle NXDOMAIN, NODATA and normal response here.
	if nxdomain {
		m.Rcode = dns.RcodeNameError
		if soa != nil {
			m.Ns = []dns.RR{soa}
		}
		w.WriteMsg(m)
		return dns.RcodeSuccess, nil
	}

	if len(m.Answer) == 0 {
		if soa != nil {
			m.Ns = []dns.RR{soa}
		}
	}

	w.WriteMsg(m)
	return dns.RcodeSuccess, nil

servfail:
	m.Rcode = dns.RcodeServerFailure
	m.Answer = nil
	if soa != nil {
		m.Ns = []dns.RR{soa}
	}
	w.WriteMsg(m)
	return dns.RcodeServerFailure, nil
}

// Name implements the plugin.Handle interface.
func (re *Records) Name() string { return "records" }

// New returns a pointer to a new and intialized Records.
func New() *Records {
	re := &Records{
		m: make(map[string][]dns.RR),
		upstream: upstream.New(),
	}
	return re
}
