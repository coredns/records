package records

import (
	"fmt"
	"strings"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"

	"github.com/miekg/dns"
)

var log = clog.NewWithPlugin("records")

func init() { plugin.Register("records", setup) }

func setup(c *caddy.Controller) error {
	re, err := recordsParse(c)
	if err != nil {
		return plugin.Error("records", err)
	}

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		re.Next = next
		return re
	})

	return nil
}

func recordsParse(c *caddy.Controller) (*Records, error) {
	re := New()

	i := 0
	for c.Next() {
		if i > 0 {
			return re, plugin.ErrOnce
		}
		i++

		// copy the server block origins, if ZONES are given we will overwrite these again
		re.origins = plugin.OriginsFromArgsOrServerBlock(c.RemainingArgs(), c.ServerBlockKeys)

		if len(re.origins) == 0 { // do we really need this default, just in the tests?
			re.origins = []string{"."}
		}

		// c.Val() +  c.RemainingArgs() is the record we need to parse (for each zone given; now tracked in re.origins). When parsing
		// the record we just set the ORIGIN to the correct value and magic will happen. If no origin we set it to "."

	parseBlocks:
		for c.NextBlock() {
			s := c.Val()
			if s == "$OPTION" {
				if !c.NextArg() {
					return nil, fmt.Errorf("parsing block failed: $OPTION missing argument")
				}
				opt := c.Val()
				switch opt {
				case "fallthrough":
					re.Fall.SetZonesFromArgs(re.origins)
				default:
					return nil, fmt.Errorf("parsing block failed: unknown option: %q", opt)
				}
				if len(c.RemainingArgs()) > 0 {
					return nil, fmt.Errorf("parsing block failed: extra arguments after option %q", opt)
				}
				continue parseBlocks
			}
			s += " " + strings.Join(c.RemainingArgs(), " ")
			for _, o := range re.origins {
				rr, err := dns.NewRR("$ORIGIN " + o + "\n" + s + "\n")
				if err != nil {
					return nil, err
				}
				rr.Header().Name = strings.ToLower(rr.Header().Name)
				re.m[o] = append(re.m[o], rr)
			}
		}
	}

	return re, nil
}
