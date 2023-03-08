package records

import (
	"context"
	"testing"

	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"

	"github.com/coredns/caddy"
	"github.com/miekg/dns"
)

func TestLookup(t *testing.T) {
	const input = `
records {
        example.org.   60  IN SOA ns.icann.org. noc.dns.icann.org. 2020091001 7200 3600 1209600 3600
        example.org.   60  IN MX 10 mx.example.org.
        mx.example.org. 60 IN A  127.0.0.1
}
`

	c := caddy.NewTestController("dns", input)
	re, err := recordsParse(c)
	if err != nil {
		t.Fatal(err)
	}

	for i, tc := range testCases {
		m := tc.Msg()

		rec := dnstest.NewRecorder(&test.ResponseWriter{})
		_, err := re.ServeDNS(context.Background(), rec, m)
		if err != nil {
			t.Errorf("Test %d, expected no error, got %v", i, err)
			return
		}

		if rec.Msg.Rcode != tc.Rcode {
			t.Errorf("Test %d, expected rcode is %d, but got %d", i, tc.Rcode, rec.Msg.Rcode)
			return
		}

		if resp := rec.Msg; rec.Msg != nil {
			if err := test.SortAndCheck(resp, tc); err != nil {
				t.Errorf("Test %d: %v", i, err)
			}
		}
	}
}

var testCases = []test.Case{
	{
		Qname: "mx.example.org.", Qtype: dns.TypeA,
		Answer: []dns.RR{
			test.A("mx.example.org. 60	IN	A 127.0.0.1"),
		},
	},
	{
		Rcode: dns.RcodeNameError,
		Qname: "bla.example.org.", Qtype: dns.TypeA,
		Ns: []dns.RR{
			test.SOA("example.org.   60  IN SOA ns.icann.org. noc.dns.icann.org. 2020091001 7200 3600 1209600 3600"),
		},
	},
	{
		Qname: "mx.example.org.", Qtype: dns.TypeAAAA,
		Ns: []dns.RR{
			test.SOA("example.org.   60  IN SOA ns.icann.org. noc.dns.icann.org. 2020091001 7200 3600 1209600 3600"),
		},
	},
}

func TestLookupNoSOA(t *testing.T) {
	const input = `
records {
        example.org.                60    IN    MX       10 mx.example.org.
        mx.example.org.             60    IN    A        127.0.0.1
        cname.example.org.          60    IN    CNAME    mx.example.org.
        cnameloop1.example.org.     60    IN    CNAME    cnameloop2.example.org.
        cnameloop2.example.org.     60    IN    CNAME    cnameloop1.example.org.
        cnameext.example.org.       60    IN    CNAME    mx.example.net.

        cnamedepth.example.org.     60    IN    CNAME    cnamedepth1.example.org.
        cnamedepth1.example.org.    60    IN    CNAME    cnamedepth2.example.org.
        cnamedepth2.example.org.    60    IN    CNAME    cnamedepth3.example.org.
        cnamedepth3.example.org.    60    IN    CNAME    cnamedepth4.example.org.
        cnamedepth4.example.org.    60    IN    CNAME    cnamedepth5.example.org.
        cnamedepth5.example.org.    60    IN    CNAME    cnamedepth6.example.org.
        cnamedepth6.example.org.    60    IN    CNAME    cnamedepth7.example.org.
        cnamedepth7.example.org.    60    IN    CNAME    cnamedepth8.example.org.
        cnamedepth8.example.org.    60    IN    CNAME    cnamedepth9.example.org.
        cnamedepth9.example.org.    60    IN    CNAME    cnamedepth10.example.org.
        cnamedepth10.example.org.   60    IN    CNAME    cnamedepth11.example.org.
        cnamedepth11.example.org.   60    IN    A        127.0.0.1
}
`

	c := caddy.NewTestController("dns", input)
	re, err := recordsParse(c)
	if err != nil {
		t.Fatal(err)
	}

	for i, tc := range testCasesNoSOA {
		m := tc.Msg()

		rec := dnstest.NewRecorder(&test.ResponseWriter{})
		_, err := re.ServeDNS(context.Background(), rec, m)
		if err != nil {
			t.Errorf("Test %d, expected no error, got %v", i, err)
			return
		}

		if rec.Msg.Rcode != tc.Rcode {
			t.Errorf("Test %d, expected rcode is %d, but got %d", i, tc.Rcode, rec.Msg.Rcode)
			return
		}

		if resp := rec.Msg; rec.Msg != nil {
			if err := test.SortAndCheck(resp, tc); err != nil {
				t.Errorf("Test %d: %v", i, err)
			}
		}
	}
}

var testCasesNoSOA = []test.Case{
	{
		Qname: "mx.example.org.", Qtype: dns.TypeA,
		Answer: []dns.RR{
			test.A("mx.example.org. 60	IN	A 127.0.0.1"),
		},
	},
	{
		Rcode: dns.RcodeNameError,
		Qname: "bla.example.org.", Qtype: dns.TypeA,
	},
	{
		Qname: "mx.example.org.", Qtype: dns.TypeAAAA,
	},
	{
		Qname: "cname.example.org.", Qtype: dns.TypeA,
		Answer: []dns.RR{
			test.CNAME("cname.example.org.	60	IN CNAME	mx.example.org."),
			test.A("mx.example.org.	60	IN A	127.0.0.1"),
		},
	},
	{
		Qname: "cnameext.example.org.", Qtype: dns.TypeA,
		Answer: []dns.RR{
			test.CNAME("cnameext.example.org.	60	IN CNAME	mx.example.net."),
		},
	},
	{
		Rcode: dns.RcodeServerFailure,
		Qname: "cnameloop1.example.org.", Qtype: dns.TypeA,
	},
	{
		Rcode: dns.RcodeServerFailure,
		Qname: "cnamedepth.example.org.", Qtype: dns.TypeA,
	},
}

func TestLookupMultipleOrigins(t *testing.T) {
	const input = `
records example.org example.net {
        @ 60  IN MX 10 mx
        mx 60 IN A  127.0.0.1
}
`

	c := caddy.NewTestController("dns", input)
	re, err := recordsParse(c)
	if err != nil {
		t.Fatal(err)
	}

	for i, tc := range testCasesMultipleOrigins {
		m := tc.Msg()

		rec := dnstest.NewRecorder(&test.ResponseWriter{})
		_, err := re.ServeDNS(context.Background(), rec, m)
		if err != nil {
			t.Errorf("Test %d, expected no error, got %v", i, err)
			return
		}

		if rec.Msg.Rcode != tc.Rcode {
			t.Errorf("Test %d, expected rcode is %d, but got %d", i, tc.Rcode, rec.Msg.Rcode)
			return
		}

		if resp := rec.Msg; rec.Msg != nil {
			if err := test.SortAndCheck(resp, tc); err != nil {
				t.Errorf("Test %d: %v", i, err)
			}
		}
	}
}

var testCasesMultipleOrigins = []test.Case{
	{
		Qname: "mx.example.org.", Qtype: dns.TypeA,
		Answer: []dns.RR{
			test.A("mx.example.org. 60	IN	A 127.0.0.1"),
		},
	},
	{
		Qname: "mx.example.net.", Qtype: dns.TypeA,
		Answer: []dns.RR{
			test.A("mx.example.net. 60	IN	A 127.0.0.1"),
		},
	},
}
