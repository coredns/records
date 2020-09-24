package records

import (
	"testing"

	"github.com/caddyserver/caddy"
)

func TestRecordsParse(t *testing.T) {
	tests := []struct {
		input           string
		shouldErr       bool
		expectedOrigins []string
	}{
		{
			`records {
			@ IN MX 10 mx1.example.org.
			}
`,
			false, []string{"."},
		},
	}

	for i, test := range tests {
		c := caddy.NewTestController("dns", test.input)
		re, err := recordsParse(c)

		if err == nil && test.shouldErr {
			t.Fatalf("Test %d expected errors, but got no error", i)
		} else if err != nil && !test.shouldErr {
			t.Fatalf("Test %d expected no errors, but got '%v'", i, err)
		} else {
			if len(re.origins) != len(test.expectedOrigins) {
				t.Fatalf("Test %d expected %v, got %v", i, test.expectedOrigins, re.origins)
			}
			for j, name := range test.expectedOrigins {
				if re.origins[j] != name {
					t.Fatalf("Test %d expected %v for %d th zone, got %v", i, name, j, re.origins[j])
				}
			}
		}
	}
}
