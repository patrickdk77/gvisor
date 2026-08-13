package confine

import "testing"

// Adjacent wildcards on a non-matching path are what made the rule-walk
// fallback take milliseconds per check.
func BenchmarkPathologicalWildcards(b *testing.B) {
	for _, tc := range []struct {
		name    string
		pattern string
		path    string
	}{
		{"ten-stars", "/a/*/*/*/*/*/*/*/*/*/*/zzz", "/a/bb/cc/dd/ee/ff/gg/hh/ii/jj/kk/no"},
		{"five-doublestars", "/a/**/**/**/**/**/zzz", "/a/bb/cc/dd/ee/ff/gg/hh/ii/jj/kk/no"},
		{"adjacent-run", "/a/**********/zzz", "/a/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/no"},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if MatchPattern(tc.pattern, tc.path) {
					b.Fatal("unexpected match")
				}
			}
		})
	}
}
