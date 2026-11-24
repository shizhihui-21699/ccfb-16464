package risk

import (
	"regexp"
	"sync"
	"time"
)

// timeNow is a seam for tests. Production always uses time.Now.
func timeNow() time.Time { return time.Now() }

var (
	patternMu    sync.Mutex
	patternCache = map[string]*regexp.Regexp{}
)

// matchesPattern compiles (and caches) a config pattern. Validation has
// already checked that every pattern compiles, so a failure here means the
// pattern was added programmatically; returning false is the safe answer.
func matchesPattern(pattern, s string) bool {
	patternMu.Lock()
	re, ok := patternCache[pattern]
	if !ok {
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			patternMu.Unlock()
			return false
		}
		re = compiled
		patternCache[pattern] = re
	}
	patternMu.Unlock()
	return re.MatchString(s)
}
