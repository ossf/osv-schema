package ecosystem

import (
	"strings"

	"github.com/ossf/osv-schema/constants"
)

type Parsed struct {
	Ecosystem constants.Ecosystem
	Suffix    string
}

func (p *Parsed) String() string {
	str := string(p.Ecosystem)

	if p.Suffix != "" {
		str += ":" + p.Suffix
	}

	return str
}

// Parse parses a string into a constants.Ecosystem and an optional suffix specified with a ":"
func Parse(str string) Parsed {
	ecosystem, suffix, _ := strings.Cut(str, ":")

	return Parsed{constants.Ecosystem(ecosystem), suffix}
}
