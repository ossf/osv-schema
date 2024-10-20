package ecosystem

import (
	"strings"

	"github.com/ossf/osv-schema/packages/go/constants"
)

type Parsed struct {
	Ecosystem constants.Ecosystem
	Suffix    string
}

// UnmarshalJSON handles unmarshalls a JSON string into a Parsed struct.
//
// This method implements the json.Unmarshaler interface.
//
//goland:noinspection GoMixedReceiverTypes
func (p *Parsed) UnmarshalJSON(data []byte) error {
	*p = Parse(strings.Trim(string(data), "\""))

	return nil
}

// MarshalJSON handles marshals a Parsed struct into a JSON string.
//
// This method implements the json.Marshaler interface.
//
//goland:noinspection GoMixedReceiverTypes
func (p Parsed) MarshalJSON() ([]byte, error) {
	return []byte(`"` + p.String() + `"`), nil
}

//goland:noinspection GoMixedReceiverTypes
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
