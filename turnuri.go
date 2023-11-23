// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package turn

import ( //nolint:gci
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// TurnURIPattern is regular expression used to parse a TURN URI.
// ABNF syntax:
// turnURI   = scheme ":" host [ ":" port ] [ "?transport=" transport ]
// host      =  (ALPHA / DIGIT) *(ALPHA / DIGIT / "-" / ".")
// port      = *DIGIT
// scheme    = "turn" / "turns"
// transport = "udp" / "tcp"
const TurnURIPattern = `^(turn|turns)\:([A-Za-z0-9][-A-Za-z0-9\-\.]*)(\:([0-9]+))?(\?transport\=(udp|tcp))?$`

// TurnURIRegexp is the compiled regular expression to match TURN URIs.
var turnURIRegexp = regexp.MustCompile(TurnURIPattern)

// URI is the representation of a parsed TURN URI.
type URI struct {
	// Either `turn` or `turns`. Scheme is mandatory.
	Scheme string
	// TURN server address. Address is mandatory.
	Host string
	// TURN server port. Optional, defaults to 3478 for TCP and UDP transport and 5349 for TLS.
	Port int
	// TURN transport: either UDP or TCP. Optional, default is UDP.
	Transport string
}

// ParseURI parses a TURN server URI using the "Uniform Resource Identifier (URI) scheme for the Traversal Using Relays around NAT (TURN) protocol" specification in RFC7065 (https://datatracker.ietf.org/doc/html/rfc7065).
func ParseURI(uri string) (URI, error) {
	res := turnURIRegexp.FindStringSubmatch(strings.ToLower(uri))
	if res == nil {
		return URI{}, errInvalidTurnURI
	}

	turn := URI{
		Scheme:    res[1],
		Host:      res[2],
		Port:      3478,
		Transport: "udp",
	}

	if res[6] != "" {
		turn.Transport = res[6]
	}

	if res[4] != "" {
		turn.Port, _ = strconv.Atoi(res[4]) //nolint: errcheck
	} else if turn.Scheme == "turns" && turn.Transport == "tcp" {
		turn.Port = 5349
	}

	return turn, nil
}

func (u *URI) String() string {
	return fmt.Sprintf("%s:%s:%d?transport=%s", u.Scheme, u.Host, u.Port, u.Transport)
}
