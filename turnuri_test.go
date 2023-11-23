// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js
// +build !js

package turn

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTurnURI(t *testing.T) {
	// valid: no defaults
	tt := []struct {
		name, input string
		err         error
		turn        URI
	}{
		{"IPHostFull", `turn:1.2.3.4:3479?transport=udp`, nil, URI{"turn", "1.2.3.4", 3479, "udp"}},
		{"FQDNHostFull", `turn:abc.com:3479?transport=udp`, nil, URI{"turn", "abc.com", 3479, "udp"}},
		{"IPHostFullCaseInsensitive", `tuRN:1.2.3.4:3479?TRAnspORT=tCp`, nil, URI{"turn", "1.2.3.4", 3479, "tcp"}},
		{"FQDNHostFullCaseInsensitive", `TUrn:ABC.COM:3479?tranSPORT=UdP`, nil, URI{"turn", "abc.com", 3479, "udp"}},
	}

	for i := range tt {
		turn, err := ParseURI(tt[i].input)
		assert.Equal(t, err, tt[i].err, fmt.Sprintf("%s: wrong parse status", tt[i].name))
		assert.Equal(t, turn, tt[i].turn, fmt.Sprintf("%s: wrong result", tt[i].name))
		assert.Equal(t, turn.String(), strings.ToLower(tt[i].input), fmt.Sprintf("%s: wrong String() result", tt[i].name))
	}

	// valid: with defaults
	tt = []struct {
		name, input string
		err         error
		turn        URI
	}{
		{"IPHostDefaultPortTransport", `turn:1.2.3.4`, nil, URI{"turn", "1.2.3.4", 3478, "udp"}},
		{"FQDNHostDefaultPortTransport", `turn:abc.com`, nil, URI{"turn", "abc.com", 3478, "udp"}},
		{"IPHostDefaultPort", `turn:1.2.3.4?transport=tcp`, nil, URI{"turn", "1.2.3.4", 3478, "tcp"}},
		{"FQDNHostDefaultPort", `turn:abc.com?transport=tcp`, nil, URI{"turn", "abc.com", 3478, "tcp"}},
		{"IPHostDefaultTransport", `turn:1.2.3.4:1111`, nil, URI{"turn", "1.2.3.4", 1111, "udp"}},
		{"FQDNHostDefaulTransport", `turn:abc.com:1111`, nil, URI{"turn", "abc.com", 1111, "udp"}},
		{"IPHostDefaultPortTransportSecure", `turns:1.2.3.4`, nil, URI{"turns", "1.2.3.4", 3478, "udp"}},
		{"FQDNHostDefaultPortTransportSecure", `turns:abc.com`, nil, URI{"turns", "abc.com", 3478, "udp"}},
		{"IPHostDefaultPortTcpSecure", `turns:1.2.3.4?transport=tcp`, nil, URI{"turns", "1.2.3.4", 5349, "tcp"}},
		{"FQDNHostDefaultPortTcpSecure", `turns:abc.com?transport=tcp`, nil, URI{"turns", "abc.com", 5349, "tcp"}},
	}

	for i := range tt {
		turn, err := ParseURI(tt[i].input)
		assert.Equal(t, err, tt[i].err, fmt.Sprintf("%s: wrong parse status", tt[i].name))
		assert.Equal(t, turn, tt[i].turn, fmt.Sprintf("%s: wrong result", tt[i].name))
	}

	// invalid
	tt = []struct {
		name, input string
		err         error
		turn        URI
	}{
		{"InvalidScheme", `xyz:1.2.3.4:3479?transport=udp`, errInvalidTurnURI, URI{}},
		{"InvalidHost", `turn:-:3479?transport=udp`, errInvalidTurnURI, URI{}},
		{"InvalidPort", `turn:1.2.3.4:abc?transport=udp`, errInvalidTurnURI, URI{}},
	}

	for i := range tt {
		turn, err := ParseURI(tt[i].input)
		assert.Equal(t, err, tt[i].err, fmt.Sprintf("%s: wrong parse status", tt[i].name))
		assert.Equal(t, turn, tt[i].turn, fmt.Sprintf("%s: wrong result", tt[i].name))
	}
}
