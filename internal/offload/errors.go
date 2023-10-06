// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package offload

import "errors"

var (
	errUnsupportedProtocol        = errors.New("offload: protocol not supported")
	errXDPAlreadyInitialized      = errors.New("offload: XDP engine is already initialized")
	errXDPLocalRedirectProhibited = errors.New("offload: XDP local redirect not allowed")
)
