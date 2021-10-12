/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package network

import (
	"context"

	ma "github.com/multiformats/go-multiaddr"
)

// Dialer provides a way to establish a connection with others.
type Dialer interface {
	// Dial try to establish an outbound connection with the remote address.
	Dial(ctx context.Context, remoteAddr ma.Multiaddr) (Conn, error)
}
