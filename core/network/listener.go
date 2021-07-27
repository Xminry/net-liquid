/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package network

import (
	"context"
	"io"

	ma "github.com/multiformats/go-multiaddr"
)

// Listener provides a way to accept connections established with others.
type Listener interface {
	io.Closer
	// Listen will run a task that start create listeners with the given
	// addresses waiting for accepting inbound connections.
	Listen(ctx context.Context, addrs ...ma.Multiaddr) error
	// ListenAddresses return the list of the local addresses for listeners.
	ListenAddresses() []ma.Multiaddr
}
