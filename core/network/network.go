/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package network

import (
	"io"

	"chainmaker.org/chainmaker/net-liquid/core/peer"
)

// ConnHandler is a function for handling connections.
type ConnHandler func(conn Conn) (bool, error)

// Network is a state machine interface provides a Dialer and a Listener to build a network.
type Network interface {
	Dialer
	Listener
	io.Closer
	// SetNewConnHandler register a ConnHandler to handle the connection established.
	SetNewConnHandler(handler ConnHandler)
	// Disconnect a connection.
	Disconnect(conn Conn) error
	// Closed return whether network closed.
	Closed() bool
	// LocalPeerID return the local peer id.
	LocalPeerID() peer.ID
}
