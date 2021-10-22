/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package blacklist

import (
	"chainmaker.org/chainmaker/net-liquid/core/network"
	"chainmaker.org/chainmaker/net-liquid/core/peer"
)

// BlackList is a blacklist implementation for net addresses or peer ids .
type BlackList interface {
	// AddPeer append a peer id to blacklist.
	AddPeer(pid peer.ID)
	// RemovePeer delete a peer id from blacklist. If pid not exist in blacklist, it is a no-op.
	RemovePeer(pid peer.ID)
	// AddIPAndPort append a string contains an ip or a net.Addr string with an ip and a port to blacklist.
	// The string should be in the following format:
	// "192.168.1.2:9000" or "192.168.1.2" or "[::1]:9000" or "[::1]"
	AddIPAndPort(ipAndPort string)
	// RemoveIPAndPort delete a string contains an ip or a net.Addr string with an ip and a port from blacklist.
	// If the string not exist in blacklist, it is a no-op.
	RemoveIPAndPort(ipAndPort string)
	// IsBlack check whether the remote peer id or the remote net address of the connection given exist in blacklist.
	IsBlack(conn network.Conn) bool
}
