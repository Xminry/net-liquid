/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mgr

import (
	"io"

	"chainmaker.org/chainmaker/net-liquid/core/basic"
	"chainmaker.org/chainmaker/net-liquid/core/network"
	"chainmaker.org/chainmaker/net-liquid/core/peer"
	ma "github.com/multiformats/go-multiaddr"
)

// ConnMgr provides a connection manager.
type ConnMgr interface {
	io.Closer
	AddPeerConn(pid peer.ID, conn network.Conn) bool
	RemovePeerConn(pid peer.ID, conn network.Conn) bool
	ExistPeerConn(pid peer.ID, conn network.Conn) bool
	GetPeerConn(pid peer.ID) network.Conn
	GetPeerAllConn(pid peer.ID) []network.Conn
	IsConnected(pid peer.ID) bool
	IsAllowed(pid peer.ID) bool
	ExpendConn(pid peer.ID)
	MaxPeerCountAllowed() int
	PeerCount() int
	AllPeer() []peer.ID
}

// ConnSupervisor maintains the connection state of the necessary peers.
// If a necessary peer is not connected to us, supervisor will try to dial to it.
type ConnSupervisor interface {
	basic.Switcher
	// SetPeerAddr will set a peer as a necessary peer and store the peer's address.
	SetPeerAddr(pid peer.ID, addr ma.Multiaddr)
	// RemovePeerAddr will unset a necessary peer.
	RemovePeerAddr(pid peer.ID)
	// RemoveAllPeer clean all necessary peers.
	RemoveAllPeer()
}
