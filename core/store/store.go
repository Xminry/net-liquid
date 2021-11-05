/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package store

import (
	"chainmaker.org/chainmaker/net-liquid/core/peer"
	"chainmaker.org/chainmaker/net-liquid/core/protocol"
	ma "github.com/multiformats/go-multiaddr"
)

// PeerStore is an interface wrapped AddrBook and ProtocolBook.
type PeerStore interface {
	AddrBook
	ProtocolBook
}

// AddrBook is a store that manage the net addresses of peers.
type AddrBook interface {
	// AddAddr append some net addresses of peer.
	AddAddr(pid peer.ID, addr ...ma.Multiaddr)
	// SetAddrs record some addresses of peer.
	// This function will clean all addresses that not in list.
	SetAddrs(pid peer.ID, addrs []ma.Multiaddr)
	// RemoveAddr remove some net addresses of peer.
	RemoveAddr(pid peer.ID, addr ...ma.Multiaddr)
	// GetFirstAddr return first net address of peer.
	// If no address stored, return nil.
	GetFirstAddr(pid peer.ID) ma.Multiaddr
	// GetAddrs return all net address of peer.
	GetAddrs(pid peer.ID) []ma.Multiaddr
}

// ProtocolBook is a store that manage the protocols supported by peers.
type ProtocolBook interface {
	// AddProtocol append some protocols supported by peer.
	AddProtocol(pid peer.ID, protocols ...protocol.ID)
	// SetProtocols record some protocols supported by peer.
	// This function will clean all protocols that not in list.
	SetProtocols(pid peer.ID, protocols []protocol.ID)
	// DeleteProtocol remove some protocols of peer.
	DeleteProtocol(pid peer.ID, protocols ...protocol.ID)
	// ClearProtocol remove all records of peer.
	ClearProtocol(pid peer.ID)
	// GetProtocols return protocols list of peer.
	GetProtocols(pid peer.ID) []protocol.ID
	// ContainsProtocol return whether peer has supported all the protocols in list.
	ContainsProtocol(pid peer.ID, protocol protocol.ID) bool
	// ProtocolContained return the list of protocols supported that was contained in the list given.
	ProtocolContained(pid peer.ID, protocol ...protocol.ID) []protocol.ID
	// AllSupportProtocolPeers return the list of peer id which is the id of peers who support all protocols given.
	AllSupportProtocolPeers(protocol ...protocol.ID) []peer.ID
}
