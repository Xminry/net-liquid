/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package host

import (
	"context"

	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/basic"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/blacklist"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/handler"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/mgr"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/network"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/peer"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/protocol"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/store"
	ma "github.com/multiformats/go-multiaddr"
)

// PeerProtocols store the peer.ID and the protocol.ID list that supported by peer.
type PeerProtocols struct {
	PID       peer.ID
	Protocols []protocol.ID
}

// Host provides the capabilities of network.
type Host interface {
	basic.Switcher

	// Context of the host instance.
	Context() context.Context

	// ID is local peer id.
	ID() peer.ID

	// RegisterMsgPayloadHandler register a handler.MsgPayloadHandler for handling
	// the msg received with the protocol which id is the given protocolID.
	RegisterMsgPayloadHandler(protocolID protocol.ID, handler handler.MsgPayloadHandler) error
	// UnregisterMsgPayloadHandler unregister the handler.MsgPayloadHandler for
	// handling the msg received with the protocol which id is the given protocolID.
	UnregisterMsgPayloadHandler(protocolID protocol.ID) error

	// SendMsg will send a msg with the protocol which id is the given protocolID
	// to the receiver whose peer.ID is the given receiverPID.
	SendMsg(protocolID protocol.ID, receiverPID peer.ID, msgPayload []byte) error

	// Dial try to establish a connection with peer whose address is the given.
	Dial(remoteAddr ma.Multiaddr) (network.Conn, error)

	// CheckClosedConnWithErr return whether the connection has closed.
	// If conn.IsClosed() is true, return true.
	// If err contains closed info, return true.
	// Otherwise return false.
	CheckClosedConnWithErr(conn network.Conn, err error) bool

	// PeerStore return the store.PeerStore instance of the host.
	PeerStore() store.PeerStore

	// ConnMgr return the mgr.ConnMgr instance of the host.
	ConnMgr() mgr.ConnMgr

	// ProtocolMgr return the mgr.ProtocolManager instance of the host.
	ProtocolMgr() mgr.ProtocolManager

	// Blacklist return the blacklist.BlackList instance of the host.
	Blacklist() blacklist.BlackList

	// PeerProtocols query peer.ID and the protocol.ID list supported by peer.
	// If protocolIDs is nil ,return the list of all connected to us.
	// Otherwise return the list of part of all which support the protocols
	// that id contains in the given protocolIDs.
	PeerProtocols(protocolIDs []protocol.ID) ([]*PeerProtocols, error)

	// IsPeerSupportProtocol return true if peer which id is the given pid
	// support the given protocol. Otherwise return false.
	IsPeerSupportProtocol(pid peer.ID, protocolID protocol.ID) bool

	// Notify registers a Notifiee to host.
	Notify(notifiee Notifiee)

	// AddDirectPeer append a direct peer.
	AddDirectPeer(dp ma.Multiaddr)

	// ClearDirectPeers remove all direct peers.
	ClearDirectPeers()

	// LocalAddresses return the list of net addresses for listener listening.
	LocalAddresses() []ma.Multiaddr
}
