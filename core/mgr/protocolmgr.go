/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mgr

import (
	"chainmaker.org/chainmaker/net-liquid/core/handler"
	"chainmaker.org/chainmaker/net-liquid/core/network"
	"chainmaker.org/chainmaker/net-liquid/core/peer"
	"chainmaker.org/chainmaker/net-liquid/core/protocol"
)

// ProtocolSupportNotifyFunc is a function to notify peer protocol supporting or not.
type ProtocolSupportNotifyFunc func(protocolID protocol.ID, pid peer.ID)

// ProtocolManager manages all protocol and protocol msg handler for all peers.
type ProtocolManager interface {
	// RegisterMsgPayloadHandler register a protocol supported by us
	// and map a handler.MsgPayloadHandler to this protocol.
	RegisterMsgPayloadHandler(protocolID protocol.ID, handler handler.MsgPayloadHandler) error
	// UnregisterMsgPayloadHandler unregister a protocol supported by us.
	UnregisterMsgPayloadHandler(protocolID protocol.ID) error
	// IsRegistered return whether a protocol given is supported by us.
	IsRegistered(protocolID protocol.ID) bool
	// GetHandler return the handler.MsgPayloadHandler mapped to the protocol supported by us and id is the given.
	// If the protocol not supported by us, return nil.
	GetHandler(protocolID protocol.ID) handler.MsgPayloadHandler
	// GetSelfSupportedProtocols return a list of protocol.ID that supported by myself.
	GetSelfSupportedProtocols() []protocol.ID
	// IsPeerSupported return whether the protocol is supported by peer which id is the given pid.
	// If peer not connected to us, return false.
	IsPeerSupported(pid peer.ID, protocolID protocol.ID) bool
	// GetPeerSupportedProtocols return a list of protocol.ID that supported by the peer which id is the given pid.
	GetPeerSupportedProtocols(pid peer.ID) []protocol.ID
	// SetPeerSupportedProtocols stores the protocols supported by the peer which id is the given pid.
	SetPeerSupportedProtocols(pid peer.ID, protocolIDs []protocol.ID)
	// CleanPeerSupportedProtocols remove all records of protocols supported by the peer which id is the given pid.
	CleanPeerSupportedProtocols(pid peer.ID)
	// SetProtocolSupportedNotifyFunc set a function for notifying peer protocol supporting.
	SetProtocolSupportedNotifyFunc(notifyFunc ProtocolSupportNotifyFunc)
	// SetProtocolUnsupportedNotifyFunc set a function for notifying peer protocol supporting canceled.
	SetProtocolUnsupportedNotifyFunc(notifyFunc ProtocolSupportNotifyFunc)
}

// ProtocolExchanger usual be used to exchange protocols supported by both peers.
type ProtocolExchanger interface {
	// ProtocolID is the protocol.ID of exchanger service.
	// The protocol id will be registered in host.RegisterMsgPayloadHandler method.
	ProtocolID() protocol.ID
	// Handle is the msg payload handler of exchanger service.
	// It will be registered in host.Host.RegisterMsgPayloadHandler method.
	Handle() handler.MsgPayloadHandler
	// ExchangeProtocol will send protocols supported by us to the other and receive protocols supported by the other.
	// This method will be invoked during connection establishing.
	ExchangeProtocol(conn network.Conn) ([]protocol.ID, error)
	// PushProtocols will send protocols supported by us to the other.
	// This method  will be invoked when new protocol registering.
	PushProtocols(pid peer.ID) error
}
