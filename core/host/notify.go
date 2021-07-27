/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package host

import (
	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/peer"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/protocol"
)

// Notifiee contains functions for host notifying call back.
type Notifiee interface {
	// PeerConnected will be invoked when a new connection established.
	PeerConnected(pid peer.ID)
	// PeerDisconnected will be invoked when a connection disconnected.
	PeerDisconnected(pid peer.ID)
	// PeerProtocolSupported will be invoked when a peer support a new protocol.
	PeerProtocolSupported(protocolID protocol.ID, pid peer.ID)
	// PeerProtocolUnsupported will be invoked when a peer cancel supporting a new protocol.
	PeerProtocolUnsupported(protocolID protocol.ID, pid peer.ID)
}

var _ Notifiee = (*NotifieeBundle)(nil)

// NotifieeBundle is a bundle implementation of Notifee interface.
type NotifieeBundle struct {
	PeerConnectedFunc           func(peer.ID)
	PeerDisconnectedFunc        func(peer.ID)
	PeerProtocolSupportedFunc   func(protocolID protocol.ID, pid peer.ID)
	PeerProtocolUnsupportedFunc func(protocolID protocol.ID, pid peer.ID)
}

func (n *NotifieeBundle) PeerConnected(pid peer.ID) {
	if n.PeerConnectedFunc != nil {
		n.PeerConnectedFunc(pid)
	}
}

func (n *NotifieeBundle) PeerDisconnected(pid peer.ID) {
	if n.PeerDisconnectedFunc != nil {
		n.PeerDisconnectedFunc(pid)
	}
}

func (n *NotifieeBundle) PeerProtocolSupported(protocolID protocol.ID, pid peer.ID) {
	if n.PeerProtocolSupportedFunc != nil {
		n.PeerProtocolSupportedFunc(protocolID, pid)
	}
}

func (n *NotifieeBundle) PeerProtocolUnsupported(protocolID protocol.ID, pid peer.ID) {
	if n.PeerProtocolUnsupportedFunc != nil {
		n.PeerProtocolUnsupportedFunc(protocolID, pid)
	}
}
