/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package network

import (
	"io"
	"net"

	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/peer"
	ma "github.com/multiformats/go-multiaddr"
)

// Conn defined a connection with remote peer.
type Conn interface {
	io.Closer
	Stat
	// LocalAddr is the local net multi-address of the connection.
	LocalAddr() ma.Multiaddr
	// LocalNetAddr is the local net address of the connection.
	LocalNetAddr() net.Addr
	// LocalPeerID is the local peer id of the connection.
	LocalPeerID() peer.ID
	// RemoteAddr is the remote net multi-address of the connection.
	RemoteAddr() ma.Multiaddr
	// RemoteNetAddr is the remote net address of the connection.
	RemoteNetAddr() net.Addr
	// RemotePeerID is the remote peer id of the connection.
	RemotePeerID() peer.ID
	// Network is the network instance who create this connection.
	Network() Network
	// CreateSendStream try to open a send stream with the connection.
	CreateSendStream() (SendStream, error)
	// AcceptReceiveStream accept a receive stream with the connection.
	// It will block until a new receive stream accepted or connection closed.
	AcceptReceiveStream() (ReceiveStream, error)
	// CreateBidirectionalStream try to open a bidirectional stream with the connection.
	CreateBidirectionalStream() (Stream, error)
	// AcceptBidirectionalStream accept a bidirectional stream with the connection.
	// It will block until a new bidirectional stream accepted or connection closed.
	AcceptBidirectionalStream() (Stream, error)
}
