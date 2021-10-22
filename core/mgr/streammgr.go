/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mgr

import (
	"io"

	"chainmaker.org/chainmaker/net-liquid/core/network"
	"chainmaker.org/chainmaker/net-liquid/core/peer"
)

// SendStreamPool is a pool stores send streams.
type SendStreamPool interface {
	io.Closer
	// Conn return the connection which send streams created by.
	Conn() network.Conn
	// InitStreams will open few send streams with the connection.
	InitStreams() error
	// BorrowStream get a sending stream from send stream queue in pool.
	// The stream borrowed should be return to this pool after sending data success,
	// or should be dropped by invoking DropStream method when errors found in sending data process.
	BorrowStream() (network.SendStream, error)
	// ReturnStream return a sending stream borrowed from this pool before.
	ReturnStream(network.SendStream) error
	// DropStream will close the sending stream then drop it.
	// This method should be invoked only when errors found.
	DropStream(network.SendStream)
	// MaxSize return cap of this pool.
	MaxSize() int
	// CurrentSize return current size of this pool.
	CurrentSize() int
	// IdleSize return current count of idle send stream.
	IdleSize() int
}

// SendStreamPoolManager manage all send stream pools.
type SendStreamPoolManager interface {
	// Reset the manager.
	Reset()
	// AddPeerConnSendStreamPool append a stream pool for a connection of peer.
	AddPeerConnSendStreamPool(pid peer.ID, conn network.Conn, streamPool SendStreamPool) error
	// RemovePeerConnAndCloseSendStreamPool remove a connection of peer and close the stream pool for it.
	RemovePeerConnAndCloseSendStreamPool(pid peer.ID, conn network.Conn) error
	// GetPeerBestConnSendStreamPool return a stream pool for the best connection of peer.
	GetPeerBestConnSendStreamPool(pid peer.ID) SendStreamPool
}

// ReceiveStreamManager manage all receive streams.
type ReceiveStreamManager interface {
	// Reset the manager.
	Reset()
	// SetPeerReceiveStreamMaxCount set the max count allowed.
	SetPeerReceiveStreamMaxCount(max int)
	// AddPeerReceiveStream append a receiving stream to manager.
	AddPeerReceiveStream(pid peer.ID, conn network.Conn, stream network.ReceiveStream) error
	// RemovePeerReceiveStream remove a receiving stream from manager.
	RemovePeerReceiveStream(pid peer.ID, conn network.Conn, stream network.ReceiveStream) error
	// GetCurrentPeerReceiveStreamCount return current count of receive streams
	// whose remote peer id is the given pid.
	GetCurrentPeerReceiveStreamCount(pid peer.ID) int
	// ClosePeerReceiveStreams will close all the receiving streams whose remote
	// peer id is the given pid and which created by the given connection.
	ClosePeerReceiveStreams(pid peer.ID, conn network.Conn) error
}
