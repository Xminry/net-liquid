/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package simple

import (
	"errors"
	"sync"
	"sync/atomic"

	"chainmaker.org/chainmaker/net-liquid/core/mgr"
	"chainmaker.org/chainmaker/net-liquid/core/network"
	"chainmaker.org/chainmaker/net-liquid/core/peer"
	"chainmaker.org/chainmaker/net-liquid/core/types"
)

var (
	// ErrReceiveStreamsCountReachMax will be returned when the count of receive streams reach the maximum value.
	ErrReceiveStreamsCountReachMax = errors.New("receive streams count reach the maximum value")
)

type receiveStreamSet struct {
	types.Set
}

type connReceiveStreamsMap struct {
	sync.Map // map[conn]*receiveStreamSet
}

var _ mgr.ReceiveStreamManager = (*receiveStreamManager)(nil)

// receiveStreamManager is a simple implementation of mgr.ReceiveStreamManager interface.
type receiveStreamManager struct {
	peerReceiveStreamMaxCount int32
	peerStreamCount           sync.Map // map[peer.ID]*int32
	peerConnStreams           sync.Map // map[peer.ID]*connReceiveStreamsMap
}

// NewReceiveStreamManager create a new simple mgr.ReceiveStreamManager instance.
func NewReceiveStreamManager(peerReceiveStreamMaxCount int32) mgr.ReceiveStreamManager {
	if peerReceiveStreamMaxCount <= 0 {
		panic("peer receive streams max count value must greater than zero")
	}
	return &receiveStreamManager{peerReceiveStreamMaxCount: peerReceiveStreamMaxCount}
}

// Reset the manager.
func (r *receiveStreamManager) Reset() {
	// clear all
	r.peerStreamCount = sync.Map{}
	r.peerConnStreams = sync.Map{}
}

// ClosePeerReceiveStreams will close all the receiving streams whose remote peer id is the given pid
// and which created by the given connection.
func (r *receiveStreamManager) ClosePeerReceiveStreams(pid peer.ID, conn network.Conn) error {
	a, ok := r.peerConnStreams.Load(pid)
	if !ok {
		return nil
	}
	connReceiveStreams, _ := a.(*connReceiveStreamsMap)
	b, loaded := connReceiveStreams.LoadAndDelete(conn)
	if !loaded {
		return nil
	}
	receiveStreams, _ := b.(*receiveStreamSet)
	c, ok := r.peerStreamCount.Load(pid)
	if !ok {
		return nil
	}
	count, _ := c.(*int32)
	if atomic.AddInt32(count, 0-int32(receiveStreams.Size())) <= 0 {
		r.peerStreamCount.Delete(pid)
		r.peerConnStreams.Delete(pid)
	}
	receiveStreams.Range(func(v interface{}) bool {
		stream, _ := v.(network.ReceiveStream)
		_ = stream.Close()
		return true
	})
	return nil
}

// SetPeerReceiveStreamMaxCount set the max count allowed.
func (r *receiveStreamManager) SetPeerReceiveStreamMaxCount(max int) {
	if max <= 0 {
		panic("peer receive streams max count value must greater than zero")
	}
	atomic.StoreInt32(&r.peerReceiveStreamMaxCount, int32(max))
}

// AddPeerReceiveStream append a receiving stream to manager.
func (r *receiveStreamManager) AddPeerReceiveStream(
	pid peer.ID, conn network.Conn, stream network.ReceiveStream) error {
	a, _ := r.peerConnStreams.LoadOrStore(pid, &connReceiveStreamsMap{})
	connReceiveStreams, _ := a.(*connReceiveStreamsMap)
	b, _ := connReceiveStreams.LoadOrStore(conn, &receiveStreamSet{})
	receiveStreams, _ := b.(*receiveStreamSet)
	ok := receiveStreams.Put(stream)
	if ok { // store
		var zero int32 = 0
		c, _ := r.peerStreamCount.LoadOrStore(pid, &zero)
		count, _ := c.(*int32)
		if atomic.LoadInt32(count) >= r.peerReceiveStreamMaxCount {
			return ErrReceiveStreamsCountReachMax
		}
		atomic.AddInt32(count, 1)
	}
	return nil
}

// RemovePeerReceiveStream remove a receiving stream from manager.
func (r *receiveStreamManager) RemovePeerReceiveStream(
	pid peer.ID, conn network.Conn, stream network.ReceiveStream) error {
	a, ok := r.peerConnStreams.Load(pid)
	if !ok {
		return nil
	}
	connReceiveStreams, _ := a.(*connReceiveStreamsMap)
	b, ok2 := connReceiveStreams.Load(conn)
	if !ok2 {
		return nil
	}
	receiveStreams, _ := b.(*receiveStreamSet)
	removed := receiveStreams.Remove(stream)
	if removed { // removed
		c, ok3 := r.peerStreamCount.Load(pid)
		if !ok3 {
			return nil
		}
		count, _ := c.(*int32)
		if atomic.AddInt32(count, -1) <= 0 {
			r.peerStreamCount.Delete(pid)
			r.peerConnStreams.Delete(pid)
		}
	}
	return nil
}

// GetCurrentPeerReceiveStreamCount return current count of receive streams whose remote peer id is the given pid.
func (r *receiveStreamManager) GetCurrentPeerReceiveStreamCount(pid peer.ID) int {
	c, ok := r.peerStreamCount.Load(pid)
	if !ok {
		return 0
	}
	count, _ := c.(*int32)
	return int(atomic.LoadInt32(count))
}
