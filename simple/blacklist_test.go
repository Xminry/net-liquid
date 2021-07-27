/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package simple

import (
	"testing"
	"time"

	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/network"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/peer"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"
)

func TestNewBlackList(t *testing.T) {
	NewBlackList()
}

func TestSimpleBlacklistAddPeer(t *testing.T) {
	l := NewBlackList()
	l.AddPeer("0")
}

func TestSimpleBlacklistRemovePeer(t *testing.T) {
	l := NewBlackList()
	l.RemovePeer("1")
	l.AddPeer("0")
	l.RemovePeer("0")
}

func TestSimpleBlacklistAddIpAndPort(t *testing.T) {
	l := NewBlackList()
	l.AddIPAndPort("192.168.1.1")
	l.AddIPAndPort("192.168.1.2:8080")
	l.AddIPAndPort("[::1]:8081")
	l.AddIPAndPort("[::2]")
	l.AddIPAndPort("::3")
}

func TestSimpleBlacklistRemoveIpAndPort(t *testing.T) {
	l := NewBlackList()
	l.AddIPAndPort("192.168.1.1")
	l.AddIPAndPort("192.168.1.2:8080")
	l.AddIPAndPort("[::1]:8081")
	l.AddIPAndPort("[::2]")
	l.AddIPAndPort("::3")
	l.RemoveIPAndPort("192.168.1.1")
	l.RemoveIPAndPort("192.168.1.2:8080")
	l.RemoveIPAndPort("[::1]:8081")
	l.RemoveIPAndPort("[::2]")
	l.RemoveIPAndPort("::3")
}

func TestSimpleBlacklistIsBlack(t *testing.T) {
	c := &mockConn{}
	c.rAddr = ma.StringCast("/ip4/192.168.1.2/udp/8080")
	l := NewBlackList()
	require.False(t, l.IsBlack(c))
	l.AddIPAndPort("192.168.1.2")
	require.True(t, l.IsBlack(c))
	l.RemoveIPAndPort("192.168.1.2")
	require.False(t, l.IsBlack(c))

	l.AddIPAndPort("192.168.1.2:8080")
	require.True(t, l.IsBlack(c))
	l.RemoveIPAndPort("192.168.1.2:8080")
	require.False(t, l.IsBlack(c))

	l.AddIPAndPort("192.168.1.2:8081")
	require.False(t, l.IsBlack(c))
	c.rAddr = ma.StringCast("/ip6/::2/udp/9080")
	l.AddIPAndPort("[::2]")
	require.True(t, l.IsBlack(c))
	l.RemoveIPAndPort("[::2]")
	require.False(t, l.IsBlack(c))
	l.AddIPAndPort("[::2]:9080")
	require.True(t, l.IsBlack(c))
	l.RemoveIPAndPort("[::2]:9080")
	require.False(t, l.IsBlack(c))
	l.AddIPAndPort("::2")
	require.True(t, l.IsBlack(c))
	l.RemoveIPAndPort("::2")
	require.False(t, l.IsBlack(c))

	l.AddIPAndPort("::3")
	require.False(t, l.IsBlack(c))

	l.AddPeer(c.RemotePeerID())
	require.True(t, l.IsBlack(c))
	l.RemovePeer(c.RemotePeerID())
	require.False(t, l.IsBlack(c))
}

var _ network.Conn = (*mockConn)(nil)

type mockConn struct {
	rAddr ma.Multiaddr
}

func (m mockConn) Close() error {
	panic("implement me")
}

func (m mockConn) Direction() network.Direction {
	panic("implement me")
}

func (m mockConn) EstablishedTime() time.Time {
	panic("implement me")
}

func (m mockConn) Extra() map[interface{}]interface{} {
	panic("implement me")
}

func (m mockConn) SetClosed() {
	panic("implement me")
}

func (m mockConn) IsClosed() bool {
	panic("implement me")
}

func (m mockConn) LocalAddr() ma.Multiaddr {
	panic("implement me")
}

func (m mockConn) LocalPeerID() peer.ID {
	panic("implement me")
}

func (m mockConn) RemoteAddr() ma.Multiaddr {
	return m.rAddr
}

func (m mockConn) RemotePeerID() peer.ID {
	return "QmcQHCuAXaFkbcsPUj7e37hXXfZ9DdN7bozseo5oX4qiC4"
}

func (m mockConn) Network() network.Network {
	panic("implement me")
}

func (m mockConn) CreateSendStream() (network.SendStream, error) {
	panic("implement me")
}

func (m mockConn) AcceptReceiveStream() (network.ReceiveStream, error) {
	panic("implement me")
}

func (m mockConn) CreateBidirectionalStream() (network.Stream, error) {
	panic("implement me")
}

func (m mockConn) AcceptBidirectionalStream() (network.Stream, error) {
	panic("implement me")
}
