/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package simple

import (
	"testing"

	"chainmaker.org/chainmaker/net-liquid/core/peer"
	"chainmaker.org/chainmaker/net-liquid/core/protocol"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"
)

func TestSimplePeerStore(t *testing.T) {
	ps := NewSimplePeerStore("QmeyNRs2DwWjcHTpcVHoUSaDAAif4VQZ2wQDQAUNDP33gH")
	var pid peer.ID = "QmcQHCuAXaFkbcsPUj7e37hXXfZ9DdN7bozseo5oX4qiC4"
	addr1 := ma.StringCast("/ip4/127.0.0.1/tcp/8080/p2p/QmcQHCuAXaFkbcsPUj7e37hXXfZ9DdN7bozseo5oX4qiC4")
	addr2 := ma.StringCast("/ip4/127.0.0.1/tcp/8081/p2p/QmcQHCuAXaFkbcsPUj7e37hXXfZ9DdN7bozseo5oX4qiC4")
	ps.AddAddr(pid, addr1)
	require.True(t, len(ps.GetAddrs(pid)) == 1)
	require.True(t, addr1.String() == ps.GetFirstAddr(pid).String())
	ps.AddAddr(pid, addr1)
	require.True(t, len(ps.GetAddrs(pid)) == 1)
	require.True(t, addr1.String() == ps.GetFirstAddr(pid).String())
	ps.AddAddr(pid, addr2)
	require.True(t, len(ps.GetAddrs(pid)) == 2)
	require.True(t, addr1.String() == ps.GetFirstAddr(pid).String())
	ps.RemoveAddr(pid, addr1)
	require.True(t, len(ps.GetAddrs(pid)) == 1)
	require.True(t, addr2.String() == ps.GetFirstAddr(pid).String())
	ps.SetAddrs(pid, []ma.Multiaddr{addr1})
	require.True(t, len(ps.GetAddrs(pid)) == 1)
	require.True(t, addr1.String() == ps.GetFirstAddr(pid).String())

	proto1 := protocol.ID("1")
	proto2 := protocol.ID("2")
	proto3 := protocol.ID("3")
	proto4 := protocol.ID("4")
	ps.AddProtocol(pid, proto1)
	ps.AddProtocol(pid, proto2)
	ps.AddProtocol(pid, proto3)
	ps.AddProtocol(pid, proto1)
	require.Equal(t, len(ps.GetProtocols(pid)), 3)
	require.True(t, ps.ContainsProtocol(pid, proto2))
	require.True(t, len(ps.ProtocolContained(pid, proto2, proto3, proto4)) == 2)
	ps.DeleteProtocol(pid, proto1)
	require.Equal(t, len(ps.GetProtocols(pid)), 2)
	require.True(t, len(ps.AllSupportProtocolPeers(proto2, proto3)) == 1)
	require.True(t, len(ps.AllSupportProtocolPeers(proto2, proto3, proto4)) == 0)
	ps.ClearProtocol(pid)
	require.Equal(t, len(ps.GetProtocols(pid)), 0)
	ps.SetProtocols(pid, []protocol.ID{proto4})
	require.True(t, ps.ContainsProtocol(pid, proto4))
	require.False(t, ps.ContainsProtocol(pid, proto1))
	require.False(t, ps.ContainsProtocol(pid, proto2))
	require.False(t, ps.ContainsProtocol(pid, proto3))
}
