/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"testing"

	"chainmaker.org/chainmaker/net-liquid/core/peer"

	ma "github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"
)

func TestGetNetAddrAndPidFromNormalMultiAddr(t *testing.T) {
	addr1 := "/ip4/127.0.0.1/udp/9001/p2p/QmcQHCuAXaFkbcsPUj7e37hXXfZ9DdN7bozseo5oX4qiC4"
	addr2 := "/ip4/127.0.0.1/udp/9001"
	addr3 := "/p2p/QmcQHCuAXaFkbcsPUj7e37hXXfZ9DdN7bozseo5oX4qiC4"
	pid := peer.ID("QmcQHCuAXaFkbcsPUj7e37hXXfZ9DdN7bozseo5oX4qiC4")
	ma1 := ma.StringCast(addr1)
	na1, pid1 := GetNetAddrAndPidFromNormalMultiAddr(ma1)
	require.True(t, na1.Equal(ma.StringCast(addr2)))
	require.True(t, pid1 == pid)

	ma2 := ma.StringCast(addr2)
	na2, pid2 := GetNetAddrAndPidFromNormalMultiAddr(ma2)
	require.True(t, na2.Equal(ma.StringCast(addr2)))
	require.True(t, pid2 == "")

	ma3 := ma.StringCast(addr3)
	na3, pid3 := GetNetAddrAndPidFromNormalMultiAddr(ma3)
	require.True(t, na3 == nil)
	require.True(t, pid3 == pid)
}
