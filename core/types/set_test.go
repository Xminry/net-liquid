/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package types

import (
	"testing"

	"chainmaker.org/chainmaker/net-liquid/core/peer"
	"github.com/stretchr/testify/require"
)

func TestSetPut(t *testing.T) {
	s := &Set{}
	require.True(t, s.Put(1))
	require.True(t, !s.Put(1))
}

func TestSetExist(t *testing.T) {
	var s Set
	require.True(t, !s.Exist(1))
	require.True(t, s.Put(1))
	require.True(t, s.Exist(1))
	require.True(t, s.Remove(1))
	require.True(t, !s.Exist(1))
}

func TestSetRemove(t *testing.T) {
	var s Set
	require.True(t, !s.Remove(1))
	require.True(t, s.Put(1))
	require.True(t, s.Remove(1))
	require.True(t, !s.Remove(1))
}

func TestSetSize(t *testing.T) {
	s := &Set{}
	require.Equal(t, 0, s.Size())
	require.True(t, s.Put(1))
	require.Equal(t, 1, s.Size())
	require.True(t, !s.Put(1))
	require.Equal(t, 1, s.Size())
	require.True(t, s.Put(2))
	require.Equal(t, 2, s.Size())
	require.True(t, s.Remove(2))
	require.Equal(t, 1, s.Size())
	require.True(t, s.Remove(1))
	require.Equal(t, 0, s.Size())
}

func TestSetRange(t *testing.T) {
	var s Set
	require.True(t, s.Put(1))
	bl := false
	s.Range(func(v interface{}) bool {
		value := v.(int)
		bl = value == 1
		return bl
	})
	require.True(t, bl)
}

func TestPeerIdSetExist(t *testing.T) {
	var s PeerIdSet
	require.True(t, !s.Exist(peer.ID("1")))
	require.True(t, s.Put(peer.ID("1")))
	require.True(t, s.Exist(peer.ID("1")))
	require.True(t, s.Remove(peer.ID("1")))
	require.True(t, !s.Exist(peer.ID("1")))
}
