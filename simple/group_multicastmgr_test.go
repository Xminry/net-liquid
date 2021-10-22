/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package simple

import (
	"strconv"
	"sync"
	"testing"

	"chainmaker.org/chainmaker/net-liquid/core/peer"
	"github.com/stretchr/testify/assert"
)

func TestNilScene(t *testing.T) {
	groupName := "test_group_1"
	peer := peer.ID("peer_1")

	groupMulticastMgr := NewGroupMulticastMgr(nil, nil)
	peers := groupMulticastMgr.getPeers(groupName)
	assert.Nil(t, peers)

	size := groupMulticastMgr.GroupSize(groupName)
	assert.Equal(t, 0, size)

	inGroup := groupMulticastMgr.InGroup(groupName, peer)
	assert.False(t, inGroup)

	groupMulticastMgr.RemoveGroup(groupName)
}

func TestSimpleScene(t *testing.T) {

	tempGroupCount := 100
	tempPeerCount := 100

	groupMulticastMgr := NewGroupMulticastMgr(nil, nil)

	//add peer to group
	for i := 0; i < tempGroupCount; i++ {
		for j := 0; j < tempPeerCount; j++ {
			groupMulticastMgr.AddPeerToGroup("test_group_"+strconv.Itoa(i), peer.ID("peer_"+strconv.Itoa(j)))
		}
	}

	//after add, peer count sholud be tempPeerCount
	for i := 0; i < tempGroupCount; i++ {
		assert.Equal(t, tempPeerCount, groupMulticastMgr.GroupSize("test_group_"+strconv.Itoa(i)))
	}

	//after add, peer should in group
	for i := 0; i < tempGroupCount; i++ {
		for j := 0; j < tempPeerCount; j++ {
			assert.True(t, groupMulticastMgr.InGroup("test_group_"+strconv.Itoa(i), peer.ID("peer_"+strconv.Itoa(j))))
		}
	}

	//add same peer to group, do nothing
	for i := 0; i < tempGroupCount; i++ {
		for j := 0; j < tempPeerCount; j++ {
			groupMulticastMgr.AddPeerToGroup("test_group_"+strconv.Itoa(i), peer.ID("peer_"+strconv.Itoa(j)))
		}
	}
	// after add, group's peer count shold not change
	for i := 0; i < tempGroupCount; i++ {
		assert.Equal(t, tempPeerCount, groupMulticastMgr.GroupSize("test_group_"+strconv.Itoa(i)))
	}

	//remove peer from group
	for i := 0; i < tempGroupCount; i++ {
		for j := 0; j < tempPeerCount; j++ {
			groupMulticastMgr.RemovePeerFromGroup("test_group_"+strconv.Itoa(i), peer.ID("peer_"+strconv.Itoa(j)))
		}
	}

	//after remove, group peer count should be zero
	for i := 0; i < tempGroupCount; i++ {
		assert.Equal(t, 0, groupMulticastMgr.GroupSize("test_group_"+strconv.Itoa(i)))
	}

	//remove group
	for i := 0; i < tempGroupCount; i++ {
		for j := 0; j < tempPeerCount; j++ {
			groupMulticastMgr.RemoveGroup("test_group_" + strconv.Itoa(i))
		}
	}

	//after remove, group peer count should be zero
	for i := 0; i < tempGroupCount; i++ {
		assert.Equal(t, 0, groupMulticastMgr.GroupSize("test_group_"+strconv.Itoa(i)))
	}
}

func TestParallel(t *testing.T) {

	parallelCount := 100

	groupCount := 100
	peerCount := 100

	waitGroup := sync.WaitGroup{}

	groupMutlicastMgr := NewGroupMulticastMgr(nil, nil)

	//add peer to group
	for i := 0; i < parallelCount; i++ {
		waitGroup.Add(1)
		go func(index int) {
			for g := 0; g < groupCount; g++ {
				for p := 0; p < peerCount; p++ {
					groupMutlicastMgr.AddPeerToGroup(getGroupName(g), getPeer(p))
				}
			}
			waitGroup.Done()
		}(i)
	}

	//add some query goroutine
	for i := 0; i < parallelCount; i++ {
		waitGroup.Add(1)
		go func(index int) {
			for g := 0; g < groupCount; g++ {
				for p := 0; p < peerCount; p++ {
					groupMutlicastMgr.InGroup(getGroupName(g), getPeer(p))
				}
			}
			waitGroup.Done()
		}(i)
	}

	waitGroup.Wait()

	for g := 0; g < groupCount; g++ {
		for p := 0; p < peerCount; p++ {
			//in group
			assert.True(t, groupMutlicastMgr.InGroup(getGroupName(g), getPeer(p)))
			//peer count
			assert.Equal(t, peerCount, groupMutlicastMgr.GroupSize(getGroupName(g)))
		}
	}

	//delete peer from group
	for i := 0; i < parallelCount; i++ {
		waitGroup.Add(1)
		go func(index int) {
			for g := 0; g < groupCount; g++ {
				for p := 0; p < peerCount; p++ {
					groupMutlicastMgr.RemovePeerFromGroup(getGroupName(g), getPeer(p))
				}
			}
			waitGroup.Done()
		}(i)
	}

	waitGroup.Wait()
	for g := 0; g < groupCount; g++ {
		for p := 0; p < peerCount; p++ {
			//in group
			assert.False(t, groupMutlicastMgr.InGroup(getGroupName(g), getPeer(p)))
			//peer count
			assert.Equal(t, 0, groupMutlicastMgr.GroupSize(getGroupName(g)))
		}
	}
}

func getGroupName(index int) string {
	return "group_" + strconv.Itoa(index)
}

func getPeer(index int) peer.ID {
	return peer.ID("peer_" + strconv.Itoa(index))
}
