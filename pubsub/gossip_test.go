/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package pubsub

import (
	"strconv"
	"testing"

	"chainmaker.org/chainmaker/net-liquid/core/peer"
	"chainmaker.org/chainmaker/net-liquid/pubsub/pb"
	"github.com/stretchr/testify/assert"
)

func TestSelect(t *testing.T) {
	peerIdCount := 100

	peerIds := make([]peer.ID, 0, peerIdCount)

	ids := selectPeer(peerIds, 0)
	assert.Equal(t, 0, len(ids))

	ids = selectPeer(peerIds, 10)
	assert.Equal(t, 0, len(ids))

	for i := 0; i < peerIdCount; i++ {
		peerIds = append(peerIds, peer.ID(strconv.Itoa(i)))
	}

	ids = selectPeer(peerIds, 0)
	assert.Equal(t, 0, len(ids))

	ids = selectPeer(peerIds, 10)
	assert.Equal(t, 10, len(ids))

	ids = selectPeer(peerIds, 99)
	assert.Equal(t, 99, len(ids))

	ids = selectPeer(peerIds, 100)
	assert.Equal(t, 100, len(ids))

	ids = selectPeer(peerIds, 1000)
	assert.Equal(t, 100, len(ids))

	peerIdMap := make(map[peer.ID]struct{})

	for _, v := range ids {
		_, ok := peerIdMap[v]
		assert.False(t, ok)
		peerIdMap[v] = struct{}{}
	}
}

func TestSplitApplicationMessage(t *testing.T) {

	data := make([]*pb.ApplicationMsg, 100)

	for i := 0; i < 100; i++ {
		data[i] = &pb.ApplicationMsg{
			Sender: strconv.Itoa(i),
		}
	}

	splitArray := splitApplicationMessage(1, data)
	assert.Equal(t, 100, len(splitArray))
	assert.Equal(t, 1, len(splitArray[0]))
	assert.Equal(t, 1, len(splitArray[99]))

	splitArray = splitApplicationMessage(2, data)
	assert.Equal(t, 50, len(splitArray))
	assert.Equal(t, 2, len(splitArray[0]))
	assert.Equal(t, 2, len(splitArray[49]))

	splitArray = splitApplicationMessage(3, data)
	assert.Equal(t, 34, len(splitArray))
	assert.Equal(t, 3, len(splitArray[0]))
	assert.Equal(t, 1, len(splitArray[33]))

	splitArray = splitApplicationMessage(99, data)
	assert.Equal(t, 2, len(splitArray))
	assert.Equal(t, 99, len(splitArray[0]))
	assert.Equal(t, 1, len(splitArray[1]))

	splitArray = splitApplicationMessage(100, data)
	assert.Equal(t, 1, len(splitArray))
	assert.Equal(t, 100, len(splitArray[0]))

	splitArray = splitApplicationMessage(101, data)
	assert.Equal(t, 1, len(splitArray))
	assert.Equal(t, 100, len(splitArray[0]))
}

func TestSplitEmptyApplicationMessage(t *testing.T) {
	data := make([]*pb.ApplicationMsg, 0)
	splitArray := splitApplicationMessage(101, data)
	assert.Equal(t, 0, len(splitArray))
}
