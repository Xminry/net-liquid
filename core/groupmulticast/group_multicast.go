/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package groupmulticast

import (
	"chainmaker.org/chainmaker/net-liquid/core/peer"
	"chainmaker.org/chainmaker/net-liquid/core/protocol"
)

// GroupMulticast send message to all peers in group.
type GroupMulticast interface {

	// AddPeerToGroup add peers to the group which name is the given groupName.
	// If the group not exists, it will be created.
	AddPeerToGroup(groupName string, peers ...peer.ID)

	// RemovePeerFromGroup remove peers from the group which name is the given groupName.
	RemovePeerFromGroup(groupName string, peers ...peer.ID)

	// GroupSize return the count of peers in the group which name is the given.
	// If the group not exists, return 0.
	GroupSize(groupName string) int

	// InGroup return whether the peer in the group.
	// If group not exists, return false.
	InGroup(groupName string, peer peer.ID) bool

	// RemoveGroup remove a group which name is the given.
	RemoveGroup(groupName string)

	// SendToGroupSync send data to the peers in the group sync.
	// It will wait until all data send success.
	SendToGroupSync(groupName string, protocolID protocol.ID, data []byte) error

	//SendToGroupAsync send data to group, no wait
	SendToGroupAsync(groupName string, protocolID protocol.ID, data []byte)
}
