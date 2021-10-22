/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package simple

import (
	"errors"
	"strings"
	"sync"

	"chainmaker.org/chainmaker/net-liquid/core/groupmulticast"
	"chainmaker.org/chainmaker/net-liquid/core/host"
	"chainmaker.org/chainmaker/net-liquid/core/peer"
	"chainmaker.org/chainmaker/net-liquid/core/protocol"
	api "chainmaker.org/chainmaker/protocol/v2"
)

var _ groupmulticast.GroupMulticast = (*GroupMulticastMgr)(nil)

// GroupMulticastMgr is an implementation of groupmulticast.GroupMulticast interface.
type GroupMulticastMgr struct {
	logger api.Logger

	host host.Host

	mutex      sync.Mutex
	peerGroups map[string]*peerGroup
}

type peerGroup struct {
	groupName string
	peers     []peer.ID
}

func NewGroupMulticastMgr(logger api.Logger, host host.Host) *GroupMulticastMgr {
	return &GroupMulticastMgr{
		logger:     logger,
		host:       host,
		peerGroups: make(map[string]*peerGroup),
	}
}

func (cm *GroupMulticastMgr) AddPeerToGroup(groupName string, peers ...peer.ID) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()
	if _, exists := cm.peerGroups[groupName]; !exists {
		cm.peerGroups[groupName] = &peerGroup{
			groupName: groupName,
			peers:     make([]peer.ID, 0, len(peers)),
		}
	}
	for _, peer := range peers {
		hasExists := false
		for _, oldPeers := range cm.peerGroups[groupName].peers {
			if peer.ToString() == oldPeers.ToString() {
				hasExists = true
				break
			}
		}
		if !hasExists {
			cm.peerGroups[groupName].peers = append(cm.peerGroups[groupName].peers, peer)
		}
	}
}

func (cm *GroupMulticastMgr) RemovePeerFromGroup(groupName string, peers ...peer.ID) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()
	if _, exists := cm.peerGroups[groupName]; !exists {
		return
	}
	for _, peer := range peers {
		oldPeers := cm.peerGroups[groupName].peers
		for index, oldPeer := range oldPeers {
			if peer.ToString() == oldPeer.ToString() {
				cm.peerGroups[groupName].peers = append(oldPeers[:index], oldPeers[index+1:]...)
				break
			}
		}
	}
}

func (cm *GroupMulticastMgr) GroupSize(groupName string) int {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()
	if group, ok := cm.peerGroups[groupName]; ok {
		return len(group.peers)
	}
	return 0
}

func (cm *GroupMulticastMgr) InGroup(groupName string, peer peer.ID) bool {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()
	if _, ok := cm.peerGroups[groupName]; !ok {
		return false
	}
	for _, oldPeer := range cm.peerGroups[groupName].peers {
		if oldPeer.ToString() == peer.ToString() {
			return true
		}
	}
	return false
}

func (cm *GroupMulticastMgr) RemoveGroup(groupName string) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()
	delete(cm.peerGroups, groupName)
}

func (cm *GroupMulticastMgr) getPeers(groupName string) []peer.ID {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()
	if _, ok := cm.peerGroups[groupName]; !ok {
		return nil
	}
	peers := cm.peerGroups[groupName].peers
	result := make([]peer.ID, len(peers))
	copy(result, peers)
	return result
}

func (cm *GroupMulticastMgr) SendToGroupSync(groupName string, protocolID protocol.ID, data []byte) error {
	groupPeers := cm.getPeers(groupName)

	errorChan := make(chan error, len(groupPeers))
	waitGroup := sync.WaitGroup{}
	for index, groupPeer := range groupPeers {
		waitGroup.Add(1)
		go func(i int, peer peer.ID) {
			defer waitGroup.Done()
			err := cm.host.SendMsg(protocolID, peer, data)
			if err != nil {
				cm.logger.Errorf("send data to group err. group: %s, protocol id: %v, peer: %v, err: %s",
					groupName, protocolID, peer, err)
				errorChan <- err
			}
		}(index, groupPeer)
	}
	//wait data dend to all peer
	waitGroup.Wait()
	close(errorChan)

	if len(errorChan) > 0 {
		errorMessage := make([]string, 0, len(errorChan))
		for err := range errorChan {
			errorMessage = append(errorMessage, err.Error())
		}
		return errors.New("[" + strings.Join(errorMessage, ",") + "]")
	}
	return nil
}

func (cm *GroupMulticastMgr) SendToGroupAsync(groupName string, protocolID protocol.ID, data []byte) {
	groupPeers := cm.getPeers(groupName)
	for index, groupPeer := range groupPeers {
		go func(i int, peer peer.ID) {
			err := cm.host.SendMsg(protocolID, peer, data)
			if err != nil {
				cm.logger.Errorf("send data to group err. group: %s, protocol id: %v, peer: %v, err: %s",
					groupName, protocolID, peer, err)
			}
		}(index, groupPeer)
	}
}
