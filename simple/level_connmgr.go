/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package simple

import (
	"errors"
	"math/rand"
	"strings"
	"sync"
	"time"

	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/host"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/mgr"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/network"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/peer"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/types"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/util"
	api "chainmaker.org/chainmaker/protocol"
)

// EliminationStrategy is strategy for eliminating connected peer
type EliminationStrategy string

const (
	// Unknown elimination strategy
	Unknown EliminationStrategy = "UNKNOWN"
	// Random elimination strategy
	Random EliminationStrategy = "RANDOM"
	// FIFO FIRST_IN_FIRST_OUT elimination strategy
	FIFO EliminationStrategy = "FIFO"
	// LIFO LAST_IN_FIRST_OUT elimination strategy
	LIFO EliminationStrategy = "LIFO"
)

// EliminationStrategyFromInt get EliminationStrategy with a int value.
// 1.Random, 2.FIFO, 3.LIFO
func EliminationStrategyFromInt(strategy int) EliminationStrategy {
	switch strategy {
	case 1:
		return Random
	case 2:
		return FIFO
	case 3:
		return LIFO
	default:
		return Unknown
		//panic(errors.New("unknown elimination strategy"))
	}
}

var eliminatedHighLevelConnBugError = errors.New("no high level connection will be eliminated bug. pls check why")

// DefaultMaxPeerCountAllow is the default max peer count allowed.
const DefaultMaxPeerCountAllow = 20

// DefaultMaxConnCountEachPeerAllowed is the default max connections count of each peer allowed.
const DefaultMaxConnCountEachPeerAllowed = 1

// DefaultEliminationStrategy is the default strategy for elimination.
const DefaultEliminationStrategy = LIFO

type peerConnections struct {
	pid  peer.ID
	conn *types.ConnSet
}

var _ mgr.ConnMgr = (*LevelConnManager)(nil)

// LevelConnManager is a connection manager of peers.
type LevelConnManager struct {
	logger api.Logger

	cmLock                      sync.RWMutex
	maxPeerCountAllowed         int
	maxConnCountEachPeerAllowed int
	strategy                    EliminationStrategy
	highLevelPeersLock          sync.RWMutex
	highLevelPeers              *types.PeerIdSet
	highLevelConn               []*peerConnections
	lowLevelConn                []*peerConnections

	host       host.Host
	expandingC chan struct{}

	eliminatePeers *types.PeerIdSet
}

// SetStrategy set the elimination strategy. If not set, default is LIFO.
func (cm *LevelConnManager) SetStrategy(strategy EliminationStrategy) {
	strategy = EliminationStrategy(strings.ToUpper(string(strategy)))
	switch strategy {
	case Random, FIFO, LIFO:
		cm.strategy = strategy
	default:
		cm.logger.Warnf("[LevelConnManager] wrong strategy set(strategy:%s). use default(default:%s)",
			strategy, DefaultEliminationStrategy)
		cm.strategy = DefaultEliminationStrategy
	}
}

// SetMaxPeerCountAllowed set max count of peers allowed. If not set, default is 20.
func (cm *LevelConnManager) SetMaxPeerCountAllowed(max int) {
	if max < 1 {
		cm.logger.Warnf("[LevelConnManager] wrong max peer count set(max count:%d). use default(default:%d)",
			max, DefaultMaxPeerCountAllow)
		max = DefaultMaxPeerCountAllow
	}
	cm.maxPeerCountAllowed = max
}

// SetMaxConnCountEachPeerAllowed set max connections count of each peer allowed. If not set, default is 1.
func (cm *LevelConnManager) SetMaxConnCountEachPeerAllowed(max int) {
	if max < 1 {
		cm.logger.Warnf("[LevelConnManager] wrong max connections count of each peer set(max count:%d). "+
			"use default(default:%d)", max, DefaultMaxConnCountEachPeerAllowed)
		max = DefaultMaxConnCountEachPeerAllowed
	}
	cm.maxConnCountEachPeerAllowed = max
}

// NewLevelConnManager create a new LevelConnManager.
func NewLevelConnManager(logger api.Logger, h host.Host) *LevelConnManager {
	return &LevelConnManager{
		logger:                      logger,
		maxPeerCountAllowed:         DefaultMaxPeerCountAllow,
		maxConnCountEachPeerAllowed: DefaultMaxConnCountEachPeerAllowed,
		strategy:                    DefaultEliminationStrategy,
		highLevelPeers:              &types.PeerIdSet{},
		highLevelConn:               make([]*peerConnections, 0),
		lowLevelConn:                make([]*peerConnections, 0),
		host:                        h,
		expandingC:                  make(chan struct{}, 1),
		eliminatePeers:              &types.PeerIdSet{},
	}
}

func (cm *LevelConnManager) Close() error {
	cm.cmLock.Lock()
	defer cm.cmLock.Unlock()
	for idx := range cm.lowLevelConn {
		cm.lowLevelConn[idx].conn.Range(func(c network.Conn) bool {
			_ = c.Close()
			return true
		})
	}

	for idx := range cm.highLevelConn {
		cm.highLevelConn[idx].conn.Range(func(c network.Conn) bool {
			_ = c.Close()
			return true
		})
	}
	return nil
}

// IsHighLevel return true if the peer which is high-level (consensus & seeds) node. Otherwise return false.
func (cm *LevelConnManager) IsHighLevel(peerId peer.ID) bool {
	return cm.highLevelPeers.Exist(peerId)
}

// AddAsHighLevelPeer add a peer id as high level peer.
func (cm *LevelConnManager) AddAsHighLevelPeer(peerId peer.ID) {
	cm.highLevelPeers.Put(peerId)
}

// RemoveHighLevelPeer remove a high level peer id.
func (cm *LevelConnManager) RemoveHighLevelPeer(peerId peer.ID) {
	cm.highLevelPeers.Remove(peerId)
}

// ClearHighLevelPeer clear all high level peer id records.
func (cm *LevelConnManager) ClearHighLevelPeer() {
	cm.highLevelPeersLock.Lock()
	defer cm.highLevelPeersLock.Unlock()
	cm.highLevelPeers = &types.PeerIdSet{}
}

func (cm *LevelConnManager) getHighLevelConnections(pid peer.ID) (*types.ConnSet, int) {
	for idx, connections := range cm.highLevelConn {
		if pid == connections.pid {
			return connections.conn, idx
		}
	}
	return nil, -1
}

func (cm *LevelConnManager) getLowLevelConnections(pid peer.ID) (*types.ConnSet, int) {
	for idx, connections := range cm.lowLevelConn {
		if pid == connections.pid {
			return connections.conn, idx
		}
	}
	return nil, -1
}

func (cm *LevelConnManager) eliminateConnections(isHighLevel bool) (peer.ID, error) {
	switch cm.strategy {
	case Random:
		return cm.eliminateConnectionsRandom(isHighLevel)
	case FIFO:
		return cm.eliminateConnectionsFIFO(isHighLevel)
	case LIFO:
		return cm.eliminateConnectionsLIFO(isHighLevel)
	default:
		cm.logger.Warnf("[LevelConnManager] unknown elimination strategy[%s], use default[%s]",
			cm.strategy, DefaultEliminationStrategy)
		cm.strategy = DefaultEliminationStrategy
		return cm.eliminateConnections(isHighLevel)
	}
}

func (cm *LevelConnManager) closeLowLevelConnWithIdx(idx int) {
	cm.lowLevelConn[idx].conn.Range(func(c network.Conn) bool {
		go func(connToClose network.Conn) {
			_ = connToClose.Close()
		}(c)
		return true
	})
}

func (cm *LevelConnManager) closeHighLevelConnWithIdx(idx int) {
	cm.highLevelConn[idx].conn.Range(func(c network.Conn) bool {
		go func(connToClose network.Conn) {
			_ = connToClose.Close()
		}(c)
		return true
	})
}

func (cm *LevelConnManager) closeLowLevelConnRandom(lowLevelConnCount int) (peer.ID, error) {
	rand.Seed(time.Now().UnixNano())
	random := rand.Intn(lowLevelConnCount)
	eliminatedPid := cm.lowLevelConn[random].pid
	cm.closeLowLevelConnWithIdx(random)
	if random == lowLevelConnCount-1 {
		cm.lowLevelConn = cm.lowLevelConn[:random]
	} else {
		cm.lowLevelConn = append(cm.lowLevelConn[:random], cm.lowLevelConn[random+1:]...)
	}
	return eliminatedPid, nil
}

func (cm *LevelConnManager) closeHighLevelConnRandom(highLevelConnCount int) (peer.ID, error) {
	rand.Seed(time.Now().UnixNano())
	random := rand.Intn(highLevelConnCount)
	eliminatedPid := cm.highLevelConn[random].pid
	cm.closeHighLevelConnWithIdx(random)
	if random == highLevelConnCount-1 {
		cm.highLevelConn = cm.highLevelConn[:random]
	} else {
		cm.highLevelConn = append(cm.highLevelConn[:random], cm.highLevelConn[random+1:]...)
	}
	return eliminatedPid, nil
}

func (cm *LevelConnManager) eliminateConnectionsRandom(isHighLevel bool) (peer.ID, error) {
	hCount := len(cm.highLevelConn)
	lCount := len(cm.lowLevelConn)
	if hCount+lCount > cm.maxPeerCountAllowed {
		if lCount > 0 {
			eliminatedPid, err := cm.closeLowLevelConnRandom(lCount)
			if err != nil {
				return "", err
			}
			cm.logger.Infof("[LevelConnManager] eliminate connections(strategy:Random, is high-level:%v, "+
				"eliminated pid:%s)", isHighLevel, eliminatedPid)
			return eliminatedPid, nil
		}
		if !isHighLevel {
			return "", eliminatedHighLevelConnBugError
		}
		eliminatedPid, err := cm.closeHighLevelConnRandom(hCount)
		if err != nil {
			return "", err
		}
		cm.logger.Infof("[LevelConnManager] eliminate connections(strategy:Random, is high-level:%v, "+
			"eliminated pid:%s)", isHighLevel, eliminatedPid)
		return eliminatedPid, nil
	}
	return "", nil
}

func (cm *LevelConnManager) closeLowLevelConnFirst() (peer.ID, error) {
	eliminatedPid := cm.lowLevelConn[0].pid
	cm.closeLowLevelConnWithIdx(0)
	cm.lowLevelConn = cm.lowLevelConn[1:]
	return eliminatedPid, nil
}

func (cm *LevelConnManager) closeHighLevelConnFirst() (peer.ID, error) {
	eliminatedPid := cm.highLevelConn[0].pid
	cm.closeHighLevelConnWithIdx(0)
	cm.highLevelConn = cm.highLevelConn[1:]
	return eliminatedPid, nil
}

func (cm *LevelConnManager) eliminateConnectionsFIFO(isHighLevel bool) (peer.ID, error) {
	hCount := len(cm.highLevelConn)
	lCount := len(cm.lowLevelConn)
	if hCount+lCount > cm.maxPeerCountAllowed {
		if lCount > 0 {
			eliminatedPid, err := cm.closeLowLevelConnFirst()
			if err != nil {
				return "", err
			}
			cm.logger.Infof("[LevelConnManager] eliminate connections(strategy:FIFO, is high-level:%v, "+
				"eliminated pid:%s)", isHighLevel, eliminatedPid)
			return eliminatedPid, nil
		}
		if !isHighLevel {
			return "", eliminatedHighLevelConnBugError
		}
		eliminatedPid, err := cm.closeHighLevelConnFirst()
		if err != nil {
			return "", err
		}
		cm.logger.Infof("[LevelConnManager] eliminate connections(strategy:FIFO, is high-level:%v, "+
			"eliminated pid:%s)", isHighLevel, eliminatedPid)
		return eliminatedPid, nil
	}
	return "", nil
}

func (cm *LevelConnManager) closeLowLevelConnLast(lowLevelConnCount int) (peer.ID, error) {
	idx := lowLevelConnCount - 1
	eliminatedPid := cm.lowLevelConn[idx].pid
	cm.closeLowLevelConnWithIdx(idx)
	cm.lowLevelConn = cm.lowLevelConn[0:idx]
	return eliminatedPid, nil
}

func (cm *LevelConnManager) closeHighLevelConnLast(highLevelConnCount int) (peer.ID, error) {
	idx := highLevelConnCount - 1
	eliminatedPid := cm.highLevelConn[idx].pid
	cm.closeHighLevelConnWithIdx(idx)
	cm.highLevelConn = cm.highLevelConn[0:idx]
	return eliminatedPid, nil
}

func (cm *LevelConnManager) eliminateConnectionsLIFO(isHighLevel bool) (peer.ID, error) {
	hCount := len(cm.highLevelConn)
	lCount := len(cm.lowLevelConn)
	if hCount+lCount > cm.maxPeerCountAllowed {
		if lCount > 0 {
			eliminatedPid, err := cm.closeLowLevelConnLast(lCount)
			if err != nil {
				return "", err
			}
			cm.logger.Infof("[LevelConnManager] eliminate connections(strategy:LIFO, is high-level:%v, "+
				"eliminated pid:%s)", isHighLevel, eliminatedPid)
			return eliminatedPid, nil
		}
		if !isHighLevel {
			return "", eliminatedHighLevelConnBugError
		}
		eliminatedPid, err := cm.closeHighLevelConnLast(hCount)
		if err != nil {
			return "", err
		}
		cm.logger.Infof("[LevelConnManager] eliminate connections(strategy:LIFO, is high-level:%v, "+
			"eliminated pid:%s)", isHighLevel, eliminatedPid)
		return eliminatedPid, nil
	}
	return "", nil
}

// AddPeerConn add a connection.
func (cm *LevelConnManager) AddPeerConn(pid peer.ID, conn network.Conn) bool {
	cm.cmLock.Lock()
	defer cm.cmLock.Unlock()
	cm.logger.Debugf("[LevelConnManager] add conn(pid:%s)", pid)
	isHighLevel := cm.IsHighLevel(pid)
	if isHighLevel {
		connSet, _ := cm.getHighLevelConnections(pid)
		if connSet != nil {
			if !connSet.Put(conn) {
				cm.logger.Warnf("[LevelConnManager] connection exist(pid:%s). ignored.", pid)
				return false
			}
			return true
		}
		connSet = &types.ConnSet{}
		connSet.Put(conn)
		pcs := &peerConnections{
			pid:  pid,
			conn: connSet,
		}
		cm.highLevelConn = append(cm.highLevelConn, pcs)
	} else {
		connSet, _ := cm.getLowLevelConnections(pid)
		if connSet != nil {
			if !connSet.Put(conn) {
				cm.logger.Warnf("[LevelConnManager] connection exist(pid:%s). ignored.", pid)
				return false
			}
			return true
		}
		connSet = &types.ConnSet{}
		connSet.Put(conn)
		pcs := &peerConnections{
			pid:  pid,
			conn: connSet,
		}
		cm.lowLevelConn = append(cm.lowLevelConn, pcs)
	}
	ePid, err := cm.eliminateConnections(isHighLevel)
	if err != nil {
		cm.logger.Errorf("[LevelConnManager] eliminate connection failed, %s", err.Error())
	} else if ePid != "" {
		cm.eliminatePeers.Put(ePid)
		cm.logger.Infof("[LevelConnManager] eliminate connection ok(pid:%s)", ePid)
	}
	return true
}

// RemovePeerConn remove a connection.
func (cm *LevelConnManager) RemovePeerConn(pid peer.ID, conn network.Conn) bool {
	cm.cmLock.Lock()
	defer cm.cmLock.Unlock()
	res := false

	c, idx := cm.getHighLevelConnections(pid)
	if idx != -1 {
		if c.Exist(conn) {
			if idx == len(cm.highLevelConn)-1 {
				cm.highLevelConn = cm.highLevelConn[:idx]
			} else {
				cm.highLevelConn = append(cm.highLevelConn[:idx], cm.highLevelConn[idx+1:]...)
			}
			res = true
		}
	}

	c2, idx2 := cm.getLowLevelConnections(pid)
	if idx2 != -1 {
		if c2.Exist(conn) {
			if idx2 == len(cm.lowLevelConn)-1 {
				cm.lowLevelConn = cm.lowLevelConn[:idx2]
			} else {
				cm.lowLevelConn = append(cm.lowLevelConn[:idx2], cm.lowLevelConn[idx2+1:]...)
			}
			res = true
		}
	}

	if cm.eliminatePeers.Remove(pid) {
		res = true
	}
	return res
}

// ExistPeerConn return whether connection exist.
func (cm *LevelConnManager) ExistPeerConn(pid peer.ID, conn network.Conn) bool {
	cm.cmLock.RLock()
	defer cm.cmLock.RUnlock()
	var s *types.ConnSet
	var idx int
	if s, idx = cm.getHighLevelConnections(pid); idx == -1 {
		s, _ = cm.getLowLevelConnections(pid)
	}
	return s.Exist(conn)
}

// GetPeerConn return a connection of peer.
func (cm *LevelConnManager) GetPeerConn(pid peer.ID) network.Conn {
	cm.cmLock.RLock()
	defer cm.cmLock.RUnlock()
	var res network.Conn
	var s *types.ConnSet
	var idx int
	if s, idx = cm.getHighLevelConnections(pid); idx == -1 {
		s, idx = cm.getLowLevelConnections(pid)
	}
	if idx != -1 {
		s.Range(func(conn network.Conn) bool {
			res = conn
			return false
		})
	}
	return res
}

// GetPeerAllConn return all connections of peer.
func (cm *LevelConnManager) GetPeerAllConn(pid peer.ID) []network.Conn {
	cm.cmLock.RLock()
	defer cm.cmLock.RUnlock()
	var res []network.Conn
	var s *types.ConnSet
	var idx int
	if s, idx = cm.getHighLevelConnections(pid); idx == -1 {
		s, idx = cm.getLowLevelConnections(pid)
	}
	if idx != -1 {
		res = make([]network.Conn, 0, s.Size())
		s.Range(func(conn network.Conn) bool {
			res = append(res, conn)
			return true
		})
	}
	return res
}

// IsConnected return true if peer has connected. Otherwise return false.
func (cm *LevelConnManager) IsConnected(pid peer.ID) bool {
	cm.cmLock.RLock()
	defer cm.cmLock.RUnlock()
	if s, idx := cm.getHighLevelConnections(pid); idx != -1 && s.Size() > 0 {
		return true
	}
	if s, idx := cm.getLowLevelConnections(pid); idx != -1 && s.Size() > 0 {
		return true
	}
	return false
}

// IsAllowed return true if peer can connect to self. Otherwise return false.
func (cm *LevelConnManager) IsAllowed(pid peer.ID) bool {
	cm.cmLock.RLock()
	defer cm.cmLock.RUnlock()
	currentCount := 0
	if s, idx := cm.getHighLevelConnections(pid); idx != -1 {
		currentCount = currentCount + s.Size()
	}
	if s, idx := cm.getLowLevelConnections(pid); idx != -1 {
		currentCount = currentCount + s.Size()
	}
	if currentCount > 0 {
		return currentCount < cm.maxConnCountEachPeerAllowed
	}
	if cm.strategy == LIFO {
		if cm.IsHighLevel(pid) {
			return len(cm.highLevelConn) < cm.maxPeerCountAllowed
		}
		if len(cm.highLevelConn)+len(cm.lowLevelConn) >= cm.maxPeerCountAllowed {
			return false
		}
	}
	return true
}

func (cm *LevelConnManager) expendConn(pid peer.ID) {
	defer func() {
		<-cm.expandingC
	}()
	if !cm.IsConnected(pid) {
		return
	}
	if !cm.IsAllowed(pid) {
		return
	}
	existConn := cm.GetPeerConn(pid)
	if existConn == nil {
		return
	}
	cm.logger.Infof("[LevelConnManager] trying to establish a new connection with peer. "+
		"(remote pid: %s, remote addr: %s)", existConn.RemotePeerID(), existConn.RemoteAddr().String())
	_, err := cm.host.Dial(util.CreateMultiAddrWithPidAndNetAddr(existConn.RemotePeerID(), existConn.RemoteAddr()))
	if err != nil {
		cm.logger.Warnf("[LevelConnManager] establish a new connection with peer failed. %s "+
			"(remote pid: %s, remote addr: %s)", err.Error(), existConn.RemotePeerID(), existConn.RemoteAddr().String())
		return
	}
}

// ExpendConn try to establish a new connection with peer if the count of connections does not reach the max.
func (cm *LevelConnManager) ExpendConn(pid peer.ID) {
	select {
	case cm.expandingC <- struct{}{}:
		go cm.expendConn(pid)
	default:
		return
	}
}

// PeerCount return the count num of peers.
func (cm *LevelConnManager) PeerCount() int {
	cm.cmLock.RLock()
	defer cm.cmLock.RUnlock()
	return len(cm.highLevelConn) + len(cm.lowLevelConn)
}

// MaxPeerCountAllowed return max peer count allowed .
func (cm *LevelConnManager) MaxPeerCountAllowed() int {
	return cm.maxPeerCountAllowed
}

// AllPeer return peer id list of all peers connected.
func (cm *LevelConnManager) AllPeer() []peer.ID {
	cm.cmLock.RLock()
	defer cm.cmLock.RUnlock()
	hl := len(cm.highLevelConn)
	ll := len(cm.lowLevelConn)
	res := make([]peer.ID, 0, hl+ll)
	for idx := range cm.highLevelConn {
		res = append(res, cm.highLevelConn[idx].pid)
	}
	for idx := range cm.lowLevelConn {
		res = append(res, cm.lowLevelConn[idx].pid)
	}
	return res
}
