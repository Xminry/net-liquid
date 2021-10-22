/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package pubsub

import (
	"errors"
	"sync"
	"time"

	"chainmaker.org/chainmaker/net-liquid/core/peer"
	"chainmaker.org/chainmaker/net-liquid/core/types"
	"chainmaker.org/chainmaker/net-liquid/pubsub/pb"
	api "chainmaker.org/chainmaker/protocol/v2"
)

// TypeOfPeering is the type of peering stat.
type TypeOfPeering int

const (
	// UnknownTypeOfPeering is unknown peering stat.
	UnknownTypeOfPeering TypeOfPeering = iota
	// FullMsgTypeOfPeering is full-msg peering stat.
	FullMsgTypeOfPeering
	// MetadataOnlyTypeOfPeering is metadata-only peering stat.
	MetadataOnlyTypeOfPeering
	// FanOutTypeOfPeering is fan-out peering stat.
	FanOutTypeOfPeering
)

// topicPeeringMapList wraps a map mapped topic with TypeOfPeering.
type topicPeeringMapList struct {
	m sync.Map // map[string]TypeOfPeering
}

func (l *topicPeeringMapList) Set(topic string, typeOfPeering TypeOfPeering) {
	l.m.Store(topic, typeOfPeering)
}

func (l *topicPeeringMapList) Get(topic string) TypeOfPeering {
	v, ok := l.m.Load(topic)
	if ok {
		return v.(TypeOfPeering)
	}
	return UnknownTypeOfPeering
}

func (l *topicPeeringMapList) Remove(topic string) {
	l.m.LoadAndDelete(topic)
}

func (l *topicPeeringMapList) IsEmpty() bool {
	res := true
	l.m.Range(func(_, _ interface{}) bool {
		res = false
		return false
	})
	return res
}

// peerTopicPeeringStore wraps a map mapped peer.ID with *topicPeeringMapList
type peerTopicPeeringStore struct {
	m sync.Map // map[peer.ID]*topicPeeringMapList
}

func (s *peerTopicPeeringStore) SetTypeOfPeeringForTopic(pid peer.ID, topic string, typeOfPeering TypeOfPeering) {
	l, _ := s.m.LoadOrStore(pid, &topicPeeringMapList{})
	l.(*topicPeeringMapList).Set(topic, typeOfPeering)
}

func (s *peerTopicPeeringStore) GetTypeOfPeeringForTopic(pid peer.ID, topic string) TypeOfPeering {
	l, ok := s.m.Load(pid)
	if !ok {
		return UnknownTypeOfPeering
	}
	return l.(*topicPeeringMapList).Get(topic)
}

func (s *peerTopicPeeringStore) RemoveTypeOfPeeringForTopic(pid peer.ID, topic string) {
	l, ok := s.m.Load(pid)
	if !ok {
		return
	}
	list, _ := l.(*topicPeeringMapList)
	list.Remove(topic)
	if list.IsEmpty() {
		s.CleanPeer(pid)
	}
}

func (s *peerTopicPeeringStore) CleanPeer(pid peer.ID) {
	s.m.LoadAndDelete(pid)
}

// topicPeeringMgr manage peering stat of a topic.
// Also abbreviated as TPM.
type topicPeeringMgr struct {
	mu sync.RWMutex

	topic      string
	subscribed bool
	ps         *peerState

	fanOutSize    int32
	fanOutTimeout time.Duration
	fanOutPeer    *types.PeerIdSet

	degreeLow     int32
	degreeHigh    int32
	degreeDesired int32
	fullMsgPeer   *types.PeerIdSet

	metadataOnlyPeer *types.PeerIdSet

	fullMsgCheckSignal      chan struct{}
	fanOutCheckSignal       chan struct{}
	fanOutTimeoutTaskSignal chan struct{}
	fanOutTimeoutTimer      *time.Timer

	logger api.Logger
}

// newTopicPeeringMgr create a new TPM
func newTopicPeeringMgr(
	topic string,
	ps *peerState,
	fanOutSize int32,
	fanOutTimeout time.Duration,
	degreeLow int32,
	degreeHigh int32,
	degreeDesired int32,
	logger api.Logger,
) (*topicPeeringMgr, error) {
	// parameters check
	if fanOutSize < 1 {
		return nil, errors.New("fan-out size param must be greater than 0")
	}
	if degreeLow < 1 {
		return nil, errors.New("full-msg degree low param must be greater than 0")
	}
	if degreeDesired < degreeLow {
		return nil, errors.New("full-msg degree desired param must be greater than low param")
	}
	if degreeHigh < degreeDesired {
		return nil, errors.New("full-msg degree high param must be greater than desired param")
	}

	return &topicPeeringMgr{
		topic:                   topic,
		subscribed:              ps.IsSubscribed(topic),
		ps:                      ps,
		fanOutSize:              fanOutSize,
		fanOutTimeout:           fanOutTimeout,
		fanOutPeer:              &types.PeerIdSet{},
		degreeLow:               degreeLow,
		degreeHigh:              degreeHigh,
		degreeDesired:           degreeDesired,
		fullMsgPeer:             &types.PeerIdSet{},
		metadataOnlyPeer:        &types.PeerIdSet{},
		fullMsgCheckSignal:      make(chan struct{}, 1),
		fanOutCheckSignal:       make(chan struct{}, 1),
		fanOutTimeoutTaskSignal: make(chan struct{}, 1),
		fanOutTimeoutTimer:      nil,
		logger:                  logger,
	}, nil
}

// rollFewPeerInPeerIdSet rand few size in peer id set.
func rollFewPeerInPeerIdSet(rollSize int32, s *types.PeerIdSet) []peer.ID {
	res := make([]peer.ID, 0, rollSize)
	var idx int32
	s.Range(func(pid peer.ID) bool {
		res = append(res, pid)
		idx++
		return idx < rollSize
	})
	return res
}

// joinUp upgrade MetadataOnly peer to FullMsg peer
func (m *topicPeeringMgr) joinUp(pid peer.ID) {
	m.fullMsgPeer.Put(pid)
	m.metadataOnlyPeer.Remove(pid)
	m.fanOutPeer.Remove(pid)
}

// sendJoinUpCtrlMsg send a join-up control message
func (m *topicPeeringMgr) sendJoinUpCtrlMsg(pid peer.ID) error {
	// send JoinUp message
	m.ps.chainPubSub.msgBasket.SendJoinUp(m.topic, pid)
	return nil
}

// fanOut upgrade MetadataOnly peer to FanOut peer
func (m *topicPeeringMgr) fanOut(pid peer.ID) {
	if m.fullMsgPeer.Exist(pid) {
		return
	}
	m.fanOutPeer.Put(pid)
	m.metadataOnlyPeer.Remove(pid)
}

// cancelFanOut downgrade FanOut peer to MetadataOnly peer
func (m *topicPeeringMgr) cancelFanOut(pid peer.ID) {
	if m.fullMsgPeer.Exist(pid) {
		return
	}
	m.metadataOnlyPeer.Put(pid)
	m.fanOutPeer.Remove(pid)
}

// cutOff downgrade FullMsg peer to MetadataOnly peer
func (m *topicPeeringMgr) cutOff(pid peer.ID) {
	m.metadataOnlyPeer.Put(pid)
	m.fullMsgPeer.Remove(pid)
}

// sendCutOffCtrl send a cut-off control message
func (m *topicPeeringMgr) sendCutOffCtrl(pid peer.ID) error {
	// send CutOff message
	m.ps.chainPubSub.msgBasket.SendCutOff(m.topic, pid)
	return nil
}

// fullMsgCheck check FullMsg peering stat.
// Only one process running at the sametime.
// In this task, maybe some peers would be upgraded from MetadataOnly peering to FullMsg peering,
// also maybe some peers would be downgraded from FullMsg peering to MetadataOnly peering.
func (m *topicPeeringMgr) fullMsgCheck(lock bool) {
	select {
	case m.fullMsgCheckSignal <- struct{}{}:
		defer func() {
			<-m.fullMsgCheckSignal
		}()
	default:
		return
	}
	if lock {
		m.mu.Lock()
		defer m.mu.Unlock()
	}

	// there is no full msg peer if not subscribed
	if !m.subscribed {
		return
	}

	currentSize := int32(m.fullMsgPeer.Size())
	switch {
	case currentSize < m.degreeLow:
		// join up some peers
		joinUpSize := m.degreeDesired - currentSize
		joinUpPeers := rollFewPeerInPeerIdSet(joinUpSize, m.metadataOnlyPeer)
		for i := range joinUpPeers {
			pid := joinUpPeers[i]
			if m.fullMsgPeer.Exist(pid) {
				continue
			}
			m.joinUp(pid)
			err := m.sendJoinUpCtrlMsg(pid)
			if err != nil {
				m.logger.Warnf("[TopicPeeringMgr] send join up control msg failed, %s ", err.Error())
			}
			m.logger.Debugf("[TopicPeeringMgr] peer join up.(topic: %s, remote pid: %s)", m.topic, pid)
		}
	case currentSize > m.degreeHigh:
		// cut off some peers
		cutOffSize := currentSize - m.degreeDesired
		cutOffPeers := rollFewPeerInPeerIdSet(cutOffSize, m.fullMsgPeer)
		for i := range cutOffPeers {
			pid := cutOffPeers[i]
			m.cutOff(pid)
			err := m.sendCutOffCtrl(pid)
			if err != nil {
				m.logger.Warnf("[TopicPeeringMgr] send cut off control msg failed, %s ", err.Error())
			}
			m.logger.Debugf("[TopicPeeringMgr] peer cut off.(topic: %s, remote pid: %s)", m.topic, pid)
		}
	}
}

// fanOutTimeoutTask is a task waiting for canceling FanOut peering.
func (m *topicPeeringMgr) fanOutTimeoutTask() {
	select {
	case m.fanOutTimeoutTaskSignal <- struct{}{}:
		// only one process in running
		defer func() {
			<-m.fanOutTimeoutTaskSignal
		}()
	default:
		if m.fanOutTimeoutTimer != nil {
			// call repeated , reset timeout timer.
			m.fanOutTimeoutTimer.Reset(m.fanOutTimeout)
		}
		return
	}
	m.fanOutTimeoutTimer = time.NewTimer(m.fanOutTimeout)
	defer func() {
		m.fanOutTimeoutTimer = nil
	}()
	select {
	case <-m.fanOutTimeoutTimer.C:
		m.mu.Lock()
		defer m.mu.Unlock()
		m.fanOutPeer.Range(func(pid peer.ID) bool {
			m.cancelFanOut(pid)
			return true
		})
		m.logger.Debugf("[TopicPeeringMgr] [FanOutTimeoutTask] fan out peering timeout, "+
			"cancel fan out(topic: %s)", m.topic)
	}
}

// fanOutCheck check FanOut peering stat.
// Only one process running at the sametime.
// In this task, maybe some peers would be upgraded from MetadataOnly peering to FanOut peering,
// also maybe some peers would be downgraded from FanOut peering to MetadataOnly peering.
// A FanOut timeout task will run in process.
func (m *topicPeeringMgr) fanOutCheck(lock bool) {
	select {
	case m.fanOutCheckSignal <- struct{}{}:
		defer func() {
			<-m.fanOutCheckSignal
		}()
	default:
		return
	}
	if lock {
		m.mu.Lock()
		defer m.mu.Unlock()
	}

	// there is no fan out peer if subscribed
	if m.subscribed {
		return
	}

	currentSize := int32(m.fanOutPeer.Size())
	switch {
	case currentSize < m.fanOutSize:
		// fan out some peers
		fanOutSize := m.fanOutSize - currentSize
		fanOutPeers := rollFewPeerInPeerIdSet(fanOutSize, m.metadataOnlyPeer)
		for i := range fanOutPeers {
			pid := fanOutPeers[i]
			m.fanOut(pid)
			m.logger.Debugf("[TopicPeeringMgr] peer fan out.(topic: %s, remote pid: %s)", m.topic, pid)
		}
	case currentSize > m.fanOutSize:
		// cancel fan out some peers
		cancelSize := currentSize - m.fanOutSize
		cancelPeers := rollFewPeerInPeerIdSet(cancelSize, m.fanOutPeer)
		for i := range cancelPeers {
			pid := cancelPeers[i]
			m.cancelFanOut(pid)
			m.logger.Debugf("[TopicPeeringMgr] peer cancel fan out .(topic: %s, remote pid: %s)", m.topic, pid)
		}
	}

	// start or refresh fan-out timeout check task
	go m.fanOutTimeoutTask()
}

func (m *topicPeeringMgr) peerExist(pid peer.ID) bool {
	return m.metadataOnlyPeer.Exist(pid) || m.fanOutPeer.Exist(pid) || m.fullMsgPeer.Exist(pid)
}

// CleanPeer remove a peer from this topic peering manager.
func (m *topicPeeringMgr) CleanPeer(pid peer.ID) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.fanOutPeer.Remove(pid)
	m.fullMsgPeer.Remove(pid)
	m.metadataOnlyPeer.Remove(pid)
	// check FullMsgPeering
	m.fullMsgCheck(false)
}

// Subscribe this topic.
func (m *topicPeeringMgr) Subscribe() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.subscribed {
		return
	}
	m.logger.Infof("[TopicPeeringMgr] [Subscribe] subscribe topic, (topic:%s) ", m.topic)
	// parse all FanOutPeering to FullMsgPeering
	if m.fanOutPeer.Size() > 0 {
		m.logger.Debugf("[TopicPeeringMgr] [Subscribe] translate fan out peer to full message peer, "+
			"(fan out count :%d) ", m.fanOutPeer.Size())
		temp := m.fanOutPeer
		m.fanOutPeer = &types.PeerIdSet{}
		temp.Range(func(pid peer.ID) bool {
			m.metadataOnlyPeer.Put(pid)
			m.joinUp(pid)
			err := m.sendJoinUpCtrlMsg(pid)
			if err != nil {
				m.logger.Debugf("[TopicPeeringMgr] [Subscribe] send join up control msg failed, %s ",
					err.Error())
			}
			return true
		})
	}

	m.subscribed = true
	// check FullMsgPeering
	m.fullMsgCheck(false)
}

// Unsubscribe this topic.
func (m *topicPeeringMgr) Unsubscribe() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.subscribed {
		return
	}
	temp := m.fullMsgPeer
	m.fullMsgPeer = &types.PeerIdSet{}
	temp.Range(func(pid peer.ID) bool {
		m.cutOff(pid)
		err := m.sendCutOffCtrl(pid)
		if err != nil {
			m.logger.Debugf("[TopicPeeringMgr] [Unsubscribe] send peer cut off control msg failed, %s ",
				err.Error())
		}
		return true
	})
	m.subscribed = false
}

// GetPeerIdsWithTypeOfPeering return peer id list which type of given.
func (m *topicPeeringMgr) GetPeerIdsWithTypeOfPeering(peering TypeOfPeering) []peer.ID {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var pm *types.PeerIdSet = nil
	switch peering {
	case FullMsgTypeOfPeering:
		pm = m.fullMsgPeer
	case MetadataOnlyTypeOfPeering:
		pm = m.metadataOnlyPeer
	case FanOutTypeOfPeering:
		pm = m.fanOutPeer
	default:
		return nil
	}
	res := make([]peer.ID, 0, pm.Size())
	pm.Range(func(pid peer.ID) bool {
		res = append(res, pid)
		return true
	})
	return res
}

// PeerJoinUp upgrade a MetadataOnlyPeering peer to a FullMsgPeering peer.
func (m *topicPeeringMgr) PeerJoinUp(pid peer.ID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.joinUp(pid)
	// check FullMsgPeering
	m.fullMsgCheck(false)
	return nil
}

// PeerCutOff downgrade a FullMsgPeering peer to a MetadataOnlyPeering peer
// or add a new peer with MetadataOnlyPeering for topic.
func (m *topicPeeringMgr) PeerCutOff(pid peer.ID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cutOff(pid)
	// check FullMsgPeering
	m.fullMsgCheck(false)
	return nil
}

// AppendPeer add a peer to the tpm.
func (m *topicPeeringMgr) AppendPeer(pid peer.ID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.peerExist(pid) {
		return nil
	}
	m.metadataOnlyPeer.Put(pid)
	// check FullMsgPeering
	m.fullMsgCheck(false)
	return nil
}

// TargetFullMsgPeers return the peer.ID Set of peers which peering stat is FullMsg or FanOut
func (m *topicPeeringMgr) TargetFullMsgPeers() (*types.PeerIdSet, string) {
	m.mu.RLock()
	var typeSet *types.PeerIdSet
	var whichType string
	if m.subscribed {
		defer m.mu.RUnlock()
		// send msg to full-msg-peering peers
		typeSet = m.fullMsgPeer
		whichType = "full-msg-peering"
		//m.logger.Debugf("[TopicPeeringMgr] [PublishAppMsg] send app msg to full msg peering, (peer count:%d)",
		// len(typeSet))
	} else {
		m.mu.RUnlock()
		m.fanOutCheck(true)
		m.mu.RLock()
		defer m.mu.RUnlock()
		// send msg to fan-out-peering peers
		typeSet = m.fanOutPeer
		whichType = "fan-out-peering"
		//m.logger.Debugf("[TopicPeeringMgr] [PublishAppMsg] send app msg to fan out peering, (peer count:%d)",
		// len(typeSet))
	}
	return typeSet, whichType
}

// PublishAppMsg publish messages to the topic.
func (m *topicPeeringMgr) PublishAppMsg(messages []*pb.ApplicationMsg) {
	if len(messages) == 0 {
		return
	}
	m.ps.chainPubSub.msgBasket.PutApplicationMsg(messages...)
}
