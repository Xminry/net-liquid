/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package pubsub

import (
	"sync"
	"sync/atomic"
	"time"

	"chainmaker.org/chainmaker/net-liquid/core/peer"
	"chainmaker.org/chainmaker/net-liquid/core/types"
	"chainmaker.org/chainmaker/net-liquid/pubsub/pb"
	api "chainmaker.org/chainmaker/protocol/v2"
)

const (
	defaultMsgBasketHeartBeat = time.Second
	defaultTriggerAppMsgCount = 5
	defaultUnSubLogTimeout    = time.Minute
)

type appMsgBucket struct {
	sync.RWMutex
	size    int32
	msgList []*pb.ApplicationMsg
	m       map[string]*types.Uint64Set // sender -> appMsg sequence
}

func newAppMsgBucket() *appMsgBucket {
	return &appMsgBucket{
		RWMutex: sync.RWMutex{},
		msgList: make([]*pb.ApplicationMsg, 0, 10),
		m:       make(map[string]*types.Uint64Set),
	}
}

func (amb *appMsgBucket) putMsg(msg *pb.ApplicationMsg) int32 {
	amb.Lock()
	defer amb.Unlock()
	msgSender := msg.GetSender()
	s, ok := amb.m[msgSender]
	if !ok {
		s = &types.Uint64Set{}
		amb.m[msgSender] = s
	}
	msgSeq := msg.GetMsgSeq()
	if s.Put(msgSeq) {
		amb.msgList = append(amb.msgList, msg)
		return atomic.AddInt32(&amb.size, 1)
	}
	return amb.size
}

func (amb *appMsgBucket) getMsgList() []*pb.ApplicationMsg {
	amb.RLock()
	defer amb.RUnlock()
	return amb.msgList
}

func (amb *appMsgBucket) currentSize() int32 {
	amb.RLock()
	defer amb.RUnlock()
	return amb.size
}

type topicMsgBucket struct {
	sync.RWMutex
	cleanUnSubLogTime time.Time
	subLog            *types.StringSet // topics subscribed
	unSubLog          *types.StringSet // topics unsubscribed
}

func newTopicMsgBucket() *topicMsgBucket {
	return &topicMsgBucket{
		RWMutex:           sync.RWMutex{},
		cleanUnSubLogTime: time.Now(),
		subLog:            &types.StringSet{},
		unSubLog:          &types.StringSet{},
	}
}

func (t *topicMsgBucket) ctrl(topic string, subOrUnSub bool) {
	t.Lock()
	defer t.Unlock()
	if subOrUnSub {
		t.subLog.Put(topic)
		t.unSubLog.Remove(topic)
	} else {
		t.cleanUnSubLogTime = time.Now()
		t.unSubLog.Put(topic)
		t.subLog.Remove(topic)
	}
}

func (t *topicMsgBucket) currentStat() ([]string, []string) {
	if time.Since(t.cleanUnSubLogTime) > defaultUnSubLogTimeout {
		t.cleanUnSubLogTime = time.Now()
		t.Lock()
		t.unSubLog = &types.StringSet{}
		t.Unlock()
	}
	t.RLock()
	defer t.RUnlock()
	sub, unSub := make([]string, 0, t.subLog.Size()), make([]string, 0, t.unSubLog.Size())
	t.subLog.Range(func(str string) bool {
		sub = append(sub, str)
		return true
	})
	t.unSubLog.Range(func(str string) bool {
		unSub = append(unSub, str)
		return true
	})
	return sub, unSub
}

type peeringMsgBucket struct {
	sync.Mutex
	joinUpLog map[peer.ID]*types.StringSet // peer.ID -> topic
	cutOffLog map[peer.ID]*types.StringSet // peer.ID -> topic
}

func newPeeringMsgBucket() *peeringMsgBucket {
	return &peeringMsgBucket{
		Mutex:     sync.Mutex{},
		joinUpLog: make(map[peer.ID]*types.StringSet),
		cutOffLog: make(map[peer.ID]*types.StringSet),
	}
}

func (p *peeringMsgBucket) joinUp(topic string, pid peer.ID) {
	p.Lock()
	defer p.Unlock()
	s, ok := p.joinUpLog[pid]
	if !ok {
		s = &types.StringSet{}
		p.joinUpLog[pid] = s
	}
	s.Put(topic)
	ss, ok2 := p.cutOffLog[pid]
	if ok2 {
		ss.Remove(topic)
	}
}

func (p *peeringMsgBucket) cutOff(topic string, pid peer.ID) {
	p.Lock()
	defer p.Unlock()
	s, ok := p.cutOffLog[pid]
	if !ok {
		s = &types.StringSet{}
		p.cutOffLog[pid] = s
	}
	s.Put(topic)
	ss, ok2 := p.joinUpLog[pid]
	if ok2 {
		ss.Remove(topic)
	}
}

func (p *peeringMsgBucket) leaveTopic(topic string) {
	p.Lock()
	defer p.Unlock()
	for _, set := range p.joinUpLog {
		set.Remove(topic)
	}
	for _, set := range p.cutOffLog {
		set.Remove(topic)
	}
}

func (p *peeringMsgBucket) createPeeringMsgForPeer(pid peer.ID) *pb.PeeringMsg {
	p.Lock()
	defer p.Unlock()

	var joinUp []string
	s, ok := p.joinUpLog[pid]
	if ok {
		joinUp = make([]string, 0, 5)
		s.Range(func(str string) bool {
			joinUp = append(joinUp, str)
			return true
		})
		// clean it
		delete(p.joinUpLog, pid)
	}

	var cutOff []string
	ss, ok2 := p.cutOffLog[pid]
	if ok2 {
		cutOff = make([]string, 0, 5)
		ss.Range(func(str string) bool {
			cutOff = append(cutOff, str)
			return true
		})
		//clean it
		delete(p.cutOffLog, pid)
	}

	if !ok && !ok2 {
		return nil
	}

	res := &pb.PeeringMsg{
		CutOff: cutOff,
		JoinUp: joinUp,
		MsgSeq: 0,
	}
	return res
}

// MsgBasket manage the message that will be sent uniformly.
// Use this to reduce the times of calling send msg method.
// And then reduce occupation of resources of network.
type MsgBasket struct {
	sync.RWMutex
	once       sync.Once
	pubSub     *ChainPubSub
	closeC     chan struct{}
	heartbeatC chan struct{}
	ticker     *time.Ticker

	appMB     *appMsgBucket
	topicMB   *topicMsgBucket
	peeringMB *peeringMsgBucket

	logger api.Logger
}

// NewMsgBasket create a new *MsgBasket instance.
func NewMsgBasket(pubSub *ChainPubSub) *MsgBasket {
	return &MsgBasket{
		RWMutex:    sync.RWMutex{},
		once:       sync.Once{},
		pubSub:     pubSub,
		closeC:     make(chan struct{}),
		heartbeatC: make(chan struct{}, 1),
		ticker:     nil,
		appMB:      newAppMsgBucket(),
		topicMB:    newTopicMsgBucket(),
		peeringMB:  newPeeringMsgBucket(),
		logger:     pubSub.logger,
	}
}

// Cancel basket working.
func (mb *MsgBasket) Cancel() {
	close(mb.closeC)
}

func (mb *MsgBasket) onceFunc() {
	mb.ticker = time.NewTicker(defaultMsgBasketHeartBeat)
	go func() {
		for {
			select {
			case <-mb.closeC:
				return
			case <-mb.ticker.C:
				mb.HeartBeat()
			}
		}
	}()
}

// HeartBeat to pour out the basket.
func (mb *MsgBasket) HeartBeat() {
	select {
	case mb.heartbeatC <- struct{}{}:
		// only one heartbeat process running
		defer func() { <-mb.heartbeatC }()
	default:
		return
	}

	// refresh bucket
	newAppMB := newAppMsgBucket()
	mb.Lock()
	oldAppMB := mb.appMB
	mb.appMB = newAppMB
	peeringMB := mb.peeringMB
	mb.Unlock()

	// prepare app msg to target topic
	msgForTopic := make(map[string][]*pb.ApplicationMsg)
	msgList := oldAppMB.getMsgList()
	for i := range msgList {
		msg := msgList[i]
		msgTopics := msg.GetTopics()
		for j := range msgTopics {
			topic := msgTopics[j]
			l, ok := msgForTopic[topic]
			if !ok {
				l = make([]*pb.ApplicationMsg, 0, 10)
			}
			l = append(l, msg)
			msgForTopic[topic] = l
		}
	}

	// prepare topic msg
	sub, unSub := mb.topicMB.currentStat()
	topicMsg := &pb.TopicMsg{
		Subscribed:   sub,
		Unsubscribed: unSub,
		MsgSeq:       mb.pubSub.nextTopicMsgSeq(),
	}

	// prepare send
	allPeers := mb.pubSub.peers
	var sentPeers types.PeerIdSet
	// send application msg first
	wg := sync.WaitGroup{}
	for topic, msgs := range msgForTopic {
		msgGrp := mb.splitAppMsgList(msgs)
		tpm, err := mb.pubSub.initOrGetTPM(topic)
		if err != nil {
			mb.logger.Errorf("[MsgBasket] get topic peering manager failed, %s", err.Error())
			continue
		}
		targetPeers, _ := tpm.TargetFullMsgPeers()
		targetPeers.Range(func(pid peer.ID) bool {
			if !allPeers.Exist(pid) {
				return true
			}
			wg.Add(1)
			var finalTopicMsg *pb.TopicMsg
			var finalPeeringMsg *pb.PeeringMsg
			// if it is the first time to send to peer, will send topic control msg and peering control msg also.
			if sentPeers.Put(pid) {
				finalTopicMsg = topicMsg
				finalPeeringMsg = peeringMB.createPeeringMsgForPeer(pid)
				if finalPeeringMsg != nil {
					finalPeeringMsg.MsgSeq = mb.pubSub.nextPeeringMsgSeq()
				}
			}

			go func(pid peer.ID, msgGrp [][]*pb.ApplicationMsg, topicMsg *pb.TopicMsg, peeringMsg *pb.PeeringMsg) {
				defer wg.Done()
				mb.send(pid, msgGrp, topicMsg, peeringMsg)
			}(pid, msgGrp, finalTopicMsg, finalPeeringMsg)
			return true
		})
	}
	wg.Wait()

	// send topic control msg and peering control msg to others last.
	if sentPeers.Size() >= allPeers.Size() {
		return
	}

	allPeers.Range(func(pid peer.ID) bool {
		if !sentPeers.Put(pid) {
			return true
		}
		peeringMsg := peeringMB.createPeeringMsgForPeer(pid)
		if peeringMsg != nil {
			peeringMsg.MsgSeq = mb.pubSub.nextPeeringMsgSeq()
		}
		mb.send(pid, nil, topicMsg, peeringMsg)
		return true
	})
}

func (mb *MsgBasket) send(
	receiver peer.ID,
	msgGrp [][]*pb.ApplicationMsg,
	topicMsg *pb.TopicMsg,
	peeringMsg *pb.PeeringMsg) {
	if receiver == mb.pubSub.ID() {
		return
	}
	if len(msgGrp) > 0 {
		var topicPeeringMsgSuccessPush bool
		for _, applicationMsgs := range msgGrp {
			finalMsg := excludeMsgSender(applicationMsgs, receiver.ToString())
			finalMsg = mb.pubSub.excludeMsgReceived(finalMsg, receiver)
			if len(finalMsg) == 0 {
				continue
			}
			var err error
			if topicPeeringMsgSuccessPush {
				err = mb.pubSub.sendPubSubMsg(receiver, applicationMsgs, nil, nil, nil)
			} else {
				err = mb.pubSub.sendPubSubMsg(receiver, applicationMsgs, nil, topicMsg, peeringMsg)
			}

			if err != nil {
				mb.logger.Errorf("[MsgBasket] send pub-sub msg failed, %s  (remote pid: %s)",
					err.Error(), receiver)
			}
			mb.pubSub.recordMsgReceived(finalMsg, receiver)
		}
	} else {
		err := mb.pubSub.sendPubSubMsg(receiver, nil, nil, topicMsg, peeringMsg)
		if err != nil {
			mb.logger.Errorf("[MsgBasket] send pub-sub msg failed, %s (remote pid: %s)",
				err.Error(), receiver)
		}
	}
	if topicMsg != nil {
		for i := range topicMsg.Unsubscribed {
			mb.peeringMB.leaveTopic(topicMsg.Unsubscribed[i])
		}
	}
}

// splitAppMsgList split all msg list to multi group.
func (mb *MsgBasket) splitAppMsgList(msgs []*pb.ApplicationMsg) [][]*pb.ApplicationMsg {
	l := len(msgs)
	if l <= defaultTriggerAppMsgCount {
		return [][]*pb.ApplicationMsg{msgs}
	}
	var totalPkg int
	if l%defaultTriggerAppMsgCount == 0 {
		totalPkg = l / defaultTriggerAppMsgCount
	} else {
		totalPkg = l/defaultTriggerAppMsgCount + 1
	}
	res := make([][]*pb.ApplicationMsg, totalPkg)
	temp := msgs
	for i := 0; i < totalPkg; i++ {
		if len(temp) >= defaultTriggerAppMsgCount {
			res[i] = temp[:defaultTriggerAppMsgCount]
			temp = temp[defaultTriggerAppMsgCount:]
		} else {
			res[i] = temp
		}
	}
	return res
}

func (mb *MsgBasket) heartBeatTriggerCheck() {
	mb.RLock()
	currentSize := mb.appMB.currentSize()
	mb.RUnlock()

	if defaultTriggerAppMsgCount > currentSize {
		return
	}
	mb.ticker.Reset(defaultMsgBasketHeartBeat)
	mb.HeartBeat()
}

// PutApplicationMsg push messages into basket, then waiting for sent out.
func (mb *MsgBasket) PutApplicationMsg(msg ...*pb.ApplicationMsg) {
	mb.once.Do(mb.onceFunc)
	for i := range msg {
		mb.RLock()
		mb.appMB.putMsg(msg[i])
		mb.RUnlock()
		mb.heartBeatTriggerCheck()
	}
}

// SubOrUnSubTopic called when subscribing or unsubscribing.
func (mb *MsgBasket) SubOrUnSubTopic(topic string, subOrUnSub bool) {
	mb.once.Do(mb.onceFunc)
	mb.topicMB.ctrl(topic, subOrUnSub)
	if !subOrUnSub {
		mb.peeringMB.leaveTopic(topic)
	}
}

// SendJoinUp send join-up control msg.
func (mb *MsgBasket) SendJoinUp(topic string, pid peer.ID) {
	mb.peeringMB.joinUp(topic, pid)
}

// SendCutOff send cut-off control msg.
func (mb *MsgBasket) SendCutOff(topic string, pid peer.ID) {
	mb.peeringMB.cutOff(topic, pid)
}
