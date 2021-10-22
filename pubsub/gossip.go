/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package pubsub

import (
	"errors"
	"math/rand"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"chainmaker.org/chainmaker/net-liquid/core/peer"
	"chainmaker.org/chainmaker/net-liquid/core/types"
	"chainmaker.org/chainmaker/net-liquid/pubsub/pb"
	api "chainmaker.org/chainmaker/protocol/v2"
	"github.com/cznic/mathutil"
)

//gossip spread message between "metadata connect peer", such as:
//  step1: "A" random select some "metadata connect peer" and send "I have data" to them (such as: B C D ...).
//  step2: "B" receive "A have data" and pick need message from "A have data" and then send "I have
//  and want data" to "A".
//  step3: "A" receive "B have and B want data" and pick need message from "B have data"
//  and then send "application data and want data" to "B".
//  step4: "B" receive "A want data" and send "application data" to "A"
type gossip struct {
	logger api.Logger

	round                 int           // gossip round, from 1,2,3,....
	heartBeatTime         time.Duration // gossip interval
	gossipNodeCount       int           // gossip node count, random select node count
	batchSendMessageCount int
	intervalSetLock       sync.Mutex
	// map[peer.ID + topic]*types.IntervalSet record other peer's message interval set.
	peerMessageIntervalSet      map[string]*types.IntervalSet
	gossipSendLockExpireTime    sync.Map //map[peer.ID]time.Time record send message lock expire time
	gossipReceiveLockExpireTime sync.Map //map[peer.ID]time.Time record receive message lock expire time

	peerState PeerState // peer info store, "gossip" can get peer info from it

	state       int32
	stopChannel chan struct{}
}

//newGossip new gossip instance
func newGossip(
	heartBeetTime time.Duration,
	gossipNodeCount int,
	peerState PeerState,
	batchSendMessageCount int,
	logger api.Logger,
) *gossip {
	return &gossip{
		logger:                 logger,
		heartBeatTime:          heartBeetTime,
		gossipNodeCount:        gossipNodeCount,
		peerMessageIntervalSet: map[string]*types.IntervalSet{},
		batchSendMessageCount:  batchSendMessageCount,
		state:                  0,
		stopChannel:            nil,
		peerState:              peerState,
	}
}

// start gossip
func (g *gossip) start() {
	if !g.changeStateToStart() {
		g.logger.Error("[Gossip] start gossip, change gossip state to start error")
		return
	}
	if g.stopChannel == nil {
		g.stopChannel = make(chan struct{})
	}
	g.logger.Infof("[Gossip] start gossip, gossip config info (heart_beat_time:%vs, gossip_size: %d)",
		g.heartBeatTime.Seconds(), g.gossipNodeCount)

	go g.loop(g.stopChannel)
}

func (g *gossip) changeStateToStart() bool {
	return atomic.CompareAndSwapInt32(&g.state, 0, 1)
}

func (g *gossip) changeStateToStop() bool {
	return atomic.CompareAndSwapInt32(&g.state, 1, 0)
}

//loop gossip loop
func (g *gossip) loop(stopC chan struct{}) {
	ticker := time.NewTimer(g.heartBeatTime)
	for {
		select {
		case <-stopC:
			return
		case <-ticker.C:

		}
		g.round = g.round + 1
		peerIds := g.peerState.AllMetadataPeerId()
		ids := selectPeer(peerIds, g.gossipNodeCount)
		if len(ids) > 0 {
			g.logger.Debugf("[Gossip] gossip message(round: %d, metadata_peer_count: %d, select_peer_id:%v)",
				g.round, len(peerIds), ids)
			g.sendIHave(ids)
		}
		ticker = time.NewTimer(g.heartBeatTime)
	}
}

// stop gossip
func (g *gossip) stop() {
	if !g.changeStateToStop() {
		return
	}
	if g.stopChannel != nil {
		close(g.stopChannel)
		g.stopChannel = nil
	}
}

//selectPeer random select gossipNodeCount peer from peerIds
func selectPeer(peerIds []peer.ID, gossipNodeCount int) []peer.ID {
	metadataPeerIdCount := len(peerIds)
	if metadataPeerIdCount <= gossipNodeCount {
		return peerIds
	}

	//random pick peer id from peerId list
	randomPeerIds := make([]peer.ID, 0, gossipNodeCount)
	pickIndexList := rand.Perm(metadataPeerIdCount)[0:gossipNodeCount]
	for _, v := range pickIndexList {
		randomPeerIds = append(randomPeerIds, peerIds[v])
	}
	return randomPeerIds
}

// sendIHave send I have messages to peers
func (g *gossip) sendIHave(peerIds []peer.ID) {
	iHaveMessage := g.peerState.IHaveMessage()
	g.cleanNoUseRangeCache(iHaveMessage)
	g.logger.Debugf("[Gossip] send i have message, (peer_count: %d, message_count:%d)",
		len(peerIds), len(iHaveMessage))
	//send I have message
	waitGroup := sync.WaitGroup{}
	for _, peerId := range peerIds {
		waitGroup.Add(1)
		go func(p peer.ID) {
			defer waitGroup.Done()
			if !g.needSendIHave(p) {
				g.logger.Debugf("[Gossip] send i have message, don't need send. (peer: %v, message_count:%d)",
					p, len(iHaveMessage))
				return
			}
			beforeFilterLength := len(iHaveMessage)
			haveMessage := g.filterIHaveMessage(p, iHaveMessage)
			g.logger.Debugf("[Gossip] send i have message, filter. (peer: %v, before:%d, after:%d)",
				p, beforeFilterLength, len(haveMessage))
			haveAndWant := &pb.IHaveOrWant{
				Phase: pb.IHaveOrWant_IHave,
				Have:  haveMessage,
				Want:  nil,
			}
			err := g.peerState.GetChainPubSub().sendPubSubMsg(
				p, nil, haveAndWant, nil, nil)
			if err != nil {
				g.logger.Errorf("[Gossip] send i have message,(peer id: %s),err: %v", p.ToString(), err)
			}
		}(peerId)
	}
	waitGroup.Wait()
}

// recordHaveList record have list to peer store
func (g *gossip) recordHaveList(peerId peer.ID, list []*pb.MsgMetadata) {
	for i := range list {
		g.peerState.RecordPeerReceivedMsg(peerId, list[i])
	}
}

// handleIHaveAndSendIHaveIWant handle i have messages, after receive i have messages,
// peer send i have and i want messages
func (g *gossip) handleIHaveAndSendIHaveIWant(peerId peer.ID, have *pb.IHaveOrWant) {

	if !g.needHandleIHave(peerId) {
		g.logger.Debugf("[Gossip] handle i have message, don't need handle. (peer: %v, message_count:%d)",
			peerId, len(have.Have))
		return
	}

	go g.recordHaveList(peerId, have.Have)
	g.addHaveMsgToRange(peerId, have.Have)
	haveMessage := g.peerState.IHaveMessage()
	beforeFilterCount := len(haveMessage)
	haveMessage = g.filterIHaveMessage(peerId, haveMessage)
	g.logger.Debugf("[Gossip] handle i have message, filter. (peer: %v, before:%d,after:%d)",
		peerId, beforeFilterCount, len(haveMessage))
	haveAndWant := &pb.IHaveOrWant{
		Phase: pb.IHaveOrWant_IHaveAndIWant,
		Have:  haveMessage,
		Want:  g.peerState.IWantMessage(have.Have),
	}
	g.logger.Debugf("[Gossip] handle i have message, "+
		"(peer id: %v, receive_have_count:%d, have_count:%d, want_count:%d)",
		peerId.ToString(), len(have.Have), len(haveAndWant.Have), len(haveAndWant.Want))
	//send I have and  want request
	err := g.peerState.GetChainPubSub().sendPubSubMsg(peerId, nil, haveAndWant, nil, nil)
	if err != nil {
		g.logger.Errorf("[Gossip] handle i have message,(peer_id:%s), err:%v", peerId.ToString(), err)
	}
}

// handleIHaveIWantAndSendIWant handle I have want message
func (g *gossip) handleIHaveIWantAndSendIWant(peerId peer.ID, haveAndWant *pb.IHaveOrWant) {
	defer g.removeSendLock(peerId)

	needSendApplicationMessage := g.peerState.GetMessageListWithMetadataList(haveAndWant.Want)
	want := &pb.IHaveOrWant{
		Phase: pb.IHaveOrWant_IWant,
		Have:  nil,
		Want:  g.peerState.IWantMessage(haveAndWant.Have),
	}
	g.logger.Debugf("[Gossip] handle i have and i want message, send message "+
		"(peer_id: %s, application_message_count:%d, want_count:%d)",
		peerId.ToString(), len(needSendApplicationMessage), len(want.Want))
	//send messages and want data
	g.addMsgToRange(peerId, needSendApplicationMessage)
	if len(needSendApplicationMessage) > 0 {
		messageArrays := splitApplicationMessage(g.batchSendMessageCount, needSendApplicationMessage)
		for _, messageArray := range messageArrays {
			err := g.peerState.GetChainPubSub().sendPubSubMsg(peerId, messageArray, want, nil, nil)
			if err != nil {
				g.logger.Errorf("[Gossip] handle i have and i want message, split and send.(peer_id: %s), %v",
					peerId.ToString(), err)
			}
			want = nil
		}
	} else {
		err := g.peerState.GetChainPubSub().sendPubSubMsg(peerId, nil, want, nil, nil)
		if err != nil {
			g.logger.Errorf("[Gossip] handle i have and i want message, (peer_id: %s), err:%v",
				peerId.ToString(), err)
		}
	}
}

// handleIWant handle I want message, send application message to node
func (g *gossip) handleIWant(peerId peer.ID, want *pb.IHaveOrWant) {
	defer g.removeReceiveLock(peerId)

	needSendApplicationMessage := g.peerState.GetMessageListWithMetadataList(want.Want)
	g.addMsgToRange(peerId, needSendApplicationMessage)

	//send message
	g.logger.Debugf("[Gossip] handle i want message, (peer_id: %s, want_count:%d, need_message_count:%d)",
		peerId.ToString(), len(want.Want), len(needSendApplicationMessage))
	messageArrays := splitApplicationMessage(g.batchSendMessageCount, needSendApplicationMessage)
	for _, messageArray := range messageArrays {
		err := g.peerState.GetChainPubSub().sendPubSubMsg(
			peerId, messageArray, nil, nil, nil)
		if err != nil {
			g.logger.Errorf("[Gossip] handle i want message, split and. (peer_id: %s), err:%v",
				peerId.ToString(), err)
		}
	}
}

func (g *gossip) needSendIHave(peer peer.ID) bool {
	receiveLockExpireTime, _ := g.gossipReceiveLockExpireTime.Load(peer)
	if receiveLockExpireTime != nil && time.Now().Before(receiveLockExpireTime.(time.Time)) {
		return false
	}
	sendToExpireTime, _ := g.gossipSendLockExpireTime.Load(peer)
	if sendToExpireTime != nil && time.Now().Before(sendToExpireTime.(time.Time)) {
		return false
	}
	g.gossipSendLockExpireTime.Store(peer, time.Now().Add(g.heartBeatTime))
	return true
}

func (g *gossip) needHandleIHave(peer peer.ID) bool {
	sendLockExpireTime, _ := g.gossipSendLockExpireTime.Load(peer)
	if sendLockExpireTime == nil {
		g.gossipReceiveLockExpireTime.Store(peer, time.Now().Add(g.heartBeatTime))
		return true
	}
	selfId := g.peerState.ID()
	if time.Now().After(sendLockExpireTime.(time.Time)) || selfId.WeightCompare(peer) {
		g.removeSendLock(peer)
		g.gossipReceiveLockExpireTime.Store(peer, time.Now().Add(g.heartBeatTime))
		return true
	}
	return false
}

func (g *gossip) removeSendLock(peer peer.ID) {
	g.gossipSendLockExpireTime.Delete(peer)
}

func (g *gossip) removeReceiveLock(peer peer.ID) {
	g.gossipReceiveLockExpireTime.Delete(peer)
}

//cleanNoUseRangeCache delete no use data
func (g *gossip) cleanNoUseRangeCache(haveMessage []*pb.MsgMetadata) {
	g.intervalSetLock.Lock()
	defer g.intervalSetLock.Unlock()
	topicMinSeq := make(map[string]uint64)
	for _, v := range haveMessage {
		if topicMinSeq[v.Topic] == 0 {
			topicMinSeq[v.Topic] = v.MsgSeq
		} else {
			topicMinSeq[v.Topic] = mathutil.MinUint64(v.MsgSeq, topicMinSeq[v.Topic])
		}
	}

	for k, v := range g.peerMessageIntervalSet {
		topic := getTopic(k)
		v.RemoveBefore(topicMinSeq[topic])
	}
}

//filterIHaveMessage filter have send messages
func (g *gossip) filterIHaveMessage(peerId peer.ID, iHaveMessage []*pb.MsgMetadata) []*pb.MsgMetadata {
	g.intervalSetLock.Lock()
	defer g.intervalSetLock.Unlock()

	if len(iHaveMessage) == 0 {
		return iHaveMessage
	}

	rangeSetMap := g.getRangeSet(peerId)
	result := make([]*pb.MsgMetadata, 0)
	for _, metadata := range iHaveMessage {
		idWithTopic := peerIdWithTopic(peerId, metadata.Topic)
		if _, ok := rangeSetMap[idWithTopic]; !ok {
			rangeSetMap[idWithTopic] = types.NewIntervalSet()
		}
		if !rangeSetMap[idWithTopic].Contains(metadata.MsgSeq) {
			rangeSetMap[idWithTopic].Add(types.NewInterval(metadata.MsgSeq, metadata.MsgSeq))
			result = append(result, metadata)
		}
	}
	return result
}

func (g *gossip) getRangeSet(peerId peer.ID) map[string]*types.IntervalSet {
	result := make(map[string]*types.IntervalSet)
	for k, v := range g.peerMessageIntervalSet {
		if strings.HasPrefix(k, string(peerId)) {
			result[k] = v
		}
	}
	return result
}

//addHaveMsgToRange add peer messages to range set
func (g *gossip) addHaveMsgToRange(peerId peer.ID, haveMsg []*pb.MsgMetadata) {
	g.intervalSetLock.Lock()
	defer g.intervalSetLock.Unlock()
	for _, metadata := range haveMsg {
		g.add(peerId, metadata.Topic, metadata.MsgSeq)
	}
}

//addMsgToRange
func (g *gossip) addMsgToRange(peerId peer.ID, haveMsg []*pb.ApplicationMsg) {
	g.intervalSetLock.Lock()
	defer g.intervalSetLock.Unlock()
	for _, metadata := range haveMsg {
		for _, topic := range metadata.Topics {
			g.add(peerId, topic, metadata.MsgSeq)
		}
	}
}

func (g *gossip) add(peerId peer.ID, topic string, index uint64) {
	idWithTopic := peerIdWithTopic(peerId, topic)
	if _, ok := g.peerMessageIntervalSet[idWithTopic]; !ok {
		g.peerMessageIntervalSet[idWithTopic] = types.NewIntervalSet()
	}
	g.peerMessageIntervalSet[idWithTopic].Add(types.NewInterval(index, index))
}

// ClearPeerCache clear peer's gossip cache data
func (g *gossip) ClearPeerCache(peerId peer.ID) {
	g.intervalSetLock.Lock()
	defer g.intervalSetLock.Unlock()
	for k := range g.peerMessageIntervalSet {
		if strings.HasPrefix(k, string(peerId)) {
			delete(g.peerMessageIntervalSet, k)
		}
	}
}

func peerIdWithTopic(peerId peer.ID, topic string) string {
	builder := strings.Builder{}
	builder.Grow(len(peerId) + 1 + len(topic))
	builder.WriteString(string(peerId))
	builder.WriteString("_")
	builder.WriteString(topic)
	return builder.String()
}

func getTopic(peerIdWithTopic string) string {
	return strings.Split(peerIdWithTopic, "_")[1]
}

//splitApplicationMessage split message list
func splitApplicationMessage(splitSize int, messages []*pb.ApplicationMsg) [][]*pb.ApplicationMsg {
	if splitSize <= 0 {
		panic(errors.New("split size should grater than zero"))
	}

	arraySize := len(messages)

	if messages == nil || arraySize == 0 {
		return make([][]*pb.ApplicationMsg, 0)
	}

	size := arraySize/splitSize + 1

	if splitSize > arraySize {
		size = 1
	}

	if arraySize%splitSize == 0 {
		size = arraySize / splitSize
	}

	result := make([][]*pb.ApplicationMsg, size)
	for i := 0; i < size; i++ {
		start := i * splitSize
		end := start + splitSize
		if end > arraySize {
			end = arraySize
		}
		temp := make([]*pb.ApplicationMsg, end-start)
		copy(temp, messages[start:end])
		result[i] = temp
	}
	return result
}
