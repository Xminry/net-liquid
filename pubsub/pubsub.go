/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package pubsub

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"chainmaker.org/chainmaker/chainmaker-net-common/utils"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/broadcast"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/handler"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/host"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/peer"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/protocol"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/types"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/pubsub/pb"
	api "chainmaker.org/chainmaker/protocol"
)

const (
	// ProtocolIDTemplate is the template for making pub-sub protocol id.
	ProtocolIDTemplate = "/chain-pubsub/v0.0.1/chain-%s"

	// DefaultFanOutSize is the default value of fan-out-size when fan out peering used.
	DefaultFanOutSize int32 = DefaultDegreeLow
	// DefaultFanOutTimeout is the default value of fan-out-timeout when fan out peering finished.
	DefaultFanOutTimeout = 2 * time.Second
	// DefaultDegreeLow is the default lower boundary of full-msg peering count.
	DefaultDegreeLow int32 = 4
	// DefaultDegreeDesired is the default desired value of full-msg peering count.
	DefaultDegreeDesired int32 = 6
	// DefaultDegreeHigh is the default higher boundary of full-msg peering count.
	DefaultDegreeHigh int32 = 12
	// DefaultMetadataCacheTimeout is the default timeout for metadata cache.
	DefaultMetadataCacheTimeout = 2 * time.Minute
	// DefaultMetadataCacheMaxSize is the default max size for metadata cache.
	DefaultMetadataCacheMaxSize = 120
	// DefaultAppMsgCacheTimeout is the default timeout for application msg cache.
	DefaultAppMsgCacheTimeout = 10 * time.Second
	// DefaultAppMsgCacheMaxSize is the default max size for application msg cache.
	DefaultAppMsgCacheMaxSize = 20
	// DefaultGossipSize is the default gossip size for spreading metadata.
	DefaultGossipSize = 3
	// DefaultGossipInterval is the default gossip interval(seconds).
	DefaultGossipInterval = time.Second
	// DefaultMaxSendApplicationMsgSize is the default size for max send application message size.(M)
	DefaultMaxSendApplicationMsgSize = 30
	// DefaultGossipBatchSendApplicationLength is the default max count of application messages
	// which sent when gossiping.
	DefaultGossipBatchSendApplicationLength = 3
	// DefaultAppMsgStationsLength is the default length of spread stations can be stored in an application message.
	DefaultAppMsgStationsLength = 10
)

var (
	// ErrNilHost will be returned if host is nil.
	ErrNilHost = errors.New("nil host")
	// ErrDiffHost will be returned if the host given is not the same one that we used.
	ErrDiffHost = errors.New("different host")
)

type config struct {
	fanOutSize    int32
	fanOutTimeout time.Duration
	degreeLow     int32
	degreeHigh    int32
	degreeDesired int32

	pubsubMessageMaxSize int32

	metadataCacheTimeout            time.Duration
	metadataCacheMaxSize            int
	appMsgCacheTimeout              time.Duration
	appMsgCacheMaxSize              int
	gossipInterval                  time.Duration
	gossipSize                      int
	gossipMaxSendApplicationMsgSize int
}

// Option for ChainPubSub.
type Option func(pubsub *ChainPubSub)

var _ broadcast.PubSub = (*ChainPubSub)(nil)

// ChainPubSub is an implementation of broadcast.PubSub interface.
// It is based on supporting of application protocols.
// Different ChainPubSub use different protocol, that these ChainPubSub will be isolated when spreading messages.
type ChainPubSub struct {
	cfg *config

	chainId          string
	protocolID       protocol.ID
	host             host.Host
	peers            *types.PeerIdSet
	ps               *peerState
	gossip           *gossip
	topicPeeringMgrs sync.Map // map[string]*topicPeeringMgr, map[topic]*topicPeeringMgr,

	peerTopicCtrlLogMap   sync.Map // map[peer.ID]uint64,  peer.ID -> TopicMsgSeq
	peerPeeringCtrlLogMap sync.Map // map[peer.ID]uint64,  peer.ID -> PeeringMsgSeq

	appMsgSeq     uint64
	topicMsgSeq   uint64
	peeringMsgSeq uint64

	msgBasket *MsgBasket

	hostNotifiee *host.NotifieeBundle

	logger api.Logger
}

// NewChainPubSub create a new ChainPubSub instance.
func NewChainPubSub(chainId string, logger api.Logger, opts ...Option) *ChainPubSub {
	protocolId := protocol.ID(fmt.Sprintf(ProtocolIDTemplate, chainId))
	cps := &ChainPubSub{
		cfg: &config{
			fanOutSize:    DefaultFanOutSize,
			fanOutTimeout: DefaultFanOutTimeout,
			degreeLow:     DefaultDegreeLow,
			degreeHigh:    DefaultDegreeHigh,
			degreeDesired: DefaultDegreeDesired,

			pubsubMessageMaxSize: DefaultMaxSendApplicationMsgSize << 20,

			metadataCacheTimeout:            DefaultMetadataCacheTimeout,
			metadataCacheMaxSize:            DefaultMetadataCacheMaxSize,
			appMsgCacheTimeout:              DefaultAppMsgCacheTimeout,
			appMsgCacheMaxSize:              DefaultAppMsgCacheMaxSize,
			gossipSize:                      DefaultGossipSize,
			gossipInterval:                  DefaultGossipInterval,
			gossipMaxSendApplicationMsgSize: DefaultGossipBatchSendApplicationLength,
		},
		chainId:               chainId,
		protocolID:            protocolId,
		host:                  nil,
		peers:                 &types.PeerIdSet{},
		ps:                    nil,
		gossip:                nil,
		topicPeeringMgrs:      sync.Map{},
		peerTopicCtrlLogMap:   sync.Map{},
		peerPeeringCtrlLogMap: sync.Map{},
		appMsgSeq:             uint64(utils.CurrentTimeMillisSeconds()) * 1000000,
		topicMsgSeq:           uint64(utils.CurrentTimeMillisSeconds()) * 1000000,
		peeringMsgSeq:         uint64(utils.CurrentTimeMillisSeconds()) * 1000000,
		msgBasket:             nil,
		hostNotifiee:          &host.NotifieeBundle{},
		logger:                logger,
	}
	cps.optionsApply(opts...)
	cps.ps = newPeerState(cps)
	cps.msgBasket = NewMsgBasket(cps)
	cps.hostNotifiee.PeerConnectedFunc = cps.peerConnectedHandle
	cps.hostNotifiee.PeerDisconnectedFunc = cps.peerDisconnectedHandle
	cps.hostNotifiee.PeerProtocolSupportedFunc = cps.peerProtocolSupportedHandle
	cps.hostNotifiee.PeerProtocolUnsupportedFunc = cps.peerProtocolUnsupportedHandle
	cps.gossip = newGossip(
		cps.cfg.gossipInterval,
		cps.cfg.gossipSize,
		cps.ps,
		cps.cfg.gossipMaxSendApplicationMsgSize,
		cps.logger)

	return cps
}

func (p *ChainPubSub) optionsApply(opts ...Option) {
	for i := range opts {
		opts[i](p)
	}
}

// WithFanOutSize set fan-out size.
func WithFanOutSize(size int32) Option {
	return func(chainPubSub *ChainPubSub) {
		chainPubSub.cfg.fanOutSize = size
	}
}

// WithFanOutTimeout set fan-out timeout duration.
func WithFanOutTimeout(timeout time.Duration) Option {
	return func(chainPubSub *ChainPubSub) {
		chainPubSub.cfg.fanOutTimeout = timeout
	}
}

// WithDegreeLow set degree low for full-msg type.
func WithDegreeLow(low int32) Option {
	return func(chainPubSub *ChainPubSub) {
		chainPubSub.cfg.degreeLow = low
	}
}

// WithDegreeDesired set degree desired for full-msg type.
func WithDegreeDesired(desired int32) Option {
	return func(chainPubSub *ChainPubSub) {
		chainPubSub.cfg.degreeDesired = desired
	}
}

// WithDegreeHigh set degree high for full-msg type.
func WithDegreeHigh(high int32) Option {
	return func(chainPubSub *ChainPubSub) {
		chainPubSub.cfg.degreeHigh = high
	}
}

// WithPubSubMessageMaxSize set max size allowed of pub-sub message.
func WithPubSubMessageMaxSize(size int32) Option {
	return func(chainPubSub *ChainPubSub) {
		chainPubSub.cfg.pubsubMessageMaxSize = size
	}
}

// WithMetadataCacheTimeout set cache timeout for metadata .
func WithMetadataCacheTimeout(timeout time.Duration) Option {
	return func(chainPubSub *ChainPubSub) {
		chainPubSub.cfg.metadataCacheTimeout = timeout
	}
}

// WithMetadataCacheMaxSize set max cache size for metadata.
func WithMetadataCacheMaxSize(size int) Option {
	return func(chainPubSub *ChainPubSub) {
		chainPubSub.cfg.metadataCacheMaxSize = size
	}
}

// WithAppMsgCacheTimeout set cache timeout for full application message.
func WithAppMsgCacheTimeout(timeout time.Duration) Option {
	return func(chainPubSub *ChainPubSub) {
		chainPubSub.cfg.appMsgCacheTimeout = timeout
	}
}

// WithAppMsgCacheMaxSize set max cache size for full application message.
func WithAppMsgCacheMaxSize(size int) Option {
	return func(chainPubSub *ChainPubSub) {
		chainPubSub.cfg.appMsgCacheMaxSize = size
	}
}

// WithGossipSize set max count of peers that gossiping choose.
func WithGossipSize(size int) Option {
	return func(chainPubSub *ChainPubSub) {
		chainPubSub.cfg.gossipSize = size
	}
}

// WithGossipInterval set heartbeat interval for gossiping.
func WithGossipInterval(interval time.Duration) Option {
	return func(pubsub *ChainPubSub) {
		pubsub.cfg.gossipInterval = interval
	}
}

// AttachHost set up a host.
func (p *ChainPubSub) AttachHost(h host.Host) error {
	if h == nil {
		return ErrNilHost
	}
	p.host = h
	if err := p.host.RegisterMsgPayloadHandler(p.ProtocolID(), p.ProtocolMsgHandler()); err != nil {
		return err
	}
	p.host.Notify(p.HostNotifiee())

	pps, err := p.host.PeerProtocols([]protocol.ID{p.ProtocolID()})
	if err != nil {
		return err
	}
	for _, pp := range pps {
		// add to peerList
		p.peers.Put(pp.PID)
	}
	p.gossip.start()
	return nil
}

func (p *ChainPubSub) Stop() error {
	p.msgBasket.Cancel()
	p.gossip.stop()
	return nil
}

// ID return the local peer.ID.
func (p *ChainPubSub) ID() peer.ID {
	return p.host.ID()
}

//func (p *ChainPubSub) DetachHost() error {
//	if p.host == nil {
//		return ErrNilHost
//	}
//	if err := p.host.UnregisterMsgPayloadHandler(p.ProtocolID()); err != nil {
//		return err
//	}
//	return nil
//}

// sendPubSubMsg send pub-sub message.
func (p *ChainPubSub) sendPubSubMsg(
	pid peer.ID,
	appMsgs []*pb.ApplicationMsg,
	spreadMsg *pb.IHaveOrWant,
	topicMsg *pb.TopicMsg,
	peeringMsg *pb.PeeringMsg) error {
	// create pub-sub msg payload
	payload, err := CreatePubSubMsgPayload(appMsgs, spreadMsg, topicMsg, peeringMsg)
	if err != nil {
		p.logger.Debugf("[ChainPubSub] create pubsub msg payload failed, %s", err.Error())
		return err
	}
	// send payload with pub-sub protocol
	err = p.host.SendMsg(p.protocolID, pid, payload)
	if err != nil {
		p.logger.Debugf("[ChainPubSub] send pubsub msg failed, %s, (remote pid: %s)", err.Error(), pid)
		return err
	}

	return nil
}

// appendPeer add a peer to this chain pub-sub.
func (p *ChainPubSub) appendPeer(pid peer.ID) {
	// whether this peer support pub-sub protocol ID
	if !p.host.IsPeerSupportProtocol(pid, p.ProtocolID()) {
		return
	}
	// add to peerList
	p.peers.Put(pid)
}

// peerConnectedHandle handle a peer new connected.
func (p *ChainPubSub) peerConnectedHandle(pid peer.ID) {
	// whether peer support protocol of pub-sub
	if p.host.IsPeerSupportProtocol(pid, p.ProtocolID()) {
		// append peer
		p.appendPeer(pid)
		p.logger.Debugf("[ChainPubSub] [PeerConnectedHandle] append peer (remote pid: %s, protocol: %s)",
			pid, p.ProtocolID())
	}
}

// cleanPeer remove a peer from this chain pub-sub.
func (p *ChainPubSub) cleanPeer(pid peer.ID) {
	// clean peer
	p.peers.Remove(pid)
	p.ps.peerTopicPeeringStore.CleanPeer(pid)
	p.topicPeeringMgrs.Range(func(_, value interface{}) bool {
		tpm, _ := value.(*topicPeeringMgr)
		tpm.CleanPeer(pid)
		return true
	})
	p.gossip.ClearPeerCache(pid)
	p.peerPeeringCtrlLogMap.Delete(pid)
	p.peerTopicCtrlLogMap.Delete(pid)
}

// peerDisconnectedHandle handle a peer disconnected.
func (p *ChainPubSub) peerDisconnectedHandle(pid peer.ID) {
	p.cleanPeer(pid)
	p.logger.Debugf("[ChainPubSub] [PeerDisconnectedHandle] clean peer (remote pid: %s, protocol: %s)",
		pid, p.ProtocolID())
}

// peerProtocolSupportedHandle handle a peer supporting new protocol.
func (p *ChainPubSub) peerProtocolSupportedHandle(protocolID protocol.ID, pid peer.ID) {
	// whether protocol supported is that of this chain pub-sub.
	if protocolID == p.ProtocolID() {
		// append peer
		p.appendPeer(pid)
		p.logger.Debugf("[ChainPubSub] [PeerProtocolSupportedHandle] append peer (remote pid: %s, protocol: %s)",
			pid, p.ProtocolID())
	}
}

// peerProtocolUnsupportedHandle handle a peer canceling support any protocol
func (p *ChainPubSub) peerProtocolUnsupportedHandle(protocolID protocol.ID, pid peer.ID) {
	// whether protocol canceled is that of this chain pub-sub.
	if protocolID == p.ProtocolID() {
		// clean peer
		p.cleanPeer(pid)
		p.logger.Debugf("[ChainPubSub] [PeerProtocolUnsupportedHandle] clean peer(remote pid: %s, protocol: %s)",
			pid, p.ProtocolID())
	}
}

// HostNotifiee return an implementation of host.Notifiee interface.
// It will be registered in host.Host.Notify method.
func (p *ChainPubSub) HostNotifiee() host.Notifiee {
	return p.hostNotifiee
}

// ProtocolID return the protocol.ID of the PubSub service.
// The protocol id will be registered in host.RegisterMsgPayloadHandler method.
func (p *ChainPubSub) ProtocolID() protocol.ID {
	return p.protocolID
}

// ProtocolMsgHandler return a function which type is handler.MsgPayloadHandler.
// It will be registered in host.Host.RegisterMsgPayloadHandler method.
func (p *ChainPubSub) ProtocolMsgHandler() handler.MsgPayloadHandler {
	return func(senderPID peer.ID, msgPayload []byte) {
		// parse msg payload to pub-sub msg
		psMsg, err := GetPubSubMsgWithPayload(msgPayload)
		if err != nil {
			p.logger.Errorf("[ChainPubSub] get pubsub msg with payload failed, %s, (remote pid: %s)",
				err.Error(), senderPID)
			return
		}
		// topic control msg
		p.handleTopicControlMsg(senderPID, psMsg.TopicCtrl)

		// peering control msg
		p.handlePeeringControlMsg(senderPID, psMsg.PeeringCtrl)

		// app msg
		p.handleAppMessages(psMsg.Msg)

		// spread control msg
		p.handleSpreadControlMsg(senderPID, psMsg.SpreadCtrl)

	}
}

// newTPM create a new topic peering manager.
func (p *ChainPubSub) newTPM(topic string) (*topicPeeringMgr, error) {
	return newTopicPeeringMgr(
		topic,
		p.ps,
		p.cfg.fanOutSize,
		p.cfg.fanOutTimeout,
		p.cfg.degreeLow,
		p.cfg.degreeHigh,
		p.cfg.degreeDesired,
		p.logger,
	)
}

// initOrGetTPM will return the topic peering manager if tpm exist.
// If tpm not exist, it will create it then return.
func (p *ChainPubSub) initOrGetTPM(topic string) (*topicPeeringMgr, error) {
	// whether tpm exist
	v, ok := p.topicPeeringMgrs.Load(topic)
	if !ok {
		// not exist, create new tpm
		tpm, err := p.newTPM(topic)
		if err != nil {
			return nil, err
		}
		// store new tpm
		v, _ = p.topicPeeringMgrs.LoadOrStore(topic, tpm)
		ok = true
	}
	// return tpm
	tpm := v.(*topicPeeringMgr)
	return tpm, nil
}

// callTopicMsgHandler will call all handler.SubMsgHandler of topics that msg published to.
func (p *ChainPubSub) callTopicMsgHandler(msg *pb.ApplicationMsg) {
	// range all topics
	for i := range msg.Topics {
		topic := msg.Topics[i]
		// whether topic subscribed
		v, ok := p.ps.subscriptions.Load(topic)
		if ok {
			// call handler.SubMsgHandler
			h := v.(handler.SubMsgHandler)
			h(peer.ID(msg.Sender), topic, msg.MsgBody)
		}
	}
}

// handleAppMessages handle the messages received from others.
func (p *ChainPubSub) handleAppMessages(messages []*pb.ApplicationMsg) {
	if len(messages) == 0 {
		return
	}
	topicMessage := make(map[string]*[]*pb.ApplicationMsg)
	for i := range messages {
		msg := messages[i]
		// TODO: verify msg sign

		// do some works with spread stations
		if !p.procAppMsgStations(msg) {
			p.logger.Debugf("[ChainPubSub][HandleAppMsg] local pid in stations of msg, "+
				"(local: %s, sender:%s, seq:%d)",
				p.ID(), msg.Sender, msg.MsgSeq)
			continue
		}
		//p.logger.Debugf("[ChainPubSub][HandleAppMsg] (sender:%s, local:%s, stations:%v)", msg.Sender, p.ID(), msg.Stations)
		// whether msg exist
		// if not exist, put into cache
		if !p.ps.msgCache.PutIfNoExists(msg) {
			//p.logger.Debugf("[ChainPubSub][HandleAppMsg] msg have seen, (sender:%s, seq:%d)", msg.Sender, msg.MsgSeq)
			continue
		}

		// call topic msg handler
		go p.callTopicMsgHandler(msg)

		// append message to topic message list
		for ti := range msg.Topics {
			l, ok := topicMessage[msg.Topics[ti]]
			if !ok {
				topicMessage[msg.Topics[ti]] = &[]*pb.ApplicationMsg{msg}
			} else {
				*l = append(*l, msg)
			}
		}
	}
	// publish each message to topic in topic message list
	for topic, msgList := range topicMessage {
		tpm, err := p.initOrGetTPM(topic)
		if err != nil {
			p.logger.Errorf("[ChainPubSub][HandleAppMsg] create topic peering manager failed, %s, (topic: %s)",
				err.Error(), topic)
			continue
		}
		tpm.PublishAppMsg(*msgList)
	}
}

// handleCutOff handle peer cut-off peering control operation.
func (p *ChainPubSub) handleCutOff(pid peer.ID, cutOffTopics []string) {
	for i := range cutOffTopics {
		cutOffTopic := cutOffTopics[i]
		k, ok := p.topicPeeringMgrs.Load(cutOffTopic)
		if ok {
			// call tpm peer cut-off
			tpm, _ := k.(*topicPeeringMgr)
			err := tpm.PeerCutOff(pid)
			if err != nil {
				p.logger.Errorf("[ChainPubSub][HandlePeeringControlMsg] cut off peer failed, %s, "+
					"(topic: %s, remote pid: %s)", err.Error(), cutOffTopic, pid)
			}
		} else {
			p.logger.Debugf("[ChainPubSub][HandlePeeringControlMsg] topic peering manager not found, "+
				"(topic: %s, remote pid: %s)", cutOffTopic, pid)
		}
	}

}

// handleJoinUp handle peer join-up peering control operation.
func (p *ChainPubSub) handleJoinUp(pid peer.ID, joinUpTopics []string) {
	for i := range joinUpTopics {
		joinUpTopic := joinUpTopics[i]
		k, ok := p.topicPeeringMgrs.Load(joinUpTopic)
		if ok {
			// call tpm peer join-up
			tpm, _ := k.(*topicPeeringMgr)
			err := tpm.PeerJoinUp(pid)
			if err != nil {
				p.logger.Errorf("[ChainPubSub][HandlePeeringControlMsg] join up peer failed, %s, "+
					"(topic: %s, remote pid: %s)", err.Error(), joinUpTopic, pid)
			}
		} else {
			p.logger.Debugf("[ChainPubSub][HandlePeeringControlMsg] topic peering manager not found, "+
				"(topic: %s, remote pid: %s)", joinUpTopic, pid)
		}
	}
}

// handlePeeringControlMsg handle a peering control message received.
func (p *ChainPubSub) handlePeeringControlMsg(pid peer.ID, peeringCtrlMsg *pb.PeeringMsg) {
	if peeringCtrlMsg == nil {
		return
	}
	// peering control message sequence
	seq := peeringCtrlMsg.MsgSeq
	if seq == 0 {
		p.logger.Errorf("[ChainPubSub][HandlePeeringControlMsg] zero topic msg sequence. (remote pid: %s)", pid)
		return
	}
	// check whether msg sequence is expire
	v, loaded := p.peerPeeringCtrlLogMap.LoadOrStore(pid, seq)
	if loaded {
		currentSeq, _ := v.(uint64)
		if seq <= currentSeq {
			// early peering msg
			//p.logger.Debugf("[ChainPubSub][HandlePeeringControlMsg] early peering msg sequence. ignore. (remote pid: %s, current-seq: %d, early: %d)", pid, currentSeq, seq)
			return
		}
		p.peerPeeringCtrlLogMap.Store(pid, seq)
	}

	p.logger.Debugf("[ChainPubSub][HandlePeeringControlMsg] handle peer control message, "+
		"(peer:%s, cutoff:%s, join-up:%s)", pid, peeringCtrlMsg.CutOff, peeringCtrlMsg.JoinUp)
	// handle cut-off
	cutOffTopics := peeringCtrlMsg.CutOff
	go p.handleCutOff(pid, cutOffTopics)

	// handle join-up
	joinUpTopics := peeringCtrlMsg.JoinUp
	go p.handleJoinUp(pid, joinUpTopics)
}

// handleSpreadControlMsg handle  a spread control message received.
// Spread control message handled by gossip.
func (p *ChainPubSub) handleSpreadControlMsg(pid peer.ID, spreadCtrlMsg *pb.IHaveOrWant) {
	if spreadCtrlMsg == nil {
		return
	}
	switch spreadCtrlMsg.Phase {
	case pb.IHaveOrWant_IHave:
		// IHave msg
		go p.gossip.handleIHaveAndSendIHaveIWant(pid, spreadCtrlMsg)
	case pb.IHaveOrWant_IHaveAndIWant:
		// IHave and IWant
		go p.gossip.handleIHaveIWantAndSendIWant(pid, spreadCtrlMsg)
	case pb.IHaveOrWant_IWant:
		// IWant
		go p.gossip.handleIWant(pid, spreadCtrlMsg)
	default:
	}
}

// handleTopicControlMsg handle a topic control message received.
func (p *ChainPubSub) handleTopicControlMsg(pid peer.ID, topicCtrlMsg *pb.TopicMsg) {
	if topicCtrlMsg == nil {
		return
	}
	// topic control message sequence
	seq := topicCtrlMsg.MsgSeq
	if seq == 0 {
		p.logger.Errorf("[ChainPubSub][HandleTopicControlMsg] zero topic msg sequence. (remote pid: %s)", pid)
		return
	}
	// check whether msg sequence is expire
	v, loaded := p.peerTopicCtrlLogMap.LoadOrStore(pid, seq)
	if loaded {
		currentSeq, _ := v.(uint64)
		if seq <= currentSeq {
			// early topic msg
			//p.logger.Debugf("[ChainPubSub][HandleTopicControlMsg] early topic msg sequence. ignore. (remote pid: %s, current-seq: %d, early: %d)", pid, currentSeq, seq)
			return
		}
		p.peerTopicCtrlLogMap.Store(pid, seq)
	}

	//p.logger.Debugf("[ChainPubSub][HandleTopicControlMsg] handle topic control message,
	//  (peer:%s, subscribe:%s, unsubscribe:%s)", pid, topicCtrlMsg.Subscribed, topicCtrlMsg.Unsubscribed)
	// handle subscribed
	subs := topicCtrlMsg.Subscribed
	for i := range subs {
		subTopic := subs[i]

		tpm, err := p.initOrGetTPM(subTopic)
		if err != nil {
			p.logger.Errorf("[ChainPubSub][HandleTopicControlMsg] create topic peering manager failed, %s, "+
				"(remote pid: %s, topic: %s)", err.Error(), pid, subTopic)
			continue
		}
		err = tpm.AppendPeer(pid)
		if err != nil {
			p.logger.Errorf("[ChainPubSub][topic peering mgr] append peer failed, %s, "+
				"(remote pid: %s, topic: %s)", err.Error(), pid, subTopic)
		}
	}
	// handle unsubscribed
	unsubs := topicCtrlMsg.Unsubscribed
	for i := range unsubs {
		unsubTopic := unsubs[i]
		k, ok := p.topicPeeringMgrs.Load(unsubTopic)
		if ok {
			tpm, _ := k.(*topicPeeringMgr)
			tpm.CleanPeer(pid)
		}
	}
}

func (p *ChainPubSub) nextAppMsgSeq() uint64 {
	return atomic.AddUint64(&p.appMsgSeq, 1)
}

func (p *ChainPubSub) nextTopicMsgSeq() uint64 {
	return atomic.AddUint64(&p.topicMsgSeq, 1)
}

func (p *ChainPubSub) nextPeeringMsgSeq() uint64 {
	return atomic.AddUint64(&p.peeringMsgSeq, 1)
}

// AllMetadataOnlyPeers return a list of peer.ID who communicates with us in a metadata-only link.
func (p *ChainPubSub) AllMetadataOnlyPeers() []peer.ID {
	res := make([]peer.ID, 0)
	p.topicPeeringMgrs.Range(func(_, value interface{}) bool {
		tpm, _ := value.(*topicPeeringMgr)
		metadataOnlyPeers := tpm.GetPeerIdsWithTypeOfPeering(MetadataOnlyTypeOfPeering)
		res = append(res, metadataOnlyPeers...)
		return true
	})
	return res
}

// Subscribe register a sub-msg handler for handling the msg listened from the topic given.
func (p *ChainPubSub) Subscribe(topic string, msgHandler handler.SubMsgHandler) {
	//0. tell others
	p.msgBasket.SubOrUnSubTopic(topic, true)

	// 1. init tpm and call subscribe
	p.logger.Infof("[ChainPubSub][Subscribe] subscribe topic, (peer:%s, topic: %s)", p.host.ID(), topic)
	tpm, err := p.initOrGetTPM(topic)
	if err != nil {
		p.logger.Errorf("[ChainPubSub][Subscribe] init or get topic peering manager failed, %s, (topic: %s)",
			err.Error(), topic)
		return
	}

	tpm.Subscribe()

	// 2. register msg handler
	err = p.ps.Subscribe(topic, msgHandler)
	if err != nil {
		p.logger.Errorf("[ChainPubSub][Subscribe] register msg handler for topic failed, %s, (topic: %s)",
			err.Error(), topic)
	}

}

// Unsubscribe cancels listening the topic given and unregister the sub-msg handler registered for this topic.
func (p *ChainPubSub) Unsubscribe(topic string) {
	// 1. unregister msg handler
	p.ps.Unsubscribe(topic)

	// 2. unsubscribe tpm
	tpm, err := p.initOrGetTPM(topic)
	if err != nil {
		p.logger.Errorf("[ChainPubSub][Unsubscribe] init or get topic peering manager failed, %s, (topic: %s)",
			err.Error(), topic)
		return
	}
	tpm.Unsubscribe()
	// 3. tell others
	p.msgBasket.SubOrUnSubTopic(topic, false)
}

// Publish will push a msg to the network of the topic given.
func (p *ChainPubSub) Publish(topic string, msg []byte) {
	if p.cfg.pubsubMessageMaxSize != 0 && len(msg) > int(p.cfg.pubsubMessageMaxSize) {
		p.logger.Errorf("[ChainPubSub][Publish] msg too big, ignore. (msg-size: %dkb, max-size: %dkb)",
			len(msg)/1024, p.cfg.pubsubMessageMaxSize/1024)
		return
	}
	// 1. create pb.ApplicationMsg
	appMsg := &pb.ApplicationMsg{
		Topics:     []string{topic},
		Sender:     string(p.host.ID()),
		MsgSeq:     p.nextAppMsgSeq(),
		MsgBody:    msg,
		SenderKey:  nil, // TODO
		SenderSign: nil, // TODO
		Stations:   make([]string, 0, 1),
	}

	// 2. copy msg to cache
	p.ps.CacheMsg(appMsg)

	// 3. tpm publish
	tpm, err := p.initOrGetTPM(topic)
	if err != nil {
		p.logger.Errorf("[ChainPubSub][Publish] init or get topic peering manager failed, %s, (topic: %s)",
			err.Error(), topic)
		return
	}

	tpm.PublishAppMsg([]*pb.ApplicationMsg{appMsg})
}

// procAppMsgStations check whether received before (self peer.ID in stations), if not, append self to stations.
func (p *ChainPubSub) procAppMsgStations(appMsg *pb.ApplicationMsg) bool {
	localPid := p.ID().ToString()[40:]
	if appMsg.Sender[40:] != localPid {
		for i := range appMsg.Stations {
			if appMsg.Stations[i] == localPid {
				return false
			}
		}
		if len(appMsg.Stations) >= DefaultAppMsgStationsLength {
			appMsg.Stations = append(appMsg.Stations[1:], localPid)
		} else {
			appMsg.Stations = append(appMsg.Stations, localPid)
		}
		return true
	}
	return false
}

// excludeMsgSender exclude messages published by me from message list wait for being sent.
func excludeMsgSender(appMsg []*pb.ApplicationMsg, sender string) []*pb.ApplicationMsg {
	res := make([]*pb.ApplicationMsg, 0, len(appMsg))
	for i := range appMsg {
		m := appMsg[i]
		if m.Sender != sender {
			res = append(res, m)
		}
	}
	return res
}

// excludeMsgReceived exclude messages has received by receiver before(receiver peer.ID in stations)
// from message list wait for being sent.
func (p *ChainPubSub) excludeMsgReceived(appMsg []*pb.ApplicationMsg, receiver peer.ID) []*pb.ApplicationMsg {
	if len(appMsg) == 0 {
		return appMsg
	}
	res := make([]*pb.ApplicationMsg, 0, len(appMsg))
	for i := range appMsg {
		msg := appMsg[i]
		if !isPeerInStations(receiver, msg) && !p.ps.IsPeerReceivedMsg(receiver, msg) {
			res = append(res, msg)
		}
	}
	return res
}

// recordMsgReceived create all metadata of the messages and save it to metadata cache.
func (p *ChainPubSub) recordMsgReceived(appMsg []*pb.ApplicationMsg, receiver peer.ID) {
	if len(appMsg) == 0 {
		return
	}
	for i := range appMsg {
		msg := appMsg[i]
		p.ps.RecordPeerReceivedMsg(receiver, &pb.MsgMetadata{
			Topic:  msg.Topics[0],
			Sender: msg.Sender,
			MsgSeq: msg.MsgSeq,
		})
	}
}

// isPeerInStations return whether receiver peer.ID in stations.
func isPeerInStations(pid peer.ID, appMsg *pb.ApplicationMsg) bool {
	for j := range appMsg.Stations {
		if appMsg.Stations[j] == pid.ToString()[40:] {
			return true
		}
	}
	return false
}
