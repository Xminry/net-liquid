/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package pubsub

import (
	"errors"
	"sync"

	"chainmaker.org/chainmaker/net-liquid/core/handler"
	"chainmaker.org/chainmaker/net-liquid/core/peer"
	"chainmaker.org/chainmaker/net-liquid/pubsub/pb"
)

// PeerState stored subscription infos and cached necessary data of message published or received.
// It also provides some method to support gossip service to get all necessary info.
type PeerState interface {
	// CacheMsg store the app msg into cache.
	CacheMsg(applicationMsg *pb.ApplicationMsg)
	// IsPeerReceivedMsg return whether the app msg exist in cache.
	IsPeerReceivedMsg(pid peer.ID, applicationMsg *pb.ApplicationMsg) bool
	// RecordPeerReceivedMsg add a record that who has received the msg.
	RecordPeerReceivedMsg(pid peer.ID, meta *pb.MsgMetadata) bool
	// AllMetadataPeerId return the peer.ID list of peers who linking us with metadata-only stat.
	AllMetadataPeerId() []peer.ID
	// GetChainPubSub return ChainPubSub instance of this PeerState.
	GetChainPubSub() *ChainPubSub
	// Subscribe listen a topic and register a topic sub message handler.
	Subscribe(topic string, handler handler.SubMsgHandler) error
	// Unsubscribe cancel listening a topic and unregister the topic sub message handler.
	Unsubscribe(topic string)
	// IsSubscribed return whether the topic has subscribed.
	IsSubscribed(topic string) bool
	// GetTopics return the list of topics that subscribed before.
	GetTopics() []string
	// GetAllMsgMetadata return the list of all the metadata in cache.
	GetAllMsgMetadata() []*pb.MsgMetadata
	// IHaveMessage return the list of the metadata of full app messages in cache.
	IHaveMessage() []*pb.MsgMetadata
	// IWantMessage return the list of metadata that peer having and not received by me.
	IWantMessage(peerHaveMessage []*pb.MsgMetadata) []*pb.MsgMetadata
	// GetMessageListWithMetadataList query full app messages with msg metadata infos.
	GetMessageListWithMetadataList(metadataList []*pb.MsgMetadata) []*pb.ApplicationMsg
	// ID return local peer.ID
	ID() peer.ID
}

var _ PeerState = (*peerState)(nil)

// peerState is an implementation of PeerState interface.
type peerState struct {
	subscriptions sync.Map // map[string]broadcast.SubMsgHandler, map[topic]broadcast.SubMsgHandler

	chainPubSub           *ChainPubSub
	peerTopicPeeringStore *peerTopicPeeringStore

	msgCache          *MsgCache          //cache application msg and metadata message
	peerReceivedCache *peerReceivedCache // store last metadata of messages other peers received.
}

// CacheMsg store the app msg into cache.
func (ps *peerState) CacheMsg(msg *pb.ApplicationMsg) {
	ps.msgCache.Put(msg)
}

// IsPeerReceivedMsg return whether the app msg exist in cache.
func (ps *peerState) IsPeerReceivedMsg(pid peer.ID, applicationMsg *pb.ApplicationMsg) bool {
	meta := &pb.MsgMetadata{
		Topic:  applicationMsg.Topics[0],
		Sender: applicationMsg.Sender,
		MsgSeq: applicationMsg.MsgSeq,
	}
	return ps.peerReceivedCache.Exist(pid, meta)
}

// RecordPeerReceivedMsg add a record that who has received the msg.
func (ps *peerState) RecordPeerReceivedMsg(pid peer.ID, meta *pb.MsgMetadata) bool {
	return ps.peerReceivedCache.Put(pid, meta)
}

// Subscribe listen a topic and register a topic sub message handler.
func (ps *peerState) Subscribe(topic string, handler handler.SubMsgHandler) error {
	_, loaded := ps.subscriptions.LoadOrStore(topic, handler)
	if loaded {
		return errors.New("topic has been subscribed")
	}
	return nil
}

// Unsubscribe cancel listening a topic and unregister the topic sub message handler.
func (ps *peerState) Unsubscribe(topic string) {
	ps.subscriptions.LoadAndDelete(topic)
}

// AllMetadataPeerId return the peer.ID list of peers who linking us with metadata-only stat.
func (ps *peerState) AllMetadataPeerId() []peer.ID {
	return ps.chainPubSub.AllMetadataOnlyPeers()
}

// GetChainPubSub return ChainPubSub instance of this PeerState.
func (ps *peerState) GetChainPubSub() *ChainPubSub {
	return ps.chainPubSub
}

// GetAllMsgMetadata return the list of all the metadata in cache.
func (ps *peerState) GetAllMsgMetadata() []*pb.MsgMetadata {
	return ps.msgCache.AllMsgMetadata()
}

//IWantMessage compare with cache data and return not in cache message
func (ps *peerState) IWantMessage(peerHaveMessage []*pb.MsgMetadata) []*pb.MsgMetadata {
	iWantMessage := make([]*pb.MsgMetadata, 0)
	if len(peerHaveMessage) == 0 {
		return iWantMessage
	}
	metadata := ps.GetAllMsgMetadata()
	metadataMap := make(map[string]struct{})
	for _, meta := range metadata {
		metadataMap[GetMsgKey(meta.Sender, meta.MsgSeq)] = struct{}{}
	}

	for _, v := range peerHaveMessage {
		if _, ok := metadataMap[GetMsgKey(v.Sender, v.MsgSeq)]; !ok {
			iWantMessage = append(iWantMessage, v)
		}
	}

	return iWantMessage
}

//IHaveMessage return I have message in cache
func (ps *peerState) IHaveMessage() []*pb.MsgMetadata {
	applicationMessage := ps.msgCache.AllApplicationMsg()
	iHaveMessage := make([]*pb.MsgMetadata, 0)
	for _, v := range applicationMessage {
		for _, topic := range v.Topics {
			metadata := &pb.MsgMetadata{
				Topic:  topic,
				Sender: v.Sender,
				MsgSeq: v.MsgSeq,
			}
			iHaveMessage = append(iHaveMessage, metadata)
		}
	}
	return iHaveMessage
}

// GetMessageListWithMetadataList query full app messages with msg metadata infos.
func (ps *peerState) GetMessageListWithMetadataList(metadataList []*pb.MsgMetadata) []*pb.ApplicationMsg {
	result := make([]*pb.ApplicationMsg, 0)
	if len(metadataList) == 0 {
		return result
	}

	keyMap := make(map[string]struct{})
	for _, v := range metadataList {
		key := GetMsgKey(v.Sender, v.MsgSeq)
		keyMap[key] = struct{}{}
	}

	applicationMessage := ps.msgCache.AllApplicationMsg()

	for _, v := range applicationMessage {
		key := GetMsgKey(v.Sender, v.MsgSeq)
		if _, ok := keyMap[key]; ok {
			result = append(result, v)
		}
	}
	return result
}

// GetTopics return the list of topics that subscribed before.
func (ps *peerState) GetTopics() []string {
	res := make([]string, 0)
	ps.subscriptions.Range(func(key, _ interface{}) bool {
		topic, _ := key.(string)
		res = append(res, topic)
		return true
	})
	return res
}

// ID return local peer.ID
func (ps *peerState) ID() peer.ID {
	return ps.chainPubSub.ID()
}

// IsSubscribed return whether the topic has subscribed.
func (ps *peerState) IsSubscribed(topic string) bool {
	_, res := ps.subscriptions.Load(topic)
	return res
}

// newPeerState create a new peerState instance.
func newPeerState(chainPubSub *ChainPubSub) *peerState {
	return &peerState{
		subscriptions:         sync.Map{},
		chainPubSub:           chainPubSub,
		peerTopicPeeringStore: &peerTopicPeeringStore{m: sync.Map{}},
		msgCache: NewMsgCache(
			chainPubSub.cfg.appMsgCacheTimeout,
			chainPubSub.cfg.metadataCacheTimeout,
			chainPubSub.cfg.appMsgCacheMaxSize,
			chainPubSub.cfg.metadataCacheMaxSize),
		peerReceivedCache: newPeerReceivedCache(defaultReceivedCacheCap),
	}
}
