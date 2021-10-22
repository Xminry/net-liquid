/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package pubsub

import (
	"strconv"
	"strings"
	"time"

	"chainmaker.org/chainmaker/net-liquid/core/peer"
	"chainmaker.org/chainmaker/net-liquid/core/types"
	"chainmaker.org/chainmaker/net-liquid/pubsub/pb"
)

const (
	separator               = "-"
	defaultReceivedCacheCap = 500
)

type MsgCache struct {
	applicationMsgDuration time.Duration //cache msg duration
	metadataMsgDuration    time.Duration //cache msg duration

	applicationCache *types.FixedCapDurationCache
	metadataCache    *types.FixedCapDurationCache
}

func NewMsgCache(
	applicationMsgDuration time.Duration,
	metadataMsgDuration time.Duration,
	applicationMaxLength int,
	metadataMsgMaxLength int) *MsgCache {
	applicationCache := types.NewFixedCapDurationCache(applicationMsgDuration, applicationMaxLength)
	metadataCache := types.NewFixedCapDurationCache(metadataMsgDuration, metadataMsgMaxLength)
	return &MsgCache{
		applicationMsgDuration: applicationMsgDuration,
		metadataMsgDuration:    metadataMsgDuration,
		applicationCache:       applicationCache,
		metadataCache:          metadataCache,
	}
}

//PutIfNoExists put message to cache, if message not exists return ture, if message has exists return false
func (c *MsgCache) PutIfNoExists(msg *pb.ApplicationMsg) bool {
	msgKey := GetMsgKey(msg.Sender, msg.MsgSeq)
	metadata := &pb.MsgMetadata{Sender: msg.Sender, MsgSeq: msg.MsgSeq}
	if c.metadataCache.AddIfNotExist(msgKey, metadata) {
		c.applicationCache.Add(msgKey, msg)
		return true
	}
	return false
}

//Put message to cache
func (c *MsgCache) Put(msg *pb.ApplicationMsg) bool {
	key := GetMsgKey(msg.Sender, msg.MsgSeq)
	c.applicationCache.Add(key, msg)
	metadata := &pb.MsgMetadata{Sender: msg.Sender, MsgSeq: msg.MsgSeq}
	c.metadataCache.Add(key, metadata)
	return true
}

// AllMsgMetadata get all cached metadata
func (c *MsgCache) AllMsgMetadata() []*pb.MsgMetadata {
	allMetadata := c.metadataCache.GetAll()
	result := make([]*pb.MsgMetadata, 0, len(allMetadata))
	for _, v := range allMetadata {
		result = append(result, v.(*pb.MsgMetadata))
	}
	return result
}

// AllApplicationMsg return all application message in cache
func (c *MsgCache) AllApplicationMsg() []*pb.ApplicationMsg {
	applicationMsg := c.applicationCache.GetAll()
	result := make([]*pb.ApplicationMsg, 0, len(applicationMsg))
	for _, v := range applicationMsg {
		result = append(result, v.(*pb.ApplicationMsg))
	}
	return result
}

type peerReceivedCache struct {
	cache *types.FIFOCache
}

func newPeerReceivedCache(cap int) *peerReceivedCache {
	if cap <= 0 {
		return nil
	}
	return &peerReceivedCache{
		cache: types.NewFIFOCache(cap, true),
	}
}

func (c *peerReceivedCache) createMetaKey(pid peer.ID, meta *pb.MsgMetadata) string {
	if meta == nil {
		return ""
	}
	builder := strings.Builder{}
	builder.WriteString(pid.ToString())
	builder.WriteString(separator)
	builder.WriteString(meta.Topic)
	builder.WriteString(separator)
	builder.WriteString(meta.Sender)
	builder.WriteString(separator)
	builder.WriteString(strconv.FormatUint(meta.MsgSeq, 10))
	return builder.String()
}

func (c *peerReceivedCache) Put(pid peer.ID, meta *pb.MsgMetadata) bool {
	key := c.createMetaKey(pid, meta)
	return c.cache.PutIfNotExist(key, meta)
}

func (c *peerReceivedCache) Exist(pid peer.ID, meta *pb.MsgMetadata) bool {
	key := c.createMetaKey(pid, meta)
	return c.cache.Exist(key)
}
