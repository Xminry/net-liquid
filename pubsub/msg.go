/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package pubsub

import (
	"strconv"
	"strings"

	"chainmaker.org/chainmaker/net-liquid/pubsub/pb"
	"github.com/gogo/protobuf/proto"
)

// CreatePubSubMsgPayload create payload bytes for PubSub.
func CreatePubSubMsgPayload(
	appMsgs []*pb.ApplicationMsg,
	spreadMsg *pb.IHaveOrWant,
	topicMsg *pb.TopicMsg,
	peeringMsg *pb.PeeringMsg) ([]byte, error) {
	psMsg := &pb.PubsubMsg{
		Msg:         appMsgs,
		SpreadCtrl:  spreadMsg,
		TopicCtrl:   topicMsg,
		PeeringCtrl: peeringMsg,
	}
	return proto.Marshal(psMsg)
}

// GetPubSubMsgWithPayload parse payload bytes to *pb.PubsubMsg
func GetPubSubMsgWithPayload(payload []byte) (*pb.PubsubMsg, error) {
	psMsg := &pb.PubsubMsg{}
	err := proto.Unmarshal(payload, psMsg)
	if err != nil {
		return nil, err
	}
	return psMsg, nil
}

// GetMsgKey build a cache key with sender and sequence string.
func GetMsgKey(sender string, seq uint64) string {
	formatUint := strconv.FormatUint(seq, 16)
	builder := strings.Builder{}
	builder.Grow(len(sender) + 1 + len(formatUint))
	builder.WriteString(sender)
	builder.WriteString("_")
	builder.WriteString(formatUint)
	return builder.String()
}
