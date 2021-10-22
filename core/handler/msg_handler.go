/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package handler

import "chainmaker.org/chainmaker/net-liquid/core/peer"

// MsgPayloadHandler is a function to handle the msg payload received from sender.
type MsgPayloadHandler func(senderPID peer.ID, msgPayload []byte)

// SubMsgHandler is a function to handle the msg payload received from the PubSub topic network.
type SubMsgHandler func(publisher peer.ID, topic string, msg []byte)
