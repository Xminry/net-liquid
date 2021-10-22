/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package liquidnet

import (
	"errors"
	"strings"

	"chainmaker.org/chainmaker/net-liquid/core/protocol"
)

const (
	NetProtocolTemplatePrefix = "/net/v0.0.1/chain-"
	protocolSeparator         = "::"
)

// CreateProtocolIdWithChainIdAndMsgFlag create a protocol.ID with the chain id and the msg flag given.
func CreateProtocolIdWithChainIdAndMsgFlag(chainId, msgFlag string) protocol.ID {
	builder := strings.Builder{}
	builder.WriteString(NetProtocolTemplatePrefix)
	builder.WriteString(chainId)
	builder.WriteString(protocolSeparator)
	builder.WriteString(msgFlag)
	return protocol.ID(builder.String())
}

//LoadChainIdAndFlagWithProtocolId resolves the chain id and the msg flag from a protocol.ID given.
func LoadChainIdAndFlagWithProtocolId(protocolId protocol.ID) (string, string, error) {
	protocolStr := string(protocolId)
	if !strings.HasPrefix(protocolStr, NetProtocolTemplatePrefix) {
		return "", "", errors.New("parse chain id and message flag failed")
	}
	chainIdAndFlag := strings.SplitN(strings.TrimPrefix(protocolStr, NetProtocolTemplatePrefix),
		protocolSeparator, 2)
	if len(chainIdAndFlag) != 2 {
		return "", "", errors.New("parse chain id and mseeage flag fail")
	}
	return chainIdAndFlag[0], chainIdAndFlag[1], nil
}
