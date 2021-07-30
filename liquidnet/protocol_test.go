/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package liquidnet

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseChainId(t *testing.T) {
	protocolId := CreateProtocolIdWithChainIdAndMsgFlag("chain", "flag")
	chainId, flag, err := LoadChainIdAndFlagWithProtocolId(protocolId)
	assert.Nil(t, err)
	assert.Equal(t, "chain", chainId)
	assert.Equal(t, "flag", flag)

	protocolId = CreateProtocolIdWithChainIdAndMsgFlag("", "flag")
	chainId, flag, err = LoadChainIdAndFlagWithProtocolId(protocolId)
	assert.Nil(t, err)
	assert.Equal(t, "", chainId)
	assert.Equal(t, "flag", flag)

	protocolId = CreateProtocolIdWithChainIdAndMsgFlag("chain", "")
	chainId, flag, err = LoadChainIdAndFlagWithProtocolId(protocolId)
	assert.Nil(t, err)
	assert.Equal(t, "chain", chainId)
	assert.Equal(t, "", flag)

	protocolId = CreateProtocolIdWithChainIdAndMsgFlag("", "")
	chainId, flag, err = LoadChainIdAndFlagWithProtocolId(protocolId)
	assert.Nil(t, err)
	assert.Equal(t, "", chainId)
	assert.Equal(t, "", flag)
}
