/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"chainmaker.org/chainmaker/common/v2/crypto"
	"chainmaker.org/chainmaker/common/v2/helper"
	"chainmaker.org/chainmaker/net-liquid/core/peer"
)

// ResolvePIDFromCertDER load the peer.ID from cert der bytes.
func ResolvePIDFromCertDER(der []byte) (peer.ID, error) {
	pidStr, err := helper.GetLibp2pPeerIdFromCertDer(der)
	if err != nil {
		return "", err
	}
	return peer.ID(pidStr), nil
}

// ResolvePIDFromPubKey create a peer.ID with a crypto.PublicKey.
func ResolvePIDFromPubKey(pubKey crypto.PublicKey) (peer.ID, error) {
	pidStr, err := helper.CreateLibp2pPeerIdWithPublicKey(pubKey)
	if err != nil {
		return "", err
	}
	return peer.ID(pidStr), err
}
