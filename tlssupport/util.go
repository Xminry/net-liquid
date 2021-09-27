/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package tlssupport

import (
	"crypto/x509"
	"encoding/pem"
	"errors"

	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/peer"
	cmx509 "chainmaker.org/chainmaker/common/v2/crypto/x509"
	"chainmaker.org/chainmaker/common/v2/helper"
	gmx509 "github.com/tjfoc/gmsm/x509"
)

// PeerIdFunction is a function can load peer.ID from certificates got when tls handshaking.
func PeerIdFunction() func(certificates []*cmx509.Certificate) (peer.ID, error) {
	return func(certificates []*cmx509.Certificate) (peer.ID, error) {
		pid, err := helper.GetLibp2pPeerIdFromCertDer(certificates[0].Raw)
		if err != nil {
			return "", err
		}
		return peer.ID(pid), err
	}
}

// UseGMTls return true if it is a tls certificate with GM crypto.
func UseGMTls(tlsCertBytes []byte) (bool, error) {
	var block *pem.Block
	block, _ = pem.Decode(tlsCertBytes)
	if block == nil {
		return false, errors.New("empty pem block")
	}
	if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
		return false, errors.New("not certificate pem")
	}
	_, err := x509.ParseCertificate(block.Bytes)
	if err == nil {
		return false, nil
	}
	_, err = gmx509.ParseCertificate(block.Bytes)
	return err == nil, nil
}
