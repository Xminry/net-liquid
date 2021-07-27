/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package tls

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"

	"chainmaker.org/chainmaker/common/helper"
)

// NewTlsConfig create a new tls config for tls handshake.
func NewTlsConfig(
	certificate tls.Certificate,
	certValidator *CertValidator,
) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		Certificates:          []tls.Certificate{certificate},
		InsecureSkipVerify:    true,
		ClientAuth:            tls.RequireAnyClientCert,
		VerifyPeerCertificate: certValidator.VerifyPeerCertificateFunc(),
	}
	return tlsConfig, nil
}

// AppendNewCertsToTrustRoots will load all cert from cert pem bytes, then append them to chain trust roots.
func AppendNewCertsToTrustRoots(tlsTrustRoots *ChainTrustRoots, chainId string, certPemBytes []byte) (bool, error) {
	return loadAllCertsFromCertBytes(certPemBytes, chainId, tlsTrustRoots)
}

func loadAllCertsFromCertBytes(certByte []byte, chainId string, tlsTrustRoots *ChainTrustRoots) (ok bool, err error) {
	// 1. read all certs from bytes
	allCertsBytes := getAllCertsBytes(certByte)
	// 2. add certs to pool
	if allCertsBytes == nil || len(allCertsBytes) == 0 {
		return false, nil
	}
	for _, cert := range allCertsBytes {
		c, e := x509.ParseCertificate(cert)
		if e != nil {
			return false, e
		}
		if c.IsCA {
			tlsTrustRoots.AddRoot(chainId, c)
		} else {
			tlsTrustRoots.AddIntermediates(chainId, c)
		}
	}
	return true, nil
}

func getAllCertsBytes(source []byte) [][]byte {
	result := make([][]byte, 0)
	if source == nil {
		return nil
	}
	for len(source) > 0 {
		var block *pem.Block
		block, source = pem.Decode(source)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}
		result = append(result, block.Bytes)
	}
	return result
}

// BuildTlsTrustRoots build the cert pool with cert bytes of chain.
func BuildTlsTrustRoots(chainTrustRoots map[string][][]byte) (*ChainTrustRoots, error) {
	tlsTrustRoots := NewChainTrustRoots()
	for chainId, trustRootCertBytes := range chainTrustRoots {
		for _, certByte := range trustRootCertBytes {
			ok, err := loadAllCertsFromCertBytes(certByte, chainId, tlsTrustRoots)
			if err != nil {
				return nil, err
			}
			if !ok {
				break
			}
		}
	}
	return tlsTrustRoots, nil
}

// GetCertAndPeerIdWithKeyPair will create a tls cert with x509 key pair and load the peer id from cert.
func GetCertAndPeerIdWithKeyPair(certPEMBlock []byte, keyPEMBlock []byte) (*tls.Certificate, string, error) {
	certificate, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		return nil, "", err
	}
	peerID, err2 := helper.GetLibp2pPeerIdFromCert(certPEMBlock)
	if err2 != nil {
		return nil, "", err2
	}
	return &certificate, peerID, nil
}
