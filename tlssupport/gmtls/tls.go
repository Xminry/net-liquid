/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gmtls

import (
	"crypto/rand"
	"encoding/pem"

	"chainmaker.org/chainmaker/common/helper"
	"github.com/tjfoc/gmsm/gmtls"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/x509"
)

// NewTlsServerConfigDualCertMode create a new gm tls config for server with dual cert mode.
func NewTlsServerConfigDualCertMode(
	signCertificate gmtls.Certificate,
	certificate gmtls.Certificate,
	certValidator *CertValidator,
) (*gmtls.Config, error) {
	tlsConfig := &gmtls.Config{
		GMSupport:             &gmtls.GMSupport{},
		Certificates:          []gmtls.Certificate{signCertificate, certificate},
		InsecureSkipVerify:    true,
		ClientAuth:            gmtls.RequireAndVerifyClientCert,
		VerifyPeerCertificate: certValidator.VerifyPeerCertificateFunc(false),
	}
	return tlsConfig, nil
}

// NewTlsServerConfigSingleCertMode create a new gm tls config for server with single cert mode.
func NewTlsServerConfigSingleCertMode(
	certificate gmtls.Certificate,
	certValidator *CertValidator,
) (*gmtls.Config, error) {
	tlsConfig := &gmtls.Config{
		Certificates:          []gmtls.Certificate{certificate},
		InsecureSkipVerify:    true,
		ClientAuth:            gmtls.RequireAndVerifyClientCert,
		VerifyPeerCertificate: certValidator.VerifyPeerCertificateFunc(false),
	}
	return tlsConfig, nil
}

// NewTlsClientConfig create a new gm tls config for client.
func NewTlsClientConfig(
	certificate gmtls.Certificate,
	certValidator *CertValidator,
	dualCert bool,
) (*gmtls.Config, error) {
	var GMSupport *gmtls.GMSupport = nil
	if dualCert {
		GMSupport = &gmtls.GMSupport{}
	}
	tlsConfig := &gmtls.Config{
		GMSupport:             GMSupport,
		Certificates:          []gmtls.Certificate{certificate},
		InsecureSkipVerify:    true,
		ClientAuth:            gmtls.RequireAndVerifyClientCert,
		VerifyPeerCertificate: certValidator.VerifyPeerCertificateFunc(dualCert),
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

// GetCertAndPeerIdWithKeyPair will create a gmtls cert with gmx509 key pair and load the peer id from cert.
func GetCertAndPeerIdWithKeyPair(certPEMBlock []byte, keyPEMBlock []byte) (*gmtls.Certificate, string, error) {
	certificate, err := gmtls.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		return nil, "", err
	}
	peerID, err2 := helper.GetLibp2pPeerIdFromCert(certPEMBlock)
	if err2 != nil {
		return nil, "", err2
	}
	return &certificate, peerID, nil
}

// GenerateSignCertificateWithEncryptCertificate will create a new random sign cert with the encrypt cert given.
func GenerateSignCertificateWithEncryptCertificate(encryptCert *x509.Certificate) (*gmtls.Certificate, error) {
	certKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	certDER, err := x509.CreateCertificate(encryptCert, encryptCert, &certKey.PublicKey, certKey)
	if err != nil {
		return nil, err
	}
	return &gmtls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  certKey,
	}, nil

}

// GenerateGMTlsServerConfigWithDualCerts will generate a gm tls config for server on dual certs mode.
// If sign key or sign cert bytes is empty, random sign cert will be created with the encrypt cert, and second value returned will be true, otherwise be false.
func GenerateGMTlsServerConfigWithDualCerts(encryptCert *gmtls.Certificate, signKeyBytes, signCertBytes []byte, certValidator *CertValidator) (*gmtls.Config, bool, error) {
	var tlsServerCfg *gmtls.Config
	var gmTlsSignCert *gmtls.Certificate
	if len(signKeyBytes) > 0 && len(signCertBytes) > 0 {
		c, e := gmtls.X509KeyPair(signCertBytes, signKeyBytes)
		if e != nil {
			return nil, false, e
		}
		gmTlsSignCert = &c
		tlsServerCfg, e = NewTlsServerConfigDualCertMode(*gmTlsSignCert, *encryptCert, certValidator)
		if e != nil {
			return nil, false, e
		}
		return tlsServerCfg, false, e
	} else {
		c, e := x509.ParseCertificate(encryptCert.Certificate[0])
		if e != nil {
			return nil, false, e
		}
		gmTlsSignCert, e = GenerateSignCertificateWithEncryptCertificate(c)
		if e != nil {
			return nil, false, e
		}
		tlsServerCfg, e = NewTlsServerConfigDualCertMode(*gmTlsSignCert, *encryptCert, certValidator)
		if e != nil {
			return nil, false, e
		}
		return tlsServerCfg, true, e
	}
}
