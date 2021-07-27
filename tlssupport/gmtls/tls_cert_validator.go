/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gmtls

import (
	"chainmaker.org/chainmaker/common/helper"
	"chainmaker.org/chainmaker/common/helper/libp2ppeer"
	"fmt"
	"sync"

	"chainmaker.org/chainmaker/chainmaker-net-common/common"
	cmx509 "chainmaker.org/chainmaker/common/crypto/x509"
	"github.com/tjfoc/gmsm/x509"
)

// DerivedInfoWithCert contains infos loaded from tls cert when verifying peer certificate.
type DerivedInfoWithCert struct {
	TlsCertBytes []byte
	ChainIds     []string
	PeerId       string
	CertId       string
}

// CertValidator wraps a ChainTrustRoots instance and a common.RevokedValidator.
// It provides a function for verifying peer certificate when tls handshaking.
// In handshaking process, the function will load remote tls certificate and verify it by chain trust roots, also load remote peer id and cert id. All these infos will stored in validator.
// These infos could be queried with QueryDerivedInfoWithPeerId function. And could be removed with CleanDerivedInfoWithPeerId function.
type CertValidator struct {
	tlsTrustRoots    *ChainTrustRoots
	revokedValidator *common.RevokedValidator
	infoStore        map[string]*DerivedInfoWithCert // map[peer.ID]*DerivedInfoWithCert
	mu               sync.RWMutex
}

// NewCertValidator create a new CertValidator instance.
func NewCertValidator(tlsTrustRoots *ChainTrustRoots, revokedValidator *common.RevokedValidator) *CertValidator {
	return &CertValidator{
		tlsTrustRoots:    tlsTrustRoots,
		revokedValidator: revokedValidator,
		infoStore:        make(map[string]*DerivedInfoWithCert),
		mu:               sync.RWMutex{},
	}
}

// VerifyPeerCertificateFunc provides a function for verify peer certificate in tls config.
// In handshaking process, the function will load remote tls certificate and verify it by chain trust roots,
// also load remote peer id and cert id. All these infos will stored in validator.
func (v *CertValidator) VerifyPeerCertificateFunc(dualCert bool) func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		var tlsCertBytes []byte
		if dualCert {
			if len(rawCerts) < 2 {
				return fmt.Errorf("amount of certificates must be greater than 2, which will sign and encipher respectively")
			}
			tlsCertBytes = rawCerts[1]
		} else {
			tlsCertBytes = rawCerts[0]
		}
		revoked, err := isRevoked(v.revokedValidator, rawCerts)
		if err != nil {
			return err
		}
		if revoked {
			return fmt.Errorf("certificate revoked")
		}

		cert, err := x509.ParseCertificate(tlsCertBytes)
		if err != nil {
			return fmt.Errorf("parse certificate failed: %s", err.Error())
		}
		chainIds, err := v.tlsTrustRoots.VerifyCert(cert)
		if err != nil {
			return fmt.Errorf("verify certificate failed: %s", err.Error())
		}
		pubKey, err := helper.ParseGoPublicKeyToPubKey(cert.PublicKey)
		if err != nil {
			return fmt.Errorf("parse pubkey failed: %s", err.Error())
		}
		pid, err := libp2ppeer.IDFromPublicKey(pubKey)
		if err != nil {
			return fmt.Errorf("parse pid from pubkey failed: %s", err.Error())
		}
		peerId := pid.Pretty()
		certId, err := cmx509.GetNodeIdFromSm2Certificate(cmx509.OidNodeId, *cert)
		if err != nil {
			return fmt.Errorf("get certid failed: %s", err.Error())
		}

		info := &DerivedInfoWithCert{
			TlsCertBytes: tlsCertBytes,
			ChainIds:     chainIds,
			PeerId:       peerId,
			CertId:       string(certId),
		}

		v.mu.Lock()
		defer v.mu.Unlock()
		v.infoStore[peerId] = info
		return nil
	}
}

// QueryDerivedInfoWithPeerId return all infos that loaded with VerifyPeerCertificateFunc and stored in validator.
func (v *CertValidator) QueryDerivedInfoWithPeerId(peerId string) *DerivedInfoWithCert {
	v.mu.RLock()
	defer v.mu.RUnlock()
	res, ok := v.infoStore[peerId]
	if !ok {
		return nil
	}
	return res
}

// CleanDerivedInfoWithPeerId remove all infos of peer if exist.
func (v *CertValidator) CleanDerivedInfoWithPeerId(peerId string) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	delete(v.infoStore, peerId)
}

func isRevoked(revokeValidator *common.RevokedValidator, rawCerts [][]byte) (bool, error) {
	certs := make([]*cmx509.Certificate, 0)
	for idx := range rawCerts {
		cert, err := cmx509.ParseCertificate(rawCerts[idx])
		if err != nil {
			return false, err
		}
		certs = append(certs, cert)
	}
	return revokeValidator.ValidateCertsIsRevoked(certs), nil
}
