/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package tlssupport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"time"

	"chainmaker.org/chainmaker/chainmaker-net-common/utils"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/peer"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/types"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/util"
	"chainmaker.org/chainmaker/common/crypto"
	"chainmaker.org/chainmaker/common/crypto/asym"
	"golang.org/x/sys/cpu"
)

const (
	certValidityPeriod        = 100 * 365 * 24 * time.Hour // ~100 years
	certificatePrefix         = "chainmaker-tls-handshake:"
	alpn               string = "chainmaker"
)

// MakeTlsConfigAndLoadPeerIdFuncWithPrivateKey create a tls config and load peer id function for the host config with private key given.
func MakeTlsConfigAndLoadPeerIdFuncWithPrivateKey(
	privateKey crypto.PrivateKey) (*tls.Config, types.LoadPeerIdFromTlsCertFunc, error) {
	cert, err := PrivateKeyToCertificate(privateKey)
	if err != nil {
		return nil, nil, err
	}
	conf := &tls.Config{
		MinVersion:               tls.VersionTLS13,
		PreferServerCipherSuites: preferServerCipherSuites(),
		InsecureSkipVerify:       true, // This is not insecure here. We will verify the cert chain ourselves.
		ClientAuth:               tls.RequireAnyClientCert,
		Certificates:             []tls.Certificate{*cert},
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			chain := make([]*x509.Certificate, len(rawCerts))
			for i := 0; i < len(rawCerts); i++ {
				cert, err := x509.ParseCertificate(rawCerts[i])
				if err != nil {
					return err
				}
				chain[i] = cert
			}

			bl, err := verifyCertChain(chain)
			if err != nil {
				return err
			}
			if !bl {
				return errors.New("verify cert chain failed")
			}
			return nil
		},
		NextProtos:             []string{alpn},
		SessionTicketsDisabled: true,
	}

	var loadPidFunc types.LoadPeerIdFromTlsCertFunc = func(certificates []*x509.Certificate) (peer.ID, error) {
		if len(certificates) == 0 {
			return "", errors.New("empty certificates")
		}
		cert := certificates[0]
		ext := searchCertExtension(cert)
		if ext == nil {
			return "", errors.New("no necessary extension found")
		}
		keyBytes, _ := loadKeyBytesAndSignatureBytesFromCertExt(ext)
		pubKey, err := asym.PublicKeyFromDER(keyBytes)
		if err != nil {
			return "", err
		}
		return util.ResolvePIDFromPubKey(pubKey)
	}
	return conf, loadPidFunc, nil
}

func searchCertExtension(cert *x509.Certificate) *pkix.Extension {
	for _, ext := range cert.Extensions {
		if extensionIDEqual(ext.Id, extensionID) {
			return &ext
		}
	}
	return nil
}

func loadKeyBytesAndSignatureBytesFromCertExt(ext *pkix.Extension) ([]byte, []byte) {
	keyBytesLenBytes := ext.Value[:8]
	keyBytesLen := int(utils.BytesToUint64(keyBytesLenBytes))
	keyBytes := ext.Value[8 : 8+keyBytesLen]
	signBytes := ext.Value[8+keyBytesLen:]
	return keyBytes, signBytes
}

func createExtValueWithKeyBytesAndSignatureBytes(keyBytes, signatureBytes []byte) []byte {
	keyBytesLen := len(keyBytes)
	signatureLen := len(signatureBytes)
	extensionValue := make([]byte, 0, 16+keyBytesLen+signatureLen)

	extensionValue = append(extensionValue, utils.Uint64ToBytes(uint64(keyBytesLen))...)
	extensionValue = append(extensionValue, keyBytes...)
	extensionValue = append(extensionValue, signatureBytes...)
	return extensionValue
}

func verifyCertChain(chain []*x509.Certificate) (bool, error) {
	if len(chain) != 1 {
		return false, errors.New("no certificates found")
	}
	cert := chain[0]
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
		return false, fmt.Errorf("certificate verification failed: %s", err)
	}

	ext := searchCertExtension(cert)
	if ext == nil {
		return false, errors.New("the key extension not found in certificate")
	}

	keyBytes, signBytes := loadKeyBytesAndSignatureBytesFromCertExt(ext)

	certKeyPub, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return false, err
	}
	ok, err := asym.Verify(keyBytes, append([]byte(certificatePrefix), certKeyPub...), signBytes)
	if err != nil {
		return false, fmt.Errorf("signature verification failed: %s", err)
	}
	if !ok {
		return false, errors.New("signature invalid")
	}
	return true, nil
}

// PrivateKeyToCertificate create a certificate simply with a private key.
func PrivateKeyToCertificate(privateKye crypto.PrivateKey) (*tls.Certificate, error) {
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	certKeyPub, err := x509.MarshalPKIXPublicKey(certKey.Public())
	if err != nil {
		return nil, err
	}
	keyBytes, err := privateKye.PublicKey().Bytes()
	if err != nil {
		return nil, err
	}
	signature, err := privateKye.Sign(append([]byte(certificatePrefix), certKeyPub...))
	if err != nil {
		return nil, err
	}

	extensionValue := createExtValueWithKeyBytesAndSignatureBytes(keyBytes, signature)

	sn, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: sn,
		NotBefore:    time.Time{},
		NotAfter:     time.Now().Add(certValidityPeriod),
		ExtraExtensions: []pkix.Extension{
			{Id: extensionID, Value: extensionValue},
		},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, certKey.Public(), certKey)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  certKey,
	}, nil
}

func preferServerCipherSuites() bool {
	// Copied from the Go TLS implementation.

	// Check the cpu flags for each platform that has optimized GCM implementations.
	// Worst case, these variables will just all be false.
	var (
		hasGCMAsmAMD64 = cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ
		hasGCMAsmARM64 = cpu.ARM64.HasAES && cpu.ARM64.HasPMULL
		// Keep in sync with crypto/aes/cipher_s390x.go.
		hasGCMAsmS390X = cpu.S390X.HasAES &&
			cpu.S390X.HasAESCBC &&
			cpu.S390X.HasAESCTR &&
			(cpu.S390X.HasGHASH || cpu.S390X.HasAESGCM)

		hasGCMAsm = hasGCMAsmAMD64 || hasGCMAsmARM64 || hasGCMAsmS390X
	)
	return !hasGCMAsm
}
