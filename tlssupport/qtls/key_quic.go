package qtls

import (
	"chainmaker.org/chainmaker/common/helper/libp2pcrypto"
	"chainmaker.org/chainmaker/common/helper/libp2pcrypto/pb"
	gocrypto "crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/subtle"
	"errors"
	"github.com/xiaotianfork/q-tls-common/sm2"
	qx509 "github.com/xiaotianfork/q-tls-common/x509"
)

var _ libp2pcrypto.PubKey = (*QuicSM2PublicKey)(nil)

// QuicSM2PublicKey is an implementation of an SM2 public key
type QuicSM2PublicKey struct {
	pub *sm2.PublicKey
}

// NewQuicSM2PublicKey create a QuicSM2PublicKey with sm2.PublicKey.
func NewQuicSM2PublicKey(pub *sm2.PublicKey) *QuicSM2PublicKey {
	return &QuicSM2PublicKey{pub: pub}
}

// Bytes returns the public key as protobuf bytes
func (ePub *QuicSM2PublicKey) Bytes() ([]byte, error) {
	return libp2pcrypto.MarshalPublicKey(ePub)
}

// Type returns the key type
func (ePub *QuicSM2PublicKey) Type() pb.KeyType {
	return pb.KeyType_SM2
}

// Raw returns x509 bytes from a public key
func (ePub *QuicSM2PublicKey) Raw() ([]byte, error) {
	return qx509.MarshalSm2PublicKey(ePub.pub)
}

// Equals compares to public keys
func (ePub *QuicSM2PublicKey) Equals(other libp2pcrypto.Key) bool {
	if ePub.Type() != other.Type() {
		return false
	}

	a, err := ePub.Raw()
	if err != nil {
		return false
	}
	b, err := other.Raw()
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}

// Verify compares data to a signature
func (ePub *QuicSM2PublicKey) Verify(data, sigBytes []byte) (bool, error) {
	return ePub.pub.Verify(data, sigBytes), nil
}

func ParsePublicKeyToPubKey4Quic(publicKey gocrypto.PublicKey) (libp2pcrypto.PubKey, error) {
	switch p := publicKey.(type) {
	case *ecdsa.PublicKey:
		if p.Curve == sm2.P256Sm2() {
			pub := &sm2.PublicKey{
				Curve: p.Curve,
				X:     p.X,
				Y:     p.Y,
			}
			return NewQuicSM2PublicKey(pub), nil
		}
		return libp2pcrypto.NewECDSAPublicKey(p), nil
	case *sm2.PublicKey:
		return NewQuicSM2PublicKey(p), nil
	case *rsa.PublicKey:
		return libp2pcrypto.NewRsaPublicKey(*p), nil
	}
	return nil, errors.New("unsupported public key type")
}
