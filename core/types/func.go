package types

import (
	"crypto/x509"

	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/peer"
	gmx509 "github.com/tjfoc/gmsm/x509"
	qx509 "github.com/xiaotianfork/q-tls-common/x509"
)

// LoadPeerIdFromTlsCertFunc is a function can load the peer.ID
// from []*x509.Certificate exchanged during tls handshaking.
type LoadPeerIdFromTlsCertFunc func([]*x509.Certificate) (peer.ID, error)

// LoadPeerIdFromQTlsCertFunc is a function can load the peer.ID
// from []*qx509.Certificate exchanged during quic tls handshaking.
type LoadPeerIdFromQTlsCertFunc func([]*qx509.Certificate) (peer.ID, error)

// LoadPeerIdFromGMTlsCertFunc is a function can load the peer.ID
// from []*gmx509.Certificate exchanged during tls handshaking.
type LoadPeerIdFromGMTlsCertFunc func([]*gmx509.Certificate) (peer.ID, error)
