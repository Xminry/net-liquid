package types

import (
	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/peer"
	cmx509 "chainmaker.org/chainmaker/common/v2/crypto/x509"
)

// LoadPeerIdFromCMTlsCertFunc is a function can load the peer.ID
// from []*cmx509.Certificate exchanged during tls handshaking.
type LoadPeerIdFromCMTlsCertFunc func([]*cmx509.Certificate) (peer.ID, error)
