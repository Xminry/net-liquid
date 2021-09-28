package quic

import (
	cmTls "chainmaker.org/chainmaker/common/v2/crypto/tls"
	cmx509 "chainmaker.org/chainmaker/common/v2/crypto/x509"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"github.com/tjfoc/gmsm/sm2"
	qx509 "github.com/xiaotianfork/q-tls-common/x509"
)

func ParseQX509CertsToCMX509Certs(qCerts []*qx509.Certificate) ([]*cmx509.Certificate, error) {
	if len(qCerts) == 0 {
		return make([]*cmx509.Certificate, 0, 1), nil
	}
	res := make([]*cmx509.Certificate, 0, len(qCerts))
	for _, qCert := range qCerts {
		cmCert, err := cmx509.ParseCertificate(qCert.Raw)
		if err != nil {
			return nil, err
		}
		res = append(res, cmCert)
	}
	return res, nil
}

func ParseCMX509CertsToGoX509Certs(cmCerts []*cmx509.Certificate) ([]*x509.Certificate, error) {
	if len(cmCerts) == 0 {
		return make([]*x509.Certificate, 0, 1), nil
	}
	res := make([]*x509.Certificate, 0, len(cmCerts))
	for _, cmCert := range cmCerts {
		qCert, err := qx509.ParseCertificate(cmCert.Raw)
		if err != nil {
			return nil, err
		}
		cert := qx509.ToStandX509Cert(qCert)
		res = append(res, cert)
	}
	return res, nil
}

func ParseCMTLSCertsToGoTLSCerts(cmCerts []cmTls.Certificate) ([]tls.Certificate, error) {
	if len(cmCerts) == 0 {
		return make([]tls.Certificate, 0, 1), nil
	}
	res := make([]tls.Certificate, 0, len(cmCerts))
	for _, cmCert := range cmCerts {
		cert := tls.Certificate{
			Certificate:                  cmCert.Certificate,
			PrivateKey:                   cmCert.PrivateKey,
			SupportedSignatureAlgorithms: parseSignatureScheme(cmCert.SupportedSignatureAlgorithms),
			OCSPStaple:                   cmCert.OCSPStaple,
			SignedCertificateTimestamps:  cmCert.SignedCertificateTimestamps,
			Leaf:                         cmCert.Leaf,
		}
		res = append(res, cert)
	}
	return res, nil
}

func parseSignatureScheme(ss []cmTls.SignatureScheme) []tls.SignatureScheme {
	if ss == nil {
		return nil
	}
	res := make([]tls.SignatureScheme, 0, 16)
	for _, s := range ss {
		res = append(res, tls.SignatureScheme(s))
	}
	return res
}

// IsGMPrivateKey return true if it is a sm2.PrivateKey.
func IsGMPrivateKey(sk crypto.PrivateKey) bool {
	_, bl := sk.(*sm2.PrivateKey)
	return bl
}
