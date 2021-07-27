/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package liquid

import (
	"chainmaker.org/chainmaker/chainmaker-net-liquid/host"
	ma "github.com/multiformats/go-multiaddr"
)

// SetListenAddrStr set the local address will be listening on fot host.HostConfig.
func SetListenAddrStr(hc *host.HostConfig, listenAddrStr string) error {
	a, err := ma.NewMultiaddr(listenAddrStr)
	if err != nil {
		return err
	}
	hc.ListenAddresses = []ma.Multiaddr{a}
	return nil
}

type cryptoConfig struct {
	KeyBytes                 []byte
	CertBytes                []byte
	SignKeyBytes             []byte
	SignCertBytes            []byte
	ChainTrustRootCertsBytes map[string][][]byte
}

func (cc *cryptoConfig) AddTrustRootCert(chainId string, rootCert []byte) {
	if cc.ChainTrustRootCertsBytes == nil {
		cc.ChainTrustRootCertsBytes = make(map[string][][]byte)
	}
	if _, ok := cc.ChainTrustRootCertsBytes[chainId]; !ok {
		cc.ChainTrustRootCertsBytes[chainId] = make([][]byte, 0, 10)
	}
	cc.ChainTrustRootCertsBytes[chainId] = append(cc.ChainTrustRootCertsBytes[chainId], rootCert)
}

type pubSubConfig struct {
	MaxPubMessageSize int
}

type extensionsConfig struct {
	EnablePkt          bool
	EnablePriorityCtrl bool
}
