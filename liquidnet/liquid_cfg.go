/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package liquidnet

import (
	"chainmaker.org/chainmaker/net-liquid/host"
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
	PubKeyMode                     bool
	KeyBytes                       []byte
	CertBytes                      []byte
	CustomChainTrustRootCertsBytes map[string][][]byte
}

func (cc *cryptoConfig) SetCustomTrustRootCert(chainId string, rootCerts [][]byte) {
	if cc.CustomChainTrustRootCertsBytes == nil {
		cc.CustomChainTrustRootCertsBytes = make(map[string][][]byte)
	}
	if _, ok := cc.CustomChainTrustRootCertsBytes[chainId]; !ok {
		cc.CustomChainTrustRootCertsBytes[chainId] = make([][]byte, 0, 10)
	}
	cc.CustomChainTrustRootCertsBytes[chainId] = rootCerts
}

type pubSubConfig struct {
	MaxPubMessageSize int
}

type extensionsConfig struct {
	EnablePkt          bool
	EnablePriorityCtrl bool
}
