/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package tlssupport

import (
	"context"
	"strconv"

	"chainmaker.org/chainmaker/common/v2/crypto"
	"chainmaker.org/chainmaker/common/v2/crypto/asym"
	"chainmaker.org/chainmaker/net-liquid/core/host"
	"chainmaker.org/chainmaker/net-liquid/core/peer"
	host2 "chainmaker.org/chainmaker/net-liquid/host"
	api "chainmaker.org/chainmaker/protocol/v2"
	ma "github.com/multiformats/go-multiaddr"
)

// CreateHostRandom create a host instance with random crypto.
// This method only for testing.
func CreateHostRandom(
	hostSeq int,
	ip string,
	seeds map[peer.ID]ma.Multiaddr,
	logger api.Logger) (host.Host, peer.ID, ma.Multiaddr, error) {
	privateKey, err := asym.GenerateKeyPair(crypto.RSA2048)
	if err != nil {
		return nil, "", nil, err
	}
	return CreateHostWithCrypto(hostSeq, ip, privateKey, seeds, logger)
}

// CreateHostWithCrypto create a host instance with quic network type and simple config.
func CreateHostWithCrypto(
	hostSeq int,
	ip string,
	privateKey crypto.PrivateKey,
	seeds map[peer.ID]ma.Multiaddr,
	logger api.Logger) (host.Host, peer.ID, ma.Multiaddr, error) {
	tlsCfg, loadPidFunc, err := MakeTlsConfigAndLoadPeerIdFuncWithPrivateKey(privateKey)
	if err != nil {
		return nil, "", nil, err
	}
	addrs := []ma.Multiaddr{ma.StringCast("/ip4/" + ip + "/tcp/" + strconv.Itoa(9000+hostSeq))}
	hostCfg := &host2.HostConfig{
		TlsCfg:                    tlsCfg,
		LoadPidFunc:               loadPidFunc,
		SendStreamPoolInitSize:    10,
		SendStreamPoolCap:         100,
		PeerReceiveStreamMaxCount: 100,
		ListenAddresses:           addrs,
		DirectPeers:               seeds,
		MsgCompress:               false,
		PrivateKey:                privateKey,
	}
	h, err := hostCfg.NewHost(host2.TcpNetwork, context.Background(), logger)
	if err != nil {
		return nil, "", nil, err
	}
	return h, h.ID(), addrs[0], nil
}
