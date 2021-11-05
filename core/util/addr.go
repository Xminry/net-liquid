/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"net"

	"chainmaker.org/chainmaker/net-liquid/core/peer"
	ma "github.com/multiformats/go-multiaddr"
)

const (
	pidAddrPrefix = "/p2p/"
)

// GetNetAddrAndPidFromNormalMultiAddr resolves a NetAddr and a peer.ID from addr given.
// For example,
// if addr is "/ip4/127.0.0.1/tcp/8080/p2p/QmcQHCuAXaFkbcsPUj7e37hXXfZ9DdN7bozseo5oX4qiC4",
// will return "/ip4/127.0.0.1/tcp/8080" as net addr and "QmcQHCuAXaFkbcsPUj7e37hXXfZ9DdN7bozseo5oX4qiC4" as peer.ID.
// If addr is "/ip4/127.0.0.1/tcp/8080", will return "/ip4/127.0.0.1/tcp/8080" as net addr and "" as peer.ID.
func GetNetAddrAndPidFromNormalMultiAddr(addr ma.Multiaddr) (ma.Multiaddr, peer.ID) {
	var addrMa, pidMa ma.Multiaddr
	var pid peer.ID
	addrMa, pidMa = ma.SplitFunc(addr, func(component ma.Component) bool {
		return component.Protocol().Code == ma.P_P2P
	})
	if pidMa == nil {
		return addrMa, pid
	}
	pidStr, err := pidMa.ValueForProtocol(ma.P_P2P)
	if err == nil {
		pid = peer.ID(pidStr)
	}
	return addrMa, pid
}

// GetLocalAddrs return a list of net.Addr can be used that bound in each net interfaces.
func GetLocalAddrs() ([]net.Addr, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	res := make([]net.Addr, 0)
	for _, iface := range ifaces {
		if (iface.Flags & net.FlagUp) == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}
		res = append(res, addrs...)
	}
	return res, nil
}

// CreateMultiAddrWithPid parse a peer.ID to p2p multiaddr.
// For example,
// "QmcQHCuAXaFkbcsPUj7e37hXXfZ9DdN7bozseo5oX4qiC4" -->> "/p2p/QmcQHCuAXaFkbcsPUj7e37hXXfZ9DdN7bozseo5oX4qiC4"
func CreateMultiAddrWithPid(pid peer.ID) ma.Multiaddr {
	return ma.StringCast(pidAddrPrefix + pid.ToString())
}

// CreateMultiAddrWithPidAndNetAddr will parse the peer.ID to p2p multiaddr then join the net addr with it.
// For example,
// "QmcQHCuAXaFkbcsPUj7e37hXXfZ9DdN7bozseo5oX4qiC4" & "/ip4/127.0.0.1/tcp/8080"
// -->> "/ip4/127.0.0.1/tcp/8080/p2p/QmcQHCuAXaFkbcsPUj7e37hXXfZ9DdN7bozseo5oX4qiC4"
func CreateMultiAddrWithPidAndNetAddr(pid peer.ID, netAddr ma.Multiaddr) ma.Multiaddr {
	return ma.Join(netAddr, CreateMultiAddrWithPid(pid))
}
