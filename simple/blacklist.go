/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package simple

import (
	"net"
	"strings"

	"chainmaker.org/chainmaker/net-liquid/core/blacklist"
	"chainmaker.org/chainmaker/net-liquid/core/network"
	"chainmaker.org/chainmaker/net-liquid/core/peer"
	"chainmaker.org/chainmaker/net-liquid/core/types"
)

var _ blacklist.BlackList = (*simpleBlacklist)(nil)

// simpleBlacklist is an implementation of blacklist.Blacklist interface.
type simpleBlacklist struct {
	ipAndPort *types.StringSet
	peerIds   *types.PeerIdSet
}

// NewBlackList create a new *simpleBlacklist instance.
func NewBlackList() blacklist.BlackList {
	return &simpleBlacklist{
		ipAndPort: &types.StringSet{},
		peerIds:   &types.PeerIdSet{},
	}
}

// AddPeer append a peer id to blacklist.
func (s *simpleBlacklist) AddPeer(pid peer.ID) {
	s.peerIds.Put(pid)
}

// RemovePeer delete a peer id from blacklist. If pid not exist in blacklist, it is a no-op.
func (s *simpleBlacklist) RemovePeer(pid peer.ID) {
	s.peerIds.Remove(pid)
}

func (s *simpleBlacklist) checkIpAndPort(ipAndPort string) (bool, string) {
	_, _, err := net.SplitHostPort(ipAndPort)
	if err == nil {
		return true, ipAndPort
	}
	// not ip+port
	// whether only ip
	_, _, err = net.SplitHostPort(ipAndPort + ":80")
	if err == nil {
		return true, ipAndPort
	}
	// maybe an ip of v6 ?
	newIp := "[" + ipAndPort + "]"
	_, _, err = net.SplitHostPort(newIp + ":80")
	if err == nil {
		return true, newIp
	}
	return false, ""
}

// AddIPAndPort append a string contains an ip or a net.Addr string with an ip and a port to blacklist.
// The string should be in the following format:
// "192.168.1.2:9000" or "192.168.1.2" or "[::1]:9000" or "[::1]"
func (s *simpleBlacklist) AddIPAndPort(ipAndPort string) {
	var bl bool
	bl, ipAndPort = s.checkIpAndPort(ipAndPort)
	if bl {
		s.ipAndPort.Put(ipAndPort)
	}
}

// RemoveIPAndPort delete a string contains an ip or a net.Addr string with an ip and a port from blacklist.
// If the string not exist in blacklist, it is a no-op.
func (s *simpleBlacklist) RemoveIPAndPort(ipAndPort string) {
	var bl bool
	bl, ipAndPort = s.checkIpAndPort(ipAndPort)
	if bl {
		s.ipAndPort.Remove(ipAndPort)
	}
}

// IsBlack check whether the remote peer id or the remote net address of the connection given exist in blacklist.
func (s *simpleBlacklist) IsBlack(conn network.Conn) bool {
	if conn == nil {
		return false
	}
	remotePid := conn.RemotePeerID()
	if s.peerIds.Exist(remotePid) {
		return true
	}
	netAddrStr := conn.RemoteNetAddr().String()
	if s.ipAndPort.Exist(netAddrStr) {
		return true
	}
	ip6 := strings.Contains(netAddrStr, "[")
	ip, _, err2 := net.SplitHostPort(netAddrStr)
	if err2 != nil {
		return false
	}
	if ip6 {
		ip = "[" + ip + "]"
	}
	if s.ipAndPort.Exist(ip) {
		return true
	}
	return false
}
