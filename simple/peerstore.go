/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package simple

import (
	"sync"

	"chainmaker.org/chainmaker/net-liquid/core/peer"
	"chainmaker.org/chainmaker/net-liquid/core/protocol"
	"chainmaker.org/chainmaker/net-liquid/core/store"
	"chainmaker.org/chainmaker/net-liquid/core/types"
	ma "github.com/multiformats/go-multiaddr"
)

type addrList struct {
	mu sync.RWMutex
	l  []string
}

func newAddrList() *addrList {
	return &addrList{
		mu: sync.RWMutex{},
		l:  make([]string, 0),
	}
}

func (s *addrList) Append(addr ...ma.Multiaddr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ma := range addr {
		s.l = append(s.l, ma.String())
	}
}

func (s *addrList) Save(addr ...ma.Multiaddr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tempM := make(map[string]struct{})
	for i := range s.l {
		tempM[s.l[i]] = struct{}{}
	}
	for _, ma := range addr {
		addrStr := ma.String()
		if _, ok := tempM[addrStr]; !ok {
			s.l = append(s.l, ma.String())
		}
	}
}

func (s *addrList) Remove(addr ...ma.Multiaddr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.l) == 0 {
		return
	}
	res := make([]string, 0)
	m := make(map[string]struct{})
	for i := range addr {
		m[addr[i].String()] = struct{}{}
	}
	for i := range s.l {
		tmp := s.l[i]
		if _, ok := m[tmp]; !ok {
			res = append(res, tmp)
		}
	}
	s.l = res
}

func (s *addrList) List() []ma.Multiaddr {
	s.mu.RLock()
	defer s.mu.RUnlock()
	res := make([]ma.Multiaddr, len(s.l))
	for i, _ := range s.l {
		res[i] = ma.StringCast(s.l[i])
	}
	return res
}

func (s *addrList) Size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.l)
}

var _ store.AddrBook = (*addrBook)(nil)

// addrBook is a simple implementation of store.AddrBook interface.
type addrBook struct {
	book sync.Map // map[peer.ID]*addrList
}

// newAddrBook create a new addBook.
func newAddrBook() store.AddrBook {
	return &addrBook{book: sync.Map{}}
}

// AddAddr append some net addresses of peer.
func (s *addrBook) AddAddr(pid peer.ID, addr ...ma.Multiaddr) {
	list, ok := s.book.Load(pid)
	if !ok {
		l := newAddrList()
		list, ok = s.book.LoadOrStore(pid, l)
		if !ok {
			list = l
		}
	}
	for i := range addr {
		newAddr := addr[i]
		list.(*addrList).Save(newAddr)
	}
}

// SetAddrs record some addresses of peer.
// This function will clean all addresses that not in list.
func (s *addrBook) SetAddrs(pid peer.ID, addrs []ma.Multiaddr) {
	list := newAddrList()
	list.Append(addrs...)
	s.book.Store(pid, list)
}

// RemoveAddr remove some net addresses of peer.
func (s *addrBook) RemoveAddr(pid peer.ID, addr ...ma.Multiaddr) {
	list, ok := s.book.Load(pid)
	if ok {
		list.(*addrList).Remove(addr...)
	}
}

// GetFirstAddr return first net address of peer.
// If no address stored, return nil.
func (s *addrBook) GetFirstAddr(pid peer.ID) ma.Multiaddr {
	var res ma.Multiaddr
	list, ok := s.book.Load(pid)
	if ok {
		tmp := list.(*addrList).List()
		if len(tmp) > 0 {
			res = tmp[0]
		}
	}
	return res
}

// GetAddrs return all net address of peer.
func (s *addrBook) GetAddrs(pid peer.ID) []ma.Multiaddr {
	list, ok := s.book.Load(pid)
	if ok {
		return list.(*addrList).List()
	}
	return nil
}

type protocolSet struct {
	s types.Set
}

func newProtocolSet() *protocolSet {
	return &protocolSet{}
}

func (pm *protocolSet) AppendProtocol(p ...protocol.ID) {
	for i := range p {
		pm.s.Put(p[i])
	}
}

func (pm *protocolSet) RemoveProtocol(p ...protocol.ID) {
	for i := range p {
		pm.s.Remove(p[i])
	}
}

func (pm *protocolSet) ContainsProtocolsAll(p ...protocol.ID) bool {
	for i := range p {
		if !pm.s.Exist(p[i]) {
			return false
		}
	}
	return true
}

func (pm *protocolSet) ProtocolsContained(p ...protocol.ID) []protocol.ID {
	res := make([]protocol.ID, 0, len(p))
	for i := range p {
		pp := p[i]
		if pm.s.Exist(pp) {
			res = append(res, pp)
		}
	}
	return res
}

func (pm *protocolSet) All() []protocol.ID {
	res := make([]protocol.ID, 0, pm.s.Size())
	pm.s.Range(func(v interface{}) bool {
		p, _ := v.(protocol.ID)
		res = append(res, p)
		return true
	})
	return res
}

var _ store.ProtocolBook = (*protocolBook)(nil)

// protocolBook is a simple implementation of store.ProtocolBook interface.
type protocolBook struct {
	mu       sync.RWMutex
	book     map[peer.ID]*protocolSet
	localPid peer.ID
}

func (p *protocolBook) initOrGetPeerProtocolSet(pid peer.ID) *protocolSet {
	pm, ok := p.book[pid]
	if !ok {
		pm = newProtocolSet()
		p.book[pid] = pm
	}
	return pm
}

// AddProtocol append some protocols supported by peer.
func (p *protocolBook) AddProtocol(pid peer.ID, protocols ...protocol.ID) {
	p.mu.Lock()
	defer p.mu.Unlock()
	pm := p.initOrGetPeerProtocolSet(pid)
	pm.AppendProtocol(protocols...)
}

// SetProtocols record some protocols supported by peer.
// This function will clean all protocols that not in list.
func (p *protocolBook) SetProtocols(pid peer.ID, protocols []protocol.ID) {
	p.mu.Lock()
	defer p.mu.Unlock()
	pm := newProtocolSet()
	pm.AppendProtocol(protocols...)
	p.book[pid] = pm
}

// DeleteProtocol remove some protocols of peer.
func (p *protocolBook) DeleteProtocol(pid peer.ID, protocols ...protocol.ID) {
	p.mu.Lock()
	defer p.mu.Unlock()
	pm, ok := p.book[pid]
	if !ok {
		return
	}
	pm.RemoveProtocol(protocols...)
}

// ClearProtocol remove all records of peer.
func (p *protocolBook) ClearProtocol(pid peer.ID) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.book, pid)
}

// GetProtocols return protocols list of peer.
func (p *protocolBook) GetProtocols(pid peer.ID) []protocol.ID {
	p.mu.RLock()
	defer p.mu.RUnlock()
	pm, ok := p.book[pid]
	if !ok {
		return nil
	}
	return pm.All()
}

// ContainsProtocol return whether peer has supported all the protocols in list.
func (p *protocolBook) ContainsProtocol(pid peer.ID, protocol protocol.ID) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	pm, ok := p.book[pid]
	if !ok {
		return false
	}
	return pm.ContainsProtocolsAll(protocol)
}

// ProtocolContained return the list of protocols supported that was contained in the list given.
func (p *protocolBook) ProtocolContained(pid peer.ID, protocol ...protocol.ID) []protocol.ID {
	p.mu.RLock()
	defer p.mu.RUnlock()
	pm, ok := p.book[pid]
	if !ok {
		return nil
	}
	return pm.ProtocolsContained(protocol...)
}

// AllSupportProtocolPeers return the list of peer id which is the id of peers who support all protocols given.
func (p *protocolBook) AllSupportProtocolPeers(protocol ...protocol.ID) []peer.ID {
	p.mu.RLock()
	defer p.mu.RUnlock()
	res := make([]peer.ID, 0, len(p.book))
	for pid, pm := range p.book {
		if pid != p.localPid && pm.ContainsProtocolsAll(protocol...) {
			res = append(res, pid)
		}
	}
	return res
}

// newProtocolBook create a new *protocolBook instance.
func newProtocolBook(localPid peer.ID) store.ProtocolBook {
	return &protocolBook{
		book:     make(map[peer.ID]*protocolSet),
		localPid: localPid,
	}
}

var _ store.PeerStore = (*SimplePeerStore)(nil)

// SimplePeerStore is a simple implementation of store.PeerStore interface.
// It wrapped with a *protocolBook and a *addrBook.
type SimplePeerStore struct {
	store.ProtocolBook
	store.AddrBook
}

// NewSimplePeerStore create a simple store.PeerStore instance.
func NewSimplePeerStore(localPid peer.ID) store.PeerStore {
	return &SimplePeerStore{ProtocolBook: newProtocolBook(localPid), AddrBook: newAddrBook()}
}
