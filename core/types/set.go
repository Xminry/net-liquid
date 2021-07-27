package types

import (
	"sync"
	"sync/atomic"

	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/network"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/peer"
)

type Set struct {
	size int32
	m    sync.Map
}

func (s *Set) Put(v interface{}) bool {
	_, ok := s.m.LoadOrStore(v, struct{}{})
	if !ok {
		atomic.AddInt32(&s.size, 1)
	}
	return !ok
}

func (s *Set) Remove(v interface{}) bool {
	_, ok := s.m.LoadAndDelete(v)
	if ok {
		atomic.AddInt32(&s.size, -1)
	}
	return ok
}

func (s *Set) Exist(v interface{}) bool {
	_, ok := s.m.Load(v)
	return ok
}

func (s *Set) Range(f func(v interface{}) bool) {
	s.m.Range(func(key, _ interface{}) bool {
		return f(key)
	})
}

func (s *Set) Size() int {
	return int(atomic.LoadInt32(&s.size))
}

type Uint64Set struct {
	s Set
}

func (us *Uint64Set) Put(v uint64) bool {
	return us.s.Put(v)
}

func (us *Uint64Set) Remove(v uint64) bool {
	return us.s.Remove(v)
}

func (us *Uint64Set) Exist(v uint64) bool {
	return us.s.Exist(v)
}

func (us *Uint64Set) Size() int {
	return us.s.Size()
}

func (us *Uint64Set) Range(f func(v uint64) bool) {
	us.s.Range(func(v interface{}) bool {
		uv, _ := v.(uint64)
		return f(uv)
	})
}

type StringSet struct {
	s Set
}

func (ss *StringSet) Put(str string) bool {
	return ss.s.Put(str)
}

func (ss *StringSet) Remove(str string) bool {
	return ss.s.Remove(str)
}

func (ss *StringSet) Exist(str string) bool {
	return ss.s.Exist(str)
}

func (ss *StringSet) Size() int {
	return ss.s.Size()
}

func (ss *StringSet) Range(f func(str string) bool) {
	ss.s.Range(func(v interface{}) bool {
		uv, _ := v.(string)
		return f(uv)
	})
}

type PeerIdSet struct {
	s Set
}

func (ps *PeerIdSet) Put(pid peer.ID) bool {
	return ps.s.Put(pid)
}

func (ps *PeerIdSet) Remove(pid peer.ID) bool {
	return ps.s.Remove(pid)
}

func (ps *PeerIdSet) Exist(pid peer.ID) bool {
	return ps.s.Exist(pid)
}

func (ps *PeerIdSet) Size() int {
	return ps.s.Size()
}

func (ps *PeerIdSet) Range(f func(pid peer.ID) bool) {
	ps.s.Range(func(v interface{}) bool {
		uv, _ := v.(peer.ID)
		return f(uv)
	})
}

type ConnSet struct {
	s Set
}

func (cs *ConnSet) Put(conn network.Conn) bool {
	return cs.s.Put(conn)
}

func (cs *ConnSet) Remove(conn network.Conn) bool {
	return cs.s.Remove(conn)
}

func (cs *ConnSet) Exist(conn network.Conn) bool {
	return cs.s.Exist(conn)
}

func (cs *ConnSet) Size() int {
	return cs.s.Size()
}

func (cs *ConnSet) Range(f func(conn network.Conn) bool) {
	cs.s.Range(func(v interface{}) bool {
		uv, _ := v.(network.Conn)
		return f(uv)
	})
}
