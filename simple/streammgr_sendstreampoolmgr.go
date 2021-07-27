package simple

import (
	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/mgr"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/network"
	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/peer"
	api "chainmaker.org/chainmaker/protocol"

	"errors"
	"sync"
)

var (
	// ErrConnExist will be returned when connection already exist.
	ErrConnExist = errors.New("conn exist")
	// ErrConnNotExist will be returned if connection not exist.
	ErrConnNotExist = errors.New("conn not exist")
)

var _ mgr.SendStreamPoolManager = (*sendStreamPoolManager)(nil)

type sendStreamPoolManager struct {
	mu    sync.RWMutex
	poolM map[peer.ID]map[network.Conn]mgr.SendStreamPool

	connMgr mgr.ConnMgr
	log     api.Logger
}

// NewSendStreamPoolManager create a simple implementation instance of mgr.SendStreamPoolManager interface.
func NewSendStreamPoolManager(connMgr mgr.ConnMgr, log api.Logger) mgr.SendStreamPoolManager {
	return &sendStreamPoolManager{
		poolM:   make(map[peer.ID]map[network.Conn]mgr.SendStreamPool),
		connMgr: connMgr,
		log:     log}
}

// Reset the manager.
func (s *sendStreamPoolManager) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.poolM = make(map[peer.ID]map[network.Conn]mgr.SendStreamPool)
}

// AddPeerConnSendStreamPool append a stream pool for a connection of peer.
func (s *sendStreamPoolManager) AddPeerConnSendStreamPool(
	pid peer.ID, conn network.Conn, streamPool mgr.SendStreamPool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.poolM[pid]
	if !ok {
		m = make(map[network.Conn]mgr.SendStreamPool)
		s.poolM[pid] = m
	}
	_, ok2 := m[conn]
	if ok2 {
		return ErrConnExist
	}
	m[conn] = streamPool
	return nil
}

// RemovePeerConnAndCloseSendStreamPool remove a connection of peer and close the stream pool for it.
func (s *sendStreamPoolManager) RemovePeerConnAndCloseSendStreamPool(pid peer.ID, conn network.Conn) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.poolM[pid]
	if !ok {
		return ErrConnNotExist
	}
	p, ok := m[conn]
	if !ok {
		return ErrConnNotExist
	}
	delete(m, conn)
	if len(m) <= 0 {
		delete(s.poolM, pid)
	}
	return p.Close()
}

// GetPeerBestConnSendStreamPool return a stream pool for the best connection of peer.
func (s *sendStreamPoolManager) GetPeerBestConnSendStreamPool(pid peer.ID) mgr.SendStreamPool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m, ok := s.poolM[pid]
	if !ok {
		return nil
	}
	var res mgr.SendStreamPool
	var idleSize int
	for _, pool := range m {
		idle := pool.IdleSize()
		if idleSize <= idle {
			res = pool
			idleSize = idle
		}
	}
	if res == nil {
		return res
	}
	if res.CurrentSize() >= res.MaxSize()/2 && res.IdleSize() < res.CurrentSize()/2 {
		// try to establish a new connection
		s.connMgr.ExpendConn(pid)
	}
	return res
}
