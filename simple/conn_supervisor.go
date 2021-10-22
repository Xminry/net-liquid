/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package simple

import (
	"sync"
	"sync/atomic"
	"time"

	"chainmaker.org/chainmaker/net-common/utils"
	"chainmaker.org/chainmaker/net-liquid/core/host"
	"chainmaker.org/chainmaker/net-liquid/core/mgr"
	"chainmaker.org/chainmaker/net-liquid/core/peer"
	api "chainmaker.org/chainmaker/protocol/v2"
	ma "github.com/multiformats/go-multiaddr"
)

const DefaultTryTimes = 50

var _ mgr.ConnSupervisor = (*connSupervisor)(nil)

// connSupervisor is an implementation of mgr.ConnSupervisor interface.
// connSupervisor maintains the connection state of the necessary peers.
// If a necessary peer is not connected to us, supervisor will try to dial to it.
type connSupervisor struct {
	sync.RWMutex
	once sync.Once
	host host.Host

	directPeer map[peer.ID]ma.Multiaddr

	checkTimer *time.Timer
	signalChan chan struct{}
	closeChan  chan struct{}

	logger api.Logger

	tryTimes     int
	actuators    map[peer.ID]*tryToDialActuator
	allConnected int32

	hostNotifiee *host.NotifieeBundle
}

// NewConnSupervisor create a new *connSupervisor instance.
func NewConnSupervisor(h host.Host, logger api.Logger) mgr.ConnSupervisor {
	cs := &connSupervisor{
		once:         sync.Once{},
		host:         h,
		directPeer:   make(map[peer.ID]ma.Multiaddr),
		signalChan:   make(chan struct{}, 1),
		closeChan:    nil,
		logger:       logger,
		tryTimes:     DefaultTryTimes,
		actuators:    make(map[peer.ID]*tryToDialActuator),
		allConnected: 0,
		hostNotifiee: &host.NotifieeBundle{},
	}
	cs.hostNotifiee.PeerDisconnectedFunc = cs.NoticeDisconnected
	return cs
}

// SetPeerAddr will set a peer as a necessary peer and store the peer's address.
func (c *connSupervisor) SetPeerAddr(pid peer.ID, addr ma.Multiaddr) {
	c.Lock()
	defer c.Unlock()
	c.directPeer[pid] = addr
	select {
	case c.signalChan <- struct{}{}:
	default:
	}
}

// RemoveAllPeer clean all necessary peers.
func (c *connSupervisor) RemoveAllPeer() {
	c.Lock()
	defer c.Unlock()
	c.directPeer = make(map[peer.ID]ma.Multiaddr)
}

// RemovePeerAddr will unset a necessary peer.
func (c *connSupervisor) RemovePeerAddr(pid peer.ID) {
	c.Lock()
	defer c.Unlock()
	delete(c.directPeer, pid)
}

func (c *connSupervisor) Start() error {
	c.once.Do(func() {
		c.closeChan = make(chan struct{})
		go c.loop()
		c.signalChan <- struct{}{}
		c.host.Notify(c.hostNotifiee)
	})
	return nil
}

func (c *connSupervisor) Stop() error {
	close(c.closeChan)
	c.once = sync.Once{}
	return nil
}

// NoticeDisconnected is a function called back when any peer disconnected.
// When called, supervisor will start to check connections.
func (c *connSupervisor) NoticeDisconnected(pid peer.ID) {
	c.RLock()
	if _, ok := c.directPeer[pid]; !ok {
		c.RUnlock()
		return
	}
	c.RUnlock()
	select {
	case <-c.closeChan:
	case c.signalChan <- struct{}{}:
	default:
	}
}

func (c *connSupervisor) loop() {
	c.checkTimer = time.NewTimer(5 * time.Second)
	for {
		select {
		case <-c.closeChan:
			return
		case <-c.signalChan:
			c.checkConn()
		case <-c.checkTimer.C:
			select {
			case c.signalChan <- struct{}{}:
			default:

			}
		}
	}
}

func (c *connSupervisor) checkConn() {
	c.RLock()
	defer c.RUnlock()
	allSize := len(c.directPeer)
	if allSize == 0 {
		return
	}
	curSize := 0
	necessaryPeers := c.directPeer
	for pid, addr := range necessaryPeers {
		if pid == c.host.ID() || c.host.ConnMgr().IsConnected(pid) {
			curSize++
			_, ok := c.actuators[pid]
			if ok {
				delete(c.actuators, pid)
			}
			continue
		}
		c.allConnected = 0
		ac, ok := c.actuators[pid]
		if !ok || ac.hasFinished() {
			c.actuators[pid] = newTryToDialActuator(pid, addr, c, c.tryTimes)
			ac = c.actuators[pid]
		}
		go ac.run()
	}
	select {
	case <-c.closeChan:
		return
	default:
	}
	if curSize >= allSize {
		if atomic.LoadInt32(&c.allConnected) == 0 {
			c.logger.Debugf("[ConnSupervisor][CheckConn] necessary peers count:%d, connected:%d)",
				allSize, curSize)
			c.logger.Infof("[ConnSupervisor] all necessary peers connected.")
			atomic.StoreInt32(&c.allConnected, 1)
			select {
			case c.signalChan <- struct{}{}:
			default:

			}
		}
	} else {
		c.logger.Debugf("[ConnSupervisor][CheckConn] necessary peers count:%d, connected:%d)", allSize, curSize)
		c.checkTimer.Reset(5 * time.Second)
	}
}

type tryToDialActuator struct {
	peerId     peer.ID
	peerAddr   ma.Multiaddr
	fibonacci  []int64
	idx        int
	giveUp     bool
	finishFlag int32
	statC      chan struct{}

	cs *connSupervisor
}

func newTryToDialActuator(pid peer.ID, addr ma.Multiaddr, cs *connSupervisor, tryTimes int) *tryToDialActuator {
	return &tryToDialActuator{
		peerId:     pid,
		peerAddr:   addr,
		fibonacci:  utils.FibonacciArray(tryTimes),
		idx:        0,
		giveUp:     false,
		finishFlag: 0,
		statC:      make(chan struct{}, 1),
		cs:         cs,
	}
}

func (a *tryToDialActuator) hasFinished() bool {
	return atomic.LoadInt32(&a.finishFlag) == 1
}

func (a *tryToDialActuator) finished() {
	atomic.StoreInt32(&a.finishFlag, 1)
}

func (a *tryToDialActuator) run() {
	select {
	case a.statC <- struct{}{}:
		defer func() {
			<-a.statC
		}()
	default:
		return
	}
	if a.giveUp || a.hasFinished() {
		return
	}
Loop:
	for {
		select {
		case <-a.cs.closeChan:
			break Loop
		default:

		}
		if a.cs.host.ConnMgr().IsConnected(a.peerId) {
			a.finished()
			break Loop
		}
		a.cs.logger.Infof("[ConnSupervisor] try to dial to peer(pid: %s,addr:%s)", a.peerId, a.peerAddr.String())
		conn, err := a.cs.host.Dial(a.peerAddr)
		select {
		case <-a.cs.closeChan:
			break Loop
		default:
		}
		if a.cs.host.ConnMgr().IsConnected(a.peerId) {
			a.finished()
			break Loop
		}
		if err != nil {
			a.cs.logger.Warnf("[ConnSupervisor] try to dial to peer failed(peer: %s, times: %d),%s",
				a.peerId, a.idx+1, err.Error())
			a.idx = a.idx + 1
			if a.idx >= len(a.fibonacci) {
				a.cs.logger.Warnf("[ConnSupervisor] can not dial to peer, give it up. (peer:%s)", a.peerId)
				a.giveUp = true
				break
			}
			timeout := time.Duration(a.fibonacci[a.idx]) * time.Second
			time.Sleep(timeout)
			continue Loop
		}
		if conn == nil {
			a.cs.logger.Errorf("[ConnSupervisor] try to dial to peer(pid: %s) failed, nil conn", a.peerId)
			a.idx = a.idx + 1
			if a.idx >= len(a.fibonacci) {
				a.cs.logger.Warnf("[ConnSupervisor] can not dial to peer, give it up. (peer:%s)", a.peerId)
				a.giveUp = true
				break Loop
			}
			timeout := time.Duration(a.fibonacci[a.idx]) * time.Second
			time.Sleep(timeout)
			continue Loop
		}
		if a.peerId != conn.RemotePeerID() {
			a.cs.logger.Errorf("[ConnSupervisor] try to dial to peer(pid: %s) failed, pid mismatch(got: %s), "+
				"close the connection.", a.peerId, conn.RemotePeerID())
			_ = conn.Close()
			break Loop
		}
		a.cs.logger.Debugf("[ConnSupervisor] dial to peer(pid: %s) success", a.peerId)
		a.finished()
		break Loop
	}
}
