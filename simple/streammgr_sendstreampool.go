/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package simple

import (
	"errors"
	"math"
	"sync"
	"sync/atomic"

	"chainmaker.org/chainmaker/net-liquid/core/host"
	"chainmaker.org/chainmaker/net-liquid/core/mgr"
	"chainmaker.org/chainmaker/net-liquid/core/network"
	api "chainmaker.org/chainmaker/protocol/v2"
)

var (
	// ErrStreamPoolClosed will be returned if stream pool closed.
	ErrStreamPoolClosed = errors.New("stream pool closed")
	// ErrNoStreamCanBeBorrowed will be returned if no stream can be borrowed.
	ErrNoStreamCanBeBorrowed = errors.New("no stream can be borrowed")
	sendStreamPoolSeq        uint64
)

var _ mgr.SendStreamPool = (*sendStreamPool)(nil)

// sendStreamPool is an implementation of mgr.SendStreamPool interface.
type sendStreamPool struct {
	once        sync.Once
	host        host.Host
	conn        network.Conn
	initSize    int32
	cap         int32
	idleSize    int32
	currentSize int32
	pool        chan network.SendStream

	expandingSignalChan chan struct{}
	idlePercentage      float64
	closeChan           chan struct{}

	seq uint64
	log api.Logger
}

// NewSimpleStreamPool create a new simple mgr.SendStreamPool instance.
func NewSimpleStreamPool(
	initSize, cap int32, conn network.Conn, host host.Host, log api.Logger) (mgr.SendStreamPool, error) {
	if initSize >= cap {
		return nil, errors.New("init size must be smaller than cap")
	}
	return &sendStreamPool{
		once:                sync.Once{},
		host:                host,
		conn:                conn,
		initSize:            initSize,
		cap:                 cap,
		idleSize:            0,
		currentSize:         0,
		pool:                make(chan network.SendStream, cap),
		expandingSignalChan: make(chan struct{}, 1),
		idlePercentage:      0.2,
		closeChan:           make(chan struct{}),
		seq:                 atomic.AddUint64(&sendStreamPoolSeq, 1),
		log:                 log,
	}, nil
}

// Conn return the connection which send streams created by.
func (s *sendStreamPool) Conn() network.Conn {
	return s.conn
}

// InitStreams will open few send streams with the connection.
func (s *sendStreamPool) InitStreams() error {
	var err error
	s.once.Do(func() {
		for i := 0; i < int(s.initSize) && atomic.LoadInt32(&s.currentSize) < s.initSize; i++ {
			stream, e := s.conn.CreateSendStream()
			if e != nil {
				err = e
				return
			}
			s.pool <- stream
			atomic.AddInt32(&s.idleSize, 1)
			atomic.AddInt32(&s.currentSize, 1)
		}
		s.log.Infof("[SendStreamPool] init streams finished.(seq: %d, init-size: %d, remote pid: %s)",
			s.seq, s.initSize, s.conn.RemotePeerID())
		go s.expandLoop()
	})
	return err
}

// BorrowStream get a sending stream from send stream queue in pool.
// The stream borrowed should be return to this pool after sending data success,
// or should be dropped by invoking DropStream method when errors found in sending data process.
func (s *sendStreamPool) BorrowStream() (network.SendStream, error) {
	_ = s.InitStreams()
	var (
		stream network.SendStream
	)
	select {
	case <-s.closeChan:
		return nil, ErrStreamPoolClosed
	case stream = <-s.pool:
		atomic.AddInt32(&s.idleSize, -1)
		s.triggerExpand()
		return stream, nil
	default:
		if s.CurrentSize() >= s.MaxSize() {
			return nil, ErrNoStreamCanBeBorrowed
		}
		select {
		case <-s.closeChan:
			return nil, ErrStreamPoolClosed
		case stream = <-s.pool:
			atomic.AddInt32(&s.idleSize, -1)
			s.triggerExpand()
			return stream, nil
		}
	}
}

func (s *sendStreamPool) triggerExpand() {
	select {
	case <-s.closeChan:
	case s.expandingSignalChan <- struct{}{}:
	default:
	}
}

func (s *sendStreamPool) expandLoop() {
	for {
		select {
		case <-s.closeChan:
			return
		case <-s.expandingSignalChan:
			if s.needExpand() {
				expandSize := s.initSize / 2
				if expandSize == 0 {
					expandSize = 1
				}
				s.log.Debugf("[SendStreamPool] expanding started."+
					"(seq: %d, expand: %d, cap: %d, current: %d, idle: %d, pid: %s)",
					s.seq, expandSize, s.cap, atomic.LoadInt32(&s.currentSize),
					atomic.LoadInt32(&s.idleSize), s.conn.RemotePeerID())
				if expandSize+atomic.LoadInt32(&s.currentSize) > s.cap {
					expandSize = s.cap - atomic.LoadInt32(&s.currentSize)
				}
				temp := 0
				for i := 0; i < int(expandSize); i++ {
					stream, e := s.conn.CreateSendStream()
					if e != nil {
						if s.host.CheckClosedConnWithErr(s.conn, e) {
							s.log.Errorf("[SendStreamPool] expanding failed, connection closed."+
								"(seq: %d, expand: %d, cap: %d, current: %d, idle: %d, pid: %s)",
								s.seq, temp, s.cap, atomic.LoadInt32(&s.currentSize),
								atomic.LoadInt32(&s.idleSize), s.conn.RemotePeerID())
							_ = s.Close()
							return
						}
						s.log.Errorf("[SendStreamPool] create send stream failed, %s", e.Error())
						continue
					}
					s.pool <- stream
					atomic.AddInt32(&s.idleSize, 1)
					atomic.AddInt32(&s.currentSize, 1)
					temp++
				}
				s.log.Infof("[SendStreamPool] expanding finished."+
					"(seq: %d, expand: %d, cap: %d, current: %d, idle: %d, pid: %s)",
					s.seq, temp, s.cap, atomic.LoadInt32(&s.currentSize),
					atomic.LoadInt32(&s.idleSize), s.conn.RemotePeerID())
				s.triggerExpand()
			}
		}
	}
}

func (s *sendStreamPool) needExpand() bool {
	threshold := s.expandingThreshold()
	if threshold >= atomic.LoadInt32(&s.idleSize) && atomic.LoadInt32(&s.currentSize) < s.cap {
		return true
	}
	return false
}

func (s *sendStreamPool) expandingThreshold() int32 {
	return int32(math.Round(s.idlePercentage * float64(atomic.LoadInt32(&s.currentSize))))
}

// ReturnStream return a sending stream borrowed from this pool before.
func (s *sendStreamPool) ReturnStream(stream network.SendStream) error {
	select {
	case <-s.closeChan:
		return ErrStreamPoolClosed
	case s.pool <- stream:
		atomic.AddInt32(&s.idleSize, 1)
	default:
		_ = stream.Close()
	}
	return nil
}

// DropStream will close the sending stream then drop it.
// This method should be invoked only when errors found.
func (s *sendStreamPool) DropStream(stream network.SendStream) {
	_ = stream.Close()
	if atomic.AddInt32(&s.currentSize, -1) < 0 {
		atomic.AddInt32(&s.currentSize, 1)
	}
}

// Close the SendStreamPool.
func (s *sendStreamPool) Close() error {
	select {
	case <-s.closeChan:
		return nil
	default:

	}
	close(s.closeChan)
Loop:
	for {
		select {
		case stream := <-s.pool:
			s.DropStream(stream)
		default:
			break Loop
		}
	}
	atomic.StoreInt32(&s.currentSize, 0)
	atomic.StoreInt32(&s.idleSize, 0)
	return nil
}

// MaxSize return cap of this pool.
func (s *sendStreamPool) MaxSize() int {
	return int(atomic.LoadInt32(&s.cap))
}

// CurrentSize return current size of this pool.
func (s *sendStreamPool) CurrentSize() int {
	return int(atomic.LoadInt32(&s.currentSize))
}

// IdleSize return current count of idle send stream.
func (s *sendStreamPool) IdleSize() int {
	return int(atomic.LoadInt32(&s.idleSize))
}
