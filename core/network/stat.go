/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package network

import (
	"sync/atomic"
	"time"
)

// Direction of a connection or a stream.
type Direction int

const (
	// Unknown is the default direction.
	Unknown Direction = iota
	// Inbound is for when the remote peer initiated a connection.
	Inbound
	// Outbound is for when the local peer initiated a connection.
	Outbound
)

func (d Direction) String() string {
	str := []string{"Unknown", "Inbound", "Outbound"}
	if d < 0 || int(d) >= len(str) {
		return "[unrecognized]"
	}
	return str[d]
}

// Stat is an interface for storing metadata of a Conn or a Stream.
type Stat interface {
	Direction() Direction
	EstablishedTime() time.Time
	Extra() map[interface{}]interface{}
	SetClosed()
	IsClosed() bool
}

// BasicStat stores metadata of a Conn or a Stream.
type BasicStat struct {
	// direction specifies whether this is an inbound or an outbound connection.
	direction Direction
	// establishedTime is the timestamp when this connection was established.
	establishedTime time.Time
	// closed specifies whether this connection has been closed. 0 means open, 1 means closed
	closed int32
	// extra stores other metadata of this connection.
	extra map[interface{}]interface{}
}

// NewStat create a new BasicStat instance.
func NewStat(direction Direction, establishedTime time.Time, extra map[interface{}]interface{}) *BasicStat {
	return &BasicStat{direction: direction, establishedTime: establishedTime, closed: 0, extra: extra}
}

func (s *BasicStat) Direction() Direction {
	return s.direction
}

func (s *BasicStat) EstablishedTime() time.Time {
	return s.establishedTime
}

func (s *BasicStat) Extra() map[interface{}]interface{} {
	return s.extra
}

func (s *BasicStat) SetClosed() {
	atomic.StoreInt32(&s.closed, 1)
}

func (s *BasicStat) IsClosed() bool {
	return atomic.LoadInt32(&s.closed) == 1
}
