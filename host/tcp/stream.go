/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package tcp

import (
	"sync"
	"time"

	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/network"
	"github.com/libp2p/go-yamux/v2"
)

var _ network.SendStream = (*yamuxSendStream)(nil)

type yamuxSendStream struct {
	network.BasicStat
	c  *conn
	ys *yamux.Stream

	closeOnce sync.Once
}

func newSendStream(c *conn, ys *yamux.Stream) *yamuxSendStream {
	ss := &yamuxSendStream{
		BasicStat: *network.NewStat(network.Outbound, time.Now(), nil),
		c:         c,
		ys:        ys,
		closeOnce: sync.Once{},
	}
	return ss
}

func (y *yamuxSendStream) Close() error {
	var err error
	y.closeOnce.Do(func() {
		y.SetClosed()
		err = y.ys.CloseWrite()
	})
	return err
}

func (y *yamuxSendStream) Conn() network.Conn {
	return y.c
}

func (y *yamuxSendStream) Write(p []byte) (n int, err error) {
	return y.ys.Write(p)
}

var _ network.ReceiveStream = (*yamuxReceiveStream)(nil)

type yamuxReceiveStream struct {
	network.BasicStat
	c  *conn
	ys *yamux.Stream

	closeOnce sync.Once
}

func newReceiveStream(c *conn, ys *yamux.Stream) *yamuxReceiveStream {
	rs := &yamuxReceiveStream{
		BasicStat: *network.NewStat(network.Inbound, time.Now(), nil),
		c:         c,
		ys:        ys,
		closeOnce: sync.Once{},
	}
	return rs
}

func (y *yamuxReceiveStream) Close() error {
	var err error
	y.closeOnce.Do(func() {
		y.SetClosed()
		err = y.ys.CloseRead()
	})
	return err
}

func (y *yamuxReceiveStream) Conn() network.Conn {
	return y.c
}

func (y *yamuxReceiveStream) Read(p []byte) (n int, err error) {
	return y.ys.Read(p)
}

var _ network.Stream = (*yamuxStream)(nil)

type yamuxStream struct {
	network.BasicStat

	c  *conn
	ys *yamux.Stream

	closeOnce sync.Once
}

func newStream(c *conn, ys *yamux.Stream, dir network.Direction) *yamuxStream {
	s := &yamuxStream{
		BasicStat: *network.NewStat(dir, time.Now(), nil),
		c:         c,
		ys:        ys,
		closeOnce: sync.Once{},
	}
	return s
}

func (y *yamuxStream) Close() error {
	var err error
	y.closeOnce.Do(func() {
		y.SetClosed()
		err = y.ys.Close()
	})
	return err
}

func (y *yamuxStream) Conn() network.Conn {
	return y.c
}

func (y *yamuxStream) Write(p []byte) (n int, err error) {
	return y.ys.Write(p)
}

func (y *yamuxStream) Read(p []byte) (n int, err error) {
	return y.ys.Read(p)
}
