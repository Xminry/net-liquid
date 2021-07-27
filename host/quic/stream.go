/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package quic

import (
	"sync"
	"time"

	"chainmaker.org/chainmaker/chainmaker-net-liquid/core/network"
	"github.com/xiaotianfork/quic-go"
)

var _ network.SendStream = (*qSendStream)(nil)

type qSendStream struct {
	network.BasicStat
	qc *qConn
	qs quic.SendStream

	closeOnce sync.Once
}

func NewQSendStream(qc *qConn, qs quic.SendStream) network.SendStream {
	q := &qSendStream{
		BasicStat: *network.NewStat(network.Outbound, time.Now(), nil),
		qc:        qc,
		qs:        qs,
	}
	return q
}

func (q *qSendStream) Close() error {
	var err error
	q.closeOnce.Do(func() {
		q.SetClosed()
		err = q.qs.Close()
	})
	return err
}

func (q *qSendStream) Write(p []byte) (n int, err error) {
	return q.qs.Write(p)
}

func (q *qSendStream) Conn() network.Conn {
	return q.qc
}

var _ network.ReceiveStream = (*qReceiveStream)(nil)

type qReceiveStream struct {
	network.BasicStat
	qc *qConn
	qs quic.ReceiveStream

	closeOnce sync.Once
}

func NewQReceiveStream(qc *qConn, qs quic.ReceiveStream) network.ReceiveStream {
	q := &qReceiveStream{
		BasicStat: *network.NewStat(network.Inbound, time.Now(), nil),
		qc:        qc,
		qs:        qs,
	}
	return q
}

func (q *qReceiveStream) Close() error {
	var err error
	q.closeOnce.Do(func() {
		q.SetClosed()
		q.qs.CancelRead(ErrCodeCloseStream)
	})
	return err
}

func (q *qReceiveStream) Read(p []byte) (n int, err error) {
	return q.qs.Read(p)
}

func (q *qReceiveStream) Conn() network.Conn {
	return q.qc
}

var _ network.Stream = (*qStream)(nil)

type qStream struct {
	network.BasicStat
	qc *qConn
	qs quic.Stream

	closeOnce sync.Once
}

func NewQStream(qc *qConn, qs quic.Stream, direction network.Direction) network.Stream {
	q := &qStream{
		BasicStat: *network.NewStat(direction, time.Now(), nil),
		qc:        qc,
		qs:        qs,
	}
	return q
}

func (q *qStream) Close() error {
	var err error
	q.closeOnce.Do(func() {
		q.SetClosed()
		err = q.qs.Close()
		q.qs.CancelRead(ErrCodeCloseStream)
	})
	return err
}

func (q *qStream) Read(p []byte) (n int, err error) {
	return q.qs.Read(p)
}

func (q *qStream) Write(p []byte) (n int, err error) {
	return q.qs.Write(p)
}

func (q *qStream) Conn() network.Conn {
	return q.qc
}
