/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package simple

import (
	"strconv"
	"sync"
	"testing"
	"time"

	"chainmaker.org/chainmaker/net-liquid/core/network"
	"chainmaker.org/chainmaker/net-liquid/core/peer"
	"chainmaker.org/chainmaker/net-liquid/logger"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"
)

func TestSendStreamPoolExpand(t *testing.T) {

	var zero int32 = 0
	var poolSize int32 = 10
	var poolCapacity int32 = 20
	var threshold = 4

	stub := connStub{}
	streamPool, err := NewSimpleStreamPool(poolSize, poolCapacity, &stub, nil, logger.NilLogger)
	require.Nil(t, err, "new stream pool error")
	require.NotNil(t, streamPool, "new stream pool error, stream is nil")
	require.True(t, int(poolCapacity) == streamPool.MaxSize())
	require.Equal(t, int(zero), streamPool.CurrentSize(), "pool size is not zero")

	err = streamPool.InitStreams()
	require.Nil(t, err, "new stream pool error")
	require.Equal(t, int(poolSize), streamPool.CurrentSize(), "pool size is not"+strconv.Itoa(int(poolSize)))

	//expand
	for i := int32(0); i < poolSize+1; i++ {
		_, err = streamPool.BorrowStream()
		require.Nil(t, err, "borrow stream error")
	}

	require.GreaterOrEqual(t, streamPool.IdleSize(), threshold)
}

func TestSendStreamPoolClose(t *testing.T) {

	var poolSize int32 = 10
	var poolCapacity int32 = 20

	stub := connStub{}
	streamPool, err := NewSimpleStreamPool(poolSize, poolCapacity, &stub, nil, logger.NilLogger)
	require.Nil(t, err, "new stream pool error")
	err = streamPool.Close()
	require.Nil(t, err, "close chain error")
	stream, err := streamPool.BorrowStream()
	require.Nil(t, stream, "chain has close, borrow stream should fail")
	require.NotNil(t, err, "chain has close, borrow stream should return err")
	require.Equal(t, err, ErrStreamPoolClosed)
}

func TestSendStreamPoolReturnStream(t *testing.T) {
	var poolSize int32 = 10
	var poolCapacity int32 = 20
	stub := connStub{}
	streamPool, err := NewSimpleStreamPool(poolSize, poolCapacity, &stub, nil, logger.NilLogger)
	require.Nil(t, err, "new stream pool error")
	err = streamPool.InitStreams()
	require.Nil(t, err, "new stream pool error")
	require.Equal(t, int(poolSize), streamPool.CurrentSize(), "pool size is not"+strconv.Itoa(int(poolSize)))

	stream, err := streamPool.BorrowStream()
	require.Nil(t, err, "borrow stream error")

	err = streamPool.ReturnStream(stream)
	require.Nil(t, err, "return stream error")
	require.Equal(t, int(poolSize), streamPool.IdleSize(), "idle size is not"+strconv.Itoa(int(poolSize)))
}

func TestSendStreamPoolBorrowStreamOverCapacity(t *testing.T) {
	var poolSize int32 = 10
	var poolCapacity int32 = 20
	stub := connStub{}
	streamPool, err := NewSimpleStreamPool(poolSize, poolCapacity, &stub, nil, logger.NilLogger)
	require.Nil(t, err, "new stream pool error")
	err = streamPool.InitStreams()
	require.Nil(t, err, "new stream pool error")
	require.Equal(t, int(poolSize), streamPool.CurrentSize(),
		"pool size is not %d", strconv.Itoa(int(poolSize)))
	for i := int32(0); i < poolCapacity; i++ {
		_, err = streamPool.BorrowStream()
		if err != nil {
			i--
		}
	}
	stream, err := streamPool.BorrowStream()
	require.Nil(t, stream, "stream pool current stream count have reach limit, should return nil")
	require.NotNil(t, err, "lend stream count grater than pool capacity should return err")
}

func TestSendStreamPoolBenchmark(t *testing.T) {
	var poolSize int32 = 10
	var poolCapacity int32 = 100
	times := 1000000
	goroutineCount := 100
	stub := connStub{}
	streamPool, err := NewSimpleStreamPool(poolSize, poolCapacity, &stub, nil, logger.NewLogPrinter("Test_Expand"))
	require.Nil(t, err, "new stream pool error")
	err = streamPool.InitStreams()
	require.Nil(t, err, "init stream pool error")
	require.Equal(t, int(poolSize), streamPool.CurrentSize(),
		"pool size is not ", strconv.Itoa(int(poolSize)))
	var wg sync.WaitGroup
	wg.Add(goroutineCount)
	startTime := time.Now()
	for i := 0; i < goroutineCount; i++ {
		go func() {
			for j := 0; j < times/goroutineCount; j++ {
				stream, e := streamPool.BorrowStream()
				require.Nil(t, e)
				e = streamPool.ReturnStream(stream)
				require.Nil(t, e)
			}
			wg.Done()
		}()
	}
	wg.Wait()
	endTime := time.Now()
	useTime := endTime.Sub(startTime).Milliseconds()
	println("use time:", useTime, " ms")
	println("tps:", int64(times)*1000/useTime)
}

func TestUseStreamPoolDynamic(t *testing.T) {
	var poolSize int32 = 10
	var poolCapacity int32 = 100

	// verify stream pool variable
	// 20 goroutine
	// 10 borrow, every borrow 1000
	// 10 return, get stream from streamCache and return to pool

	goroutineCount := 200

	borrowCount := 1000

	stub := connStub{}
	streamPool, err := NewSimpleStreamPool(poolSize, poolCapacity, &stub, nil, logger.NewLogPrinter("Test_Expand"))
	require.Nil(t, err)
	err = streamPool.InitStreams()
	require.Nil(t, err)
	defer streamPool.Close()

	require.Nil(t, err, "new stream pool error")
	streamCache := make(chan network.SendStream, poolCapacity*2)

	waitReturnGroup := sync.WaitGroup{}
	waitReturnGroup.Add(goroutineCount * borrowCount)
	//return stream
	go func() {
		for {
			s := <-streamCache
			e := streamPool.ReturnStream(s)
			if e == nil {
				waitReturnGroup.Done()
			}
		}
	}()

	//borrow stream
	for i := 0; i < goroutineCount; i++ {
		go func(num int) {
			for j := 0; j < borrowCount; j++ {
				stream, borrowErr := streamPool.BorrowStream()
				if borrowErr != nil {
					j--
				} else {
					streamCache <- stream
				}
			}
		}(i)
	}

	waitReturnGroup.Wait()

	//verify
	require.Equal(t, int(poolCapacity), streamPool.MaxSize(),
		"stream pool capacity shold be [%d], actual: [%d]", poolCapacity, streamPool.MaxSize())
	require.Equal(t, int(poolCapacity), streamPool.IdleSize(),
		"stream pool idle size shold be [%d], actual: [%d]", poolCapacity, streamPool.IdleSize())
	require.Equal(t, int(poolCapacity), streamPool.CurrentSize(),
		"stream pool current size shold be [%d], actual: [%d]", poolCapacity, streamPool.CurrentSize())
}

var _ network.Conn = (*connStub)(nil)

type connStub struct {
}

func (stub *connStub) Close() error {
	return nil
}

func (stub *connStub) Direction() network.Direction {
	panic("implement me")
}

func (stub *connStub) EstablishedTime() time.Time {
	panic("implement me")
}

func (stub *connStub) Extra() map[interface{}]interface{} {
	panic("implement me")
}

func (stub *connStub) SetClosed() {
	panic("implement me")
}

func (stub *connStub) IsClosed() bool {
	panic("implement me")
}

func (stub *connStub) LocalAddr() ma.Multiaddr {
	panic("implement me")
}

func (stub *connStub) LocalPeerID() peer.ID {
	panic("implement me")
}

func (stub *connStub) RemoteAddr() ma.Multiaddr {
	panic("implement me")
}

func (stub *connStub) RemotePeerID() peer.ID {
	return ""
}

func (stub *connStub) Network() network.Network {
	panic("implement me")
}

func (stub *connStub) CreateSendStream() (network.SendStream, error) {
	return &streamStub{conn: stub}, nil
}

func (stub *connStub) AcceptReceiveStream() (network.ReceiveStream, error) {
	panic("implement me")
}

func (stub *connStub) CreateBidirectionalStream() (network.Stream, error) {
	panic("implement me")
}

func (stub *connStub) AcceptBidirectionalStream() (network.Stream, error) {
	panic("implement me")
}

func (stub *connStub) NewSendStream() (network.SendStream, error) {
	stream := &streamStub{
		conn: stub,
	}
	return stream, nil
}

var _ network.SendStream = (*streamStub)(nil)

type streamStub struct {
	conn network.Conn
}

func (s streamStub) Close() error {
	return nil
}

func (s streamStub) Direction() network.Direction {
	panic("implement me")
}

func (s streamStub) EstablishedTime() time.Time {
	panic("implement me")
}

func (s streamStub) Extra() map[interface{}]interface{} {
	panic("implement me")
}

func (s streamStub) SetClosed() {
	panic("implement me")
}

func (s streamStub) IsClosed() bool {
	panic("implement me")
}

func (s streamStub) Conn() network.Conn {
	panic("implement me")
}

func (s streamStub) Write(p []byte) (n int, err error) {
	panic("implement me")
}
