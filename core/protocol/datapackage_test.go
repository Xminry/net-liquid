/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package protocol

import (
	"bytes"
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestPackage(t *testing.T) {
	payload := []byte("Hello world!")
	pkg := NewPackage(TestingPID, payload)
	pkgBytes, err := pkg.ToBytes(false)
	require.Nil(t, err)
	//require.True(t, bytes.Equal(pkgBytes, []byte{10, 9, 47, 95, 116, 101, 115, 116, 105, 110, 103, 18, 12, 72, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100, 33}))
	pkg2 := &Package{}
	err = pkg2.FromBytes(pkgBytes)
	require.Nil(t, err)
	require.Equal(t, TestingPID, pkg2.ProtocolID())
	require.True(t, bytes.Equal(payload, pkg2.Payload()))

	pkgBytes3, err := pkg.ToBytes(true)
	require.Nil(t, err)
	//require.True(t, bytes.Equal(pkgBytes3, []byte{10, 9, 47, 95, 116, 101, 115, 116, 105, 110, 103, 18, 40, 31, 139, 8, 0, 0, 0, 0, 0, 4, 255, 0, 12, 0, 243, 255, 72, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100, 33, 1, 0, 0, 255, 255, 149, 25, 133, 27, 12, 0, 0, 0, 24, 1}))
	pkg3 := &Package{}
	err = pkg3.FromBytes(pkgBytes3)
	require.Nil(t, err)
	require.Equal(t, TestingPID, pkg3.ProtocolID())
	require.True(t, bytes.Equal(payload, pkg3.Payload()))
}

func TestPackageToBytesBenchmark(t *testing.T) {
	count := 10000000
	payload := []byte("Hello world!")
	pkg := NewPackage(TestingPID, payload)

	startTime := time.Now()
	for i := 0; i < count; i++ {
		_, _ = pkg.ToBytes(false)
	}
	endTime := time.Now()
	useTime := endTime.Sub(startTime)
	useMilSec := useTime.Milliseconds()
	fmt.Printf("use time:%d ms \n", useMilSec)
	timeAvg := float64(useMilSec) / float64(count)
	timeAvg = math.Round(timeAvg)
	fmt.Printf("avg time:%f ms \n", timeAvg)
	tps := float64(count) / useTime.Seconds()
	fmt.Printf("tps:%f  \n", tps)
}

func TestPackageFromBytesBenchmark(t *testing.T) {
	count := 10000000
	payload := []byte("Hello world!")
	pkg := NewPackage(TestingPID, payload)
	bytes, _ := pkg.ToBytes(false)
	startTime := time.Now()
	for i := 0; i < count; i++ {
		pkg2 := &Package{}
		_ = pkg2.FromBytes(bytes)
	}
	endTime := time.Now()
	useTime := endTime.Sub(startTime)
	useMilSec := useTime.Milliseconds()
	fmt.Printf("use time:%d ms \n", useMilSec)
	timeAvg := float64(useMilSec) / float64(count)
	timeAvg = math.Round(timeAvg)
	fmt.Printf("avg time:%f ms \n", timeAvg)
	tps := float64(count) / useTime.Seconds()
	fmt.Printf("tps:%f  \n", tps)
}
