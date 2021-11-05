/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package types

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewFIFOCache(t *testing.T) {
	NewFIFOCache(20, false)
	NewFIFOCache(20, true)
}

func TestFIFOCachePutAndGetAndRemoveAndSizeAndExist(t *testing.T) {
	c := NewFIFOCache(20, false)
	v := c.Get(1)
	require.Nil(t, v)
	c.Put(1, 1)
	v = c.Get(1)
	require.NotNil(t, v)
	require.True(t, v.(int) == 1)
	require.True(t, c.Size() == 1)
	require.True(t, c.Exist(1))
	require.True(t, !c.Exist(2))
	v = c.Get(2)
	require.Nil(t, v)
	c.Put(2, 2)
	require.True(t, c.Exist(2))
	require.True(t, c.Size() == 2)
	c.Remove(1)
	require.True(t, !c.Exist(1))
	require.True(t, c.Size() == 1)
	c.Put(2, 4)
	v = c.Get(2)
	require.NotNil(t, v)
	require.True(t, v.(int) == 4)
	c.PutIfNotExist(2, 2)
	v = c.Get(2)
	require.NotNil(t, v)
	require.True(t, v.(int) == 4)
}

func TestFIFOCacheEntryOut(t *testing.T) {
	c := NewFIFOCache(1, false)
	c.Put(1, 1)
	c.Put(2, 2)
	require.True(t, c.Size() == 1)
	v := c.Get(1)
	require.Nil(t, v)
	v = c.Get(2)
	require.NotNil(t, v)
	require.True(t, v.(int) == 2)
}

/*func TestFIFOCacheBenchmark(t *testing.T) {
	c := NewFIFOCache(100, true)
	count := 30000000
	println("testing put...")
	startTime := time.Now()
	for i := 0; i < count; i++ {
		//c.Put(i,i)
		c.PutIfNotExist(i, i)
	}
	endTime := time.Now()
	useTime := endTime.Sub(startTime)
	useMillisec := useTime.Milliseconds()
	timeAvg := float64(useMillisec) / float64(count)
	timeAvg = math.Round(timeAvg)
	fmt.Printf("time avg:%vms \n", timeAvg)
	tps := float64(count) / useTime.Seconds()
	fmt.Printf("tps:%f  \n", tps)
}*/
