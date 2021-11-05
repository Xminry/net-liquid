/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package types

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type pTest struct {
	id   string
	name string
	age  int
}

func TestNewFixDurationCacheLength(t *testing.T) {
	maxLength := 1
	cache := NewFixedCapDurationCache(time.Second*100, maxLength)
	assert.Equal(t, 0, cache.Length())
	v1 := pTest{id: "1", name: "1", age: 1}
	cache.Add(v1.id, v1)
	assert.Equal(t, 1, cache.Length())
	v2 := pTest{id: "2", name: "2", age: 2}
	cache.Add(v2.id, v2)
	assert.Equal(t, 1, cache.Length())
	v3 := pTest{id: "3", name: "3", age: 3}
	cache.Add(v3.id, v3)
	assert.Equal(t, 1, cache.Length())
	v3FromCache := cache.GetByKey("3").(pTest)
	assert.NotNil(t, v3FromCache)

	assert.NotNil(t, cache)
}

func TestNewFixDurationCache(t *testing.T) {
	maxLength := 10000
	cache := NewFixedCapDurationCache(time.Second*100, maxLength)

	assert.NotNil(t, cache)
}

func TestExistsAndExpire(t *testing.T) {
	duration := time.Millisecond * 100
	maxLength := 10000

	cache := NewFixedCapDurationCache(duration, maxLength)
	assert.NotNil(t, cache)

	v1 := pTest{id: "1", name: "1", age: 1}
	cache.Add(v1.id, v1)
	v2 := pTest{id: "2", name: "2", age: 2}
	cache.Add(v2.id, v2)

	assert.True(t, cache.ExistsByKey(v1.id))
	assert.True(t, cache.ExistsByKey(v2.id))
	assert.True(t, cache.ExistsByKey("1"))
	assert.True(t, cache.ExistsByKey("2"))

	all := cache.GetAll()
	assert.Equal(t, 2, len(all))

	time.Sleep(duration)
	assert.False(t, cache.ExistsByKey(v1.id))
	assert.False(t, cache.ExistsByKey(v2.id))
	assert.False(t, cache.ExistsByKey("1"))
	assert.False(t, cache.ExistsByKey("2"))

	v3 := pTest{id: "3", name: "3", age: 3}
	cache.Add(v3.id, v3)

	assert.Equal(t, "3", cache.start.value.(pTest).id)
}

func TestDiff(t *testing.T) {
	maxLength := 10000
	duration := time.Millisecond * 100
	cache := NewFixedCapDurationCache(duration, maxLength)
	assert.NotNil(t, cache)

	v1 := pTest{id: "1", name: "1", age: 1}
	cache.Add(v1.id, v1)
	v2 := pTest{id: "2", name: "2", age: 2}
	cache.Add(v2.id, v2)
	v3 := pTest{id: "3", name: "3", age: 3}
	cache.Add(v3.id, v3)
	v4 := pTest{id: "4", name: "4", age: 4}
	cache.Add(v4.id, v4)

	all := cache.GetAll()
	assert.Equal(t, 4, len(all))

	diff := cache.Diff([]string{"2", "4"})
	assert.Equal(t, 2, len(diff))
}

func TestParallel(t *testing.T) {
	goroutine := 10
	addCount := 100000
	maxLength := 10000

	duration := time.Millisecond * 5000

	cache := NewFixedCapDurationCache(duration, maxLength)

	start := time.Now().UnixNano()
	waitGroup := sync.WaitGroup{}
	for i := 0; i < goroutine; i++ {
		waitGroup.Add(1)
		go func(index int) {
			for c := 0; c < addCount; c++ {
				temp := pTest{id: getId(index, c), name: "_", age: index}
				cache.Add(temp.id, temp)
			}
			waitGroup.Done()
		}(i)
	}
	waitGroup.Wait()
	end := time.Now().UnixNano()
	fmt.Println((end - start) / 1000000)

	start = time.Now().UnixNano()
	p := pTest{id: getId(goroutine-1, addCount-1), name: "_", age: 0}
	end = time.Now().UnixNano()
	fmt.Println((end - start) / 1000000)
	cache.Add(p.id, p)
	assert.True(t, cache.ExistsByKey(p.id))

	all := cache.GetAll()
	assert.LessOrEqual(t, 0, len(all))

	assert.Equal(t, maxLength, cache.Length())

	time.Sleep(duration)

	all = cache.GetAll()
	assert.Equal(t, 0, len(all))
}

/*func TestBenchmark(t *testing.T) {
	cache := NewFixedCapDurationCache(time.Second, 10000)
	count := 30000000

	startTime := time.Now()
	for i := 0; i < count; i++ {
		cache.Add(strconv.Itoa(i), i)
	}
	endTime := time.Now()
	useTime := endTime.Sub(startTime)
	useMillisecond := useTime.Milliseconds()
	timeAvg := float64(useMillisecond) / float64(count)
	timeAvg = math.Round(timeAvg)
	fmt.Printf("time avg:%vms \n", timeAvg)
	tps := float64(count) / useTime.Seconds()
	fmt.Printf("tps:%f  \n", tps)
	fmt.Printf("size:%d  \n", cache.Length())
}*/

func getId(prefix int, index int) string {
	return fmt.Sprintf("%d_%d", prefix, index)
}
