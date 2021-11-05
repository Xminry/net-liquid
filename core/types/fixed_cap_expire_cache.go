/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package types

import (
	"sync"
	"time"
)

//cacheNode store cache info
type cacheNode struct {
	key        string
	createTime int64       //node create time
	expireTime int64       //node expire time
	value      interface{} //cache value
	next       *cacheNode  //next node,create time must after this node
	prev       *cacheNode  //prev node,create time must before this node
}

//FixedCapDurationCache cache data with fixed capacity and duration from [now - duration,now]
type FixedCapDurationCache struct {
	mutex sync.RWMutex

	duration int64 //data cache duration, if node's cache time grate than this value, data will expire
	capacity int   //cache's max capacity

	start  *cacheNode //start node
	end    *cacheNode //end node
	length int        //cache size

	existsMap map[string]*cacheNode // a copy for cache info, to fast check cache info exists or not
}

//NewFixedCapDurationCache new cache instance
func NewFixedCapDurationCache(duration time.Duration, capacity int) *FixedCapDurationCache {
	return &FixedCapDurationCache{
		capacity:  capacity,
		duration:  duration.Nanoseconds(),
		existsMap: make(map[string]*cacheNode),
	}
}

//Add data to cache
func (fdc *FixedCapDurationCache) Add(key string, v interface{}) {
	fdc.mutex.Lock()
	defer fdc.mutex.Unlock()
	fdc.add(key, v)
}

//AddIfNotExist add data to cache is key not exists
func (fdc *FixedCapDurationCache) AddIfNotExist(key string, v interface{}) bool {
	fdc.mutex.Lock()
	defer fdc.mutex.Unlock()
	_, ok := fdc.existsMap[key]
	if ok {
		return false
	}
	fdc.add(key, v)
	return true
}

//add data to cache
func (fdc *FixedCapDurationCache) add(key string, v interface{}) {
	//new node
	node := newCacheNode(v, key, fdc.duration)
	fdc.length = fdc.length + 1

	if fdc.end == nil {
		fdc.start = node
		fdc.end = node
		fdc.existsMap[key] = node
		return
	}

	//add to end
	node.prev = fdc.end
	fdc.end.next = node
	fdc.end = node
	fdc.existsMap[key] = node

	//after add data to cache we can assert that last data is not expire
	node = fdc.start
	for {
		lessThanMaxLength := fdc.length <= fdc.capacity
		noExpire := node.expireTime >= time.Now().UnixNano()
		if lessThanMaxLength && noExpire {
			fdc.start = node
			prev := node.prev
			//cut link list from node
			if prev != nil {
				node.prev.next = nil
				node.prev = nil
			}
			break
		}
		delete(fdc.existsMap, node.key)
		node = node.next
		fdc.length = fdc.length - 1
	}
}

//ExistsByKey if key in cache and not expire return ture, else return false
func (fdc *FixedCapDurationCache) ExistsByKey(key string) bool {
	fdc.mutex.RLock()
	defer fdc.mutex.RUnlock()
	if result, ok := fdc.existsMap[key]; ok && result.expireTime > time.Now().UnixNano() {
		return true
	}
	return false
}

//GetByKey if key in cache and not expire return value, else return nil
func (fdc *FixedCapDurationCache) GetByKey(key string) interface{} {
	fdc.mutex.RLock()
	defer fdc.mutex.RUnlock()
	if result, ok := fdc.existsMap[key]; ok && result.expireTime > time.Now().UnixNano() {
		return result.value
	}
	return nil
}

//Diff return cache data not exists in key list
func (fdc *FixedCapDurationCache) Diff(keyList []string) []interface{} {
	fdc.mutex.RLock()
	defer fdc.mutex.RUnlock()
	if len(keyList) == 0 {
		return fdc.GetAll()
	}

	keyMap := make(map[string]struct{})
	for _, key := range keyList {
		keyMap[key] = struct{}{}
	}

	result := make([]interface{}, 0)
	for node := fdc.end; node != nil; node = node.prev {
		if node.expireTime < time.Now().UnixNano() {
			break
		}
		if _, ok := keyMap[node.key]; !ok {
			result = append(result, node.value)
		}
	}
	return result
}

//GetAll get not expire value in cache
func (fdc *FixedCapDurationCache) GetAll() []interface{} {
	fdc.mutex.RLock()
	defer fdc.mutex.RUnlock()
	result := make([]interface{}, 0)
	for node := fdc.end; node != nil; node = node.prev {
		if node.expireTime < time.Now().UnixNano() {
			break
		}
		result = append(result, node.value)
	}
	return result
}

//Length return cache data count
func (fdc *FixedCapDurationCache) Length() int {
	fdc.mutex.RLock()
	defer fdc.mutex.RUnlock()
	return fdc.length
}

//newCacheNode new node instance
func newCacheNode(v interface{}, key string, duration int64) *cacheNode {
	now := time.Now().UnixNano()
	return &cacheNode{
		createTime: now,
		expireTime: now + duration,
		key:        key,
		value:      v,
		next:       nil,
		prev:       nil,
	}
}
