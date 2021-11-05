/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package types

import (
	"container/list"
	"sync"
)

// FIFOCache is a cache with FIFO elimination strategy.
type FIFOCache struct {
	mu          sync.RWMutex
	threadSafe  bool
	maxSize     int
	currentSize int
	ll          *list.List
	cache       map[interface{}]*list.Element

	onRemoved func(k, v interface{})

	onRemoveElement func(ele *list.Element)
}

// NewFIFOCache create a new FIFOCache.
// The cap is the max entry size for cache.
// The threadSafe set whether all operations bind a lock.
func NewFIFOCache(cap int, threadSafe bool) *FIFOCache {
	if cap < 0 {
		panic("wrong cap")
	}
	return &FIFOCache{
		threadSafe:  threadSafe,
		maxSize:     cap,
		currentSize: 0,
		ll:          list.New(),
		cache:       make(map[interface{}]*list.Element),
		onRemoved:   nil,
	}
}

type cacheEntry struct {
	key   interface{}
	value interface{}
}

// OnRemove register a call back function, it will be invoked when entry eliminating or removing.
func (c *FIFOCache) OnRemove(f func(k, v interface{})) {
	if c.threadSafe {
		c.mu.Lock()
		defer c.mu.Unlock()
	}
	c.onRemoved = f
}

func (c *FIFOCache) putWithOverwriteExist(k, v interface{}, overwrite bool) bool {
	if c.threadSafe {
		c.mu.Lock()
		defer c.mu.Unlock()
	}

	// whether exist
	ele, ok := c.cache[k]
	if ok {
		// exist
		// whether overwrite
		if overwrite {
			// overwrite and move to front
			c.ll.MoveToFront(ele)
			ele.Value.(*cacheEntry).value = v
			return true
		}
		return false
	}

	// not exist, create new entry then push front
	en := &cacheEntry{k, v}
	newEle := c.ll.PushFront(en)
	c.cache[k] = newEle

	// whether current size each cap
	if c.currentSize >= c.maxSize {
		// need elimination, get one entry from back then remove it.
		outEle := c.ll.Back()
		if outEle != nil {
			outEn, _ := outEle.Value.(*cacheEntry)
			delete(c.cache, outEn.key)
			c.ll.Remove(outEle)
			if c.onRemoved != nil {
				c.onRemoved(outEn.key, outEn.value)
			}
			if c.onRemoveElement != nil {
				c.onRemoveElement(outEle)
			}
		}
	} else {
		c.currentSize++
	}
	return true
}

// Put a key-value pair to cache.
func (c *FIFOCache) Put(k, v interface{}) {
	c.putWithOverwriteExist(k, v, true)
}

// PutIfNotExist will put a key-value pair to cache if the key not exist in cache, then return true.
// If not put, return false.
func (c *FIFOCache) PutIfNotExist(k, v interface{}) bool {
	return c.putWithOverwriteExist(k, v, false)
}

// Get a value with key given.
// If not exist, return nil.
func (c *FIFOCache) Get(k interface{}) interface{} {
	if c.threadSafe {
		c.mu.RLock()
		defer c.mu.RUnlock()
	}
	ele, ok := c.cache[k]
	if !ok {
		return nil
	}
	return ele.Value.(*cacheEntry).value
}

// Remove a key-value pair existed in cache.
// If the key existed return true, otherwise return false.
func (c *FIFOCache) Remove(k interface{}) bool {
	if c.threadSafe {
		c.mu.Lock()
		defer c.mu.Unlock()
	}
	ele, ok := c.cache[k]
	if ok {
		c.ll.Remove(ele)
		delete(c.cache, k)
		c.currentSize--
		if c.onRemoved != nil {
			en, _ := ele.Value.(*cacheEntry)
			c.onRemoved(en.key, en.value)
		}
		if c.onRemoveElement != nil {
			c.onRemoveElement(ele)
		}
		return true
	}
	return false
}

// Exist return whether the key given exist in cache.
func (c *FIFOCache) Exist(k interface{}) bool {
	if c.threadSafe {
		c.mu.RLock()
		defer c.mu.RUnlock()
	}
	_, ok := c.cache[k]
	return ok
}

// Reset clear all the entries in cache.
func (c *FIFOCache) Reset() {
	if c.threadSafe {
		c.mu.Lock()
		defer c.mu.Unlock()
	}
	c.currentSize = 0
	c.cache = make(map[interface{}]*list.Element)
	c.ll = list.New()
}

// Size is the current entries count in cache.
func (c *FIFOCache) Size() int {
	if c.threadSafe {
		c.mu.RLock()
		defer c.mu.RUnlock()
	}
	return c.currentSize
}
