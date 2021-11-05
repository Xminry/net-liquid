/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package types

import (
	"strconv"
	"strings"

	"github.com/cznic/mathutil"
)

//Interval such as: [2,3],[5,9]
type Interval struct {
	start uint64
	end   uint64
}

// IntervalSet is a set of Interval.
type IntervalSet struct {
	intervalSet []*Interval
}

// NewIntervalSet create a new IntervalSet instance.
func NewIntervalSet() *IntervalSet {
	return &IntervalSet{
		intervalSet: make([]*Interval, 0),
	}
}

// NewInterval create a new Interval
func NewInterval(start, end uint64) *Interval {
	return &Interval{start: start, end: end}
}

// Add an Interval to IntervalSet.
func (is *IntervalSet) Add(iv *Interval) {
	if iv == nil {
		return
	}

	if iv.start > iv.end {
		return
	}

	if len(is.intervalSet) == 0 {
		is.intervalSet = append(is.intervalSet, &Interval{start: iv.start, end: iv.end})
		return
	}

	insertIndex := -1
	for index, rv := range is.intervalSet {
		if iv.start < rv.start && insertIndex == -1 {
			insertIndex = index
		}
		if isContinuous(iv, rv) {
			rv.start = mathutil.MinUint64(iv.start, rv.start)
			rv.end = mathutil.MaxUint64(iv.end, rv.end)
			nextIndex := index + 1
			if nextIndex < len(is.intervalSet) && rv.end+1 >= is.intervalSet[nextIndex].start {
				temp := is.intervalSet[nextIndex]
				if index+2 < len(is.intervalSet) {
					is.intervalSet = append(is.intervalSet[0:nextIndex], is.intervalSet[index+2:]...)
				} else {
					is.intervalSet = is.intervalSet[0:nextIndex]
				}
				is.Add(temp)
			}
			return
		}
	}

	if insertIndex == -1 {
		insertIndex = len(is.intervalSet)
	}

	insert := &Interval{
		start: iv.start,
		end:   iv.end,
	}
	is.intervalSet = append(is.intervalSet, insert)
	copy(is.intervalSet[insertIndex+1:], is.intervalSet[insertIndex:])
	is.intervalSet[insertIndex] = insert
}

// RemoveBefore remove Interval before removeIntervalEnd
func (is *IntervalSet) RemoveBefore(removeIntervalEnd uint64) {
	removeIndex := -1
	for index, v := range is.intervalSet {
		if v.end >= removeIntervalEnd {
			break
		}
		removeIndex = index
	}
	if removeIndex == -1 {
		return
	}
	removeIndex = removeIndex + 1
	if removeIndex >= len(is.intervalSet) {
		is.intervalSet = make([]*Interval, 0)
		return
	}
	is.intervalSet = is.intervalSet[removeIndex:]
}

// String return all Interval in IntervalSet.
func (is *IntervalSet) String() string {
	builder := strings.Builder{}
	for _, r := range is.intervalSet {
		builder.WriteString("[")
		builder.WriteString(strconv.FormatUint(r.start, 10))
		builder.WriteString(",")
		builder.WriteString(strconv.FormatUint(r.end, 10))
		builder.WriteString("] ")
	}
	return builder.String()
}

// MissingCount return the count of numbers than not record in IntervalSet from 1 to max number.
func (is *IntervalSet) MissingCount() int {
	if len(is.intervalSet) == 0 {
		return 0
	}
	var start uint64 = 1
	missingCount := 0
	for _, r := range is.intervalSet {
		for {
			if start < r.start {
				start++
				missingCount++
			}
			if start == r.start {
				start = r.end + 1
				break
			}
		}
	}
	return missingCount
}

// Contains return whether number in IntervalSet.
func (is *IntervalSet) Contains(index uint64) bool {
	for _, r := range is.intervalSet {
		if index >= r.start && index <= r.end {
			return true
		}
	}
	return false
}

//isContinuous judge whether two Interval is continuous, if so, merge them
func isContinuous(a *Interval, b *Interval) bool {
	return (a.start >= b.start-1 && a.start <= b.end+1) || (a.end >= b.start-1 && a.end <= b.end+1)
}
