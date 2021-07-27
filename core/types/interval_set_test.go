package types

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRangeSet_add(t *testing.T) {
	set := NewIntervalSet()

	set.Add(&Interval{start: 1, end: 1})
	assert.Equal(t, uint64(1), set.intervalSet[0].start)
	assert.Equal(t, uint64(1), set.intervalSet[0].end)

	set.Add(&Interval{start: 3, end: 3})
	assert.Equal(t, uint64(1), set.intervalSet[0].start)
	assert.Equal(t, uint64(1), set.intervalSet[0].end)

	assert.Equal(t, uint64(3), set.intervalSet[1].start)
	assert.Equal(t, uint64(3), set.intervalSet[1].end)

	set.Add(&Interval{start: 2, end: 2})
	assert.Equal(t, 1, len(set.intervalSet))
	assert.Equal(t, uint64(1), set.intervalSet[0].start)
	assert.Equal(t, uint64(3), set.intervalSet[0].end)

	set.Add(&Interval{start: 5, end: 5})
	assert.Equal(t, 2, len(set.intervalSet))
	assert.Equal(t, uint64(5), set.intervalSet[1].start)
	assert.Equal(t, uint64(5), set.intervalSet[1].end)

	set.Add(&Interval{start: 10, end: 10})
	assert.Equal(t, 3, len(set.intervalSet))
	assert.Equal(t, uint64(10), set.intervalSet[2].start)
	assert.Equal(t, uint64(10), set.intervalSet[2].end)

	set.Add(&Interval{start: 4, end: 10})
	assert.Equal(t, 1, len(set.intervalSet))
	assert.Equal(t, uint64(1), set.intervalSet[0].start)
	assert.Equal(t, uint64(10), set.intervalSet[0].end)

	set.Add(&Interval{start: 1, end: 1})
	assert.Equal(t, 1, len(set.intervalSet))
	assert.Equal(t, uint64(1), set.intervalSet[0].start)
	assert.Equal(t, uint64(10), set.intervalSet[0].end)

	set.Add(&Interval{start: 10, end: 12})
	assert.Equal(t, 1, len(set.intervalSet))
	assert.Equal(t, uint64(1), set.intervalSet[0].start)
	assert.Equal(t, uint64(12), set.intervalSet[0].end)

	set.Add(&Interval{start: 13, end: 14})
	assert.Equal(t, 1, len(set.intervalSet))
	assert.Equal(t, uint64(1), set.intervalSet[0].start)
	assert.Equal(t, uint64(14), set.intervalSet[0].end)

	set.Add(&Interval{start: 100, end: 120})
	assert.Equal(t, 2, len(set.intervalSet))
	assert.Equal(t, uint64(100), set.intervalSet[1].start)
	assert.Equal(t, uint64(120), set.intervalSet[1].end)

	set.Add(&Interval{start: 130, end: 140})
	assert.Equal(t, 3, len(set.intervalSet))
	assert.Equal(t, uint64(130), set.intervalSet[2].start)
	assert.Equal(t, uint64(140), set.intervalSet[2].end)

	set.Add(&Interval{start: 122, end: 123})
	assert.Equal(t, 4, len(set.intervalSet))
	assert.Equal(t, uint64(122), set.intervalSet[2].start)
	assert.Equal(t, uint64(123), set.intervalSet[2].end)

	set.Add(&Interval{start: 15, end: 99})
	set.Add(&Interval{start: 120, end: 140})
	assert.Equal(t, 1, len(set.intervalSet))
	assert.Equal(t, uint64(1), set.intervalSet[0].start)
	assert.Equal(t, uint64(140), set.intervalSet[0].end)
}

func TestA(t *testing.T) {
	set := NewIntervalSet()
	set.Add(NewInterval(7208, 7208))
	set.Add(NewInterval(5448, 5448))
	set.Add(NewInterval(7762, 7762))
	set.Add(NewInterval(4610, 4610))

	assert.Equal(t, uint64(4610), set.intervalSet[0].start)
}

func TestRangeSet(t *testing.T) {
	set := NewIntervalSet()
	for {
		value := rand.Intn(10000) + 1
		set.Add(NewInterval(uint64(value), uint64(value)))

		r := NewInterval(0, 0)
		for _, v := range set.intervalSet {
			b := r.end < v.start
			if !b {
				fmt.Println(set.String())
			}
			assert.True(t, b)
			r = v
		}
		if set.intervalSet[0].start == uint64(1) && set.intervalSet[0].end == uint64(10000) {
			fmt.Println(set.String())
			break
		}
	}
}

func TestHaveSameIndex(t *testing.T) {
	a := &Interval{start: 1, end: 1}
	b := &Interval{start: 1, end: 10}
	assert.True(t, isContinuous(a, b))
}

func TestRemoveBefore(t *testing.T) {
	set := NewIntervalSet()
	set.Add(NewInterval(1, 1))
	set.Add(NewInterval(3, 3))
	set.Add(NewInterval(5, 5))
	set.Add(NewInterval(7, 7))

	set.RemoveBefore(0)
	assert.Equal(t, 4, len(set.intervalSet))

	set.RemoveBefore(2)
	assert.Equal(t, 3, len(set.intervalSet))

	set.RemoveBefore(7)
	assert.Equal(t, 1, len(set.intervalSet))

	set.RemoveBefore(8)
	assert.Equal(t, 0, len(set.intervalSet))
}

func TestRemoveBeforeEmpty(t *testing.T) {
	set := NewIntervalSet()

	set.RemoveBefore(0)
	assert.Equal(t, 0, len(set.intervalSet))
}

func TestContains(t *testing.T) {
	set := NewIntervalSet()

	set.Add(NewInterval(1, 1))

	set.Add(NewInterval(3, 3))

	set.Add(NewInterval(9, 100))
	set.Add(NewInterval(100, 200))

	set.Add(NewInterval(10000, 99999))

	assert.False(t, set.Contains(0))
	assert.True(t, set.Contains(1))
	assert.False(t, set.Contains(2))
	assert.True(t, set.Contains(3))
	assert.False(t, set.Contains(4))

	assert.False(t, set.Contains(7))
	assert.False(t, set.Contains(8))
	assert.True(t, set.Contains(9))
	assert.True(t, set.Contains(10))
	assert.True(t, set.Contains(99))
	assert.True(t, set.Contains(100))
	assert.True(t, set.Contains(199))
	assert.True(t, set.Contains(200))
	assert.False(t, set.Contains(201))
	assert.False(t, set.Contains(202))

	assert.False(t, set.Contains(8888))
	assert.False(t, set.Contains(9999))
	assert.True(t, set.Contains(10000))
	assert.True(t, set.Contains(88888))
	assert.True(t, set.Contains(99999))

	assert.False(t, set.Contains(100000))
	assert.False(t, set.Contains(100001))
	assert.False(t, set.Contains(500001))
}
