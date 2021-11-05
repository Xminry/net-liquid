/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package peer

// ID is the union identity of peer.
type ID string

func (i ID) ToString() string {
	return string(i)
}

// WeightCompare return whether weight of our ID is higher than other's.
// This function usually used to decide which peer should be saved when a conflict found with both peers.
func (i ID) WeightCompare(other ID) bool {
	l := string(i)
	r := string(other)
	for i := 0; i < len(l) && i < len(r); i++ {
		if l[i] != r[i] {
			return l[i] > r[i]
		}
	}
	return true
}
