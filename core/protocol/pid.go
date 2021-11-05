/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package protocol

// ID is an identifier used to mark the module which the net msg belong to.
type ID string

const (
	// TestingPID is a protocol id for testing.
	TestingPID ID = "/_testing"
)

// ParseStringsToIDs parses string slice to ID slice.
func ParseStringsToIDs(strs []string) []ID {
	res := make([]ID, len(strs))
	for idx := range strs {
		res[idx] = ID(strs[idx])
	}
	return res
}

// ParseIDsToStrings parses ID slice to string slice.
func ParseIDsToStrings(pids []ID) []string {
	res := make([]string, len(pids))
	for i := range pids {
		res[i] = string(pids[i])
	}
	return res
}
