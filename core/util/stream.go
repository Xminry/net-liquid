/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"chainmaker.org/chainmaker/net-common/utils"
	"chainmaker.org/chainmaker/net-liquid/core/network"
)

const (
	defaultBatchSize = 4 << 10 // 4KB
)

// ReadPackageLength will read 8 bytes from network.ReceiveStream, then parse these bytes to an uint64 value.
func ReadPackageLength(stream network.ReceiveStream) (uint64, []byte, error) {
	lengthBytes, err := ReadPackageData(stream, 8)
	if err != nil {
		return 0, nil, err
	}
	length := utils.BytesToUint64(lengthBytes)
	return length, lengthBytes, nil
}

// ReadPackageData will read some bytes from network.ReceiveStream.
// The length is the size of bytes will be read.
func ReadPackageData(stream network.ReceiveStream, length uint64) ([]byte, error) {
	var readLength uint64
	var batchSize uint64 = defaultBatchSize
	result := make([]byte, length)
	for length > 0 {
		if length < batchSize {
			batchSize = length
		}
		bytes := make([]byte, batchSize)
		c, err := stream.Read(bytes)
		if err != nil {
			return nil, err
		}
		length = length - uint64(c)
		copy(result[readLength:], bytes[0:c])
		readLength = readLength + uint64(c)
	}
	return result, nil
}
