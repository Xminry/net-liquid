/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"encoding/pem"
	"testing"

	"chainmaker.org/chainmaker/common/v2/crypto/asym"
	"github.com/stretchr/testify/require"
)

func TestResolvePIDFromCertDER(t *testing.T) {
	certPEM1 := []byte("-----BEGIN CERTIFICATE-----\nMIIDFTCCArugAwIBAgIDBOOCMAoGCCqGSM49BAMCMIGKMQswCQYDVQQGEwJDTjEQ\nMA4GA1UECBMHQmVpamluZzEQMA4GA1UEBxMHQmVpamluZzEfMB0GA1UEChMWd3gt\nb3JnMS5jaGFpbm1ha2VyLm9yZzESMBAGA1UECxMJcm9vdC1jZXJ0MSIwIAYDVQQD\nExljYS53eC1vcmcxLmNoYWlubWFrZXIub3JnMB4XDTIwMTIwODA2NTM0M1oXDTI1\nMTIwNzA2NTM0M1owgZYxCzAJBgNVBAYTAkNOMRAwDgYDVQQIEwdCZWlqaW5nMRAw\nDgYDVQQHEwdCZWlqaW5nMR8wHQYDVQQKExZ3eC1vcmcxLmNoYWlubWFrZXIub3Jn\nMRIwEAYDVQQLEwljb25zZW5zdXMxLjAsBgNVBAMTJWNvbnNlbnN1czEudGxzLnd4\nLW9yZzEuY2hhaW5tYWtlci5vcmcwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQr\nB6ZGGvO/kZJKazLgRESGdAniOhxq7JacPV1dTH1fxzhXCEbmFZDuhz5wzLPqtc8p\nOtTEoPnRX44HQVWSlju8o4IBADCB/TAOBgNVHQ8BAf8EBAMCAaYwDwYDVR0lBAgw\nBgYEVR0lADApBgNVHQ4EIgQgqzFBKQ6cAvTThFgrn//B/SDhAFEDfW5Y8MOE7hvY\nBf4wKwYDVR0jBCQwIoAgNSQ/cRy5t8Q1LpMfcMVzMfl0CcLZ4Pvf7BxQX9sQiWcw\nUQYDVR0RBEowSIIOY2hhaW5tYWtlci5vcmeCCWxvY2FsaG9zdIIlY29uc2Vuc3Vz\nMS50bHMud3gtb3JnMS5jaGFpbm1ha2VyLm9yZ4cEfwAAATAvBguBJ1iPZAsej2QL\nBAQgMDAxNjQ2ZTY3ODBmNGIwZDhiZWEzMjNlZThjMjQ5MTUwCgYIKoZIzj0EAwID\nSAAwRQIgNVNGr+G8dbYnzmmNMr9GCSUEC3TUmRcS4uOd5/Sw4mECIQDII1R7dCcx\n02YrxI8jEQZhmWeZ5FJhnSG6p6H9pCIWDQ==\n-----END CERTIFICATE-----\n")
	certP1, _ := pem.Decode(certPEM1)
	pid, err2 := ResolvePIDFromCertDER(certP1.Bytes)
	require.Nil(t, err2)
	require.NotEqual(t, "", pid)
}

func TestResolvePIDFromPubKey(t *testing.T) {
	privateKeyPem := "-----BEGIN RSA PRIVATE KEY-----\nMIIEpQIBAAKCAQEAz1lVwv+pRaRxaTfxAEJsKxxv1otPh5Gh31XiHEwVWDPpvCbU\n3WnY9n711xhm03890L+ddL7tl9v3GHnsg0YKtxV6/u+giqTOnhbkMJS2Zg5NgDjU\nNTYp9zvs5f1YM9AxL5tihrIlBep8XKXAZ9ioOoFX1e/JKUowifDXSIBs4N3tJN5a\nlg/bn38B9dpSeDC8bf7yXkv0seDNbLPxmliZe5uC3iCotnLwf+WSc/+Lazh9+zHk\nevz0XPN9jIzcP4zCx8b90rjq3/jVL+6QRR6BiGGh8bQpOlhaw6U0St7m8zVolJqP\nBa2KIJZd13ozkbmQL+qQ7DJXe37HkwCWzekI5wIDAQABAoIBADwP/K/HrxjlUZTR\nB5azpvG2Aw96u0biAKnZDu5ze5tZLlO6S973UknU7RGpl9+b9CQL3Wh8Bgb/SMxm\nRQShvWjbaA2BDFgc9V0F9IO+EDfv3LNPwujHD9D2IuFcSbh4jkbkE95ArEjSa8PK\nn7l1IQYRgYgPNY4oV3cdtL7jtKZOHXDxhCH4sdvDuc+QALvhPpmmTP7Fgc4P9I5s\num265icZMcfXom1QpBaQfDQFJ985/MrTalHBXtx14XRsWlW7CexDHkS+PwCFzI/8\nz07lLuMOEOPM+5GVpoRws/Nm6OHHvsgFewVI3Sgyk7qUdDQy+yOOUxiMqUnFWIna\nl8Z/QcECgYEA5VX/eVj2xW8HI92NysUbiZQxKCI11VVOenL6FuHzayxKq7hrbrIe\nl1373DFtLvlNZbKk6r81eUU/VuNiaZChZ2LRSvHO8KLwi/6NViSC13nZ9oXXvY6Q\ny/Q7YU59YIdYzJxWCm21DMTQu8SPzu+rdg0CyU7vCfqQQQKs631q1+MCgYEA53Tp\nmXODMHO10tS9zOgGflP3V5jwCHFeZfv5YmaM1BhOPUvFRSty3ACEKMSoNVVOEyXr\nFe2tlMwfoMAQ5afVrYAvfQxUMGky1H8I/Y56QFSxeVb1/ymoz4Kc9EP5lBziiPxq\n4d9xY/4HEEIOjKXXhglRaaptdYxirn2DcC5qci0CgYEAljvD5AZ3gda94qzcmhyN\ncY72tMfUZDBB/M0dL6hNAcQ+Fkf1eMqOZ7JVr2VhlQgTv69LgcxIh2zplU3XxjfM\nxCFj4aiOW+0hj1Pt2qSIYgec1XXQYojmKfWQgKoeUAHaFg/D/Yjotbio1JhrbLBs\nriTP0ng2916A6VWLWakLOOkCgYEAzYi3a+n0xJDsFGWQiiY8pe/ARAxuksDBmASy\nx1vTkQBocewYKL1ViOH4eg9wY7P12fEhGl7udqTxLRmBp75rdF/RS9Un6blxRtvs\nSuU70GalFuBPIKCI5ITTBeJa/djMneKwsxVtpuLMuPY/30vh4IfjwNZzzx+z/ck9\nb9/37J0CgYEAshP5wuIFb4CZSuZvGqwUQsqFdPJaxP1W/A5EHagZjsoaPmmY5aXD\nSsZVvicnGpEK+nosPofSkXH/l8iol9sxgUT7W/hMSA3EIJZrRuKxfktnhTOnOS0N\n+469rp9Lc06Bk9C4vqBacg07s+I9bP8RT8NkCNoBbRhFmmxrzyH6UV8=\n-----END RSA PRIVATE KEY-----"
	sk, err := asym.PrivateKeyFromPEM([]byte(privateKeyPem), nil)
	require.Nil(t, err)
	pid, err := ResolvePIDFromPubKey(sk.PublicKey())
	require.Nil(t, err)
	require.True(t, pid == "Qmdwdxac5wTRTRbWQQAPjedqLd8C3JZYXHkUsrSYY2eDhC")
}
