//go:build amd64 || arm64 || ppc64 || ppc64le

package aes6

import (
	_ "unsafe"
)

//go:linkname encryptBlockAsm crypto/aes.encryptBlockAsm
func encryptBlockAsm(nr int, xk *uint32, dst, src *byte)

// copy from crypto/aes
type aesCipherAsm struct {
	aesCipher
}

// copy from crypto/aes
type aesCipherGCM struct {
	aesCipherAsm
}
