package aes6

import _ "unsafe"

//go:linkname encryptBlockGo crypto/aes.encryptBlockGo
func encryptBlockGo(xk []uint32, dst, src []byte)

//go:linkname decryptBlockGo crypto/aes.decryptBlockGo
func decryptBlockGo(xk []uint32, dst, src []byte)

//go:linkname expandKeyGo crypto/aes.expandKeyGo
func expandKeyGo(key []byte, enc, dec []uint32)
