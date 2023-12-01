// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build amd64 || arm64

package aes6

import (
	"crypto/cipher"
	"crypto/subtle"
	"github.com/birneee/aes6/alias"
)

import (
	_ "unsafe"
)

// The following functions are defined in gcm_*.s.

//go:linkname gcmAesInit crypto/aes.gcmAesInit
func gcmAesInit(productTable *[256]byte, ks []uint32)

//go:linkname gcmAesData crypto/aes.gcmAesData
func gcmAesData(productTable *[256]byte, data []byte, T *[16]byte)

//go:linkname gcmAesEnc crypto/aes.gcmAesEnc
func gcmAesEnc(productTable *[256]byte, dst, src []byte, ctr, T *[16]byte, ks []uint32)

//go:linkname gcmAesDec crypto/aes.gcmAesDec
func gcmAesDec(productTable *[256]byte, dst, src []byte, ctr, T *[16]byte, ks []uint32)

//go:linkname gcmAesFinish crypto/aes.gcmAesFinish
func gcmAesFinish(productTable *[256]byte, tagMask, T *[16]byte, pLen, dLen uint64)

const (
	gcmBlockSize         = 16
	gcmTagSize           = 16
	gcmMinimumTagSize    = 6 // ignore NIST SP 800-38D recommended tags of 12 or more bytes.
	gcmStandardNonceSize = 12
)

// Assert that aesCipherGCM implements the gcmAble interface.
var _ gcmAble = (*aesCipherGCM)(nil)

// copy of crypto/aes with reduced minimum tag size
func (c *aesCipherGCM) NewGCM(nonceSize, tagSize int) (cipher.AEAD, error) {
	g := &gcmAsm{ks: c.enc, nonceSize: nonceSize, tagSize: tagSize}
	gcmAesInit(&g.productTable, g.ks)
	return g, nil
}

// copy of crypto/aes with reduced minimum tag size
type gcmAsm struct {
	// ks is the key schedule, the length of which depends on the size of
	// the AES key.
	ks []uint32
	// productTable contains pre-computed multiples of the binary-field
	// element used in GHASH.
	productTable [256]byte
	// nonceSize contains the expected size of the nonce, in bytes.
	nonceSize int
	// tagSize contains the size of the tag, in bytes.
	tagSize int
}

//go:linkname _gcmAsmNonceSize crypto/aes.(*gcmAsm).NonceSize
func _gcmAsmNonceSize(g *gcmAsm) int

func (g *gcmAsm) NonceSize() int {
	return _gcmAsmNonceSize(g)
}

//go:linkname _gcmAsmOverhead crypto/aes.(*gcmAsm).Overhead
func _gcmAsmOverhead(g *gcmAsm) int

func (g *gcmAsm) Overhead() int {
	return _gcmAsmOverhead(g)
}

//go:linkname _gcmAsmSeal crypto/aes.(*gcmAsm).Seal
func _gcmAsmSeal(g *gcmAsm, dst, nonce, plaintext, data []byte) []byte

func (g *gcmAsm) Seal(dst, nonce, plaintext, data []byte) []byte {
	return _gcmAsmSeal(g, dst, nonce, plaintext, data)
}

// copy of crypto/aes with reduced minimum tag size
func (g *gcmAsm) Open(dst, nonce, ciphertext, data []byte) ([]byte, error) {
	if len(nonce) != g.nonceSize {
		panic("crypto/cipher: incorrect nonce length given to GCM")
	}
	// Sanity check to prevent the authentication from always succeeding if an implementation
	// leaves tagSize uninitialized, for example.
	if g.tagSize < gcmMinimumTagSize {
		panic("crypto/cipher: incorrect GCM tag size")
	}

	if len(ciphertext) < g.tagSize {
		return nil, errOpen
	}
	if uint64(len(ciphertext)) > ((1<<32)-2)*uint64(BlockSize)+uint64(g.tagSize) {
		return nil, errOpen
	}

	tag := ciphertext[len(ciphertext)-g.tagSize:]
	ciphertext = ciphertext[:len(ciphertext)-g.tagSize]

	// See GCM spec, section 7.1.
	var counter, tagMask [gcmBlockSize]byte

	if len(nonce) == gcmStandardNonceSize {
		// Init counter to nonce||1
		copy(counter[:], nonce)
		counter[gcmBlockSize-1] = 1
	} else {
		// Otherwise counter = GHASH(nonce)
		gcmAesData(&g.productTable, nonce, &counter)
		gcmAesFinish(&g.productTable, &tagMask, &counter, uint64(len(nonce)), uint64(0))
	}

	encryptBlockAsm(len(g.ks)/4-1, &g.ks[0], &tagMask[0], &counter[0])

	var expectedTag [gcmTagSize]byte
	gcmAesData(&g.productTable, data, &expectedTag)

	ret, out := sliceForAppend(dst, len(ciphertext))
	if alias.InexactOverlap(out, ciphertext) {
		panic("crypto/cipher: invalid buffer overlap")
	}
	if len(ciphertext) > 0 {
		gcmAesDec(&g.productTable, out, ciphertext, &counter, &expectedTag, g.ks)
	}
	gcmAesFinish(&g.productTable, &tagMask, &expectedTag, uint64(len(ciphertext)), uint64(len(data)))

	if subtle.ConstantTimeCompare(expectedTag[:g.tagSize], tag) != 1 {
		for i := range out {
			out[i] = 0
		}
		return nil, errOpen
	}

	return ret, nil
}
