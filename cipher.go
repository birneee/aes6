package aes6

// copy from crypto/aes
const BlockSize = 16

// copy from crypto/aes
type aesCipher struct {
	enc []uint32
	dec []uint32
}
