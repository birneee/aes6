package aes6

import (
	"crypto/aes"
	"github.com/stretchr/testify/assert"
	"testing"
)

func testAesGcmWithTagSize(t *testing.T, tagSize int) (tag []byte, err error) {
	var key [16]byte
	var nonce [12]byte
	block, err := aes.NewCipher(key[:])
	assert.NoError(t, err)

	aesgcm, err := NewGCMWithTagSize(block, tagSize)
	if err != nil {
		return nil, err
	}
	plaintext := []byte("hello aes")
	ciphertext := aesgcm.Seal(nil, nonce[:], plaintext, nil)
	assert.Equal(t, len(plaintext)+tagSize, len(ciphertext))
	openedtext, err := aesgcm.Open(nil, nonce[:], ciphertext, nil)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, openedtext)
	return ciphertext[len(plaintext):], nil
}

func TestAesGcm(t *testing.T) {
	var previousTag []byte
	for i := 6; i < 16; i++ {
		tag, err := testAesGcmWithTagSize(t, i)
		assert.NoError(t, err)
		if previousTag != nil {
			assert.Equal(t, previousTag, tag[:len(previousTag)])
		}
		previousTag = tag
	}
}

func TestAesGcm5(t *testing.T) {
	_, err := testAesGcmWithTagSize(t, 5)
	assert.ErrorContains(t, err, "incorrect tag size")
}

func TestAesGcm17(t *testing.T) {
	_, err := testAesGcmWithTagSize(t, 17)
	assert.ErrorContains(t, err, "incorrect tag size")
}
