package aes6

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"github.com/stretchr/testify/assert"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
)

func randomAead(t assert.TestingT, tagSize int) (cipher.AEAD, [12]byte) {
	var key [16]byte
	_, err := rand.Read(key[:])
	assert.NoError(t, err)
	var nonce [12]byte
	_, err = rand.Read(nonce[:])
	assert.NoError(t, err)
	block, err := aes.NewCipher(key[:])
	assert.NoError(t, err)

	aesgcm, err := NewGCMWithTagSize(block, tagSize)
	assert.NoError(t, err)
	return aesgcm, nonce
}

func BenchmarkSeal(b *testing.B) {
	aead, nonce := randomAead(b, 6)
	var buf [1516]byte
	sealed := 0
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		aead.Seal(buf[:], nonce[:], buf[:1500], nil)
		sealed += len(buf)
	}
	b.StopTimer()

	b.ReportMetric(float64(sealed)/b.Elapsed().Seconds()/1e9, "GB/s")
}

func BenchmarkOpen(b *testing.B) {
	aead, nonce := randomAead(b, 6)
	var buf [1500]byte
	_, err := rand.Read(buf[:])
	assert.NoError(b, err)
	ciphertext := aead.Seal(nil, nonce[:], buf[:], nil)
	opened := 0
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		plaintext, err := aead.Open(buf[:], nonce[:], ciphertext, nil)
		assert.NoError(b, err)
		opened += len(plaintext)
	}
	b.StopTimer()

	b.ReportMetric(float64(opened)/b.Elapsed().Seconds()/1e9, "GB/s")
}

func BenchmarkOpenParallel(b *testing.B) {
	aead, nonce := randomAead(b, 6)
	var buf [1516]byte
	_, err := rand.Read(buf[:])
	assert.NoError(b, err)
	ciphertext := aead.Seal(nil, nonce[:], buf[:1500], nil)
	totalOpened := atomic.Int64{}
	workers := runtime.NumCPU()
	jobsPerWorker := b.N
	wg := sync.WaitGroup{}
	wg.Add(workers)
	b.ResetTimer()
	for i := 0; i < workers; i++ {
		go func() {
			opened := 0
			for j := 0; j < jobsPerWorker; j++ {
				plaintext, _ := aead.Open(buf[:], nonce[:], ciphertext, nil)
				opened += len(plaintext)
			}
			totalOpened.Add(int64(opened))
			wg.Done()
		}()
	}
	wg.Wait()
	b.StopTimer()

	b.ReportMetric(float64(totalOpened.Load())/b.Elapsed().Seconds()/1e9, "GB/s")
}
