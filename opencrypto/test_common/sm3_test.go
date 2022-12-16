package test_common

import (
	"testing"

	gsm3 "github.com/rongzer/gmssl-go/opencrypto/gmssl/sm3"
	tsm3 "github.com/rongzer/gmssl-go/opencrypto/tencentsm/sm3"
	"github.com/stretchr/testify/assert"
	tjsm3 "github.com/rongzer/gmssl-go/opencrypto/gmssl/sm3"
)

func TestSM3Standard(t *testing.T) {
	//tencentsm, rongzer and gmssl hash compare
	h := tsm3.New()
	_, err := h.Write(msg)
	assert.NoError(t, err)
	digest1 := h.Sum(nil)

	h = tjsm3.New()
	_, err = h.Write(msg)
	assert.NoError(t, err)
	digest2 := h.Sum(nil)

	h = gsm3.New()
	_, err = h.Write(msg)
	assert.NoError(t, err)
	digest3 := h.Sum(nil)

	assert.Equal(t, digest1, digest2)
	assert.Equal(t, digest2, digest3)
}

func BenchmarkTjfocSM3(b *testing.B) {
	h := tjsm3.New()
	for i := 0; i < b.N; i++ {
		h.Write(msg)
		h.Sum(nil)
	}
}

func BenchmarkTecentSMSM3(b *testing.B) {
	h := tsm3.New()
	for i := 0; i < b.N; i++ {
		h.Write(msg)
		h.Sum(nil)
	}
}

func BenchmarkGmsslSM3(b *testing.B) {
	h := gsm3.New()
	for i := 0; i < b.N; i++ {
		h.Write(msg)
		h.Sum(nil)
	}
}
