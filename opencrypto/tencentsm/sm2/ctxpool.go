/*
Copyright (C) BABEC. All rights reserved.
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sm2

import (
	"crypto/sha256"
	"encoding/hex"
	"runtime"
	"sync"

	"github.com/rongzer/gmssl-go/opencrypto/tencentsm/tencentsm"

	"github.com/spf13/viper"
)

const (
	CTX_POOLSIZE_PER_PK = 1
)

var (
	lock          sync.RWMutex
	pubCtxPoolMap map[string]*CtxPool
)

func init() {
	pubCtxPoolMap = make(map[string]*CtxPool, 1000)
}

type CtxPool struct {
	poolSize int
	ctxChan  chan *tencentsm.SM2_ctx_t
	pubkey   []byte

	lock sync.Mutex
}

func NewCtxPoolWithPubKey(pubkey []byte) *CtxPool {
	//if exist
	dgst := sha256.Sum256(pubkey)
	pubHex := hex.EncodeToString(dgst[:20])
	if _, exist := pubCtxPoolMap[pubHex]; exist {
		return pubCtxPoolMap[pubHex]
	}

	//new pool per public key
	poolSize := CTX_POOLSIZE_PER_PK
	if viper.IsSet("common.tencentsm.ctx_pool_size") {
		ctxPoolSize := viper.GetInt("common.tencentsm.ctx_pool_size")
		if ctxPoolSize > 0 {
			poolSize = ctxPoolSize
		}
	}

	lock.Lock()
	defer lock.Unlock()
	if _, exist := pubCtxPoolMap[pubHex]; exist {
		return pubCtxPoolMap[pubHex]
	}

	pool := &CtxPool{
		ctxChan:  make(chan *tencentsm.SM2_ctx_t, poolSize),
		poolSize: poolSize,
		pubkey:   pubkey,
	}

	//init tencentsm sm2Ctx
	go func() {
		for j := 0; j < poolSize; j++ {
			var ctx tencentsm.SM2_ctx_t
			tencentsm.SM2InitCtxWithPubKey(&ctx, pubkey)
			pool.ctxChan <- &ctx
			runtime.Gosched()
		}
	}()

	pubCtxPoolMap[pubHex] = pool

	return pool
}

func (c *CtxPool) GetCtx() *tencentsm.SM2_ctx_t {
	return <-c.ctxChan
}

func (c *CtxPool) ReleaseCtx(ctx *tencentsm.SM2_ctx_t) {
	c.ctxChan <- ctx
}

func (c *CtxPool) Close() {
	c.lock.Lock()
	defer c.lock.Unlock()
	close(c.ctxChan)

	for ctx := range c.ctxChan {
		tencentsm.SM2FreeCtx(ctx)
	}
}
