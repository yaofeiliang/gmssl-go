/*
Copyright (C) BABEC. All rights reserved.
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sm2

import (
	"encoding/pem"
	"fmt"

	"github.com/rongzer/gmssl-go/opencrypto/utils"

	"github.com/rongzer/gmssl-go/crypto/hash"

	"github.com/rongzer/gmssl-go/opencrypto/gmssl/gmssl"

	bccrypto "github.com/rongzer/gmssl-go/crypto"
	"github.com/rongzer/gmssl-go/opencrypto/gmssl/gmssl/sm3"
)

type PublicKey struct {
	*gmssl.PublicKey
}

// PublicKey implements bccyrpto.PublicKey
var _ bccrypto.PublicKey = (*PublicKey)(nil)

func (pk *PublicKey) verifyWithSM3(msg, sig []byte, uid string) bool {
	sm2zid, _ := pk.ComputeSM2IDDigest(uid)

	sm3Hash := sm3.New()
	sm3Hash.Write(sm2zid)
	sm3Hash.Write(msg)
	dgst := sm3Hash.Sum(nil)
	if err := pk.PublicKey.Verify("sm2sign", dgst, sig, nil); err != nil {
		return false
	}
	return true
}

func (pk *PublicKey) Bytes() ([]byte, error) {
	pkPem, err := pk.PublicKey.GetPEM()
	if err != nil {
		return nil, err
	}
	p, _ := pem.Decode([]byte(pkPem))
	return p.Bytes, nil
}

func (pk *PublicKey) Type() bccrypto.KeyType {
	return bccrypto.SM2
}

func (pk *PublicKey) String() (string, error) {
	return pk.GetPEM()
}

func (pk *PublicKey) Verify(msg []byte, sig []byte) (bool, error) {
	return pk.verifyWithSM3(msg, sig, utils.SM2_DEFAULT_USER_ID), nil
}

func (pk *PublicKey) VerifyWithOpts(msg []byte, sig []byte, opts *bccrypto.SignOpts) (bool, error) {
	if opts == nil {
		return pk.Verify(msg, sig)
	}
	if opts.Hash == bccrypto.HASH_TYPE_SM3 && pk.Type() == bccrypto.SM2 {
		uid := opts.UID
		if len(uid) == 0 {
			uid = bccrypto.CRYPTO_DEFAULT_UID
		}

		if sig == nil {
			return false, fmt.Errorf("nil signature")
		}
		return pk.verifyWithSM3(msg, sig, uid), nil
	}
	dgst, err := hash.Get(opts.Hash, msg)
	if err != nil {
		return false, err
	}
	return pk.Verify(dgst, sig)
}

//// ToStandardKey nolint
//func (pk *PublicKey) ToStandardKey() crypto.PublicKey {
//	der, err := MarshalPublicKey(pk)
//	if err != nil {
//		fmt.Println("failed to MarshalPublicKey, err = " + err.Error())
//	}
//
//	pub, err := rzx509.ParseSm2PublicKey(der)
//	if err != nil {
//		fmt.Println("failed to ParseSm2PublicKey, err = " + err.Error())
//	}
//	return pub
//}

// PublicKey implements bccyrpto.PublicKey
var _ bccrypto.EncryptKey = (*PublicKey)(nil)

func (pk *PublicKey) EncryptWithOpts(data []byte, opts *bccrypto.EncOpts) ([]byte, error) {
	return pk.Encrypt(data)
}

func (pk *PublicKey) Encrypt(plaintext []byte) ([]byte, error) {
	return pk.PublicKey.Encrypt("sm2encrypt-with-sm3", plaintext, nil)
}

//func P256Sm2(pkPem string) (*PublicKey, error) {
//	pk, err := gmssl.UnmarshalPublicKey(pkPem)
//	if err != nil {
//		return nil, err
//	}
//	pubKey := PublicKey{
//		PublicKey: pk,
//	}
//	return &pubKey, nil
//}
