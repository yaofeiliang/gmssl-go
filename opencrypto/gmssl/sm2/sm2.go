/*
Copyright (C) BABEC. All rights reserved.
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sm2

import (
	"crypto"
	"encoding/asn1"
	"encoding/pem"
	"github.com/rongzer/gmssl-go/opencrypto/utils"
	"io"
	"math/big"

	"github.com/pkg/errors"
	"github.com/rongzer/gmssl-go/opencrypto/gmssl/gmssl"
)

func GenerateKeyPair() (*PrivateKey, error) {
	sm2keygenargs := &gmssl.PkeyCtxParams{
		Keys:   []string{"ec_paramgen_curve", "ec_param_enc"},
		Values: []string{"sm2p256v1", "named_curve"},
	}
	sk, err := gmssl.GeneratePrivateKey("EC", sm2keygenargs, nil)
	if err != nil {
		return nil, err
	}
	skPem, err := sk.GetUnencryptedPEM()
	if err != nil {
		return nil, err
	}
	p, _ := pem.Decode([]byte(skPem))
	if p == nil {
		return nil, errors.New("invalid private key pem")
	}

	pkPem, err := sk.GetPublicKeyPEM()
	if err != nil {
		return nil, err
	}
	pk, err := gmssl.NewPublicKeyFromPEM(pkPem)
	if err != nil {
		return nil, err
	}

	pubKey := PublicKey{
		PublicKey: pk,
	}

	return &PrivateKey{PrivateKey: sk, Pub: pubKey}, nil
}

type signer struct {
	PrivateKey
}

//this is for crypto.Signer impl
func (s *signer) Public() crypto.PublicKey {
	return s.PublicKey()
}

func (s *signer) Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.PrivateKey.signWithSM3(msg, utils.SM2_DEFAULT_USER_ID)
}

type sm2Cipher struct {
	XCoordinate *big.Int
	YCoordinate *big.Int
	HASH        []byte
	CipherText  []byte
}

// 32byte
func zeroByteSlice() []byte {
	return []byte{
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
	}
}

/*
*sm2密文转asn.1编码格式
*sm2密文结构如下:
*  x
*  y
*  hash
*  CipherText
 */
func CipherMarshal(data []byte) ([]byte, error) {
	data = data[1:]
	x := new(big.Int).SetBytes(data[:32])
	y := new(big.Int).SetBytes(data[32:64])
	hash := data[64:96]
	cipherText := data[96:]
	return asn1.Marshal(sm2Cipher{x, y, hash, cipherText})
}

/*
sm2密文asn.1编码格式转C1|C3|C2拼接格式
*/
func CipherUnmarshal(data []byte) ([]byte, error) {
	var cipher sm2Cipher
	_, err := asn1.Unmarshal(data, &cipher)
	if err != nil {
		return nil, err
	}
	x := cipher.XCoordinate.Bytes()
	y := cipher.YCoordinate.Bytes()
	hash := cipher.HASH
	if err != nil {
		return nil, err
	}
	cipherText := cipher.CipherText
	if err != nil {
		return nil, err
	}
	if n := len(x); n < 32 {
		x = append(zeroByteSlice()[:32-n], x...)
	}
	if n := len(y); n < 32 {
		y = append(zeroByteSlice()[:32-n], y...)
	}
	c := []byte{}
	c = append(c, x...)          // x分量
	c = append(c, y...)          // y分
	c = append(c, hash...)       // x分量
	c = append(c, cipherText...) // y分
	return append([]byte{0x04}, c...), nil
}

func PemToSm2PrivateKey(raw []byte, pwd []byte) (*PrivateKey, error) {
	privateKey, err := gmssl.NewPrivateKeyFromPEM(string(raw), string(pwd))
	if err != nil {
		return nil, err
	}
	pubPEM, err := privateKey.GetPublicKeyPEM()
	if err != nil {
		return nil, err
	}
	publicKey, err := gmssl.NewPublicKeyFromPEM(pubPEM)
	if err != nil {
		return nil, err
	}
	pub := PublicKey{publicKey}
	sm2PrivateKey := &PrivateKey{privateKey, pub}
	return sm2PrivateKey, nil
}
