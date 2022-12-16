/*
Copyright Suzhou Tongji Fintech Research Institute 2017 All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package x509

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"hash"
	"reflect"

	"github.com/rongzer/gmssl-go/opencrypto/gmssl/sm2"
)

/*
 * reference to RFC5959 and RFC2898
 */

var (
	oidPBES1  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 3}  // pbeWithMD5AndDES-CBC(PBES1)
	oidPBES2  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13} // id-PBES2(PBES2)
	oidPBKDF2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12} // id-PBKDF2

	oidKEYMD5    = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 5}
	oidKEYSHA1   = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}
	oidKEYSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidKEYSHA512 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11}

	oidAES128CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	oidAES256CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}

	//oidSM2 = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidSM2 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301}
)

// reference to https://www.rfc-editor.org/rfc/rfc5958.txt
type PrivateKeyInfo struct {
	Version             int // v1 or v2
	PrivateKeyAlgorithm []asn1.ObjectIdentifier
	PrivateKey          []byte
}

// reference to https://www.rfc-editor.org/rfc/rfc5958.txt
type EncryptedPrivateKeyInfo struct {
	EncryptionAlgorithm Pbes2Algorithms
	EncryptedData       []byte
}

// reference to https://www.ietf.org/rfc/rfc2898.txt
type Pbes2Algorithms struct {
	IdPBES2     asn1.ObjectIdentifier
	Pbes2Params Pbes2Params
}

// reference to https://www.ietf.org/rfc/rfc2898.txt
type Pbes2Params struct {
	KeyDerivationFunc Pbes2KDfs // PBES2-KDFs
	EncryptionScheme  Pbes2Encs // PBES2-Encs
}

// reference to https://www.ietf.org/rfc/rfc2898.txt
type Pbes2KDfs struct {
	IdPBKDF2    asn1.ObjectIdentifier
	Pkdf2Params Pkdf2Params
}

type Pbes2Encs struct {
	EncryAlgo asn1.ObjectIdentifier
	IV        []byte
}

// reference to https://www.ietf.org/rfc/rfc2898.txt
type Pkdf2Params struct {
	Salt           []byte
	IterationCount int
	Prf            pkix.AlgorithmIdentifier
}

type sm2PrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

type pkcs8 struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
}

// copy from crypto/pbkdf2.go
func pbkdf(password, salt []byte, iter, keyLen int, h func() hash.Hash) []byte {
	prf := hmac.New(h, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen

	var buf [4]byte
	dk := make([]byte, 0, numBlocks*hashLen)
	U := make([]byte, hashLen)
	for block := 1; block <= numBlocks; block++ {
		// N.B.: || means concatenation, ^ means XOR
		// for each block T_i = U_1 ^ U_2 ^ ... ^ U_iter
		// U_1 = PRF(password, salt || uint(i))
		prf.Reset()
		prf.Write(salt)
		buf[0] = byte(block >> 24)
		buf[1] = byte(block >> 16)
		buf[2] = byte(block >> 8)
		buf[3] = byte(block)
		prf.Write(buf[:4])
		dk = prf.Sum(dk)
		T := dk[len(dk)-hashLen:]
		copy(U, T)

		// U_n = PRF(password, U_(n-1))
		for n := 2; n <= iter; n++ {
			prf.Reset()
			prf.Write(U)
			U = U[:0]
			U = prf.Sum(U)
			for x := range U {
				T[x] ^= U[x]
			}
		}
	}
	return dk[:keyLen]
}

func ParseSm2PublicKey(der []byte) (*sm2.PublicKey, error) {
	var pubkey pkixPublicKey

	if _, err := asn1.Unmarshal(der, &pubkey); err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(pubkey.Algo.Algorithm, oidSM2) {
		return nil, errors.New("x509: not sm2 elliptic curve")
	}
	pub, err := sm2.UnmarshalPublicKey(pubkey.BitString.Bytes)
	if err != nil {
		return nil, err
	}
	return pub, nil
}

func MarshalSm2PublicKey(key *sm2.PublicKey) ([]byte, error) {
	return key.Bytes()
	//var r pkixPublicKey
	//var algo pkix.AlgorithmIdentifier
	//
	////if key.Curve.Params() != sm2.P256Sm2().Params() {
	////	return nil, errors.New("x509: unsupported elliptic curve")
	////}
	//algo.Algorithm = oidSM2
	//algo.Parameters.Class = 0
	//algo.Parameters.Tag = 6
	//algo.Parameters.IsCompound = false
	//algo.Parameters.FullBytes = []byte{6, 8, 42, 129, 28, 207, 85, 1, 130, 45} // asn1.Marshal(asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301})
	//r.Algo = algo
	//publicKey, err := sm2.MarshalPublicKey(key)
	//if err != nil {
	//	return nil, err
	//}
	//r.BitString = asn1.BitString{Bytes: publicKey}
	//return asn1.Marshal(r)
}

func ParseSm2PrivateKey(der []byte) (*sm2.PrivateKey, error) {

	return sm2.UnmarshalPrivateKey(der)

}

func ParsePKCS8UnecryptedPrivateKey(der []byte) (*sm2.PrivateKey, error) {
	return sm2.UnmarshalPrivateKey(der)
}

func ParsePKCS8EcryptedPrivateKey(der, pwd []byte) (*sm2.PrivateKey, error) {
	return sm2.UnmarshalPrivateKey(der)
}

//func ParsePKCS8PrivateKey(der, pwd []byte) (*sm2.PrivateKey, error) {
//	return sm2.UnmarshalPrivateKey(der)
//}
func ParsePKCS8PrivateKey(der []byte, pwd []byte) (key any, err error) {

	gmKey, err := sm2.UnmarshalPrivateKey(der)
	if err == nil {
		return gmKey, err
	}

	var privKey pkcs8
	if _, err := asn1.Unmarshal(der, &privKey); err != nil {
		return nil, err
	}
	switch {
	//case privKey.Algo.Algorithm.Equal(oidPublicKeySM2):
	//	return sm2.UnmarshalPrivateKey(der)
	case privKey.Algo.Algorithm.Equal(oidPublicKeyRSA):
		key, err = ParsePKCS1PrivateKey(privKey.PrivateKey)
		if err != nil {
			return nil, errors.New("x509: failed to parse RSA private key embedded in PKCS#8: " + err.Error())
		}
		return key, nil

	case privKey.Algo.Algorithm.Equal(oidPublicKeyECDSA):
		bytes := privKey.Algo.Parameters.FullBytes
		namedCurveOID := new(asn1.ObjectIdentifier)
		if _, err := asn1.Unmarshal(bytes, namedCurveOID); err != nil {
			namedCurveOID = nil
		}
		key, err = parseECPrivateKey(namedCurveOID, privKey.PrivateKey)
		if err != nil {
			return nil, errors.New("x509: failed to parse EC private key embedded in PKCS#8: " + err.Error())
		}
		return key, nil

	case privKey.Algo.Algorithm.Equal(oidPublicKeyEd25519):
		if l := len(privKey.Algo.Parameters.FullBytes); l != 0 {
			return nil, errors.New("x509: invalid Ed25519 private key parameters")
		}
		var curvePrivateKey []byte
		if _, err := asn1.Unmarshal(privKey.PrivateKey, &curvePrivateKey); err != nil {
			return nil, fmt.Errorf("x509: invalid Ed25519 private key: %v", err)
		}
		if l := len(curvePrivateKey); l != ed25519.SeedSize {
			return nil, fmt.Errorf("x509: invalid Ed25519 private key length: %d", l)
		}
		return ed25519.NewKeyFromSeed(curvePrivateKey), nil

	default:
		return nil, fmt.Errorf("x509: PKCS#8 wrapping contained private key with unknown algorithm: %v", privKey.Algo.Algorithm)
	}
}

func MarshalSm2UnecryptedPrivateKey(key *sm2.PrivateKey) ([]byte, error) {
	return sm2.MarshalPrivateKey(key)
	//var r pkcs8
	//var priv sm2PrivateKey
	//var algo pkix.AlgorithmIdentifier
	//
	//algo.Algorithm = oidSM2
	//algo.Parameters.Class = 0
	//algo.Parameters.Tag = 6
	//algo.Parameters.IsCompound = false
	//algo.Parameters.FullBytes = []byte{6, 8, 42, 129, 28, 207, 85, 1, 130, 45} // asn1.Marshal(asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301})
	//priv.Version = 1
	//priv.NamedCurveOID = oidNamedCurveP256SM2
	//
	//skPem, err := key.GetUnencryptedPEM()
	//if err != nil {
	//	return nil, err
	//}
	//p, _ := pem.Decode([]byte(skPem))
	//if p == nil {
	//	return nil, errors.New("invalid private key pem")
	//}
	//pkPem, err := key.GetPublicKeyPEM()
	//if err != nil {
	//	return nil, err
	//}
	//pub, err := sm2.PublicKeyFromPEM(pkPem)
	//if err != nil {
	//	return nil, err
	//}
	//
	//privateKeyDer, err := sm2.MarshalPrivateKey(key)
	//if err != nil {
	//	return nil, err
	//}
	//
	//publicKeyDer, err := sm2.MarshalPublicKey(pub)
	//if err != nil {
	//	return nil, err
	//}
	//priv.PublicKey = asn1.BitString{Bytes: publicKeyDer}
	//priv.PrivateKey = privateKeyDer
	//r.Version = 0
	//r.Algo = algo
	//r.PrivateKey, _ = asn1.Marshal(priv)
	//return asn1.Marshal(r)
}

func MarshalSm2EcryptedPrivateKey(PrivKey *sm2.PrivateKey, pwd []byte) ([]byte, error) {
	return sm2.MarshalPrivateKey(PrivKey)
	//der, err := MarshalSm2UnecryptedPrivateKey(PrivKey)
	//if err != nil {
	//	return nil, err
	//}
	//iter := 2048
	//salt := make([]byte, 8)
	//iv := make([]byte, 16)
	//rand.Reader.Read(salt)
	//rand.Reader.Read(iv)
	//key := pbkdf(pwd, salt, iter, 32, sha1.New) // 默认是SHA1
	//padding := aes.BlockSize - len(der)%aes.BlockSize
	//if padding > 0 {
	//	n := len(der)
	//	der = append(der, make([]byte, padding)...)
	//	for i := 0; i < padding; i++ {
	//		der[n+i] = byte(padding)
	//	}
	//}
	//encryptedKey := make([]byte, len(der))
	//block, err := aes.NewCipher(key)
	//if err != nil {
	//	return nil, err
	//}
	//mode := cipher.NewCBCEncrypter(block, iv)
	//mode.CryptBlocks(encryptedKey, der)
	//var algorithmIdentifier pkix.AlgorithmIdentifier
	//algorithmIdentifier.Algorithm = oidKEYSHA1
	//algorithmIdentifier.Parameters.Tag = 5
	//algorithmIdentifier.Parameters.IsCompound = false
	//algorithmIdentifier.Parameters.FullBytes = []byte{5, 0}
	//keyDerivationFunc := Pbes2KDfs{
	//	oidPBKDF2,
	//	Pkdf2Params{
	//		salt,
	//		iter,
	//		algorithmIdentifier,
	//	},
	//}
	//encryptionScheme := Pbes2Encs{
	//	oidAES256CBC,
	//	iv,
	//}
	//pbes2Algorithms := Pbes2Algorithms{
	//	oidPBES2,
	//	Pbes2Params{
	//		keyDerivationFunc,
	//		encryptionScheme,
	//	},
	//}
	//encryptedPkey := EncryptedPrivateKeyInfo{
	//	pbes2Algorithms,
	//	encryptedKey,
	//}
	//return asn1.Marshal(encryptedPkey)
}

func MarshalSm2PrivateKey(key *sm2.PrivateKey, pwd []byte) ([]byte, error) {
	if pwd == nil {
		return MarshalSm2UnecryptedPrivateKey(key)
	}
	return MarshalSm2EcryptedPrivateKey(key, pwd)
}
