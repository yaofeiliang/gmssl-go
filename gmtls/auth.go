// Copyright (c) 2022 zhaochun
// gmgo is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

/*
gmtls是基于`golang/go`的`tls`包实现的国密改造版本。
对应版权声明: thrid_licenses/github.com/golang/go/LICENSE
*/

package gmtls

/*
gmtls/auth.go 补充了国密sm2相关处理
*/

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"errors"
	"fmt"
	"hash"
	"io"

	"github.com/rongzer/gmssl-go/opencrypto/gmssl/sm2"
	"github.com/rongzer/gmssl-go/x509"
)

// 使用pubkey，根据sigType选择对应的签名算法对sig进行验签。
//  - sigType : 签名算法
//  - pubkey : 公钥
//  - hashFunc : 散列算法
//  - signed : 签名内容
//  - sig : 签名
// 已补充国密SM2分支
// verifyHandshakeSignature verifies a signature against pre-hashed
// (if required) handshake contents.
func verifyHandshakeSignature(sigType uint8, pubkey crypto.PublicKey, hashFunc x509.Hash, signed, sig []byte) error {
	switch sigType {
	// 补充sm2分支
	case signatureSM2:
		//pubKey, ok := pubkey.(*ecdsa.PublicKey)
		pubKey, ok := pubkey.(*sm2.PublicKey)
		if !ok {
			return fmt.Errorf("expected an SM2 public key, got %T", pubkey)
		}

		//if !sm2.VerifyASN1(pubKey, signed, sig) {
		//    return errors.New("SM2 verification failure")
		//}
		_, err := pubKey.Verify(signed, sig)
		if err != nil {
			return errors.New("SM2 verification failure")
		}
	case signatureECDSA:
		pubKey, ok := pubkey.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("expected an ECDSA public key, got %T", pubkey)
		}
		if !ecdsa.VerifyASN1(pubKey, signed, sig) {
			return errors.New("ECDSA verification failure")
		}
	case signatureEd25519:
		pubKey, ok := pubkey.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("expected an Ed25519 public key, got %T", pubkey)
		}
		if !ed25519.Verify(pubKey, signed, sig) {
			return errors.New("ed25519 verification failure")
		}
	case signaturePKCS1v15:
		pubKey, ok := pubkey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("expected an RSA public key, got %T", pubkey)
		}
		if err := rsa.VerifyPKCS1v15(pubKey, hashFunc.HashFunc(), signed, sig); err != nil {
			return err
		}
	case signatureRSAPSS:
		pubKey, ok := pubkey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("expected an RSA public key, got %T", pubkey)
		}
		signOpts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}
		if err := rsa.VerifyPSS(pubKey, hashFunc.HashFunc(), signed, sig, signOpts); err != nil {
			return err
		}
	default:
		return errors.New("internal error: unknown signature type")
	}
	return nil
}

const (
	serverSignatureContext = "TLS 1.3, server CertificateVerify\x00"
	clientSignatureContext = "TLS 1.3, client CertificateVerify\x00"
)

// 签名填充
var signaturePadding = []byte{
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
}

// 生成一个前置的消息散列，用于证书公私钥的签名与验签。
// signedMessage returns the pre-hashed (if necessary) message to be signed by
// certificate keys in TLS 1.3. See RFC 8446, Section 4.4.3.
func signedMessage(sigHash x509.Hash, context string, transcript hash.Hash) []byte {
	// directSigning 表示不做签名内容的前置散列
	if sigHash == directSigning {
		b := &bytes.Buffer{}
		b.Write(signaturePadding)
		_, err := io.WriteString(b, context)
		if err != nil {
			return nil
		}
		b.Write(transcript.Sum(nil))
		return b.Bytes()
	}
	h := sigHash.New()
	h.Write(signaturePadding)
	_, err := io.WriteString(h, context)
	if err != nil {
		return nil
	}
	h.Write(transcript.Sum(nil))
	return h.Sum(nil)
}

// 获取签名算法与散列算法
//  已补充国密SM2签名算法分支
// typeAndHashFromSignatureScheme returns the corresponding signature type and
// crypto.Hash for a given TLS SignatureScheme.
func typeAndHashFromSignatureScheme(signatureAlgorithm SignatureScheme) (sigType uint8, hash x509.Hash, err error) {
	switch signatureAlgorithm {
	// 补充国密SM2签名算法
	case SM2WITHSM3:
		sigType = signatureSM2
	case PKCS1WithSHA1, PKCS1WithSHA256, PKCS1WithSHA384, PKCS1WithSHA512:
		sigType = signaturePKCS1v15
	case PSSWithSHA256, PSSWithSHA384, PSSWithSHA512:
		sigType = signatureRSAPSS
	case ECDSAWithSHA1, ECDSAWithP256AndSHA256, ECDSAWithP384AndSHA384, ECDSAWithP521AndSHA512:
		sigType = signatureECDSA
	case Ed25519:
		sigType = signatureEd25519
	default:
		return 0, 0, fmt.Errorf("unsupported signature algorithm: %v", signatureAlgorithm)
	}
	// 签名算法
	switch signatureAlgorithm {
	// 补充国密SM3散列算法
	case SM2WITHSM3:
		hash = x509.SM3
	case PKCS1WithSHA1, ECDSAWithSHA1:
		hash = x509.SHA1
	case PKCS1WithSHA256, PSSWithSHA256, ECDSAWithP256AndSHA256:
		hash = x509.SHA256
	case PKCS1WithSHA384, PSSWithSHA384, ECDSAWithP384AndSHA384:
		hash = x509.SHA384
	case PKCS1WithSHA512, PSSWithSHA512, ECDSAWithP521AndSHA512:
		hash = x509.SHA512
	case Ed25519:
		hash = directSigning
	default:
		return 0, 0, fmt.Errorf("unsupported signature algorithm: %v", signatureAlgorithm)
	}
	return sigType, hash, nil
}

// 已补充国密SM2分支
// legacyTypeAndHashFromPublicKey returns the fixed signature type and crypto.Hash for
// a given public key used with TLS 1.0 and 1.1, before the introduction of
// signature algorithm negotiation.
// 从公钥遗产类型和散列 遗产类型从公钥和散列返回固定的签名和加密类型。哈希对于一个给定的公共密钥使用TLS 1.0和1.1,之前签名算法的引入谈判。
func legacyTypeAndHashFromPublicKey(pub crypto.PublicKey) (sigType uint8, hash x509.Hash, err error) {
	switch pub.(type) {
	// 补充sm2分支
	case *sm2.PublicKey:
		return signatureSM2, x509.SM3, nil
	case *rsa.PublicKey:
		return signaturePKCS1v15, x509.MD5SHA1, nil
	case *ecdsa.PublicKey:
		return signatureECDSA, x509.SHA1, nil
	case ed25519.PublicKey:
		// RFC 8422 specifies support for Ed25519 in TLS 1.0 and 1.1,
		// but it requires holding on to a handshake transcript to do a
		// full signature, and not even OpenSSL bothers with the
		// complexity, so we can't even test it properly.
		// RFC 8422指定支持Ed25519 TLS 1.0和1.1,但它需要持有一个握手记录做一个完整的签名,甚至不是开放SSL困扰的复杂性,我们甚至不能正确地测试它。
		return 0, 0, fmt.Errorf("gmtls: Ed25519 public keys are not supported before TLS 1.2")
	default:
		return 0, 0, fmt.Errorf("gmtls: unsupported public key: %T", pub)
	}
}

// rsa签名方案
var rsaSignatureSchemes = []struct {
	scheme          SignatureScheme // 签名方案标识一个签名算法支持TLS。看到RFC 8446, 4.2.3节。
	minModulusBytes int
	maxVersion      uint16
}{
	// RSA-PSS is used with PSSSaltLengthEqualsHash, and requires
	//    emLen >= hLen + sLen + 2
	// 使用RSA - PSS PSSSalt长度等于散列,并要求他们Len Len > = h + s Len + 2
	{PSSWithSHA256, crypto.SHA256.Size()*2 + 2, VersionTLS13},
	{PSSWithSHA384, crypto.SHA384.Size()*2 + 2, VersionTLS13},
	{PSSWithSHA512, crypto.SHA512.Size()*2 + 2, VersionTLS13},
	// PKCS #1 v1.5 uses prefixes from hashPrefixes in crypto/rsa, and requires
	//    emLen >= len(prefix) + hLen + 11
	// TLS 1.3 dropped support for PKCS #1 v1.5 in favor of RSA-PSS.
	// PKCS # 1 v1.5使用前缀从加密散列前缀/ rsa,并要求他们Len > = Len(前缀)+ h Len + 11 TLS 1.3支持下降PKCS # 1 v1.5赞成rsa - PSS。
	{PKCS1WithSHA256, 19 + crypto.SHA256.Size() + 11, VersionTLS12},
	{PKCS1WithSHA384, 19 + crypto.SHA384.Size() + 11, VersionTLS12},
	{PKCS1WithSHA512, 19 + crypto.SHA512.Size() + 11, VersionTLS12},
	{PKCS1WithSHA1, 15 + crypto.SHA1.Size() + 11, VersionTLS12},
}

// 已补充国密SM2分支
// signatureSchemesForCertificate returns the list of supported SignatureSchemes
// for a given certificate, based on the public key and the protocol version,
// and optionally filtered by its explicit SupportedSignatureAlgorithms.
//
// This function must be kept in sync with supportedSignatureAlgorithms.
// 证书签名方案 证书签名方案返回的列表支持对一个给定的证书签名方案,基于公钥协议版本,并选择性地过滤的显式支持签名算法。这个函数必须保持同步支持签名算法。
func signatureSchemesForCertificate(version uint16, cert *Certificate) []SignatureScheme {
	priv, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		return nil
	}
	var sigAlgs []SignatureScheme
	switch pub := priv.Public().(type) {
	// 补充国密sm2分支
	case *sm2.PublicKey:
		sigAlgs = []SignatureScheme{SM2WITHSM3}
	case sm2.PublicKey:
		sigAlgs = []SignatureScheme{SM2WITHSM3}
	case *ecdsa.PublicKey:
		if version != VersionTLS13 {
			// In TLS 1.2 and earlier, ECDSA algorithms are not
			// constrained to a single curve.
			// 在TLS 1.2和更早的ECDSA算法并不局限于单一的曲线。
			sigAlgs = []SignatureScheme{
				ECDSAWithP256AndSHA256,
				ECDSAWithP384AndSHA384,
				ECDSAWithP521AndSHA512,
				ECDSAWithSHA1,
			}
			break
		}
		switch pub.Curve {
		case elliptic.P256():
			sigAlgs = []SignatureScheme{ECDSAWithP256AndSHA256}
		case elliptic.P384():
			sigAlgs = []SignatureScheme{ECDSAWithP384AndSHA384}
		case elliptic.P521():
			sigAlgs = []SignatureScheme{ECDSAWithP521AndSHA512}
		default:
			return nil
		}
	case *rsa.PublicKey:
		size := pub.Size()
		// rsa签名方案
		sigAlgs = make([]SignatureScheme, 0, len(rsaSignatureSchemes))
		for _, candidate := range rsaSignatureSchemes {
			//          候选人.最小模量字节                          候选人.最大版本
			if size >= candidate.minModulusBytes && version <= candidate.maxVersion {
				sigAlgs = append(sigAlgs, candidate.scheme)
			}
		}
	case ed25519.PublicKey:
		sigAlgs = []SignatureScheme{Ed25519}
	default:
		return nil
	}
	// 如果证书提供了支持签名算法信息，则检查是否与私钥对应的签名算法匹配，
	// 支持签名算法  并返回匹配的签名算法集合
	if cert.SupportedSignatureAlgorithms != nil {
		var filteredSigAlgs []SignatureScheme
		for _, sigAlg := range sigAlgs {
			// 支持签名算法
			if isSupportedSignatureAlgorithm(sigAlg, cert.SupportedSignatureAlgorithms) {
				filteredSigAlgs = append(filteredSigAlgs, sigAlg)
			}
		}
		// 过滤团体alg
		return filteredSigAlgs
	}
	// 若证书没有提供支持签名算法信息，则直接返回私钥支持的签名算法集合
	return sigAlgs
}

// selectSignatureScheme picks a SignatureScheme from the peer's preference list
// that works with the selected certificate. It's only called for protocol
// versions that support signature algorithms, so TLS 1.2 and 1.3.
// 选择签名方案 选择签名方案选择同行的签名方案的偏好与选择的证书列表。只有呼吁支持签名算法的协议版本,所以TLS 1.2和1.3。
func selectSignatureScheme(vers uint16, c *Certificate, peerAlgs []SignatureScheme) (SignatureScheme, error) {
	// 获取证书支持的签名算法
	supportedAlgs := signatureSchemesForCertificate(vers, c)
	if len(supportedAlgs) == 0 {
		return 0, unsupportedCertificateError(c)
	}
	if len(peerAlgs) == 0 && vers == VersionTLS12 {
		// For TLS 1.2, if the client didn't send signature_algorithms then we
		// can assume that it supports SHA1. See RFC 5246, Section 7.4.1.4.1.
		// 补充VersionTLS12下的国密签名算法组件
		peerAlgs = []SignatureScheme{SM2WITHSM3, PKCS1WithSHA1, ECDSAWithSHA1}
	}
	// Pick signature scheme in the peer's preference order, as our
	// preference order is not configurable.
	for _, preferredAlg := range peerAlgs {
		if isSupportedSignatureAlgorithm(preferredAlg, supportedAlgs) {
			// 返回第一个匹配的签名算法
			return preferredAlg, nil
		}
	}
	return 0, errors.New("gmtls: peer doesn't support any of the certificate's signature algorithms")
}

// 已补充国密sm2对应
// unsupportedCertificateError returns a helpful error for certificates with
// an unsupported private key.
// 不支持的证书错误 不支持的证书错误返回一个有帮助的错误与不受支持的私钥证书。
func unsupportedCertificateError(cert *Certificate) error {
	switch cert.PrivateKey.(type) {
	// 补充sm2匹配条件
	case rsa.PrivateKey, ecdsa.PrivateKey, sm2.PrivateKey:
		return fmt.Errorf("gmtls: unsupported certificate: private key is %T, expected *%T",
			cert.PrivateKey, cert.PrivateKey)
	case *ed25519.PrivateKey:
		return fmt.Errorf("gmtls: unsupported certificate: private key is *ed25519.PrivateKey, expected ed25519.PrivateKey")
	}

	signer, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		return fmt.Errorf("gmtls: certificate private key (%T) does not implement crypto.Signer",
			cert.PrivateKey)
	}

	switch pub := signer.Public().(type) {
	// 补充sm2分支
	case *sm2.PublicKey:
		//switch pub.Curve {
		//case sm2.P256Sm2():
		//default:
		//	return fmt.Errorf("gmtls: unsupported certificate curve (%s)", pub.Curve.Params().Name)
		//}
		return fmt.Errorf("gmtls: unsupported certificate  (%T)", pub)
	case *ecdsa.PublicKey:
		switch pub.Curve {
		case elliptic.P256():
		case elliptic.P384():
		case elliptic.P521():
		default:
			return fmt.Errorf("gmtls: unsupported certificate curve (%s)", pub.Curve.Params().Name)
		}
	case *rsa.PublicKey:
		return fmt.Errorf("gmtls: certificate RSA key size too small for supported signature algorithms")
	case ed25519.PublicKey:
	default:
		return fmt.Errorf("gmtls: unsupported certificate key (%T)", pub)
	}

	if cert.SupportedSignatureAlgorithms != nil {
		return fmt.Errorf("gmtls: peer doesn't support the certificate custom signature algorithms")
	}

	return fmt.Errorf("gmtls: internal error: unsupported key (%T)", cert.PrivateKey)
}
