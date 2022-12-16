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

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/rc4"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"hash"
	"runtime"

	"github.com/rongzer/gmssl-go/internal/cpu"
	"github.com/rongzer/gmssl-go/opencrypto/gmssl/sm4"
	"github.com/rongzer/gmssl-go/x509"
	"golang.org/x/crypto/chacha20poly1305"
)

// CipherSuite is a TLS cipher suite. Note that most functions in this package
// accept and expose cipher suite IDs instead of this type.
// 密码学套件结构体 // 密码套件是TLS密码套件。注意,大多数函数在这个包中接受这种类型id,而不是和公开密码套件。
type CipherSuite struct {
	ID   uint16
	Name string

	// Supported versions is the list of TLS protocol versions that can
	// negotiate this cipher suite.
	// 支持版本是TLS协议版本的列表,可以协商这个密码套件。
	SupportedVersions []uint16 // 支持版本

	// Insecure is true if the cipher suite has known security issues
	// due to its primitives, design, or implementation.
	// 不安全的是正确的密码套件是否有已知的安全问题由于其原语,设计、实现。
	Insecure bool // 不安全的
}

var (
	supportedUpToTLS12 = []uint16{VersionTLS10, VersionTLS11, VersionTLS12} //支持多达TLS12
	supportedOnlyTLS12 = []uint16{VersionTLS12}                             // 只支持TLS12
	supportedOnlyTLS13 = []uint16{VersionTLS13}                             // 只支持TLS13
	// 补充上国密SSL, 其实现与国密改造后的tls1.3一致
	supportedTLS13AndGMSSL = []uint16{VersionTLS13, VersionGMSSL} // 支持TLS13和GMSSL
)

// CipherSuites 返回此包当前实现的密码套件列表，不包括由 InsecureCipherSuites 返回的有安全问题的密码套件。
// CipherSuites returns a list of cipher suites currently implemented by this
// package, excluding those with security issues, which are returned by
// InsecureCipherSuites.
//
// The list is sorted by ID. Note that the default cipher suites selected by
// this package might depend on logic that can't be captured by a static list,
// and might not match those returned by this function.
// 密码套件 密码套件返回一个列表的密码套件目前实施这一方案,排除那些有安全问题,返回的不安全的密码套件。
// 按ID列表。请注意,默认密码套件选择这个包可能取决于逻辑不能捕捉到一个静态列表,并且可能不匹配所返回的这个函数。
func CipherSuites() []*CipherSuite {
	return []*CipherSuite{
		{TLS_RSA_WITH_AES_128_CBC_SHA, "TLS_RSA_WITH_AES_128_CBC_SHA", supportedUpToTLS12, false},
		{TLS_RSA_WITH_AES_256_CBC_SHA, "TLS_RSA_WITH_AES_256_CBC_SHA", supportedUpToTLS12, false},
		{TLS_RSA_WITH_AES_128_GCM_SHA256, "TLS_RSA_WITH_AES_128_GCM_SHA256", supportedOnlyTLS12, false},
		{TLS_RSA_WITH_AES_256_GCM_SHA384, "TLS_RSA_WITH_AES_256_GCM_SHA384", supportedOnlyTLS12, false},

		{TLS_AES_128_GCM_SHA256, "TLS_AES_128_GCM_SHA256", supportedOnlyTLS13, false},
		{TLS_AES_256_GCM_SHA384, "TLS_AES_256_GCM_SHA384", supportedOnlyTLS13, false},
		{TLS_CHACHA20_POLY1305_SHA256, "TLS_CHACHA20_POLY1305_SHA256", supportedOnlyTLS13, false},
		// 补充国密套件 TLS_SM4_GCM_SM3 ，在 VersionTLS13, VersionGMSSL 中可以使用
		{TLS_SM4_GCM_SM3, "TLS_SM4_GCM_SM3", supportedTLS13AndGMSSL, false},

		{TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", supportedUpToTLS12, false},
		{TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", supportedUpToTLS12, false},
		{TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", supportedUpToTLS12, false},
		{TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", supportedUpToTLS12, false},
		{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", supportedOnlyTLS12, false},
		{TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", supportedOnlyTLS12, false},
		{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", supportedOnlyTLS12, false},
		{TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", supportedOnlyTLS12, false},
		{TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", supportedOnlyTLS12, false},
		{TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", supportedOnlyTLS12, false},
		// 暂不提供 tls1.2 的国密密码学套件
		// {TLS_ECDHE_SM2_WITH_SM4_128_CBC_SM3, "TLS_ECDHE_SM2_WITH_SM4_128_CBC_SM3", supportedOnlyTLS12, false},
	}
}

// InsecureCipherSuites returns a list of cipher suites currently implemented by
// this package and which have security issues.
//
// Most applications should not use the cipher suites in this list, and should
// only use those returned by CipherSuites.
// 不安全的密码套件返回一个列表的密码套件目前由这个包实现和安全问题。
// 大多数应用程序不应该使用这个列表中的密码套件,并且应该只使用这些返回的密码套件。
func InsecureCipherSuites() []*CipherSuite {
	// This list includes RC4, CBC_SHA256, and 3DES cipher suites. See
	// cipherSuitesPreferenceOrder for details.
	// 这个列表包括RC4, CBC SHA256和3 DES密码套件。有关详细信息,请参阅密码套件的偏好顺序。
	return []*CipherSuite{
		{TLS_RSA_WITH_RC4_128_SHA, "TLS_RSA_WITH_RC4_128_SHA", supportedUpToTLS12, true},
		{TLS_RSA_WITH_3DES_EDE_CBC_SHA, "TLS_RSA_WITH_3DES_EDE_CBC_SHA", supportedUpToTLS12, true},
		{TLS_RSA_WITH_AES_128_CBC_SHA256, "TLS_RSA_WITH_AES_128_CBC_SHA256", supportedOnlyTLS12, true},
		{TLS_ECDHE_ECDSA_WITH_RC4_128_SHA, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", supportedUpToTLS12, true},
		{TLS_ECDHE_RSA_WITH_RC4_128_SHA, "TLS_ECDHE_RSA_WITH_RC4_128_SHA", supportedUpToTLS12, true},
		{TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", supportedUpToTLS12, true},
		{TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", supportedOnlyTLS12, true},
		{TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", supportedOnlyTLS12, true},
	}
}

// CipherSuiteName returns the standard name for the passed cipher suite ID
// (e.g. "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"), or a fallback representation
// of the ID value if the cipher suite is not implemented by this package.
// 密码套件名称 密码套件名称返回标准的名称通过密码套件ID(例如。“TLS ECDHE ECDSA AES 128 GCM SHA256”),或回退的ID值表示这个包如果没有实现的密码套件。
func CipherSuiteName(id uint16) string {
	for _, c := range CipherSuites() { // 密码套件
		if c.ID == id {
			return c.Name
		}
	}
	for _, c := range InsecureCipherSuites() { // 不安全的密码套件
		if c.ID == id {
			return c.Name
		}
	}
	return fmt.Sprintf("0x%04X", id)
}

const (
	// suiteECDHE indicates that the cipher suite involves elliptic curve
	// Diffie-Hellman. This means that it should only be selected when the
	// client indicates that it supports ECC with a curve and point format
	// that we're happy with.
	// 套件ECDHE表明密码套件包括椭圆曲线Diffie -赫尔曼。这意味着它应该只被选中当客户机表明它支持ECC曲线和点格式,我们满意。
	suiteECDHE = 1 << iota
	// suiteECSign indicates that the cipher suite involves an ECDSA or
	// EdDSA signature and therefore may only be selected when the server's
	// certificate is ECDSA or EdDSA. If this is not set then the cipher suite
	// is RSA based.
	// suiteECSign 表示密码套件涉及 ECDSA 或 EdDSA 签名因此只能在服务器的时候被选中证书是 ECDSA 或 EdDSA。 如果未设置，则密码套件基于 RSA。
	suiteECSign
	// suiteTLS12 indicates that the cipher suite should only be advertised
	// and accepted when using TLS 1.2.
	// 套件TLS12表明密码套件只能宣传和接受当使用TLS 1.2。
	suiteTLS12
	// suiteSHA384 indicates that the cipher suite uses SHA384 as the
	// handshake hash.
	// 套件SHA384表明密码套件使用SHA384作为握手散列。
	suiteSHA384
)

// A cipherSuite is a TLS 1.0–1.2 cipher suite, and defines the key exchange
// mechanism, as well as the cipher+MAC pair or the AEAD.
// 密码套件是一个TLS 1.0 - -1.2密码套件,并定义密钥交换机制,以及密码+ MAC或AEAD。
type cipherSuite struct {
	id uint16
	// the lengths, in bytes, of the key material needed for each component.
	// 长度的字节,每个组件所需的关键材料。
	keyLen int
	macLen int
	ivLen  int
	ka     func(version uint16) keyAgreement
	// flags is a bitmask of the suite* values, above.
	// 国旗是一个套件的位掩码值,以上。
	flags  int
	cipher func(key, iv []byte, isRead bool) interface{}
	mac    func(key []byte) hash.Hash
	aead   func(key, fixedNonce []byte) aead
}

// TLS 1.0–1.2的密码学套件集合 暂时没有添加对应的国密密码学套件
var cipherSuites = []*cipherSuite{ // 替换为一个地图,因为订单没关系。  replace with a map, since the order doesn't matter.
	{TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305, 32, 0, 12, ecdheRSAKA, suiteECDHE | suiteTLS12, nil, nil, aeadChaCha20Poly1305},
	{TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, 32, 0, 12, ecdheECDSAKA, suiteECDHE | suiteECSign | suiteTLS12, nil, nil, aeadChaCha20Poly1305},
	{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, 16, 0, 4, ecdheRSAKA, suiteECDHE | suiteTLS12, nil, nil, aeadAESGCM},
	{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, 16, 0, 4, ecdheECDSAKA, suiteECDHE | suiteECSign | suiteTLS12, nil, nil, aeadAESGCM},
	{TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, 32, 0, 4, ecdheRSAKA, suiteECDHE | suiteTLS12 | suiteSHA384, nil, nil, aeadAESGCM},
	{TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, 32, 0, 4, ecdheECDSAKA, suiteECDHE | suiteECSign | suiteTLS12 | suiteSHA384, nil, nil, aeadAESGCM},
	{TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, 16, 32, 16, ecdheRSAKA, suiteECDHE | suiteTLS12, cipherAES, macSHA256, nil},
	{TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, 16, 20, 16, ecdheRSAKA, suiteECDHE, cipherAES, macSHA1, nil},
	{TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, 16, 32, 16, ecdheECDSAKA, suiteECDHE | suiteECSign | suiteTLS12, cipherAES, macSHA256, nil},
	{TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, 16, 20, 16, ecdheECDSAKA, suiteECDHE | suiteECSign, cipherAES, macSHA1, nil},
	{TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, 32, 20, 16, ecdheRSAKA, suiteECDHE, cipherAES, macSHA1, nil},
	{TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, 32, 20, 16, ecdheECDSAKA, suiteECDHE | suiteECSign, cipherAES, macSHA1, nil},
	{TLS_RSA_WITH_AES_128_GCM_SHA256, 16, 0, 4, rsaKA, suiteTLS12, nil, nil, aeadAESGCM},
	{TLS_RSA_WITH_AES_256_GCM_SHA384, 32, 0, 4, rsaKA, suiteTLS12 | suiteSHA384, nil, nil, aeadAESGCM},
	{TLS_RSA_WITH_AES_128_CBC_SHA256, 16, 32, 16, rsaKA, suiteTLS12, cipherAES, macSHA256, nil},
	{TLS_RSA_WITH_AES_128_CBC_SHA, 16, 20, 16, rsaKA, 0, cipherAES, macSHA1, nil},
	{TLS_RSA_WITH_AES_256_CBC_SHA, 32, 20, 16, rsaKA, 0, cipherAES, macSHA1, nil},
	{TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, 24, 20, 8, ecdheRSAKA, suiteECDHE, cipher3DES, macSHA1, nil},
	{TLS_RSA_WITH_3DES_EDE_CBC_SHA, 24, 20, 8, rsaKA, 0, cipher3DES, macSHA1, nil},
	{TLS_RSA_WITH_RC4_128_SHA, 16, 20, 0, rsaKA, 0, cipherRC4, macSHA1, nil},
	{TLS_ECDHE_RSA_WITH_RC4_128_SHA, 16, 20, 0, ecdheRSAKA, suiteECDHE, cipherRC4, macSHA1, nil},
	{TLS_ECDHE_ECDSA_WITH_RC4_128_SHA, 16, 20, 0, ecdheECDSAKA, suiteECDHE | suiteECSign, cipherRC4, macSHA1, nil},
}

// selectCipherSuite returns the first TLS 1.0–1.2 cipher suite from ids which
// is also in supportedIDs and passes the ok filter.
// 选择密码套件 返回第一个TLS 1.0 - -1.2密码套件从ids也支持id,并将好的过滤器。
func selectCipherSuite(ids, supportedIDs []uint16, ok func(*cipherSuite) bool) *cipherSuite {
	for _, id := range ids {
		candidate := cipherSuiteByID(id)
		if candidate == nil || !ok(candidate) {
			continue
		}

		for _, suppID := range supportedIDs {
			if id == suppID {
				return candidate
			}
		}
	}
	return nil
}

// A cipherSuiteTLS13 defines only the pair of the AEAD algorithm and hash
// algorithm to be used with HKDF. See RFC 8446, Appendix B.4.
// tls1.3密码学套件 密码套件TLS13定义只有一双AEAD HKDF使用算法和散列算法。看到RFC 8446,附录B.4。
type cipherSuiteTLS13 struct {
	id     uint16
	keyLen int
	aead   func(key, fixedNonce []byte) aead
	// 改为gmx509的Hash
	// hash   crypto.Hash
	hash x509.Hash
}

func (cs *cipherSuiteTLS13) ToString() string {
	switch cs.id {
	case TLS_SM4_GCM_SM3:
		return "TLS_SM4_GCM_SM3"
	case TLS_AES_128_GCM_SHA256:
		return "TLS_AES_128_GCM_SHA256"
	case TLS_CHACHA20_POLY1305_SHA256:
		return "TLS_CHACHA20_POLY1305_SHA256"
	case TLS_AES_256_GCM_SHA384:
		return "TLS_AES_256_GCM_SHA384"
	default:
		return "unknown"
	}
}

// tls1.3支持的密码套件
var cipherSuitesTLS13 = []*cipherSuiteTLS13{ // 更换地图。 replace with a map.
	{TLS_AES_128_GCM_SHA256, 16, aeadAESGCMTLS13, x509.SHA256},
	{TLS_CHACHA20_POLY1305_SHA256, 32, aeadChaCha20Poly1305, x509.SHA256},
	{TLS_AES_256_GCM_SHA384, 32, aeadAESGCMTLS13, x509.SHA384},
	// 添加国密对应实现
	{TLS_SM4_GCM_SM3, 16, aeadSM4GCMTLS13, x509.SM3},
}

// cipherSuitesPreferenceOrder is the order in which we'll select (on the
// server) or advertise (on the client) TLS 1.0–1.2 cipher suites.
//
// Cipher suites are filtered but not reordered based on the application and
// peer's preferences, meaning we'll never select a suite lower in this list if
// any higher one is available. This makes it more defensible to keep weaker
// cipher suites enabled, especially on the server side where we get the last
// word, since there are no known downgrade attacks on cipher suites selection.
//
// The list is sorted by applying the following priority rules, stopping at the
// first (most important) applicable one:
//
//   - Anything else comes before RC4
//
//       RC4 has practically exploitable biases. See https://www.rc4nomore.com.
//
//   - Anything else comes before CBC_SHA256
//
//       SHA-256 variants of the CBC ciphersuites don't implement any Lucky13
//       countermeasures. See http://www.isg.rhul.ac.uk/tls/Lucky13.html and
//       https://www.imperialviolet.org/2013/02/04/luckythirteen.html.
//
//   - Anything else comes before 3DES
//
//       3DES has 64-bit blocks, which makes it fundamentally susceptible to
//       birthday attacks. See https://sweet32.info.
//
//   - ECDHE comes before anything else
//
//       Once we got the broken stuff out of the way, the most important
//       property a cipher suite can have is forward secrecy. We don't
//       implement FFDHE, so that means ECDHE.
//
//   - AEADs come before CBC ciphers
//
//       Even with Lucky13 countermeasures, MAC-then-Encrypt CBC cipher suites
//       are fundamentally fragile, and suffered from an endless sequence of
//       padding oracle attacks. See https://eprint.iacr.org/2015/1129,
//       https://www.imperialviolet.org/2014/12/08/poodleagain.html, and
//       https://blog.cloudflare.com/yet-another-padding-oracle-in-openssl-cbc-ciphersuites/.
//
//   - AES comes before ChaCha20
//
//       When AES hardware is available, AES-128-GCM and AES-256-GCM are faster
//       than ChaCha20Poly1305.
//
//       When AES hardware is not available, AES-128-GCM is one or more of: much
//       slower, way more complex, and less safe (because not constant time)
//       than ChaCha20Poly1305.
//
//       We use this list if we think both peers have AES hardware, and
//       cipherSuitesPreferenceOrderNoAES otherwise.
//
//   - AES-128 comes before AES-256
//
//       The only potential advantages of AES-256 are better multi-target
//       margins, and hypothetical post-quantum properties. Neither apply to
//       TLS, and AES-256 is slower due to its four extra rounds (which don't
//       contribute to the advantages above).
//
//   - ECDSA comes before RSA
//
//       The relative order of ECDSA and RSA cipher suites doesn't matter,
//       as they depend on the certificate. Pick one to get a stable order.
//
// 选择tls1.0-1.2密码学套件的顺序。暂时没有添加国密密码学套件。
var cipherSuitesPreferenceOrder = []uint16{
	// AEADs w/ ECDHE
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,

	// CBC w/ ECDHE
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,

	// AEADs w/o ECDHE
	TLS_RSA_WITH_AES_128_GCM_SHA256,
	TLS_RSA_WITH_AES_256_GCM_SHA384,

	// CBC w/o ECDHE
	TLS_RSA_WITH_AES_128_CBC_SHA,
	TLS_RSA_WITH_AES_256_CBC_SHA,

	// 3DES
	TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	TLS_RSA_WITH_3DES_EDE_CBC_SHA,

	// CBC_SHA256
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	TLS_RSA_WITH_AES_128_CBC_SHA256,

	// RC4
	TLS_ECDHE_ECDSA_WITH_RC4_128_SHA, TLS_ECDHE_RSA_WITH_RC4_128_SHA,
	TLS_RSA_WITH_RC4_128_SHA,
}

var cipherSuitesPreferenceOrderNoAES = []uint16{
	// ChaCha20Poly1305
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,

	// AES-GCM w/ ECDHE
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,

	// The rest of cipherSuitesPreferenceOrder.
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	TLS_RSA_WITH_AES_128_GCM_SHA256,
	TLS_RSA_WITH_AES_256_GCM_SHA384,
	TLS_RSA_WITH_AES_128_CBC_SHA,
	TLS_RSA_WITH_AES_256_CBC_SHA,
	TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	TLS_RSA_WITH_AES_128_CBC_SHA256,
	TLS_ECDHE_ECDSA_WITH_RC4_128_SHA, TLS_ECDHE_RSA_WITH_RC4_128_SHA,
	TLS_RSA_WITH_RC4_128_SHA,
}

// disabledCipherSuites are not used unless explicitly listed in
// Config.CipherSuites. They MUST be at the end of cipherSuitesPreferenceOrder.
// 禁用密码套件 禁用密码组合不习惯,除非显式配置中列出。密码套件。他们必须在密码套件优先顺序的。
var disabledCipherSuites = []uint16{
	// CBC_SHA256
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	TLS_RSA_WITH_AES_128_CBC_SHA256,

	// RC4
	TLS_ECDHE_ECDSA_WITH_RC4_128_SHA, TLS_ECDHE_RSA_WITH_RC4_128_SHA,
	TLS_RSA_WITH_RC4_128_SHA,
}

var (
	// 默认的密码套件Len
	defaultCipherSuitesLen = len(cipherSuitesPreferenceOrder) - len(disabledCipherSuites)
	// 默认的密码套件
	defaultCipherSuites = cipherSuitesPreferenceOrder[:defaultCipherSuitesLen]
)

// defaultCipherSuitesTLS13 is also the preference order, since there are no
// disabled by default TLS 1.3 cipher suites. The same AES vs ChaCha20 logic as
// cipherSuitesPreferenceOrder applies.
// 默认的密码套件TLS13也偏好顺序,因为没有默认禁用TLS 1.3密码套件。相同的AES vs Cha Cha20逻辑作为密码套件的偏好顺序适用。
// tls1.3的默认密码学套件选择顺序，已将对应的国密密码学套件作为首选。
var defaultCipherSuitesTLS13 = []uint16{
	TLS_SM4_GCM_SM3,
	TLS_AES_128_GCM_SHA256,
	TLS_AES_256_GCM_SHA384,
	TLS_CHACHA20_POLY1305_SHA256,
}

var defaultCipherSuitesTLS13NoAES = []uint16{
	TLS_SM4_GCM_SM3,
	TLS_CHACHA20_POLY1305_SHA256,
	TLS_AES_128_GCM_SHA256,
	TLS_AES_256_GCM_SHA384,
}

var (
	hasGCMAsmAMD64 = cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ
	hasGCMAsmARM64 = cpu.ARM64.HasAES && cpu.ARM64.HasPMULL
	// Keep in sync with crypto/aes/cipher_s390x.go.
	// 与加密/ aes /密码s390x.go保持同步。
	hasGCMAsmS390X = cpu.S390X.HasAES && cpu.S390X.HasAESCBC && cpu.S390X.HasAESCTR &&
		(cpu.S390X.HasGHASH || cpu.S390X.HasAESGCM)

	hasAESGCMHardwareSupport = runtime.GOARCH == "amd64" && hasGCMAsmAMD64 ||
		runtime.GOARCH == "arm64" && hasGCMAsmARM64 ||
		runtime.GOARCH == "s390x" && hasGCMAsmS390X
)

var aesgcmCiphers = map[uint16]bool{
	// TLS 1.2
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:   true,
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:   true,
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: true,
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: true,
	// TLS 1.3
	TLS_SM4_GCM_SM3:        true,
	TLS_AES_128_GCM_SHA256: true,
	TLS_AES_256_GCM_SHA384: true,
}

// var nonAESGCMAEADCiphers = map[uint16]bool{
// 	// TLS 1.2
// 	TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305:   true,
// 	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305: true,
// 	// TLS 1.3
// 	TLS_SM4_GCM_SM3:          true,
// 	TLS_CHACHA20_POLY1305_SHA256: true,
// }

// aesgcmPreferred returns whether the first known cipher in the preference list
// is an AES-GCM cipher, implying the peer has hardware support for it.
// aesgcm首选回报偏好列表中的第一个已知密码是否一个AES - GCM密码,暗示对方有硬件支持。
func aesgcmPreferred(ciphers []uint16) bool {
	for _, cID := range ciphers {
		if c := cipherSuiteByID(cID); c != nil {
			return aesgcmCiphers[cID]
		}
		if c := cipherSuiteTLS13ByID(cID); c != nil {
			return aesgcmCiphers[cID]
		}
	}
	return false
}

func cipherRC4(key, iv []byte, isRead bool) interface{} {
	cipher, _ := rc4.NewCipher(key)
	return cipher
}

func cipher3DES(key, iv []byte, isRead bool) interface{} {
	block, _ := des.NewTripleDESCipher(key)
	if isRead {
		return cipher.NewCBCDecrypter(block, iv)
	}
	return cipher.NewCBCEncrypter(block, iv)
}

func cipherAES(key, iv []byte, isRead bool) interface{} {
	block, _ := aes.NewCipher(key)
	if isRead {
		return cipher.NewCBCDecrypter(block, iv)
	}
	return cipher.NewCBCEncrypter(block, iv)
}

// 暂时没有为tls1.2准备国密套件，因此不需要对照 cipherAES 实现 cipherSM4。
// 基于相同原因，下面的 macSHA1 与 macSHA256 同样没有准备对应的 macSM3。

// macSHA1 returns a SHA-1 based constant time MAC.
// mac SHA1返回一个基于sha - 1的常数时间的mac。
func macSHA1(key []byte) hash.Hash {
	return hmac.New(newConstantTimeHash(sha1.New), key)
}

// macSHA256 returns a SHA-256 based MAC. This is only supported in TLS 1.2 and
// is currently only used in disabled-by-default cipher suites.
// mac SHA256返回sha - 256基于mac。这只是支持TLS 1.2,目前仅用于,在默认情况下禁用密码套件。
func macSHA256(key []byte) hash.Hash {
	return hmac.New(sha256.New, key)
}

type aead interface {
	cipher.AEAD

	// explicitNonceLen returns the number of bytes of explicit nonce
	// included in each record. This is eight for older AEADs and
	// zero for modern ones.
	// 明确Nonce Len返回的字节数的显式Nonce包含在每个记录。这是老八AEADs和零对现代的人。
	explicitNonceLen() int
}

const (
	aeadNonceLength   = 12
	noncePrefixLength = 4
)

// prefixNonceAEAD wraps an AEAD and prefixes a fixed portion of the nonce to
// each call.
// 前缀Nonce AEAD 包装一个AEAD和前缀固定部分的每个调用的特定场合。
type prefixNonceAEAD struct {
	// nonce contains the fixed part of the nonce in the first four bytes.
	// 现时标志包含的固定部分nonce前四个字节。
	nonce [aeadNonceLength]byte
	aead  cipher.AEAD // AEAD密码模式为认证加密提供相关数据。方法的描述,请参阅
}

func (f *prefixNonceAEAD) NonceSize() int        { return aeadNonceLength - noncePrefixLength }
func (f *prefixNonceAEAD) Overhead() int         { return f.aead.Overhead() }
func (f *prefixNonceAEAD) explicitNonceLen() int { return f.NonceSize() }

// Seal 密封对明文进行加密并进行身份验证,验证了额外的数据和附加结果dst,返回更新后的切片。
// 现时标志必须nonce()字节大小和独特的时间,对于一个给定的键。
// 重用明文的加密存储输出,使用明文dst (: 0)。否则,dst的剩余能力不能重叠明文。
func (f *prefixNonceAEAD) Seal(out, nonce, plaintext, additionalData []byte) []byte {
	copy(f.nonce[4:], nonce)
	return f.aead.Seal(out, f.nonce[:], plaintext, additionalData)
}

// Open 打开解密并验证密文，验证
// 附加数据，如果成功，附加结果明文
// 到 dst，返回更新后的切片。 nonce 必须是 NonceSize()
//字节长，它和附加数据都必须匹配
// 传递给 Seal 的值。
//
// 要将密文的存储重新用于解密输出，请使用 ciphertext[:0]
// 作为 dst。 否则，dst 的剩余容量不得与明文重叠。
//
// 即使函数失败，dst 的内容，直到它的容量，
// 可能被覆盖。
func (f *prefixNonceAEAD) Open(out, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	copy(f.nonce[4:], nonce)
	return f.aead.Open(out, f.nonce[:], ciphertext, additionalData)
}

// xorNonceAEAD wraps an AEAD by XORing in a fixed pattern to the nonce
// before each call.
// xor Nonce AEAD包装的AEAD XORing在固定模式Nonce每个调用之前。
type xorNonceAEAD struct {
	nonceMask [aeadNonceLength]byte
	aead      cipher.AEAD
}

func (f *xorNonceAEAD) NonceSize() int        { return 8 } // 64-bit sequence number
func (f *xorNonceAEAD) Overhead() int         { return f.aead.Overhead() }
func (f *xorNonceAEAD) explicitNonceLen() int { return 0 }

func (f *xorNonceAEAD) Seal(out, nonce, plaintext, additionalData []byte) []byte {
	for i, b := range nonce {
		f.nonceMask[4+i] ^= b
	}
	result := f.aead.Seal(out, f.nonceMask[:], plaintext, additionalData)
	for i, b := range nonce {
		f.nonceMask[4+i] ^= b
	}

	return result
}

func (f *xorNonceAEAD) Open(out, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	for i, b := range nonce {
		f.nonceMask[4+i] ^= b
	}
	result, err := f.aead.Open(out, f.nonceMask[:], ciphertext, additionalData)
	for i, b := range nonce {
		f.nonceMask[4+i] ^= b
	}

	return result, err
}

func aeadAESGCM(key, noncePrefix []byte) aead {
	if len(noncePrefix) != noncePrefixLength {
		panic("gmtls: internal error: wrong nonce length")
	}
	aes, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(aes)
	if err != nil {
		panic(err)
	}

	ret := &prefixNonceAEAD{aead: aead}
	copy(ret.nonce[:], noncePrefix)
	return ret
}

func aeadAESGCMTLS13(key, nonceMask []byte) aead {
	if len(nonceMask) != aeadNonceLength {
		panic("gmtls: internal error: wrong nonce length")
	}
	aes, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(aes)
	if err != nil {
		panic(err)
	}

	ret := &xorNonceAEAD{aead: aead}
	copy(ret.nonceMask[:], nonceMask)
	return ret
}

// sm4实现AEAD，需要验证
// 只实现 aeadSM4GCMTLS13 没有实现 aeadSM4GCM 同样是因为目前没有为tls1.2准备国密密码套件
func aeadSM4GCMTLS13(key, nonceMask []byte) aead {
	if len(nonceMask) != aeadNonceLength {
		panic("gmtls: internal error: wrong nonce length")
	}
	sm4Cipher, err := sm4.NewCipher(key)
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(sm4Cipher)
	if err != nil {
		panic(err)
	}

	ret := &xorNonceAEAD{aead: aead}
	copy(ret.nonceMask[:], nonceMask)
	return ret
}

func aeadChaCha20Poly1305(key, nonceMask []byte) aead {
	if len(nonceMask) != aeadNonceLength {
		panic("gmtls: internal error: wrong nonce length")
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		panic(err)
	}

	ret := &xorNonceAEAD{aead: aead}
	copy(ret.nonceMask[:], nonceMask)
	return ret
}

// 常数时间散列
type constantTimeHash interface {
	hash.Hash
	ConstantTimeSum(b []byte) []byte // 常数时间总和
}

// cthWrapper wraps any hash.Hash that implements ConstantTimeSum, and replaces
// with that all calls to Sum. It's used to obtain a ConstantTimeSum-based HMAC.
// 车车包装器包装任何散列。散列实现恒定的时间总和,所有调用和替换。它是用于获得一个常数时间Sum-based HMAC。
type cthWrapper struct {
	h constantTimeHash
}

func (c *cthWrapper) Size() int                   { return c.h.Size() }
func (c *cthWrapper) BlockSize() int              { return c.h.BlockSize() }
func (c *cthWrapper) Reset()                      { c.h.Reset() }
func (c *cthWrapper) Write(p []byte) (int, error) { return c.h.Write(p) }
func (c *cthWrapper) Sum(b []byte) []byte         { return c.h.ConstantTimeSum(b) }

// 新的常数时间散列
func newConstantTimeHash(h func() hash.Hash) func() hash.Hash {
	return func() hash.Hash {
		return &cthWrapper{h().(constantTimeHash)}
	}
}

// tls10MAC implements the TLS 1.0 MAC function. RFC 2246, Section 6.2.3.
// tls10 MAC实现了TLS 1.0 MAC的功能。6.2.3 RFC 2246,部分。
func tls10MAC(h hash.Hash, out, seq, header, data, extra []byte) []byte {
	h.Reset()
	h.Write(seq)
	h.Write(header)
	h.Write(data)
	res := h.Sum(out)
	if extra != nil {
		h.Write(extra)
	}
	return res
}

func rsaKA(version uint16) keyAgreement {
	// rsa密钥协议实现了标准TLS密钥协议的客户端加密服务器的公钥的pre - master secret。
	return rsaKeyAgreement{}
}

func ecdheECDSAKA(version uint16) keyAgreement {
	// ecdhe关键协议实现了TLS密钥协议的服务器生成一个短暂的EC公共/私有密钥对和迹象。
	// 使用ECDH pre - master secret然后计算。签名可能ECDSA, Ed25519或RSA。
	return &ecdheKeyAgreement{
		isRSA:   false,
		version: version,
	}
}

func ecdheRSAKA(version uint16) keyAgreement {
	// ecdhe关键协议实现了TLS密钥协议的服务器生成一个短暂的EC公共/私有密钥对和迹象。
	// 使用ECDH pre - master secret然后计算。签名可能ECDSA, Ed25519或RSA。
	return &ecdheKeyAgreement{
		isRSA:   true,
		version: version,
	}
}

// mutualCipherSuite returns a cipherSuite given a list of supported
// ciphersuites and the id requested by the peer.
// 从给定的have密码套件列表中匹配want密码套件。
func mutualCipherSuite(have []uint16, want uint16) *cipherSuite {
	for _, id := range have {
		if id == want {
			return cipherSuiteByID(id)
		}
	}
	return nil
}

// 从tls1.0~1.2的密码学套件中根据ID获取对应的密码学套件
func cipherSuiteByID(id uint16) *cipherSuite {
	for _, cipherSuite := range cipherSuites {
		if cipherSuite.id == id {
			return cipherSuite
		}
	}
	return nil
}

// 协商tls1.3的密码套件
//  - have 己方拥有的密码套件
//  - want 对方需求的密码套件
func mutualCipherSuiteTLS13(have []uint16, want uint16) *cipherSuiteTLS13 {
	for _, id := range have {
		if id == want {
			return cipherSuiteTLS13ByID(id)
		}
	}
	return nil
}

// 根据id获取tls1.3对应的密码套件
func cipherSuiteTLS13ByID(id uint16) *cipherSuiteTLS13 {
	for _, cipherSuite := range cipherSuitesTLS13 {
		if cipherSuite.id == id {
			return cipherSuite
		}
	}
	return nil
}

// A list of cipher suite IDs that are, or have been, implemented by this
// package.
//
// See https://www.iana.org/assignments/tls-parameters/tls-parameters.xml
// 一个密码套件id列表,或者已经由这个包实现。
const (
	// TLS 1.0 - 1.2 cipher suites.
	TLS_RSA_WITH_RC4_128_SHA                      uint16 = 0x0005
	TLS_RSA_WITH_3DES_EDE_CBC_SHA                 uint16 = 0x000a
	TLS_RSA_WITH_AES_128_CBC_SHA                  uint16 = 0x002f
	TLS_RSA_WITH_AES_256_CBC_SHA                  uint16 = 0x0035
	TLS_RSA_WITH_AES_128_CBC_SHA256               uint16 = 0x003c
	TLS_RSA_WITH_AES_128_GCM_SHA256               uint16 = 0x009c
	TLS_RSA_WITH_AES_256_GCM_SHA384               uint16 = 0x009d
	TLS_ECDHE_ECDSA_WITH_RC4_128_SHA              uint16 = 0xc007
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA          uint16 = 0xc009
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA          uint16 = 0xc00a
	TLS_ECDHE_RSA_WITH_RC4_128_SHA                uint16 = 0xc011
	TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA           uint16 = 0xc012
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA            uint16 = 0xc013
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA            uint16 = 0xc014
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256       uint16 = 0xc023
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256         uint16 = 0xc027
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256         uint16 = 0xc02f
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256       uint16 = 0xc02b
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384         uint16 = 0xc030
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384       uint16 = 0xc02c
	TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   uint16 = 0xcca8
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 uint16 = 0xcca9
	// 暂不提供 TLS1.2 的国密密码学套件
	// TLS_ECDHE_SM2_WITH_SM4_128_CBC_SM3 uint16 = 0xccb0

	// TLS 1.3 cipher suites.
	TLS_AES_128_GCM_SHA256       uint16 = 0x1301
	TLS_AES_256_GCM_SHA384       uint16 = 0x1302
	TLS_CHACHA20_POLY1305_SHA256 uint16 = 0x1303
	// 补充国密套件定义 TLS_SM4_GCM_SM3 {0x00, 0xc6}
	TLS_SM4_GCM_SM3 uint16 = 0x00c6

	// TLS_FALLBACK_SCSV isn't a standard cipher suite but an indicator
	// that the client is doing version fallback. See RFC 7507.
	// TLS后备SCSV不是一个标准的密码套件,但表明客户端版本回退。看到RFC 7507。
	TLS_FALLBACK_SCSV uint16 = 0x5600

	// Legacy names for the corresponding cipher suites with the correct _SHA256
	// suffix, retained for backward compatibility.
	// 遗产名称对应的密码套件与正确的SHA256后缀,保留向后兼容性。
	TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305   = TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305 = TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
)
