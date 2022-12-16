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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"reflect"
	"testing"
	"time"

	"github.com/rongzer/gmssl-go/opencrypto/gmssl/sm2"
)

func TestX509CA(t *testing.T) {
	caPriv, err := sm2.GenerateKeyPair() // 生成密钥对
	if err != nil {
		t.Fatal(err)
	}
	caPrivPem, err := WritePrivateKeyToPem(caPriv, nil) // 生成密钥文件
	if err != nil {
		t.Fatal(err)
	}
	_, err = WriteFile("/Users/yao/Documents/rongzer/gowork/src/gmssl-go/test/gmCATlsGRPC/gmcakey/caKey.crt", caPrivPem)
	if err != nil {
		t.Fatal(err)
	}
	caPubKey := &caPriv.Pub
	caPubkeyPem, err := WritePublicKeyToPem(caPubKey) // 生成公钥文件
	_, err = WriteFile("/Users/yao/Documents/rongzer/gowork/src/gmssl-go/test/gmCATlsGRPC/gmcakey/caPubPem.crt", caPubkeyPem)
	if err != nil {
		t.Fatal(err)
	}

	//privKey, err := ReadPrivateKeyFromPem(privPem, nil) // 读取密钥
	//if err != nil {
	//	t.Fatal(err)
	//}
	//pubKey, err = ReadPublicKeyFromPem(pubkeyPem) // 读取公钥
	//if err != nil {
	//	t.Fatal(err)
	//}

	caTemplateReq := CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "localhost",
			Organization: []string{"Test"},
		},
		//		SignatureAlgorithm: ECDSAWithSHA256,
		SignatureAlgorithm: SM2WithSM3,
	}
	fmt.Println("创建Pem证书请求")

	// 创建Pem证书请求
	caReqPem, err := CreateCertificateRequestToPem(&caTemplateReq, caPriv)
	_, err = WriteFile("/Users/yao/Documents/rongzer/gowork/src/gmssl-go/test/gmCATlsGRPC/gmcakey/caReqPem.csr", caReqPem)
	if err != nil {
		t.Fatal(err)
	}

	caCommonName := "localhost"
	caTemplate := Certificate{
		// SerialNumber is negative to ensure that negative
		// values are parsed. This is due to the prevalence of
		// buggy code that produces certificates with negative
		// serial numbers.
		// 序列号是-确保负值解析。这是由于生产的患病率有bug的代码证书序列号为负。
		SerialNumber: big.NewInt(-1),
		Subject: pkix.Name{
			CommonName:   caCommonName,
			Organization: []string{caCommonName},
			Country:      []string{"CN"},
			ExtraNames: []pkix.AttributeTypeAndValue{
				//{
				//	Type:  []int{2, 5, 4, 42},
				//	Value: "Gopher",
				//},
				// 这将覆盖全国,以上。 This should override the Country, above.
				{
					Type:  []int{2, 5, 4, 6},
					Value: "CN",
				},
			},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Date(2023, time.October, 10, 12, 1, 1, 1, time.UTC),

		//	签名算法:ECDSAWith SHA256,	SignatureAlgorithm: ECDSAWithSHA256,
		SignatureAlgorithm: SM2WithSM3,

		SubjectKeyId: []byte{1, 2, 3, 4}, // 主题Key Id
		KeyUsage:     KeyUsageCertSign,   // 键的使用 主要使用证书签署

		//ExtKeyUsage:        testExtKeyUsage,        // Ext键使用 测试使用Ext关键
		//UnknownExtKeyUsage: testUnknownExtKeyUsage, // 未知的Ext键使用

		BasicConstraintsValid: true, // 基本约束有效
		IsCA:                  true, // 是CA

		//OCSPServer:            []string{"http://ocsp.example.com"},
		//IssuingCertificateURL: []string{"http://crt.example.com/ca1.crt"},
		//
		//DNSNames:       []string{"localhost"},
		//EmailAddresses: []string{"gopher@golang.org"},
		//IPAddresses:    []net.IP{net.IPv4(127, 0, 0, 1).To4(), net.ParseIP("0:0:0:0::68")},

		//PolicyIdentifiers: []asn1.ObjectIdentifier{[]int{1, 2, 3}},
		//PermittedDNSDomains: []string{".localhost", "localhost"},

		//CRLDistributionPoints: []string{"http://crl1.example.com/ca1.crl", "http://crl2.example.com/ca1.crl"},
		//
		//ExtraExtensions: []pkix.Extension{
		//	{
		//		Id:    []int{1, 2, 3, 4},
		//		Value: extraExtensionData,
		//	},
		//	// This extension should override the SubjectKeyId, above. 这个扩展应该覆盖主题密钥Id,以上。
		//	{
		//		Id:       oidExtensionSubjectKeyId,
		//		Critical: false,
		//		Value:    []byte{0x04, 0x04, 4, 3, 2, 1},
		//	},
		//},
	}

	caCertPem, err := CreateCertificateToPem(&caTemplate, &caTemplate, caPubKey, caPriv)
	_, err = WriteFile("/Users/yao/Documents/rongzer/gowork/src/gmssl-go/test/gmCATlsGRPC/gmcakey/caCertPem.crt", caCertPem)
	if err != nil {
		t.Fatal("failed to create cert file")
	}

	//server===
	serverPriv, err := sm2.GenerateKeyPair() // 生成密钥对
	if err != nil {
		t.Fatal(err)
	}
	serverPrivPem, err := WritePrivateKeyToPem(serverPriv, nil) // 生成密钥文件
	if err != nil {
		t.Fatal(err)
	}
	_, err = WriteFile("/Users/yao/Documents/rongzer/gowork/src/gmssl-go/test/gmCATlsGRPC/gmcakey/serverKey.crt", serverPrivPem)
	if err != nil {
		t.Fatal(err)
	}
	serverPubKey := &serverPriv.Pub
	serverPubkeyPem, err := WritePublicKeyToPem(serverPubKey) // 生成公钥文件
	_, err = WriteFile("/Users/yao/Documents/rongzer/gowork/src/gmssl-go/test/gmCATlsGRPC/gmcakey/serverPubPem.crt", serverPubkeyPem)
	if err != nil {
		t.Fatal(err)
	}
	serverTemplateReq := CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "server.io",
			Organization: []string{"Test"},
		},
		//		SignatureAlgorithm: ECDSAWithSHA256,
		SignatureAlgorithm: SM2WithSM3,
	}
	// 创建Pem证书请求
	serverReqPem, err := CreateCertificateRequestToPem(&serverTemplateReq, serverPriv)
	_, err = WriteFile("/Users/yao/Documents/rongzer/gowork/src/gmssl-go/test/gmCATlsGRPC/gmcakey/serverReqPem.csr", serverReqPem)
	if err != nil {
		t.Fatal(err)
	}
	//====
	serverCommonName := "server.io"
	serverTemplate := Certificate{
		// SerialNumber is negative to ensure that negative
		// values are parsed. This is due to the prevalence of
		// buggy code that produces certificates with negative
		// serial numbers.
		// 序列号是-确保负值解析。这是由于生产的患病率有bug的代码证书序列号为负。
		SerialNumber: big.NewInt(-1),
		Subject: pkix.Name{
			CommonName:   serverCommonName,
			Organization: []string{serverCommonName},
			Country:      []string{"CN"},
			ExtraNames: []pkix.AttributeTypeAndValue{
				//{
				//	Type:  []int{2, 5, 4, 42},
				//	Value: "Gopher",
				//},
				// 这将覆盖全国,以上。 This should override the Country, above.
				{
					Type:  []int{2, 5, 4, 6},
					Value: "CN",
				},
			},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Date(2023, time.October, 10, 12, 1, 1, 1, time.UTC),

		//	签名算法:ECDSAWith SHA256,	SignatureAlgorithm: ECDSAWithSHA256,
		SignatureAlgorithm: SM2WithSM3,

		SubjectKeyId: []byte{1, 2, 3, 4}, // 主题Key Id
		KeyUsage:     KeyUsageCertSign,   // 键的使用 主要使用证书签署

		//ExtKeyUsage:        testExtKeyUsage,        // Ext键使用 测试使用Ext关键
		//UnknownExtKeyUsage: testUnknownExtKeyUsage, // 未知的Ext键使用

		BasicConstraintsValid: true,  // 基本约束有效
		IsCA:                  false, // 是CA

		//OCSPServer:            []string{"http://ocsp.example.com"},
		//IssuingCertificateURL: []string{"http://crt.example.com/ca1.crt"},
		//
		//DNSNames:       []string{"localhost"},
		//EmailAddresses: []string{"gopher@golang.org"},
		//IPAddresses:    []net.IP{net.IPv4(127, 0, 0, 1).To4(), net.ParseIP("0:0:0:0::68")},

		//PolicyIdentifiers: []asn1.ObjectIdentifier{[]int{1, 2, 3}},
		//PermittedDNSDomains: []string{".localhost", "localhost"},

		//CRLDistributionPoints: []string{"http://crl1.example.com/ca1.crl", "http://crl2.example.com/ca1.crl"},
		//
		//ExtraExtensions: []pkix.Extension{
		//	{
		//		Id:    []int{1, 2, 3, 4},
		//		Value: extraExtensionData,
		//	},
		//	// This extension should override the SubjectKeyId, above. 这个扩展应该覆盖主题密钥Id,以上。
		//	{
		//		Id:       oidExtensionSubjectKeyId,
		//		Critical: false,
		//		Value:    []byte{0x04, 0x04, 4, 3, 2, 1},
		//	},
		//},
	}

	serverCertPem, err := CreateCertificateToPem(&serverTemplate, &caTemplate, serverPubKey, caPriv)
	// reqPem
	// -CA ca.crt -CAkey ca.key -CAcreateserial -in server.csr
	_, err = WriteFile("/Users/yao/Documents/rongzer/gowork/src/gmssl-go/test/gmCATlsGRPC/gmcakey/serverCertPem.crt", serverCertPem)
	if err != nil {
		t.Fatal("failed to create cert file")
	}

	//$ openssl req -new \
	//-subj "/C=GB/L=China/O=server/CN=server.io" \
	//-key server.key \
	//-out server.csr
	//$ openssl x509 -req -sha256 \
	//-CA ca.crt -CAkey ca.key -CAcreateserial -days 3650 \
	//-in server.csr \
	//-out server.crt

	//client===
	clientPriv, err := sm2.GenerateKeyPair() // 生成密钥对
	if err != nil {
		t.Fatal(err)
	}
	clientPrivPem, err := WritePrivateKeyToPem(clientPriv, nil) // 生成密钥文件
	if err != nil {
		t.Fatal(err)
	}
	_, err = WriteFile("/Users/yao/Documents/rongzer/gowork/src/gmssl-go/test/gmCATlsGRPC/gmcakey/clientKey.crt", clientPrivPem)
	if err != nil {
		t.Fatal(err)
	}
	clientPubKey := &clientPriv.Pub
	clientPubkeyPem, err := WritePublicKeyToPem(clientPubKey) // 生成公钥文件
	_, err = WriteFile("/Users/yao/Documents/rongzer/gowork/src/gmssl-go/test/gmCATlsGRPC/gmcakey/clientPubPem.crt", clientPubkeyPem)
	if err != nil {
		t.Fatal(err)
	}
	clientTemplateReq := CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "client.io",
			Organization: []string{"Test"},
		},
		//		SignatureAlgorithm: ECDSAWithSHA256,
		SignatureAlgorithm: SM2WithSM3,
	}
	clientReqPem, err := CreateCertificateRequestToPem(&clientTemplateReq, clientPriv)
	_, err = WriteFile("/Users/yao/Documents/rongzer/gowork/src/gmssl-go/test/gmCATlsGRPC/gmcakey/clientReqPem.csr", clientReqPem)
	if err != nil {
		t.Fatal(err)
	}
	//====
	clientCommonName := "client.io"
	clientTemplate := Certificate{
		// SerialNumber is negative to ensure that negative
		// values are parsed. This is due to the prevalence of
		// buggy code that produces certificates with negative
		// serial numbers.
		// 序列号是-确保负值解析。这是由于生产的患病率有bug的代码证书序列号为负。
		SerialNumber: big.NewInt(-1),
		Subject: pkix.Name{
			CommonName:   clientCommonName,
			Organization: []string{clientCommonName},
			Country:      []string{"CN"},
			ExtraNames: []pkix.AttributeTypeAndValue{
				//{
				//	Type:  []int{2, 5, 4, 42},
				//	Value: "Gopher",
				//},
				// 这将覆盖全国,以上。 This should override the Country, above.
				{
					Type:  []int{2, 5, 4, 6},
					Value: "CN",
				},
			},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Date(2023, time.October, 10, 12, 1, 1, 1, time.UTC),

		//	签名算法:ECDSAWith SHA256,	SignatureAlgorithm: ECDSAWithSHA256,
		SignatureAlgorithm: SM2WithSM3,

		SubjectKeyId: []byte{1, 2, 3, 4}, // 主题Key Id
		KeyUsage:     KeyUsageCertSign,   // 键的使用 主要使用证书签署

		//ExtKeyUsage:        testExtKeyUsage,        // Ext键使用 测试使用Ext关键
		//UnknownExtKeyUsage: testUnknownExtKeyUsage, // 未知的Ext键使用

		BasicConstraintsValid: true,  // 基本约束有效
		IsCA:                  false, // 是CA

		//OCSPServer:            []string{"http://ocsp.example.com"},
		//IssuingCertificateURL: []string{"http://crt.example.com/ca1.crt"},
		//
		//DNSNames:       []string{"localhost"},
		//EmailAddresses: []string{"gopher@golang.org"},
		//IPAddresses:    []net.IP{net.IPv4(127, 0, 0, 1).To4(), net.ParseIP("0:0:0:0::68")},

		//PolicyIdentifiers: []asn1.ObjectIdentifier{[]int{1, 2, 3}},
		//PermittedDNSDomains: []string{".localhost", "localhost"},

		//CRLDistributionPoints: []string{"http://crl1.example.com/ca1.crl", "http://crl2.example.com/ca1.crl"},
		//
		//ExtraExtensions: []pkix.Extension{
		//	{
		//		Id:    []int{1, 2, 3, 4},
		//		Value: extraExtensionData,
		//	},
		//	// This extension should override the SubjectKeyId, above. 这个扩展应该覆盖主题密钥Id,以上。
		//	{
		//		Id:       oidExtensionSubjectKeyId,
		//		Critical: false,
		//		Value:    []byte{0x04, 0x04, 4, 3, 2, 1},
		//	},
		//},
	}

	//clientCertPem, err := CreateCertificateToPem(&clientTemplate, &clientTemplate, clientPubKey, clientPriv)
	clientCertPem, err := CreateCertificateToPem(&clientTemplate, &caTemplate, clientPubKey, caPriv)
	_, err = WriteFile("/Users/yao/Documents/rongzer/gowork/src/gmssl-go/test/gmCATlsGRPC/gmcakey/clientCertPem.crt", clientCertPem)
	if err != nil {
		t.Fatal("failed to create cert file")
	}

}

func TestX509(t *testing.T) {
	priv, err := sm2.GenerateKeyPair() // 生成密钥对
	if err != nil {
		t.Fatal(err)
	}
	text, err := priv.GetText()
	if err != nil {
		return
	}
	fmt.Println(text)
	privPem, err := WritePrivateKeyToPem(priv, nil) // 生成密钥文件
	if err != nil {
		t.Fatal(err)
	}
	_, err = WriteFile("/Users/yao/Documents/rongzer/gowork/src/gmssl-go/test/gmCATlsGRPC/gmcakey/privPem.cert", privPem)
	if err != nil {
		t.Fatal(err)
	}
	pubKey := &priv.Pub
	pubkeyPem, err := WritePublicKeyToPem(pubKey) // 生成公钥文件
	_, err = WriteFile("/Users/yao/Documents/rongzer/gowork/src/gmssl-go/test/gmCATlsGRPC/gmcakey/pubPem.cert", pubkeyPem)
	privKey, err := ReadPrivateKeyFromPem(privPem, nil) // 读取密钥
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(privKey)
	pubKey, err = ReadPublicKeyFromPem(pubkeyPem) // 读取公钥
	if err != nil {
		t.Fatal(err)
	}
	templateReq := CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "localhost",
			Organization: []string{"Test"},
		},
		//		SignatureAlgorithm: ECDSAWithSHA256,
		SignatureAlgorithm: SM2WithSM3,
	}
	fmt.Println("创建Pem证书请求")

	// 创建Pem证书请求
	reqPem, err := CreateCertificateRequestToPem(&templateReq, priv)
	_, err = WriteFile("/Users/yao/Documents/rongzer/gowork/src/gmssl-go/test/gmCATlsGRPC/gmcakey/reqPem.cert", reqPem)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("从Pem读取证书请求")
	// 从Pem读取证书请求
	req, err := ReadCertificateRequestFromPem(reqPem)
	if err != nil {
		t.Fatal(err)
	}
	err = req.CheckSignature()
	if err != nil {
		t.Fatalf("Request CheckSignature error:%v", err)
	} else {
		fmt.Printf("CheckSignature ok\n")
	}
	//testExtKeyUsage := []ExtKeyUsage{ExtKeyUsageClientAuth, ExtKeyUsageServerAuth}
	//testUnknownExtKeyUsage := []asn1.ObjectIdentifier{[]int{1, 2, 3}, []int{2, 59, 1}}
	//extraExtensionData := []byte("extra extension")
	commonName := "localhost"
	template := Certificate{
		// SerialNumber is negative to ensure that negative
		// values are parsed. This is due to the prevalence of
		// buggy code that produces certificates with negative
		// serial numbers.
		// 序列号是-确保负值解析。这是由于生产的患病率有bug的代码证书序列号为负。
		SerialNumber: big.NewInt(-1),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{commonName},
			Country:      []string{"CN"},
			ExtraNames: []pkix.AttributeTypeAndValue{
				//{
				//	Type:  []int{2, 5, 4, 42},
				//	Value: "Gopher",
				//},
				// 这将覆盖全国,以上。 This should override the Country, above.
				{
					Type:  []int{2, 5, 4, 6},
					Value: "CN",
				},
			},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Date(2023, time.October, 10, 12, 1, 1, 1, time.UTC),

		//	签名算法:ECDSAWith SHA256,	SignatureAlgorithm: ECDSAWithSHA256,
		SignatureAlgorithm: SM2WithSM3,

		SubjectKeyId: []byte{1, 2, 3, 4}, // 主题Key Id
		KeyUsage:     KeyUsageCertSign,   // 键的使用 主要使用证书签署

		//ExtKeyUsage:        testExtKeyUsage,        // Ext键使用 测试使用Ext关键
		//UnknownExtKeyUsage: testUnknownExtKeyUsage, // 未知的Ext键使用

		BasicConstraintsValid: true,  // 基本约束有效
		IsCA:                  false, // 是CA

		//OCSPServer:            []string{"http://ocsp.example.com"},
		//IssuingCertificateURL: []string{"http://crt.example.com/ca1.crt"},
		//
		//DNSNames:       []string{"localhost"},
		//EmailAddresses: []string{"gopher@golang.org"},
		//IPAddresses:    []net.IP{net.IPv4(127, 0, 0, 1).To4(), net.ParseIP("0:0:0:0::68")},

		//PolicyIdentifiers: []asn1.ObjectIdentifier{[]int{1, 2, 3}},
		//PermittedDNSDomains: []string{".localhost", "localhost"},

		//CRLDistributionPoints: []string{"http://crl1.example.com/ca1.crl", "http://crl2.example.com/ca1.crl"},
		//
		//ExtraExtensions: []pkix.Extension{
		//	{
		//		Id:    []int{1, 2, 3, 4},
		//		Value: extraExtensionData,
		//	},
		//	// This extension should override the SubjectKeyId, above. 这个扩展应该覆盖主题密钥Id,以上。
		//	{
		//		Id:       oidExtensionSubjectKeyId,
		//		Critical: false,
		//		Value:    []byte{0x04, 0x04, 4, 3, 2, 1},
		//	},
		//},
	}
	pubKey = &priv.Pub
	//
	certPem, err := CreateCertificateToPem(&template, &template, pubKey, priv)
	_, err = WriteFile("/Users/yao/Documents/rongzer/gowork/src/gmssl-go/test/gmCATlsGRPC/gmcakey/certpem.cert", certPem)
	if err != nil {
		t.Fatal("failed to create cert file")
	}
	//_, err = WriteFile("/home/syf/go/src/rbss_manager/sc/gmssl-go/gmtls/websvr/certs/Gm3.cer", certpem)
	//if err != nil {
	//	t.Fatal(err)
	//}
	cert, err := ReadCertificateFromPem(certPem)
	if err != nil {
		t.Fatal("failed to read cert file")
	}
	err = cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
	if err != nil {
		t.Fatal(err)
	} else {
		fmt.Printf("CheckSignature ok\n")
	}
}

func TestCreateRevocationList(t *testing.T) {
	priv, err := sm2.GenerateKeyPair() // 生成密钥对
	if err != nil {
		t.Fatal(err)
	}
	privPem, err := WritePrivateKeyToPem(priv, nil) // 生成密钥文件
	if err != nil {
		t.Fatal(err)
	}
	privKey, err := ReadPrivateKeyFromPem(privPem, nil) // 读取密钥
	if err != nil {
		t.Fatal(err)
	}
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate rsa key: %s", err)
	}
	tests := []struct {
		name          string
		key           crypto.Signer
		issuer        *Certificate
		template      *RevocationList
		expectedError string
	}{
		{
			name:          "nil template",
			key:           privKey,
			issuer:        nil,
			template:      nil,
			expectedError: "x509: template can not be nil",
		},
		{
			name:          "nil issuer",
			key:           privKey,
			issuer:        nil,
			template:      &RevocationList{},
			expectedError: "x509: issuer can not be nil",
		},
		{
			name: "issuer doesn't have crlSign key usage bit set",
			key:  privKey,
			issuer: &Certificate{
				KeyUsage: KeyUsageCertSign,
			},
			template:      &RevocationList{},
			expectedError: "x509: issuer must have the crlSign key usage bit set",
		},
		{
			name: "issuer missing SubjectKeyId",
			key:  privKey,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
			},
			template:      &RevocationList{},
			expectedError: "x509: issuer certificate doesn't contain a subject key identifier",
		},
		{
			name: "nextUpdate before thisUpdate",
			key:  privKey,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				ThisUpdate: time.Time{}.Add(time.Hour),
				NextUpdate: time.Time{},
			},
			expectedError: "x509: template.ThisUpdate is after template.NextUpdate",
		},
		{
			name: "nil Number",
			key:  privKey,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
			},
			expectedError: "x509: template contains nil Number field",
		},
		{
			name: "invalid signature algorithm",
			key:  privKey,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				SignatureAlgorithm: SHA256WithRSA,
				RevokedCertificates: []pkix.RevokedCertificate{
					{
						SerialNumber:   big.NewInt(2),
						RevocationTime: time.Time{}.Add(time.Hour),
					},
				},
				Number:     big.NewInt(5),
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
			},
			expectedError: "x509: requested SignatureAlgorithm does not match private key type",
		},
		{
			name: "valid",
			key:  privKey,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				RevokedCertificates: []pkix.RevokedCertificate{
					{
						SerialNumber:   big.NewInt(2),
						RevocationTime: time.Time{}.Add(time.Hour),
					},
				},
				Number:     big.NewInt(5),
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
			},
		},
		{
			name: "valid, rsa2048 key",
			key:  rsaPriv,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				RevokedCertificates: []pkix.RevokedCertificate{
					{
						SerialNumber:   big.NewInt(2),
						RevocationTime: time.Time{}.Add(time.Hour),
					},
				},
				Number:     big.NewInt(5),
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
			},
		},
		{
			name: "valid, non-default signature algorithm",
			key:  privKey,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				SignatureAlgorithm: SM2WithSM3,
				RevokedCertificates: []pkix.RevokedCertificate{
					{
						SerialNumber:   big.NewInt(2),
						RevocationTime: time.Time{}.Add(time.Hour),
					},
				},
				Number:     big.NewInt(5),
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
			},
		},
		{
			name: "valid, extra extension",
			key:  privKey,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				RevokedCertificates: []pkix.RevokedCertificate{
					{
						SerialNumber:   big.NewInt(2),
						RevocationTime: time.Time{}.Add(time.Hour),
					},
				},
				Number:     big.NewInt(5),
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
				ExtraExtensions: []pkix.Extension{
					{
						Id:    []int{2, 5, 29, 99},
						Value: []byte{5, 0},
					},
				},
			},
		},
		{
			name: "valid, empty list",
			key:  privKey,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				Number:     big.NewInt(5),
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			crl, err := CreateRevocationList(rand.Reader, tc.template, tc.issuer, tc.key)
			if err != nil && tc.expectedError == "" {
				t.Fatalf("CreateRevocationList failed unexpectedly: %s", err)
			} else if err != nil && tc.expectedError != err.Error() {
				t.Fatalf("CreateRevocationList failed unexpectedly, wanted: %s, got: %s", tc.expectedError, err)
			} else if err == nil && tc.expectedError != "" {
				t.Fatalf("CreateRevocationList didn't fail, expected: %s", tc.expectedError)
			}
			if tc.expectedError != "" {
				return
			}

			parsedCRL, err := ParseDERCRL(crl)
			if err != nil {
				t.Fatalf("Failed to parse generated CRL: %s", err)
			}
			if tc.template.SignatureAlgorithm != UnknownSignatureAlgorithm &&
				!parsedCRL.SignatureAlgorithm.Algorithm.Equal(signatureAlgorithmDetails[tc.template.SignatureAlgorithm].oid) {
				t.Fatalf("SignatureAlgorithm mismatch: got %v; want %v.", parsedCRL.SignatureAlgorithm,
					tc.template.SignatureAlgorithm)
			}

			if !reflect.DeepEqual(parsedCRL.TBSCertList.RevokedCertificates, tc.template.RevokedCertificates) {
				t.Fatalf("RevokedCertificates mismatch: got %v; want %v.",
					parsedCRL.TBSCertList.RevokedCertificates, tc.template.RevokedCertificates)
			}

			if len(parsedCRL.TBSCertList.Extensions) != 2+len(tc.template.ExtraExtensions) {
				t.Fatalf("Generated CRL has wrong number of extensions, wanted: %d, got: %d", 2+len(tc.template.ExtraExtensions), len(parsedCRL.TBSCertList.Extensions))
			}
			expectedAKI, err := asn1.Marshal(authKeyId{Id: tc.issuer.SubjectKeyId})
			if err != nil {
				t.Fatalf("asn1.Marshal failed: %s", err)
			}
			akiExt := pkix.Extension{
				Id:    oidExtensionAuthorityKeyId,
				Value: expectedAKI,
			}
			if !reflect.DeepEqual(parsedCRL.TBSCertList.Extensions[0], akiExt) {
				t.Fatalf("Unexpected first extension: got %v, want %v",
					parsedCRL.TBSCertList.Extensions[0], akiExt)
			}
			expectedNum, err := asn1.Marshal(tc.template.Number)
			if err != nil {
				t.Fatalf("asn1.Marshal failed: %s", err)
			}
			crlExt := pkix.Extension{
				Id:    oidExtensionCRLNumber,
				Value: expectedNum,
			}
			if !reflect.DeepEqual(parsedCRL.TBSCertList.Extensions[1], crlExt) {
				t.Fatalf("Unexpected second extension: got %v, want %v",
					parsedCRL.TBSCertList.Extensions[1], crlExt)
			}
			if len(parsedCRL.TBSCertList.Extensions[2:]) == 0 && len(tc.template.ExtraExtensions) == 0 {
				// If we don't have anything to check return early so we don't
				// hit a [] != nil false positive below.
				return
			}
			if !reflect.DeepEqual(parsedCRL.TBSCertList.Extensions[2:], tc.template.ExtraExtensions) {
				t.Fatalf("Extensions mismatch: got %v; want %v.",
					parsedCRL.TBSCertList.Extensions[2:], tc.template.ExtraExtensions)
			}
		})
	}
}
