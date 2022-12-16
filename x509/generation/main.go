package main

import (
	"crypto/x509/pkix"
	"fmt"
	"github.com/spf13/viper"
	"math/big"
	"os"
	"time"

	"github.com/rongzer/gmssl-go/opencrypto/gmssl/sm2"
	"github.com/rongzer/gmssl-go/x509"
)

func main() {
	if ReadConfigFile("CA.IsUse").(string) == "true" {
		caPriv, err := sm2.GenerateKeyPair() // 生成密钥对
		if err != nil {
			fmt.Println(err)
			panic(err)
		}
		caPrivPem, err := x509.WritePrivateKeyToPem(caPriv, nil) // 生成密钥文件
		if err != nil {
			fmt.Println(err)
			panic(err)
		}
		_, err = x509.WriteFile(ReadConfigFile("CA.caPrivPath").(string), caPrivPem)
		if err != nil {
			fmt.Println(err)
			panic(err)
		}
		caPubKey := &caPriv.Pub
		caPubkeyPem, err := x509.WritePublicKeyToPem(caPubKey) // 生成公钥文件
		_, err = x509.WriteFile(ReadConfigFile("CA.caPubKeyPath").(string), caPubkeyPem)
		if err != nil {
			fmt.Println(err)
			panic(err)
		}
		caTemplateReq := x509.CertificateRequest{
			Subject: pkix.Name{
				CommonName:   ReadConfigFile("CA.caCommonName").(string),
				Organization: []string{ReadConfigFile("CA.Organization").(string)},
			},
			SignatureAlgorithm: x509.SM2WithSM3,
		}
		fmt.Println("创建Pem证书请求")

		// 创建Pem证书请求
		caReqPem, err := x509.CreateCertificateRequestToPem(&caTemplateReq, caPriv)
		_, err = x509.WriteFile(ReadConfigFile("CA.caTemplateReq").(string), caReqPem)
		if err != nil {
			fmt.Println(err)
			panic(err)
		}

		caCommonName := ReadConfigFile("CA.caCommonName").(string)

		caTemplate := x509.Certificate{
			// 序列号是-确保负值解析。这是由于生产的患病率有bug的代码证书序列号为负。
			SerialNumber: big.NewInt(-1),
			Subject: pkix.Name{
				CommonName:   caCommonName,
				Organization: []string{caCommonName},
				Country:      []string{ReadConfigFile("CA.Country").(string)},
				ExtraNames: []pkix.AttributeTypeAndValue{
					{
						Type:  []int{2, 5, 4, 6},
						Value: "CN",
					},
				},
			},
			NotBefore: time.Now(),

			NotAfter: time.Date(ReadConfigFile("CA.CertificateInfo.EndYear").(int),
				time.Month(ReadConfigFile("CA.CertificateInfo.EndMonth").(int)),
				ReadConfigFile("CA.CertificateInfo.EndDay").(int),
				0, 0, 0, 0, time.UTC),
			//	签名算法:ECDSAWith SHA256,	SignatureAlgorithm: ECDSAWithSHA256,
			SignatureAlgorithm:    x509.SM2WithSM3,
			SubjectKeyId:          []byte{1, 2, 3, 4},    // 主题Key Id
			KeyUsage:              x509.KeyUsageCertSign, // 键的使用 主要使用证书签署
			BasicConstraintsValid: true,                  // 基本约束有效
			IsCA:                  true,                  // 是CA
		}

		caCertPem, err := x509.CreateCertificateToPem(&caTemplate, &caTemplate, caPubKey, caPriv)
		_, err = x509.WriteFile(ReadConfigFile("CA.CertificateInfo.CaCertPath").(string), caCertPem)
		if err != nil {
			fmt.Println(err)
			panic(err)
		}
	}

	if ReadConfigFile("Server.IsUse").(string) == "true" {
		certFile, err := os.ReadFile(ReadConfigFile("Server.caCertPath").(string))
		if err != nil {
			fmt.Println(err)
			panic(err)
		}
		caPrivfile, err := os.ReadFile(ReadConfigFile("Server.caPrivPath").(string))
		if err != nil {
			fmt.Println(err)
			panic(err)
		}
		caPriv, err := sm2.PrivateKeyFromPEM(string(caPrivfile), "")
		if err != nil {
			return
		}
		pem, err := x509.ReadCertificateFromPem(certFile)
		if err != nil {
			fmt.Println(err)
			panic(err)
		}
		caTemplate := x509.Certificate{
			// 序列号是-确保负值解析。这是由于生产的患病率有bug的代码证书序列号为负。
			SerialNumber: big.NewInt(-1),
			Subject: pkix.Name{
				CommonName:   pem.Subject.CommonName,
				Organization: pem.Subject.Organization,
				Country:      pem.Subject.Country,
				ExtraNames: []pkix.AttributeTypeAndValue{
					{
						Type:  []int{2, 5, 4, 6},
						Value: "CN",
					},
				},
			},
		}
		//server===
		serverPriv, err := sm2.GenerateKeyPair() // 生成密钥对
		if err != nil {
			fmt.Println(err)
			panic(err)
		}
		serverPrivPem, err := x509.WritePrivateKeyToPem(serverPriv, nil) // 生成密钥文件
		if err != nil {
			fmt.Println(err)
			panic(err)
		}
		_, err = x509.WriteFile(ReadConfigFile("Server.serverPrivPath").(string), serverPrivPem)
		if err != nil {
			fmt.Println(err)
			panic(err)
		}
		serverPubKey := &serverPriv.Pub
		serverPubkeyPem, err := x509.WritePublicKeyToPem(serverPubKey) // 生成公钥文件
		_, err = x509.WriteFile(ReadConfigFile("Server.serverPubKeyPath").(string), serverPubkeyPem)
		if err != nil {
			fmt.Println(err)
			panic(err)
		}
		serverTemplateReq := x509.CertificateRequest{
			Subject: pkix.Name{
				CommonName:   ReadConfigFile("Server.CommonName").(string),
				Organization: []string{ReadConfigFile("Server.Organization").(string)},
			},
			SignatureAlgorithm: x509.SM2WithSM3,
		}
		// 创建Pem证书请求
		serverReqPem, err := x509.CreateCertificateRequestToPem(&serverTemplateReq, serverPriv)
		_, err = x509.WriteFile(ReadConfigFile("Server.serverReqPem").(string), serverReqPem)
		if err != nil {
			fmt.Println(err)
			panic(err)
		}
		//====
		serverCommonName := ReadConfigFile("server.CommonName").(string)
		serverTemplate := x509.Certificate{
			// 序列号是-确保负值解析。这是由于生产的患病率有bug的代码证书序列号为负。
			SerialNumber: big.NewInt(-1),
			Subject: pkix.Name{
				CommonName:   serverCommonName,
				Organization: []string{serverCommonName},
				Country:      []string{ReadConfigFile("Server.Country").(string)},
				ExtraNames: []pkix.AttributeTypeAndValue{
					{
						Type:  []int{2, 5, 4, 6},
						Value: "CN",
					},
				},
			},
			NotBefore: time.Now(),
			NotAfter: time.Date(ReadConfigFile("Server.CertificateInfo.EndYear").(int),
				time.Month(ReadConfigFile("Server.CertificateInfo.EndMonth").(int)),
				ReadConfigFile("Server.CertificateInfo.EndDay").(int),
				0, 0, 0, 0, time.UTC),
			//	签名算法:ECDSAWith SHA256,	SignatureAlgorithm: ECDSAWithSHA256,
			SignatureAlgorithm:    x509.SM2WithSM3,
			SubjectKeyId:          []byte{1, 2, 3, 4},    // 主题Key Id
			KeyUsage:              x509.KeyUsageCertSign, // 键的使用 主要使用证书签署
			BasicConstraintsValid: true,                  // 基本约束有效
			IsCA:                  false,                 // 是CA
		}

		serverCertPem, err := x509.CreateCertificateToPem(&serverTemplate, &caTemplate, serverPubKey, caPriv)
		_, err = x509.WriteFile(ReadConfigFile("Server.CertificateInfo.ServerCertPem").(string), serverCertPem)
		if err != nil {
			fmt.Println(err)
			panic(err)
		}
	}

	if ReadConfigFile("Client.IsUse").(string) == "true" {
		certFile, err := os.ReadFile(ReadConfigFile("Client.caCertPath").(string))
		if err != nil {
			fmt.Println(err)
			panic(err)
		}
		caPrivfile, err := os.ReadFile(ReadConfigFile("Client.caPrivPath").(string))
		if err != nil {
			fmt.Println(err)
			panic(err)
		}
		caPriv, err := sm2.PrivateKeyFromPEM(string(caPrivfile), "")
		if err != nil {
			return
		}
		pem, err := x509.ReadCertificateFromPem(certFile)
		if err != nil {
			fmt.Println(err)
			panic(err)
		}
		caTemplate := x509.Certificate{
			// 序列号是-确保负值解析。这是由于生产的患病率有bug的代码证书序列号为负。
			SerialNumber: big.NewInt(-1),
			Subject: pkix.Name{
				CommonName:   pem.Subject.CommonName,
				Organization: pem.Subject.Organization,
				Country:      pem.Subject.Country,
				ExtraNames: []pkix.AttributeTypeAndValue{
					{
						Type:  []int{2, 5, 4, 6},
						Value: "CN",
					},
				},
			},
		}
		//client===
		clientPriv, err := sm2.GenerateKeyPair() // 生成密钥对
		if err != nil {
			fmt.Println(err)
			panic(err)
		}
		clientPrivPem, err := x509.WritePrivateKeyToPem(clientPriv, nil) // 生成密钥文件
		if err != nil {
			fmt.Println(err)
			panic(err)
		}
		_, err = x509.WriteFile(ReadConfigFile("Client.clientPrivPath").(string), clientPrivPem)
		if err != nil {
			fmt.Println(err)
			panic(err)
		}
		clientPubKey := &clientPriv.Pub
		clientPubkeyPem, err := x509.WritePublicKeyToPem(clientPubKey) // 生成公钥文件
		_, err = x509.WriteFile(ReadConfigFile("Client.clientPubKeyPath").(string), clientPubkeyPem)
		if err != nil {
			fmt.Println(err)
			panic(err)
		}
		clientTemplateReq := x509.CertificateRequest{
			Subject: pkix.Name{
				CommonName:   ReadConfigFile("Client.CommonName").(string),
				Organization: []string{ReadConfigFile("Client.Organization").(string)},
			},
			//		SignatureAlgorithm: ECDSAWithSHA256,
			SignatureAlgorithm: x509.SM2WithSM3,
		}
		clientReqPem, err := x509.CreateCertificateRequestToPem(&clientTemplateReq, clientPriv)
		_, err = x509.WriteFile(ReadConfigFile("Client.clientReqPem").(string), clientReqPem)
		if err != nil {
			fmt.Println(err)
			panic(err)
		}
		//====
		clientCommonName := ReadConfigFile("Client.CommonName").(string)
		clientTemplate := x509.Certificate{
			// SerialNumber is negative to ensure that negative
			// values are parsed. This is due to the prevalence of
			// buggy code that produces certificates with negative
			// serial numbers.
			// 序列号是-确保负值解析。这是由于生产的患病率有bug的代码证书序列号为负。
			SerialNumber: big.NewInt(-1),
			Subject: pkix.Name{
				CommonName:   clientCommonName,
				Organization: []string{clientCommonName},
				Country:      []string{ReadConfigFile("Client.Country").(string)},
				ExtraNames: []pkix.AttributeTypeAndValue{
					{
						Type:  []int{2, 5, 4, 6},
						Value: "CN",
					},
				},
			},
			NotBefore: time.Now(),
			NotAfter: time.Date(ReadConfigFile("Server.CertificateInfo.EndYear").(int),
				time.Month(ReadConfigFile("Server.CertificateInfo.EndMonth").(int)),
				ReadConfigFile("Server.CertificateInfo.EndDay").(int),
				0, 0, 0, 0, time.UTC),
			//	签名算法:ECDSAWith SHA256,	SignatureAlgorithm: ECDSAWithSHA256,
			SignatureAlgorithm:    x509.SM2WithSM3,
			SubjectKeyId:          []byte{1, 2, 3, 4},    // 主题Key Id
			KeyUsage:              x509.KeyUsageCertSign, // 键的使用 主要使用证书签署
			BasicConstraintsValid: true,                  // 基本约束有效
			IsCA:                  false,                 // 是CA
		}

		clientCertPem, err := x509.CreateCertificateToPem(&clientTemplate, &caTemplate, clientPubKey, caPriv)
		_, err = x509.WriteFile(ReadConfigFile("Client.CertificateInfo.clientCertPem").(string), clientCertPem)
		if err != nil {
			fmt.Println(err)
			panic(err)
		}
	}
}

func ReadConfigFile(Name string) interface{} {
	viper.AddConfigPath("./")
	viper.SetConfigName("config")
	err := viper.ReadInConfig() // 将配置读入viper中存储
	if err != nil {             // Handle errors reading the config file
		panic(fmt.Errorf("Fatal error config file: %s \n", err))
	}
	viper.SetConfigType("yaml")
	data := viper.Get(Name)
	return data
}
