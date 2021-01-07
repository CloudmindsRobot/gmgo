package x509

import (
	"crypto/rand"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"testing"
	"time"

	"crypto/x509/pkix"
	"github.com/CloudmindsRobot/gmgo/crypto/ecdsa"
	"github.com/CloudmindsRobot/gmgo/crypto/elliptic"
)

/*
func TestParseGMCertificate(t *testing.T) {
	certPEM, err := ioutil.ReadFile("testdata/cfca root cert.pem") // 从文件读取数据
	if err != nil {
		t.Fail()
	}
	certContent, _ := pem.Decode([]byte(certPEM))
	cert, err := ParseCertificate(certContent.Bytes)
	if err != nil {
		t.Errorf("parse GM cert error:%s", err)
		return
	}
	t.Logf("Cert name:%s", cert.Subject.CommonName)
	//_,err= cert.Verify(VerifyOptions{})
	//if err!=nil{
	//	t.Errorf("verify cert error:%s",err)
	//}
}
*/

func TestVerifyGMCertificateOrg1(t *testing.T) {
	// ca
	caPem, err := ioutil.ReadFile("org1/ca.pem") // 从文件读取数据
	if err != nil {
		t.Fatalf("err = %v", err)
		return
	}

	caContent, _ := pem.Decode([]byte(caPem))
	caCert, err := ParseCertificate(caContent.Bytes)
	if err != nil {
		t.Fatalf("err = %v", err)
		return
	}
	t.Logf("caCert.Subject.CommonName = %v", caCert.Subject.CommonName)

	// peer
	peerPem, err := ioutil.ReadFile("org1/peer.pem") // 从文件读取数据
	if err != nil {
		t.Fatalf("err = %v", err)
		return
	}

	peerContent, _ := pem.Decode([]byte(peerPem))
	peerCert, err := ParseCertificate(peerContent.Bytes)
	if err != nil {
		t.Fatalf("err = %v", err)
		return
	}
	t.Logf("peerCert.Subject.CommonName = %v", peerCert.Subject.CommonName)

	// func (c *Certificate) CheckSignature(algo SignatureAlgorithm, signed, signature []byte) error {
	err = caCert.CheckSignature(peerCert.SignatureAlgorithm, peerCert.RawTBSCertificate, peerCert.Signature)
	if err != nil {
		t.Fatalf("err = %v", err)
		return
	}

	/*
		_,err= cert.Verify(VerifyOptions{})
		if err != nil{
			t.Fatalf("err = %v", err)
			return
		}
	*/
}

func TestVerifyGMCertificateOrg2(t *testing.T) {
	// ca
	caPem, err := ioutil.ReadFile("org2/ca.pem") // 从文件读取数据
	if err != nil {
		t.Fatalf("err = %v", err)
		return
	}

	caContent, _ := pem.Decode([]byte(caPem))
	caCert, err := ParseCertificate(caContent.Bytes)
	if err != nil {
		t.Fatalf("err = %v", err)
		return
	}
	t.Logf("caCert.Subject.CommonName = %v", caCert.Subject.CommonName)

	// peer
	peerPem, err := ioutil.ReadFile("org2/peer.pem") // 从文件读取数据
	if err != nil {
		t.Fatalf("err = %v", err)
		return
	}

	peerContent, _ := pem.Decode([]byte(peerPem))
	peerCert, err := ParseCertificate(peerContent.Bytes)
	if err != nil {
		t.Fatalf("err = %v", err)
		return
	}
	t.Logf("peerCert.Subject.CommonName = %v", peerCert.Subject.CommonName)

	// func (c *Certificate) CheckSignature(algo SignatureAlgorithm, signed, signature []byte) error {
	err = caCert.CheckSignature(peerCert.SignatureAlgorithm, peerCert.RawTBSCertificate, peerCert.Signature)
	if err != nil {
		t.Fatalf("err = %v", err)
		return
	}

	/*
		_,err= cert.Verify(VerifyOptions{})
		if err != nil{
			t.Fatalf("err = %v", err)
			return
		}
	*/
}

func TestVerifyGMCertificateOrderer(t *testing.T) {
	// ca
	caPem, err := ioutil.ReadFile("orderer/ca.pem") // 从文件读取数据
	if err != nil {
		t.Fatalf("err = %v", err)
		return
	}

	caContent, _ := pem.Decode([]byte(caPem))
	caCert, err := ParseCertificate(caContent.Bytes)
	if err != nil {
		t.Fatalf("err = %v", err)
		return
	}
	t.Logf("caCert.Subject.CommonName = %v", caCert.Subject.CommonName)

	// peer
	peerPem, err := ioutil.ReadFile("orderer/peer.pem") // 从文件读取数据
	if err != nil {
		t.Fatalf("err = %v", err)
		return
	}

	peerContent, _ := pem.Decode([]byte(peerPem))
	peerCert, err := ParseCertificate(peerContent.Bytes)
	if err != nil {
		t.Fatalf("err = %v", err)
		return
	}
	t.Logf("peerCert.Subject.CommonName = %v", peerCert.Subject.CommonName)

	fmt.Printf("phf - createSelfSignedCert - peerCert.SignatureAlgorithm = %v\n", peerCert.SignatureAlgorithm)
	// func (c *Certificate) CheckSignature(algo SignatureAlgorithm, signed, signature []byte) error {
	err = caCert.CheckSignature(peerCert.SignatureAlgorithm, peerCert.RawTBSCertificate, peerCert.Signature)
	if err != nil {
		t.Fatalf("err = %v", err)
		return
	}

	/*
		_,err= cert.Verify(VerifyOptions{})
		if err != nil{
			t.Fatalf("err = %v", err)
			return
		}
	*/
}

//
func genTemplate() *Certificate {
	now := time.Now()

	testExtKeyUsage := []ExtKeyUsage{ExtKeyUsageClientAuth, ExtKeyUsageServerAuth}
	testUnknownExtKeyUsage := []asn1.ObjectIdentifier{[]int{1, 2, 3}, []int{2, 59, 1}}
	extraExtensionData := []byte("extra extension")
	commonName := "test.example.com"

	template := &Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"Σ Acme Co"},
			Country:      []string{"US"},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{
					Type:  []int{2, 5, 4, 42},
					Value: "Gopher",
				},
				// This should override the Country, above.
				{
					Type:  []int{2, 5, 4, 6},
					Value: "NL",
				},
			},
		},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(1 * time.Hour),
		SignatureAlgorithm:    ECDSAWithSHA256,
		SubjectKeyId:          []byte{1, 2, 3, 4},
		KeyUsage:              KeyUsageCertSign,
		ExtKeyUsage:           testExtKeyUsage,
		UnknownExtKeyUsage:    testUnknownExtKeyUsage,
		BasicConstraintsValid: true,
		IsCA:                  true,
		//OCSPServer:            []string{"http://ocurrentBCCSP.example.com"},
		IssuingCertificateURL: []string{"http://crt.example.com/ca1.crt"},
		DNSNames:              []string{"test.example.com"},
		EmailAddresses:        []string{"gophe@golang.org"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1).To4(), net.ParseIP("2001:4860:0:2001::68")},
		PolicyIdentifiers:     []asn1.ObjectIdentifier{[]int{1, 2, 3}},
		PermittedDNSDomains:   []string{".example.com", "example.com"},
		CRLDistributionPoints: []string{"http://crl1.example.com/ca1.crl", "http://crl2.example.com/ca1.crl"},
		ExtraExtensions: []pkix.Extension{
			{
				Id:    []int{1, 2, 3, 4},
				Value: extraExtensionData,
			},
		},
	}

	return template
}

func createSelfSignedCert() error {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	userKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	// Generate a self-signed certificate
	template := genTemplate()
	certRaw, err := CreateCertificate(rand.Reader, template, template, &userKey.PublicKey, rootKey)
	if err != nil {
		return err
	}

	cert, err := ParseCertificate(certRaw)
	if err != nil {
		return err
	}

	fmt.Printf("phf - createSelfSignedCert - cert.SignatureAlgorithm = %v\n", cert.SignatureAlgorithm)
	err = checkSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature, &rootKey.PublicKey)
	if err != nil {
		return err
	}

	return nil
}

func createSelfSignedCertNew() error {
	//
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	template := genTemplate()
	caCertRaw, err := CreateCertificate(rand.Reader, template, template, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}

	caCert, err := ParseCertificate(caCertRaw)
	if err != nil {
		return err
	}

	//
	userKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	template = genTemplate()
	userCertRaw, err := CreateCertificate(rand.Reader, template, template, &userKey.PublicKey, caKey)
	if err != nil {
		return err
	}

	userCert, err := ParseCertificate(userCertRaw)
	if err != nil {
		return err
	}

	fmt.Printf("phf - createSelfSignedCert - userCert.SignatureAlgorithm = %v\n", userCert.SignatureAlgorithm)
	err = checkSignature(userCert.SignatureAlgorithm, userCert.RawTBSCertificate, userCert.Signature, caCert.PublicKey)
	if err != nil {
		return err
	}

	return nil
}

func TestCreateGMCertificate(t *testing.T) {
	succTotal := 0
	failTotal := 0

	i := 1
	for i = 1; i <= 1000; i++ {
		err := createSelfSignedCertNew()
		if err != nil {
			fmt.Printf("phf - createSelfSignedCertNew - i = %v -> error\n", i)
			//t.Fatalf("err = %v", err)
			//return
			failTotal++
		} else {
			succTotal++
		}

		fmt.Printf("\n\n\n")
		//time.Sleep(time.Duration(10) * time.Millisecond)
	}

	fmt.Printf("phf - TestCreateGMCertificate - i = %v -> succTotal = %v, failTotal = %v\n",
		i, succTotal, failTotal)
}
