package centralserver

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	pathpkg "path"
	"time"

	"golang.org/x/crypto/sha3"
)

func setupSecurity(keyPath, certPath, hostIP string) error {
	for _, file := range []string{keyPath, certPath} {
		path := pathpkg.Dir(file)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			if err := os.MkdirAll(path, 0o700); err != nil {
				return err
			}
		}
	}

	if _, err := os.Stat(keyPath); err != nil {
		if err := generatePrivateKey(keyPath); err != nil {
			return err
		}
		return generateSelfSignedCertificate(keyPath, certPath, hostIP)
	}
	if _, err := os.Stat(certPath); err != nil {
		return generateSelfSignedCertificate(keyPath, certPath, hostIP)
	}
	return nil
}

func generatePrivateKey(filename string) error {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	keyFile, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer keyFile.Close()

	return pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
}

func generateSelfSignedCertificate(privateKeyFilename, certFilename, hostIP string) error {
	keyPEMBlock, err := os.ReadFile(privateKeyFilename)
	if err != nil {
		return err
	}
	keyDERBlock, _ := pem.Decode(keyPEMBlock)
	if keyDERBlock == nil {
		return errors.New("failed to decode PEM block containing private key")
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(keyDERBlock.Bytes)
	if err != nil {
		return err
	}

	applicationURI, _ := url.Parse(fmt.Sprintf("urn:%s:opc-ua-centralserver", hostIP))
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	subjectKeyHash := sha3.New224()
	subjectKeyHash.Write(privateKey.PublicKey.N.Bytes())
	subjectKeyID := subjectKeyHash.Sum(nil)
	oidDC := asn1.ObjectIdentifier([]int{0, 9, 2342, 19200300, 100, 1, 25})

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: "opc-ua-centralserver", ExtraNames: []pkix.AttributeTypeAndValue{{Type: oidDC, Value: hostIP}}},
		SubjectKeyId:          subjectKeyID,
		AuthorityKeyId:        subjectKeyID,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment | x509.KeyUsageCertSign | x509.KeyUsageDataEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{hostIP},
		IPAddresses:           []net.IP{net.ParseIP(hostIP)},
		URIs:                  []*url.URL{applicationURI},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return err
	}

	certFile, err := os.Create(certFilename)
	if err != nil {
		return err
	}
	defer certFile.Close()

	return pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
}
