/*
Copyright 2020 The Kubernetes Authors.

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

package utils

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

const (
	CERTIFICATEREQUEST = "CERTIFICATE REQUEST"
	CERTIFICATE        = "CERTIFICATE"
)

func ParseCertPEM(pemBytes []byte) (*x509.Certificate, error) {
	// extract PEM from request object
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("PEM block type must be CERTIFICATE")
	}
	return x509.ParseCertificate(block.Bytes)
}

// ParseCertsPEM attempts to parse a series of PEM encoded certificates.
// It appends any certificates found to s and reports whether any certificates
// were successfully parsed.
//
// On many Linux systems, /etc/ssl/cert.pem will contain the system wide set
// of root CAs in a format suitable for this function.
func ParseCertsPEM(pemCerts []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	pemCerts = []byte(strings.TrimSpace(string(pemCerts)))

	for len(pemCerts) > 0 {
		var block *pem.Block
		block, pemCerts = pem.Decode(pemCerts)
		if block == nil {
			return nil, errors.New("decode pem slice fail")
		}
		if block.Type != CERTIFICATE || len(block.Headers) != 0 {
			continue
		}

		certBytes := block.Bytes
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			continue
		}

		certs = append(certs, cert)

		pemCerts = []byte(strings.TrimSpace(string(pemCerts)))
	}

	return certs, nil
}

func ParseCertsDER(certsDER [][]byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	for _, der := range certsDER {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			continue
		}

		certs = append(certs, cert)
	}

	return certs, nil
}

func ParseCSRPEM(pemBytes []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != CERTIFICATEREQUEST {
		return nil, errors.New("PEM block type must be CERTIFICATE REQUEST")
	}
	return x509.ParseCertificateRequest(block.Bytes)
}

func CSRPEM2DER(pemBytes []byte) ([]byte, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != CERTIFICATEREQUEST {
		return nil, errors.New("PEM block type must be CERTIFICATE REQUEST")
	}

	return block.Bytes, nil
}

func X509DER2PEM(der []byte) []byte {
	x509PEM := pem.EncodeToMemory(&pem.Block{
		Type:  CERTIFICATE,
		Bytes: der,
	})

	return x509PEM
}

func X509DERs2PEMs(ders [][]byte) []byte {
	var pems string

	for _, der := range ders {
		pem := X509DER2PEM(der)

		pems += fmt.Sprintf("%s\n", pem)
	}

	return []byte(pems)
}
