/*
Copyright 2019 The Kubernetes Authors.

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

package spire

import (
	"crypto/x509"
	"fmt"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"sort"
	"time"
)

// SigningPolicy validates a CertificateRequest before it's signed by the
// CertificateAuthority. It may default or otherwise mutate a certificate
// template.
type SigningPolicy interface {
	// not-exporting apply forces signing policy implementations to be internal
	// to this package.
	apply(template *x509.Certificate) error
}

// PermissiveSigningPolicy is the signing policy historically used by the local
// signer.
//
//   - It forwards all SANs from the original signing request.
//   - It sets allowed usages as configured in the policy.
//   - It sets NotAfter based on the TTL configured in the policy.
//   - It zeros all extensions.
//   - It sets BasicConstraints to true.
//   - It sets IsCA to false.
type PermissiveSigningPolicy struct {
	// No matter how, the certificate to be issued out MUST not before this time
	DeadNotBefore time.Time

	// No matter how, the certificate to be issued out MUST not after this time
	DeadNotAfter time.Time

	// Usages are the allowed usages of a certificate.
	Usages []cmapi.KeyUsage

	// If the downstream certificate could be a CA certificate
	CouldCA bool

	// TODO ... any other extensions
}

func (p PermissiveSigningPolicy) apply(tmpl *x509.Certificate) error {
	// 1. usage
	usage, extUsages, err := keyUsagesFromStrings(p.Usages)
	if err != nil {
		return err
	}
	tmpl.KeyUsage = usage
	tmpl.ExtKeyUsage = extUsages

	// 2. time range
	if tmpl.NotAfter.After(p.DeadNotAfter) {
		tmpl.NotAfter = p.DeadNotAfter
	}

	if tmpl.NotBefore.Before(p.DeadNotBefore) {
		return fmt.Errorf("refusing to sign a certificate that siged out even bfore the ca")
	}

	if tmpl.NotBefore.After(tmpl.NotAfter) {
		return fmt.Errorf("refusing to sign a certificate that has wrong time range")
	}

	// 3. ca
	if !p.CouldCA {
		tmpl.IsCA = false
	}

	// 4. extensions
	tmpl.ExtraExtensions = nil
	tmpl.Extensions = nil
	tmpl.BasicConstraintsValid = true

	return nil
}

var keyUsageDict = map[cmapi.KeyUsage]x509.KeyUsage{
	cmapi.UsageSigning:           x509.KeyUsageDigitalSignature,
	cmapi.UsageDigitalSignature:  x509.KeyUsageDigitalSignature,
	cmapi.UsageContentCommitment: x509.KeyUsageContentCommitment,
	cmapi.UsageKeyEncipherment:   x509.KeyUsageKeyEncipherment,
	cmapi.UsageKeyAgreement:      x509.KeyUsageKeyAgreement,
	cmapi.UsageDataEncipherment:  x509.KeyUsageDataEncipherment,
	cmapi.UsageCertSign:          x509.KeyUsageCertSign,
	cmapi.UsageCRLSign:           x509.KeyUsageCRLSign,
	cmapi.UsageEncipherOnly:      x509.KeyUsageEncipherOnly,
	cmapi.UsageDecipherOnly:      x509.KeyUsageDecipherOnly,
}

var extKeyUsageDict = map[cmapi.KeyUsage]x509.ExtKeyUsage{
	cmapi.UsageAny:             x509.ExtKeyUsageAny,
	cmapi.UsageServerAuth:      x509.ExtKeyUsageServerAuth,
	cmapi.UsageClientAuth:      x509.ExtKeyUsageClientAuth,
	cmapi.UsageCodeSigning:     x509.ExtKeyUsageCodeSigning,
	cmapi.UsageEmailProtection: x509.ExtKeyUsageEmailProtection,
	cmapi.UsageSMIME:           x509.ExtKeyUsageEmailProtection,
	cmapi.UsageIPsecEndSystem:  x509.ExtKeyUsageIPSECEndSystem,
	cmapi.UsageIPsecTunnel:     x509.ExtKeyUsageIPSECTunnel,
	cmapi.UsageIPsecUser:       x509.ExtKeyUsageIPSECUser,
	cmapi.UsageTimestamping:    x509.ExtKeyUsageTimeStamping,
	cmapi.UsageOCSPSigning:     x509.ExtKeyUsageOCSPSigning,
	cmapi.UsageMicrosoftSGC:    x509.ExtKeyUsageMicrosoftServerGatedCrypto,
	cmapi.UsageNetscapeSGC:     x509.ExtKeyUsageNetscapeServerGatedCrypto,
}

// keyUsagesFromStrings will translate a slice of usage strings from the
// certificates API ("pkg/apis/certificates".KeyUsage) to x509.KeyUsage and
// x509.ExtKeyUsage types.
func keyUsagesFromStrings(usages []cmapi.KeyUsage) (x509.KeyUsage, []x509.ExtKeyUsage, error) {
	var keyUsage x509.KeyUsage
	var unrecognized []cmapi.KeyUsage
	extKeyUsages := make(map[x509.ExtKeyUsage]struct{})
	for _, usage := range usages {
		if val, ok := keyUsageDict[usage]; ok {
			keyUsage |= val
		} else if val, ok := extKeyUsageDict[usage]; ok {
			extKeyUsages[val] = struct{}{}
		} else {
			unrecognized = append(unrecognized, usage)
		}
	}

	var sorted sortedExtKeyUsage
	for eku := range extKeyUsages {
		sorted = append(sorted, eku)
	}
	sort.Sort(sorted)

	if len(unrecognized) > 0 {
		return 0, nil, fmt.Errorf("unrecognized usage values: %q", unrecognized)
	}

	return keyUsage, []x509.ExtKeyUsage(sorted), nil
}

type sortedExtKeyUsage []x509.ExtKeyUsage

func (s sortedExtKeyUsage) Len() int {
	return len(s)
}

func (s sortedExtKeyUsage) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s sortedExtKeyUsage) Less(i, j int) bool {
	return s[i] < s[j]
}
