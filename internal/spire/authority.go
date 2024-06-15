package spire

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/kongweiguo/spire-issuer/api/v1alpha1"
	"math/big"
	"strconv"
	"time"

	"github.com/kongweiguo/spire-issuer/internal/utils"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

const (
	NamePrivateKey       = "PrivateKey"      // PKCS #8 encoded private key in pem format
	NameCertificate      = "Cert"            // certificates, from spire issuer leaf to root
	NameCertificateChain = "CertChain"       // certificates, from spire issuer leaf to root
	NameTrustPool        = "X509Authorities" // trust pool
)

var (
	defaultBackRatio float64 = 1.0 / 3.0
)

var serialNumberLimit = new(big.Int).Lsh(big.NewInt(1), 128)

type Authority struct {
	PrivateKey      crypto.Signer
	Cert            *x509.Certificate
	CertChain       []*x509.Certificate // certificate chain from
	X509Authorities []*x509.Certificate

	PrivateKeyPem      []byte
	CertPem            []byte
	CertChainPem       []byte
	X509AuthoritiesPem []byte
}

func AuthorityToSecret(secretName *types.NamespacedName, ca *Authority) *corev1.Secret {
	secret := &corev1.Secret{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName.Name,
			Namespace: secretName.Namespace,
		},
		Data: map[string][]byte{
			NamePrivateKey:       ca.PrivateKeyPem,
			NameCertificate:      ca.CertPem,
			NameCertificateChain: ca.CertChainPem,
			NameTrustPool:        ca.X509AuthoritiesPem,
		},
		Type: corev1.SecretTypeOpaque,
	}

	return secret
}

func SecretToAuthority(s *corev1.Secret) (*Authority, error) {

	PrivateKeyPEM, ok := s.Data[NamePrivateKey]
	if !ok {
		return nil, fmt.Errorf("%s empty", NamePrivateKey)
	}
	CertPEM, ok := s.Data[NameCertificate]
	if !ok {
		return nil, fmt.Errorf("%s empty", NameCertificate)
	}
	CertChainPEM, ok := s.Data[NameCertificateChain]
	if !ok {
		return nil, fmt.Errorf("%s empty", NameCertificateChain)
	}
	BundlePEM, ok := s.Data[NameTrustPool]
	if !ok {
		return nil, fmt.Errorf("%s empty", NameTrustPool)
	}

	PrivateKey, err := utils.ParsePrivateKeyPEM(PrivateKeyPEM)
	if err != nil {

		return nil, err
	}

	Cert, err := utils.ParseCertPEM(CertPEM)
	if err != nil {
		return nil, err
	}

	CertChain, err := utils.ParseCertsPEM(CertChainPEM)
	if err != nil {
		return nil, err
	}

	Bundle, err := utils.ParseCertsPEM(BundlePEM)
	if err != nil {
		return nil, err
	}

	ca := &Authority{
		PrivateKey:      PrivateKey,
		Cert:            Cert,
		CertChain:       CertChain,
		X509Authorities: Bundle,

		PrivateKeyPem:      PrivateKeyPEM,
		CertPem:            CertPEM,
		CertChainPem:       CertChainPEM,
		X509AuthoritiesPem: BundlePEM,
	}

	return ca, nil
}

// NeedRotation check if the authorit should be rotated
func (ca *Authority) NeedRotation(cfg *v1alpha1.Config) bool {
	if ca == nil || len(ca.CertChain) < 1 {
		return true
	}

	ratio, err := strconv.ParseFloat(cfg.Ratio, 64)
	if err != nil {
		ratio = defaultBackRatio
	}

	if !(ratio > 0.3 && ratio < 0.5) {
		ratio = defaultBackRatio
	}

	cert := ca.Cert
	now := time.Now().UTC()
	gate := calculateTimePoint(cert.NotBefore, cert.NotAfter, ratio)

	if now.UTC().After(gate.UTC()) {
		return true
	}

	return false
}

func calculateTimePoint(NotBefore, NotAfter time.Time, ratio float64) time.Time {
	// 计算时间差
	duration := NotAfter.Sub(NotBefore)
	// 计算偏移时间
	offset := time.Duration(float64(duration) * ratio)
	// 计算目标时间
	targetTime := NotBefore.Add(offset)
	return targetTime
}

// Sign signs a certificate request, applying a SigningPolicy and returns
// a pem encoded x509 certificate chain
func (ca *Authority) Sign(certificateRequest *cmapi.CertificateRequestSpec) ([]byte, error) {
	csr, err := utils.ParseCSRPEM(certificateRequest.Request)
	if err != nil {
		return nil, fmt.Errorf("unable to parse certificate request: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("unable to verify certificate request signature: %v", err)
	}

	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("unable to generate a serial number for %s: %v", csr.Subject.CommonName, err)
	}

	// set up the validation period, fix to the right range
	now := time.Now()
	notBefore := now.Add(-24 * time.Hour)
	notAfter := now.Add(certificateRequest.Duration.Duration)
	if notAfter.After(ca.Cert.NotAfter) {
		notAfter = ca.Cert.NotAfter
	}
	if !now.Before(ca.Cert.NotAfter) {
		return nil, fmt.Errorf("refusing to sign a certificate that expired in the past")
	}

	tmpl := &x509.Certificate{
		SerialNumber:       serialNumber,
		Subject:            csr.Subject,
		DNSNames:           csr.DNSNames,
		IPAddresses:        csr.IPAddresses,
		EmailAddresses:     csr.EmailAddresses,
		URIs:               csr.URIs,
		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		PublicKey:          csr.PublicKey,
		Extensions:         csr.Extensions,
		ExtraExtensions:    csr.ExtraExtensions,
		NotBefore:          notBefore,
		NotAfter:           notAfter,
	}

	policy := PermissiveSigningPolicy{
		DeadNotBefore: ca.Cert.NotBefore,
		DeadNotAfter:  ca.Cert.NotAfter,
		Usages:        certificateRequest.Usages,
		CouldCA:       false,
	}

	if err := policy.apply(tmpl); err != nil {
		return nil, err
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, csr.PublicKey, ca.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign certificate: %v", err)
	}

	x509PEM := utils.X509DER2PEM(der)
	chain := append(x509PEM, ca.CertChainPem...)

	return chain, nil
}
