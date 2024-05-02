package authority

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	cfcsr "github.com/cloudflare/cfssl/csr"
	"github.com/kongweiguo/cryptoutils/encoding"
	"github.com/kongweiguo/spire-issuer/internal/utils"
	"github.com/pkg/errors"

	"github.com/spiffe/go-spiffe/v2/spiffegrpc/grpccredentials"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	svidv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/svid/v1"
)

type Cache struct {
	cache map[string]*SpireClient
	mutex sync.Mutex
}

var c Cache

func Init() {
	// nothing to do
	c.cache = make(map[string]*SpireClient)
}

func Close() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	for _, cc := range c.cache {
		cc.Close()
	}
}

func GetDownstreamAuthority(ctx context.Context, cfg *SpireConfig) (*Authority, error) {
	cli, err := c.getSpireClient(ctx, cfg)
	if err != nil {
		return nil, err
	}

	ca, err := cli.GetDownstreamAuthority(ctx)
	if err != nil {
		return nil, err
	}

	return ca, nil
}

type SpireClient struct {
	downstreamAuthority *Authority

	x509Source *workloadapi.X509Source
	conn       *grpc.ClientConn
	svidClient svidv1.SVIDClient
}

type SpireConfig struct {
	TrustDomain   string `json:"trustDomain" yaml:"trustDomain"`
	AgentSocket   string `json:"agentSocket" yaml:"agentSocket"`   // spire agent's unix domain socket path
	ServerAddress string `json:"spireAddress" yaml:"spireAddress"` // spire server listen address, looks like: “address:port”
}

func (cfg *SpireConfig) String() string {
	return fmt.Sprintf("td:%s;socket:%s;server%s", cfg.TrustDomain, cfg.AgentSocket, cfg.ServerAddress)
}

func (c *Cache) getSpireClient(ctx context.Context, cfg *SpireConfig) (*SpireClient, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	index := cfg.String()
	cli, ok := c.cache[index]
	if ok {
		// TODO
		// 1. Check if the svid client is alive
		return cli, nil
	}

	cli, err := newSpireClient(ctx, cfg)
	if err != nil {
		return nil, errors.Wrap(err, "newSpireClient fail")
	}

	c.cache[index] = cli

	return cli, nil
}

func newSpireClient(ctx context.Context, cfg *SpireConfig) (*SpireClient, error) {
	socketPath, err := utils.NormalizeUnixSocket(cfg.AgentSocket)
	if err != nil {
		return nil, errors.Wrap(err, "config socketPath invalid")
	}

	x509Source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath)))
	if err != nil {
		return nil, fmt.Errorf("unable to create X509Source: %s", err)
	}

	// 2. Build up connection to spire server
	conn, err := grpc.DialContext(ctx, cfg.ServerAddress, grpc.WithTransportCredentials(
		grpccredentials.MTLSClientCredentials(x509Source, x509Source, tlsconfig.AuthorizeAny()),
	))
	if err != nil {
		return nil, fmt.Errorf("failed to dial: %s", err)
	}

	client := &SpireClient{
		x509Source: x509Source,
		conn:       conn,
		svidClient: svidv1.NewSVIDClient(conn),
	}

	return client, nil
}

func (s *SpireClient) Close() {
	if s != nil {
		if s.x509Source != nil {
			s.x509Source.Close()
		}

		if s.conn != nil {
			s.conn.Close()
		}
	}
}

func (s *SpireClient) GetDownstreamAuthority(ctx context.Context) (*Authority, error) {
	if !(s.downstreamAuthority.NeedRotation()) {
		return s.downstreamAuthority, nil
	}

	csr, privatekey, err := s.generateKeyAndCSR()
	if err != nil {
		return nil, err
	}

	request := &svidv1.NewDownstreamX509CARequest{
		Csr: csr,
	}

	resp, err := s.svidClient.NewDownstreamX509CA(ctx, request)
	if err != nil {
		return nil, err
	}

	if len(resp.CaCertChain) == 0 {
		return nil, fmt.Errorf("spire return emtpy ca certchain")
	}

	PrivateKeyDER, err := x509.MarshalPKCS8PrivateKey(privatekey)
	if err != nil {
		return nil, errors.Wrap(err, "GetDownstreamAuthority MarshalPKCS8PrivateKey fail")
	}
	PrivateKeyPEM := utils.PKCS8PrivateKeyDERtoPEM(PrivateKeyDER)

	CertPEM := utils.X509DERToPEM(resp.CaCertChain[0])
	CertChainPEM := utils.X509DERsToPEMs(resp.X509Authorities)
	BundlePEM := utils.X509DERsToPEMs(resp.X509Authorities)

	CertChain, err := utils.ParseCertsDER(resp.CaCertChain)
	if err != nil {
		return nil, errors.Wrap(err, "GetDownstreamAuthority ParseCertsDER(resp.CaCertChain) fail")
	}

	Bundle, err := utils.ParseCertsDER(resp.X509Authorities)
	if err != nil {
		return nil, errors.Wrap(err, "GetDownstreamAuthority ParseCertsDER(resp.X509Authorities) fail")
	}

	ca := &Authority{
		PrivateKey:          privatekey,
		Certificate:         CertChain[0],
		CertificateChain:    CertChain,
		TrustPool:           Bundle,
		PrivateKeyPEM:       PrivateKeyPEM,
		CertificatePEM:      CertPEM,
		CertificateChainPEM: CertChainPEM,
		TrustPoolPEM:        BundlePEM,
	}

	return ca, nil
}

func (s *SpireClient) generateKeyAndCSR() (csr []byte, privateKey crypto.Signer, err error) {
	keyRequest := cfcsr.NewKeyRequest()

	priv, err := keyRequest.Generate()
	if err != nil {
		return nil, nil, status.Error(codes.Internal, fmt.Sprintf("failed to generate private key: %s", err))
	}

	req := &cfcsr.CertificateRequest{
		CN: "byted.sh",
		Names: []cfcsr.Name{
			{
				C: "CN",
				O: "TrustAuth",
			},
		},
	}

	csrPEM, err := cfcsr.Generate(priv.(crypto.Signer), req)
	if err != nil {
		return nil, nil, status.Error(codes.Internal, fmt.Sprintf("failed to generate csr: %s", err))
	}

	csr, err = encoding.PEM2ASN1(csrPEM, encoding.PEMTypeCertSignRequest)
	if err != nil {
		return nil, nil, fmt.Errorf("fail to transfer pem to der, err:%s", err)
	}

	return csr, priv.(crypto.Signer), nil
}
