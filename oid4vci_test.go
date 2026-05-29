package oid4vci_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	oid4vci "github.com/alanh-pyxical/go-oid4vci"
	"github.com/alanh-pyxical/go-oid4vci/client"
	"github.com/alanh-pyxical/go-oid4vci/internal/jose"
	"github.com/alanh-pyxical/go-oid4vci/issuer"
	"github.com/alanh-pyxical/go-oid4vci/types"
)

// --- test helpers ---

// ecSigner is a minimal Signer backed by an ECDSA key for testing.
type ecSigner struct {
	key *ecdsa.PrivateKey
	kid string
}

func newECSigner(t *testing.T, kid string) *ecSigner {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	return &ecSigner{key: k, kid: kid}
}

func (s *ecSigner) Sign(payload []byte) ([]byte, error) {
	return (&jose.ECDSASigner{Key: s.key, KID: s.kid}).Sign(payload)
}
func (s *ecSigner) Algorithm() string { return "ES256" }
func (s *ecSigner) KeyID() string     { return s.kid }

func (s *ecSigner) PublicKeyJWK() (map[string]any, error) {
	return jose.PublicKeyToJWKMap(&s.key.PublicKey)
}

// testFactory is a CredentialFactory that returns a fixed credential string.
type testFactory struct {
	credential string
	format     string
}

func (f *testFactory) Issue(_ context.Context, _ *issuer.CredentialRequest) (string, string, error) {
	return f.credential, f.format, nil
}

// buildTestIssuer creates an Issuer wired to in-memory stores, ready to test.
func buildTestIssuer(t *testing.T, issuerURI string, factory issuer.CredentialFactory) *issuer.Issuer {
	t.Helper()
	meta := types.IssuerMetadata{
		Issuer:             issuerURI,
		CredentialEndpoint: issuerURI + "/credential",
		TokenEndpoint:      issuerURI + "/token",
		CredentialConfigurationsSupported: map[string]types.CredentialConfiguration{
			"MortgageOffer_vc+sd-jwt": {
				Format: types.FormatSDJWTVC,
				VCT:    "MortgageOffer",
				ProofTypesSupported: map[string]types.ProofTypeMetadata{
					"jwt": {ProofSigningAlgValuesSupported: []string{"ES256"}},
				},
			},
		},
	}

	i, err := issuer.New(
		meta,
		issuer.NewMemoryOfferStore(),
		issuer.NewMemoryTokenStore(),
		factory,
	)
	if err != nil {
		t.Fatalf("building issuer: %v", err)
	}
	return i
}

// --- tests ---

func TestMetadataEndpoint(t *testing.T) {
	i := buildTestIssuer(t, "https://bank.example", &testFactory{"cred", types.FormatSDJWTVC})

	srv := httptest.NewServer(i.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/.well-known/openid-credential-issuer")
	if err != nil {
		t.Fatalf("GET metadata: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var meta types.IssuerMetadata
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		t.Fatalf("decoding metadata: %v", err)
	}
	if meta.Issuer != "https://bank.example" {
		t.Errorf("issuer: got %q", meta.Issuer)
	}
}

func TestPreAuthFlow_NoProof(t *testing.T) {
	factory := &testFactory{credential: "eyJ.testcredential.sig", format: types.FormatSDJWTVC}
	iss := buildTestIssuer(t, "https://bank.example", factory)

	// Override metadata issuer to match the test server URL at runtime.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		iss.Handler().ServeHTTP(w, r)
	}))
	defer srv.Close()

	// Build issuer pointing at the test server.
	meta := types.IssuerMetadata{
		Issuer:             srv.URL,
		CredentialEndpoint: srv.URL + "/credential",
		TokenEndpoint:      srv.URL + "/token",
		CredentialConfigurationsSupported: map[string]types.CredentialConfiguration{
			"MortgageOffer_vc+sd-jwt": {Format: types.FormatSDJWTVC, VCT: "MortgageOffer"},
		},
	}
	realIssuer, err := issuer.New(meta,
		issuer.NewMemoryOfferStore(),
		issuer.NewMemoryTokenStore(),
		factory,
	)
	if err != nil {
		t.Fatalf("building issuer: %v", err)
	}

	realSrv := httptest.NewServer(realIssuer.Handler())
	defer realSrv.Close()

	// Create an offer.
	offerResp, err := realIssuer.NewOffer(context.Background(), issuer.OfferConfig{
		SubjectID:                  "cust-123",
		CredentialConfigurationIDs: []string{"MortgageOffer_vc+sd-jwt"},
	})
	if err != nil {
		t.Fatalf("NewOffer: %v", err)
	}

	// Run the client acquisition flow.
	c := client.New(client.WithHTTPClient(realSrv.Client()))

	session, err := c.ParseOffer(context.Background(), offerResp.OfferURI)
	if err != nil {
		t.Fatalf("ParseOffer: %v", err)
	}
	// Patch the issuer URI in the session to the test server URL.
	session.Metadata.Issuer = realSrv.URL
	session.Metadata.TokenEndpoint = realSrv.URL + "/token"
	session.Metadata.CredentialEndpoint = realSrv.URL + "/credential"

	session, err = c.RedeemOffer(context.Background(), session, "")
	if err != nil {
		t.Fatalf("RedeemOffer: %v", err)
	}
	if session.AccessToken == "" {
		t.Error("expected non-empty access token")
	}
	if session.CNonce == "" {
		t.Error("expected non-empty c_nonce")
	}

	cred, format, _, err := c.RequestCredential(context.Background(), session, "", nil)
	if err != nil {
		t.Fatalf("RequestCredential: %v", err)
	}
	if cred != factory.credential {
		t.Errorf("credential: got %q, want %q", cred, factory.credential)
	}
	if format != types.FormatSDJWTVC {
		t.Errorf("format: got %q, want %q", format, types.FormatSDJWTVC)
	}
}

func TestPreAuthFlow_WithTxCode(t *testing.T) {
	factory := &testFactory{credential: "eyJ.test.sig", format: types.FormatSDJWTVC}
	meta := types.IssuerMetadata{
		Issuer:             "placeholder",
		CredentialEndpoint: "placeholder/credential",
		TokenEndpoint:      "placeholder/token",
		CredentialConfigurationsSupported: map[string]types.CredentialConfiguration{
			"MortgageOffer_vc+sd-jwt": {Format: types.FormatSDJWTVC},
		},
	}

	offerStore := issuer.NewMemoryOfferStore()
	tokenStore := issuer.NewMemoryTokenStore()

	realIssuer, _ := issuer.New(meta, offerStore, tokenStore, factory)

	srv := httptest.NewServer(realIssuer.Handler())
	defer srv.Close()

	// Patch URLs after we know the server address.
	meta.Issuer = srv.URL
	meta.TokenEndpoint = srv.URL + "/token"
	meta.CredentialEndpoint = srv.URL + "/credential"
	realIssuer2, _ := issuer.New(meta, issuer.NewMemoryOfferStore(), issuer.NewMemoryTokenStore(), factory)
	srv2 := httptest.NewServer(realIssuer2.Handler())
	defer srv2.Close()

	offerResp, err := realIssuer2.NewOffer(context.Background(), issuer.OfferConfig{
		SubjectID:                  "cust-456",
		CredentialConfigurationIDs: []string{"MortgageOffer_vc+sd-jwt"},
		TxCode:                     "1234",
	})
	if err != nil {
		t.Fatalf("NewOffer: %v", err)
	}

	c := client.New()
	session, _ := c.ParseOffer(context.Background(), offerResp.OfferURI)
	session.Metadata.Issuer = srv2.URL
	session.Metadata.TokenEndpoint = srv2.URL + "/token"
	session.Metadata.CredentialEndpoint = srv2.URL + "/credential"

	// Wrong PIN should fail.
	_, err = c.RedeemOffer(context.Background(), session, "9999")
	if err == nil {
		t.Fatal("expected error for wrong tx_code")
	}
	var pe *oid4vci.ProtocolError
	if !isProtocolErr(err, &pe) || pe.Code != oid4vci.ErrCodeInvalidGrant {
		t.Errorf("expected invalid_grant protocol error, got %v", err)
	}
}

func TestOfferAlreadyUsed(t *testing.T) {
	factory := &testFactory{credential: "cred", format: types.FormatSDJWTVC}
	meta := types.IssuerMetadata{
		Issuer:             "placeholder",
		CredentialEndpoint: "placeholder/credential",
		TokenEndpoint:      "placeholder/token",
		CredentialConfigurationsSupported: map[string]types.CredentialConfiguration{
			"c1": {Format: types.FormatSDJWTVC},
		},
	}
	realIssuer, _ := issuer.New(meta, issuer.NewMemoryOfferStore(), issuer.NewMemoryTokenStore(), factory)
	srv := httptest.NewServer(realIssuer.Handler())
	defer srv.Close()

	meta.Issuer = srv.URL
	meta.TokenEndpoint = srv.URL + "/token"
	meta.CredentialEndpoint = srv.URL + "/credential"
	realIssuer2, _ := issuer.New(meta, issuer.NewMemoryOfferStore(), issuer.NewMemoryTokenStore(), factory)
	srv2 := httptest.NewServer(realIssuer2.Handler())
	defer srv2.Close()

	offerResp, _ := realIssuer2.NewOffer(context.Background(), issuer.OfferConfig{
		SubjectID:                  "s1",
		CredentialConfigurationIDs: []string{"c1"},
	})

	c := client.New()
	session, _ := c.ParseOffer(context.Background(), offerResp.OfferURI)
	session.Metadata.Issuer = srv2.URL
	session.Metadata.TokenEndpoint = srv2.URL + "/token"
	session.Metadata.CredentialEndpoint = srv2.URL + "/credential"

	_, err := c.RedeemOffer(context.Background(), session, "")
	if err != nil {
		t.Fatalf("first redeem should succeed: %v", err)
	}

	// Second redemption with the same code must fail.
	_, err = c.RedeemOffer(context.Background(), session, "")
	if err == nil {
		t.Fatal("expected error on second redemption")
	}
}

func isProtocolErr(err error, out **oid4vci.ProtocolError) bool {
	var pe *oid4vci.ProtocolError
	ok := false
	e := err
	for e != nil {
		if pe2, ok2 := e.(*oid4vci.ProtocolError); ok2 {
			*out = pe2
			pe = pe2
			ok = true
			break
		}
		type unwrap interface{ Unwrap() error }
		if u, ok2 := e.(unwrap); ok2 {
			e = u.Unwrap()
		} else {
			break
		}
	}
	_ = pe
	return ok
}
