// Command mortgage demonstrates the full OID4VCI pre-authorised code flow
// using an in-process HTTP test server.
//
// It simulates:
//  1. A bank creating a credential offer for a customer's mortgage approval
//  2. An aggregator wallet discovering the offer and acquiring the credential
//
// Run with: go run ./example/mortgage
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"net/http/httptest"

	"github.com/alanh-pyxical/go-oid4vci/client"
	"github.com/alanh-pyxical/go-oid4vci/internal/jose"
	"github.com/alanh-pyxical/go-oid4vci/issuer"
	"github.com/alanh-pyxical/go-oid4vci/types"
)

func main() {
	ctx := context.Background()

	// --- 1. Bank sets up its issuer service ---

	// In production these would be real URLs. For this example we use a
	// test server and patch the URLs after it starts.
	offerStore := issuer.NewMemoryOfferStore()
	tokenStore := issuer.NewMemoryTokenStore()

	factory := &mortgageFactory{}

	meta := types.IssuerMetadata{
		Issuer:             "https://lloyds.example", // patched below
		CredentialEndpoint: "https://lloyds.example/credential",
		TokenEndpoint:      "https://lloyds.example/token",
		CredentialConfigurationsSupported: map[string]types.CredentialConfiguration{
			"MortgageOffer_sd-jwt": {
				Format: types.FormatSDJWTVC,
				VCT:    "https://schema.pyxical.com/MortgageOffer",
				Display: []types.CredentialDisplay{
					{Name: "Mortgage Offer", Locale: "en-GB"},
				},
				CryptographicBindingMethodsSupported: []string{"jwk"},
				ProofTypesSupported: map[string]types.ProofTypeMetadata{
					"jwt": {ProofSigningAlgValuesSupported: []string{"ES256"}},
				},
			},
		},
		Display: []types.IssuerDisplay{
			{Name: "Lloyds Bank plc", Locale: "en-GB"},
		},
	}

	bankIssuer, err := issuer.New(meta, offerStore, tokenStore, factory)
	must(err, "creating issuer")

	srv := httptest.NewServer(bankIssuer.Handler())
	defer srv.Close()

	// Rebuild with the real test server URL.
	meta.Issuer = srv.URL
	meta.TokenEndpoint = srv.URL + "/token"
	meta.CredentialEndpoint = srv.URL + "/credential"
	bankIssuer, err = issuer.New(meta, offerStore, tokenStore, factory)
	must(err, "rebuilding issuer with real URL")

	srv2 := httptest.NewServer(bankIssuer.Handler())
	defer srv2.Close()

	fmt.Println("=== Bank issuer running at", srv2.URL, "===")

	// --- 2. Bank creates an offer for customer Jane Smith ---

	offerResp, err := bankIssuer.NewOffer(ctx, issuer.OfferConfig{
		SubjectID:                  "customer-jane-smith-7829",
		CredentialConfigurationIDs: []string{"MortgageOffer_sd-jwt"},
		Metadata: map[string]any{
			"max_amount":     450000,
			"currency":       "GBP",
			"offer_expiry":   "2025-10-01",
			"applicant_name": "Jane Smith",
		},
	})
	must(err, "creating offer")

	fmt.Println("=== Credential Offer ===")
	printJSON(offerResp.CredentialOffer)
	fmt.Println()

	// --- 3. Aggregator wallet receives the offer URI and acquires the credential ---

	walletKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err, "generating wallet key")
	walletSigner := &jose.ECDSASigner{Key: walletKey, KID: "wallet-key-1"}

	// Wallet wraps the signer to also expose its public key for proof JWTs.
	walletClientSigner := &walletSigner2{ECDSASigner: walletSigner}

	c := client.New(client.WithHTTPClient(srv2.Client()))

	session, err := c.ParseOffer(ctx, offerResp.OfferURI)
	must(err, "parsing offer")

	// Patch session to use the real test server URL.
	session.Metadata.Issuer = srv2.URL
	session.Metadata.TokenEndpoint = srv2.URL + "/token"
	session.Metadata.CredentialEndpoint = srv2.URL + "/credential"

	fmt.Println("=== Fetched issuer metadata ===")
	fmt.Printf("Issuer: %s\n", session.Metadata.Issuer)
	fmt.Printf("Configurations: %d\n\n", len(session.Metadata.CredentialConfigurationsSupported))

	session, err = c.RedeemOffer(ctx, session, "")
	must(err, "redeeming offer")

	fmt.Println("=== Token Response ===")
	fmt.Printf("Access token: %s...\n", session.AccessToken[:12])
	fmt.Printf("c_nonce:      %s\n\n", session.CNonce)

	credential, format, _, err := c.RequestCredential(ctx, session, "", walletClientSigner)
	must(err, "requesting credential")

	fmt.Println("=== Credential Issued ===")
	fmt.Printf("Format:     %s\n", format)
	fmt.Printf("Credential: %s\n", credential)
}

// mortgageFactory simulates what go-sd-jwt-vc would produce in production.
type mortgageFactory struct{}

func (f *mortgageFactory) Issue(_ context.Context, req *issuer.CredentialRequest) (string, string, error) {
	// In production this calls sdjwt.Issuer.Issue(...) from go-sd-jwt-vc.
	// Here we return a placeholder to keep this example self-contained.
	b, _ := json.Marshal(map[string]any{
		"sub":              req.SubjectID,
		"vct":              "https://schema.pyxical.com/MortgageOffer",
		"bank_name":        "Lloyds Bank plc",
		"offer_expiry":     req.Metadata["offer_expiry"],
		"max_amount":       req.Metadata["max_amount"],
		"applicant_name":   req.Metadata["applicant_name"],
		"holder_key_bound": req.HolderPublicKey != nil,
	})
	return string(b), types.FormatSDJWTVC, nil
}

// walletSigner2 wraps ECDSASigner and adds PublicKeyJWK so the client can
// embed the holder's public key in the proof JWT header.
type walletSigner2 struct {
	*jose.ECDSASigner
}

func (s *walletSigner2) PublicKeyJWK() (map[string]any, error) {
	return jose.PublicKeyToJWKMap(&s.Key.PublicKey)
}

func must(err error, context string) {
	if err != nil {
		log.Fatalf("%s: %v", context, err)
	}
}

func printJSON(v any) {
	b, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(b))
}
