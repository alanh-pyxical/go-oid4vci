// Package client implements the wallet side of the OID4VCI pre-authorised
// code flow.
//
// The [Client] is deliberately stateless — between steps it returns an
// [AcquisitionSession] that the caller persists however they see fit (in
// memory, a database, a cookie, etc.). This makes the client easy to use in
// both simple CLI tools and multi-process wallet services.
//
// Typical usage:
//
//	c := client.New(client.WithHTTPClient(myHTTPClient))
//
//	// One-shot: discover, exchange token, request credential.
//	credential, format, err := c.Acquire(ctx, offerURI, mySigner)
//
//	// Or step-by-step for wallets that need to persist mid-flow state:
//	session, err := c.ParseOffer(ctx, offerURI)
//	session, err = c.RedeemOffer(ctx, session, txCode)
//	credential, format, err := c.RequestCredential(ctx, session, configID, mySigner)
package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	oid4vci "github.com/alanh-pyxical/go-oid4vci"
	"github.com/alanh-pyxical/go-oid4vci/internal/jose"
	"github.com/alanh-pyxical/go-oid4vci/types"
)

// Signer is the interface the client needs from the wallet's key management.
// It is identical to the Signer interface in go-sd-jwt-vc so that a single
// key implementation satisfies both.
type Signer interface {
	Sign(payload []byte) ([]byte, error)
	Algorithm() string
	KeyID() string
}

// Client runs the wallet side of OID4VCI credential acquisition.
// Construct one with [New]. A Client is safe for concurrent use.
type Client struct {
	http     *http.Client
	clientID string // optional; identifies the wallet to the issuer
}

// Option configures a [Client].
type Option func(*Client)

// WithHTTPClient sets the HTTP client used for all network requests.
// Defaults to [http.DefaultClient].
func WithHTTPClient(c *http.Client) Option {
	return func(cl *Client) { cl.http = c }
}

// WithClientID sets the OAuth 2.0 client_id sent in token requests. Optional
// for public clients.
func WithClientID(id string) Option {
	return func(cl *Client) { cl.clientID = id }
}

// New creates a Client.
func New(opts ...Option) *Client {
	c := &Client{http: http.DefaultClient}
	for _, o := range opts {
		o(c)
	}
	return c
}

// AcquisitionSession holds the state accumulated across the multi-step
// acquisition flow. It is returned from each step and passed into the next.
// Callers that want to persist mid-flow state (e.g. between an HTTP request
// handler and a background job) can serialise this struct.
type AcquisitionSession struct {
	// Metadata is the issuer's metadata document, populated by ParseOffer.
	Metadata *types.IssuerMetadata

	// Offer is the structured credential offer, populated by ParseOffer.
	Offer *types.CredentialOffer

	// AccessToken is populated by RedeemOffer.
	AccessToken string

	// AccessTokenExpiry is the access token's expiry time.
	AccessTokenExpiry time.Time

	// CNonce is the server-issued nonce to include in the credential request
	// proof, populated by RedeemOffer and updated after each RequestCredential
	// call.
	CNonce string

	// CNonceExpiry is when CNonce expires.
	CNonceExpiry time.Time
}

// ParseOffer parses an openid-credential-offer:// URI, fetches the issuer
// metadata, and returns a session ready for [Client.RedeemOffer].
//
// offerURI is either:
//   - an openid-credential-offer://?credential_offer=<base64url-JSON> URI
//   - an openid-credential-offer://?credential_offer_uri=<URL> URI (fetched)
func (c *Client) ParseOffer(ctx context.Context, offerURI string) (*AcquisitionSession, error) {
	offer, err := c.decodeOfferURI(ctx, offerURI)
	if err != nil {
		return nil, fmt.Errorf("oid4vci/client: parsing offer: %w", err)
	}

	meta, err := c.FetchMetadata(ctx, offer.CredentialIssuer)
	if err != nil {
		return nil, err
	}

	return &AcquisitionSession{
		Metadata: meta,
		Offer:    offer,
	}, nil
}

// FetchMetadata fetches and validates the issuer's metadata from
// <issuerURI>/.well-known/openid-credential-issuer.
func (c *Client) FetchMetadata(ctx context.Context, issuerURI string) (*types.IssuerMetadata, error) {
	metaURL := strings.TrimRight(issuerURI, "/") + "/.well-known/openid-credential-issuer"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metaURL, nil)
	if err != nil {
		return nil, fmt.Errorf("oid4vci/client: building metadata request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", oid4vci.ErrMetadataUnavailable, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: HTTP %d from %s", oid4vci.ErrMetadataUnavailable, resp.StatusCode, metaURL)
	}

	var meta types.IssuerMetadata
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return nil, fmt.Errorf("%w: decoding metadata: %v", oid4vci.ErrMetadataUnavailable, err)
	}
	if meta.Issuer == "" {
		return nil, fmt.Errorf("%w: metadata missing issuer field", oid4vci.ErrMetadataUnavailable)
	}

	return &meta, nil
}

// RedeemOffer exchanges the pre-authorised code for an access token and
// c_nonce. txCode is the optional PIN; pass an empty string if none is
// required.
func (c *Client) RedeemOffer(ctx context.Context, session *AcquisitionSession, txCode string) (*AcquisitionSession, error) {
	grant := session.Offer.Grants.PreAuthorizedCode
	if grant == nil {
		return nil, fmt.Errorf("oid4vci/client: offer has no pre-authorized_code grant")
	}

	tokenURL := session.Metadata.TokenEndpoint
	if tokenURL == "" {
		// Fall back to the issuer URI pattern.
		tokenURL = strings.TrimRight(session.Metadata.Issuer, "/") + "/token"
	}

	form := url.Values{
		"grant_type":          {types.GrantTypePreAuthorized},
		"pre-authorized_code": {grant.PreAuthorizedCode},
	}
	if txCode != "" {
		form.Set("tx_code", txCode)
	}
	if c.clientID != "" {
		form.Set("client_id", c.clientID)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("oid4vci/client: building token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oid4vci/client: token request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		var errResp types.ErrorResponse
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return nil, &oid4vci.ProtocolError{Code: errResp.Error, Description: errResp.ErrorDescription}
		}
		return nil, fmt.Errorf("oid4vci/client: token endpoint HTTP %d", resp.StatusCode)
	}

	var tokenResp types.TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("oid4vci/client: decoding token response: %w", err)
	}

	updated := *session
	updated.AccessToken = tokenResp.AccessToken
	updated.AccessTokenExpiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	updated.CNonce = tokenResp.CNonce
	if tokenResp.CNonceExpiresIn > 0 {
		updated.CNonceExpiry = time.Now().Add(time.Duration(tokenResp.CNonceExpiresIn) * time.Second)
	}

	return &updated, nil
}

// RequestCredential requests a single credential from the credential endpoint.
// signer is the wallet's key that will be bound to the credential (used to
// sign the proof JWT). Pass nil to request without key binding.
//
// configID selects which credential configuration to request. If empty, the
// first configuration from the offer is used.
func (c *Client) RequestCredential(
	ctx context.Context,
	session *AcquisitionSession,
	configID string,
	signer Signer,
) (credential string, format string, updatedSession *AcquisitionSession, err error) {

	if configID == "" {
		if len(session.Offer.CredentialConfigurationIDs) == 0 {
			return "", "", nil, fmt.Errorf("oid4vci/client: no credential configuration IDs in offer")
		}
		configID = session.Offer.CredentialConfigurationIDs[0]
	}

	credReq := types.CredentialRequest{
		CredentialConfigurationID: configID,
	}

	// Build proof of key possession if a signer was provided.
	if signer != nil {
		if session.CNonce == "" {
			return "", "", nil, oid4vci.ErrNoCNonce
		}
		proofJWT, err := c.buildProof(session, signer)
		if err != nil {
			return "", "", nil, err
		}
		credReq.Proof = &types.CredentialProof{
			ProofType: "jwt",
			JWT:       proofJWT,
		}
	}

	credURL := session.Metadata.CredentialEndpoint

	body, _ := json.Marshal(credReq)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, credURL, bytes.NewReader(body))
	if err != nil {
		return "", "", nil, fmt.Errorf("oid4vci/client: building credential request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+session.AccessToken)

	resp, err := c.http.Do(req)
	if err != nil {
		return "", "", nil, fmt.Errorf("oid4vci/client: credential request: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		var errResp types.ErrorResponse
		if json.Unmarshal(respBody, &errResp) == nil && errResp.Error != "" {
			return "", "", nil, &oid4vci.ProtocolError{
				Code:        errResp.Error,
				Description: errResp.ErrorDescription,
				CNonce:      errResp.CNonce,
			}
		}
		return "", "", nil, fmt.Errorf("oid4vci/client: credential endpoint HTTP %d", resp.StatusCode)
	}

	var credResp types.CredentialResponse
	if err := json.Unmarshal(respBody, &credResp); err != nil {
		return "", "", nil, fmt.Errorf("oid4vci/client: decoding credential response: %w", err)
	}

	// Look up the format from the issuer metadata.
	if cfg, ok := session.Metadata.CredentialConfigurationsSupported[configID]; ok {
		format = cfg.Format
	}

	// Update the session with the rotated c_nonce.
	updated := *session
	if credResp.CNonce != "" {
		updated.CNonce = credResp.CNonce
		if credResp.CNonceExpiresIn > 0 {
			updated.CNonceExpiry = time.Now().Add(time.Duration(credResp.CNonceExpiresIn) * time.Second)
		}
	}

	return credResp.Credential, format, &updated, nil
}

// Acquire is a convenience method that runs the complete pre-authorised code
// flow in a single call. It is equivalent to ParseOffer → RedeemOffer →
// RequestCredential.
//
// For wallets that need to persist session state between steps (e.g. to
// survive process restarts or present a PIN entry UI), use the individual
// methods instead.
func (c *Client) Acquire(
	ctx context.Context,
	offerURI string,
	txCode string,
	signer Signer,
) (credential string, format string, err error) {

	session, err := c.ParseOffer(ctx, offerURI)
	if err != nil {
		return "", "", err
	}

	session, err = c.RedeemOffer(ctx, session, txCode)
	if err != nil {
		return "", "", err
	}

	cred, fmt_, _, err := c.RequestCredential(ctx, session, "", signer)
	return cred, fmt_, err
}

// --- internal helpers ---

func (c *Client) buildProof(session *AcquisitionSession, signer Signer) (string, error) {
	// The proof JWT header must include the holder's public key.
	// We get this by asking the signer for its public key via JWK.
	// Signers that implement PublicKeyProvider can expose it; otherwise
	// we embed a minimal key reference.
	extra := jose.Header{}

	if pkp, ok := signer.(interface {
		PublicKeyJWK() (map[string]any, error)
	}); ok {
		jwk, err := pkp.PublicKeyJWK()
		if err != nil {
			return "", fmt.Errorf("oid4vci/client: getting public key JWK: %w", err)
		}
		extra["jwk"] = jwk
	}

	return jose.BuildProofJWT(
		&joseSignerAdapter{signer, extra},
		session.Metadata.Issuer,
		c.clientID,
		session.CNonce,
	)
}

func (c *Client) decodeOfferURI(ctx context.Context, offerURI string) (*types.CredentialOffer, error) {
	parsed, err := url.Parse(offerURI)
	if err != nil {
		return nil, fmt.Errorf("invalid offer URI: %w", err)
	}

	q := parsed.Query()

	// credential_offer= carries base64url-encoded JSON inline.
	if raw := q.Get("credential_offer"); raw != "" {
		b, err := base64.RawURLEncoding.DecodeString(raw)
		if err != nil {
			// Might be plain URL-encoded JSON rather than base64.
			b = []byte(raw)
		}
		var offer types.CredentialOffer
		if err := json.Unmarshal(b, &offer); err != nil {
			return nil, fmt.Errorf("decoding credential_offer: %w", err)
		}
		return &offer, nil
	}

	// credential_offer_uri= carries a URL to fetch.
	if offerURL := q.Get("credential_offer_uri"); offerURL != "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, offerURL, nil)
		if err != nil {
			return nil, fmt.Errorf("building offer URI request: %w", err)
		}
		resp, err := c.http.Do(req)
		if err != nil {
			return nil, fmt.Errorf("fetching offer URI: %w", err)
		}
		defer resp.Body.Close()
		var offer types.CredentialOffer
		if err := json.NewDecoder(resp.Body).Decode(&offer); err != nil {
			return nil, fmt.Errorf("decoding offer URI response: %w", err)
		}
		return &offer, nil
	}

	return nil, fmt.Errorf("offer URI has neither credential_offer nor credential_offer_uri parameter")
}

// joseSignerAdapter bridges the client's Signer interface to jose.Signer,
// adding extra headers (e.g. the jwk field for proof JWTs).
type joseSignerAdapter struct {
	inner       Signer
	extraHeader jose.Header
}

func (a *joseSignerAdapter) Sign(payload []byte) ([]byte, error) { return a.inner.Sign(payload) }
func (a *joseSignerAdapter) Algorithm() string                   { return a.inner.Algorithm() }
func (a *joseSignerAdapter) KeyID() string                       { return a.inner.KeyID() }
