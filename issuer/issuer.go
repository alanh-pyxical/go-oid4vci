package issuer

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	oid4vci "github.com/alanh-pyxical/go-oid4vci"
	"github.com/alanh-pyxical/go-oid4vci/internal/jose"
	"github.com/alanh-pyxical/go-oid4vci/types"
	"github.com/google/uuid"
)

// Issuer implements the server side of the OID4VCI pre-authorised code flow.
// Construct one with [New] and mount [Issuer.Handler] on your HTTP server.
//
// An Issuer is safe for concurrent use.
type Issuer struct {
	metadata types.IssuerMetadata
	offers   OfferStore
	tokens   TokenStore
	factory  CredentialFactory
	cfg      issuerConfig
}

type issuerConfig struct {
	preAuthCodeTTL time.Duration
	accessTokenTTL time.Duration
	cNonceTTL      time.Duration
	proofRequired  bool
}

// Option configures an [Issuer].
type Option func(*issuerConfig)

// WithPreAuthCodeTTL sets how long pre-authorised codes remain valid.
// Default: 5 minutes.
func WithPreAuthCodeTTL(d time.Duration) Option {
	return func(c *issuerConfig) { c.preAuthCodeTTL = d }
}

// WithAccessTokenTTL sets the access token lifetime. Default: 10 minutes.
func WithAccessTokenTTL(d time.Duration) Option {
	return func(c *issuerConfig) { c.accessTokenTTL = d }
}

// WithCNonceTTL sets the c_nonce lifetime. Default: 5 minutes.
func WithCNonceTTL(d time.Duration) Option {
	return func(c *issuerConfig) { c.cNonceTTL = d }
}

// RequireProof configures the issuer to reject credential requests that do
// not include a valid proof of key possession. Recommended for production.
func RequireProof() Option {
	return func(c *issuerConfig) { c.proofRequired = true }
}

// New creates an Issuer.
//
// metadata describes the credential configurations this issuer supports and
// must have its Issuer, CredentialEndpoint, and TokenEndpoint fields set.
//
// offers and tokens are the persistence interfaces — callers supply their
// own implementations (in-memory, Postgres, Redis, etc.).
//
// factory produces credentials when a wallet successfully requests one.
func New(
	metadata types.IssuerMetadata,
	offers OfferStore,
	tokens TokenStore,
	factory CredentialFactory,
	opts ...Option,
) (*Issuer, error) {
	if metadata.Issuer == "" {
		return nil, fmt.Errorf("oid4vci/issuer: metadata.Issuer is required")
	}
	if metadata.CredentialEndpoint == "" {
		return nil, fmt.Errorf("oid4vci/issuer: metadata.CredentialEndpoint is required")
	}
	if metadata.TokenEndpoint == "" {
		return nil, fmt.Errorf("oid4vci/issuer: metadata.TokenEndpoint is required")
	}
	if len(metadata.CredentialConfigurationsSupported) == 0 {
		return nil, fmt.Errorf("oid4vci/issuer: at least one credential configuration is required")
	}

	cfg := issuerConfig{
		preAuthCodeTTL: 5 * time.Minute,
		accessTokenTTL: 10 * time.Minute,
		cNonceTTL:      5 * time.Minute,
	}
	for _, o := range opts {
		o(&cfg)
	}

	return &Issuer{
		metadata: metadata,
		offers:   offers,
		tokens:   tokens,
		factory:  factory,
		cfg:      cfg,
	}, nil
}

// NewOffer creates a credential offer and returns the URI to deliver to the
// wallet.
func (i *Issuer) NewOffer(ctx context.Context, cfg OfferConfig) (*OfferResponse, error) {
	if cfg.SubjectID == "" {
		return nil, fmt.Errorf("oid4vci/issuer: OfferConfig.SubjectID is required")
	}
	if len(cfg.CredentialConfigurationIDs) == 0 {
		return nil, fmt.Errorf("oid4vci/issuer: at least one CredentialConfigurationID is required")
	}

	// Validate all requested configurations are supported.
	for _, id := range cfg.CredentialConfigurationIDs {
		if _, ok := i.metadata.CredentialConfigurationsSupported[id]; !ok {
			return nil, fmt.Errorf("oid4vci/issuer: unknown credential configuration %q", id)
		}
	}

	ttl := cfg.TTL
	if ttl == 0 {
		ttl = i.cfg.preAuthCodeTTL
	}

	code, err := generateToken(32)
	if err != nil {
		return nil, fmt.Errorf("oid4vci/issuer: generating pre-auth code: %w", err)
	}

	offer := &Offer{
		ID:                         uuid.New().String(),
		PreAuthorizedCode:          code,
		CredentialConfigurationIDs: cfg.CredentialConfigurationIDs,
		TxCode:                     cfg.TxCode,
		SubjectID:                  cfg.SubjectID,
		ExpiresAt:                  time.Now().Add(ttl),
		IssuedAt:                   time.Now(),
		Metadata:                   cfg.Metadata,
	}

	if err := i.offers.Save(ctx, offer); err != nil {
		return nil, fmt.Errorf("oid4vci/issuer: saving offer: %w", err)
	}

	credOffer := &types.CredentialOffer{
		CredentialIssuer:           i.metadata.Issuer,
		CredentialConfigurationIDs: cfg.CredentialConfigurationIDs,
	}
	credOffer.Grants.PreAuthorizedCode = &types.PreAuthorizedCodeGrant{
		PreAuthorizedCode: code,
	}
	if cfg.TxCode != "" {
		mode := "numeric"
		credOffer.Grants.PreAuthorizedCode.TxCode = &types.TxCode{
			InputMode:   mode,
			Description: "Enter the PIN provided by your bank",
		}
	}

	offerJSON, err := json.Marshal(credOffer)
	if err != nil {
		return nil, fmt.Errorf("oid4vci/issuer: marshalling offer: %w", err)
	}
	offerURI := "openid-credential-offer://?credential_offer=" +
		base64.RawURLEncoding.EncodeToString(offerJSON)

	return &OfferResponse{
		OfferURI:        offerURI,
		Offer:           offer,
		CredentialOffer: credOffer,
	}, nil
}

// Handler returns an [http.Handler] that serves all OID4VCI endpoints.
// Mount it at any path prefix using [http.StripPrefix] if needed:
//
//	mux.Handle("/vc/", http.StripPrefix("/vc", issuer.Handler()))
//
// The handler serves:
//
//	GET  /.well-known/openid-credential-issuer
//	GET  /.well-known/jwks.json  (if a JWKSFunc is configured)
//	POST /token
//	POST /credential
func (i *Issuer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-credential-issuer", i.handleMetadata)
	mux.HandleFunc("POST /token", i.handleToken)
	mux.HandleFunc("POST /credential", i.handleCredential)
	return mux
}

// --- HTTP handlers ---

func (i *Issuer) handleMetadata(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, i.metadata)
}

func (i *Issuer) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, oid4vci.ErrCodeInvalidRequest, "could not parse form body")
		return
	}

	grantType := r.FormValue("grant_type")
	if grantType != types.GrantTypePreAuthorized {
		writeError(w, http.StatusBadRequest, oid4vci.ErrCodeInvalidRequest,
			fmt.Sprintf("unsupported grant_type %q", grantType))
		return
	}

	preAuthCode := r.FormValue("pre-authorized_code")
	if preAuthCode == "" {
		writeError(w, http.StatusBadRequest, oid4vci.ErrCodeInvalidRequest, "pre-authorized_code is required")
		return
	}

	offer, err := i.offers.Consume(r.Context(), preAuthCode)
	if err != nil {
		switch {
		case isErr(err, oid4vci.ErrOfferNotFound):
			writeError(w, http.StatusBadRequest, oid4vci.ErrCodeInvalidGrant, "pre-authorized_code not found")
		case isErr(err, oid4vci.ErrOfferExpired):
			writeError(w, http.StatusBadRequest, oid4vci.ErrCodeInvalidGrant, "pre-authorized_code has expired")
		case isErr(err, oid4vci.ErrOfferAlreadyUsed):
			writeError(w, http.StatusBadRequest, oid4vci.ErrCodeInvalidGrant, "pre-authorized_code already used")
		default:
			writeError(w, http.StatusInternalServerError, oid4vci.ErrCodeServerError, "internal error")
		}
		return
	}

	// Validate tx_code (PIN) if the offer requires one.
	if offer.TxCode != "" {
		supplied := r.FormValue("tx_code")
		if supplied != offer.TxCode {
			writeError(w, http.StatusBadRequest, oid4vci.ErrCodeInvalidGrant, "invalid tx_code")
			return
		}
	}

	accessToken, err := generateToken(32)
	if err != nil {
		writeError(w, http.StatusInternalServerError, oid4vci.ErrCodeServerError, "internal error")
		return
	}
	cNonce, err := generateToken(16)
	if err != nil {
		writeError(w, http.StatusInternalServerError, oid4vci.ErrCodeServerError, "internal error")
		return
	}

	now := time.Now()
	record := &AccessTokenRecord{
		Token:                      accessToken,
		OfferID:                    offer.ID,
		SubjectID:                  offer.SubjectID,
		CredentialConfigurationIDs: offer.CredentialConfigurationIDs,
		CNonce:                     cNonce,
		CNonceExpiresAt:            now.Add(i.cfg.cNonceTTL),
		ExpiresAt:                  now.Add(i.cfg.accessTokenTTL),
		Metadata:                   offer.Metadata,
	}

	if err := i.tokens.Save(r.Context(), record); err != nil {
		writeError(w, http.StatusInternalServerError, oid4vci.ErrCodeServerError, "internal error")
		return
	}

	writeJSON(w, http.StatusOK, types.TokenResponse{
		AccessToken:     accessToken,
		TokenType:       "Bearer",
		ExpiresIn:       int(i.cfg.accessTokenTTL.Seconds()),
		CNonce:          cNonce,
		CNonceExpiresIn: int(i.cfg.cNonceTTL.Seconds()),
	})
}

func (i *Issuer) handleCredential(w http.ResponseWriter, r *http.Request) {
	// Extract and validate the access token (Bearer or DPoP scheme).
	tokenRecord, err := i.extractToken(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, oid4vci.ErrCodeInvalidToken, err.Error())
		return
	}

	// Parse the credential request body.
	var req types.CredentialRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, oid4vci.ErrCodeInvalidRequest, "invalid request body")
		return
	}

	// Resolve configuration ID.
	configID, err := i.resolveConfigID(req, tokenRecord)
	if err != nil {
		writeError(w, http.StatusBadRequest, oid4vci.ErrCodeUnsupportedCredType, err.Error())
		return
	}

	// Validate proof of possession.
	// Normalise: if only the batch "proofs" field is present, promote the
	// first JWT to a singular proof so existing validation logic handles both.
	proof := req.Proof
	if proof == nil && req.Proofs != nil && len(req.Proofs.JWT) > 0 {
		proof = &types.CredentialProof{ProofType: "jwt", JWT: req.Proofs.JWT[0]}
	}

	var holderKey any
	if proof != nil {
		holderKey, err = i.validateProof(r.Context(), proof, tokenRecord)
		if err != nil {
			cNonce, _ := generateToken(16)
			writeJSON(w, http.StatusBadRequest, types.ErrorResponse{
				Error:            oid4vci.ErrCodeInvalidProof,
				ErrorDescription: err.Error(),
				CNonce:           cNonce,
			})
			return
		}
	} else if i.cfg.proofRequired {
		writeError(w, http.StatusBadRequest, oid4vci.ErrCodeInvalidProof, "proof is required")
		return
	}

	// Delegate to the factory to produce the credential.
	credential, format, err := i.factory.Issue(r.Context(), &CredentialRequest{
		ConfigurationID: configID,
		SubjectID:       tokenRecord.SubjectID,
		HolderPublicKey: holderKey,
		Metadata:        tokenRecord.Metadata,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, oid4vci.ErrCodeServerError, "credential issuance failed")
		return
	}

	// Rotate the c_nonce after successful issuance.
	newNonce, _ := generateToken(16)
	i.tokens.RotateCNonce(r.Context(), tokenRecord.Token, newNonce, time.Now().Add(i.cfg.cNonceTTL)) //nolint:errcheck

	_ = format // format is implicit from configuration; could be added to response header

	if req.Proofs != nil {
		writeJSON(w, http.StatusOK, types.CredentialResponse{
			Credentials:     []types.CredentialResponseItem{{Credential: credential}},
			CNonce:          newNonce,
			CNonceExpiresIn: int(i.cfg.cNonceTTL.Seconds()),
		})
	} else {
		writeJSON(w, http.StatusOK, types.CredentialResponse{
			Credential:      credential,
			CNonce:          newNonce,
			CNonceExpiresIn: int(i.cfg.cNonceTTL.Seconds()),
		})
	}
}

// --- validation helpers ---

func (i *Issuer) extractToken(r *http.Request) (*AccessTokenRecord, error) {
	auth := r.Header.Get("Authorization")
	var raw string
	switch {
	case strings.HasPrefix(auth, "Bearer "):
		raw = strings.TrimPrefix(auth, "Bearer ")
	case strings.HasPrefix(auth, "DPoP "):
		raw = strings.TrimPrefix(auth, "DPoP ")
	default:
		return nil, oid4vci.ErrInvalidAccessToken
	}

	record, err := i.tokens.Get(r.Context(), raw)
	if err != nil {
		return nil, oid4vci.ErrInvalidAccessToken
	}
	if time.Now().After(record.ExpiresAt) {
		return nil, oid4vci.ErrInvalidAccessToken
	}
	return record, nil
}

func (i *Issuer) resolveConfigID(req types.CredentialRequest, record *AccessTokenRecord) (string, error) {
	var id string
	switch {
	case req.CredentialConfigurationID != "":
		id = req.CredentialConfigurationID
	case req.Format != "":
		// Find a configuration matching the requested format (and VCT if given).
		for k, cfg := range i.metadata.CredentialConfigurationsSupported {
			if cfg.Format == req.Format && (req.VCT == "" || cfg.VCT == req.VCT) {
				id = k
				break
			}
		}
		if id == "" {
			return "", fmt.Errorf("no configuration found for format %q vct %q", req.Format, req.VCT)
		}
	default:
		return "", fmt.Errorf("credential_configuration_id or format is required")
	}

	// Confirm the access token authorises this configuration.
	authorised := false
	for _, aid := range record.CredentialConfigurationIDs {
		if aid == id {
			authorised = true
			break
		}
	}
	if !authorised {
		return "", fmt.Errorf("access token does not authorise configuration %q", id)
	}
	if _, ok := i.metadata.CredentialConfigurationsSupported[id]; !ok {
		return "", fmt.Errorf("unsupported credential configuration %q", id)
	}
	return id, nil
}

func (i *Issuer) validateProof(_ context.Context, proof *types.CredentialProof, record *AccessTokenRecord) (any, error) {
	if proof.ProofType != "jwt" {
		return nil, fmt.Errorf("unsupported proof type %q", proof.ProofType)
	}
	if proof.JWT == "" {
		return nil, fmt.Errorf("proof.jwt is required")
	}

	// Check c_nonce hasn't expired.
	if time.Now().After(record.CNonceExpiresAt) {
		return nil, fmt.Errorf("c_nonce has expired")
	}

	header, _, err := jose.ValidateProofJWT(proof.JWT, i.metadata.Issuer, record.CNonce)
	if err != nil {
		return nil, fmt.Errorf("proof JWT validation: %w", err)
	}

	// Extract the holder's public key from the proof JWT header (jwk field).
	// In production, you'd also support kid references to a JWKS.
	jwkRaw, ok := header["jwk"]
	if !ok {
		return nil, fmt.Errorf("proof JWT header missing jwk")
	}

	// The jwk is already a map; convert it to a usable public key.
	holderKey, err := jwkMapToPublicKey(jwkRaw)
	if err != nil {
		return nil, fmt.Errorf("proof JWT jwk: %w", err)
	}

	// Verify the proof JWT's signature using the extracted holder key.
	alg, _ := header["alg"].(string)
	if err := jose.Verify(proof.JWT, holderKey, alg); err != nil {
		return nil, fmt.Errorf("proof JWT signature invalid: %w", err)
	}

	return holderKey, nil
}

// --- low-level helpers ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}

func writeError(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, types.ErrorResponse{Error: code, ErrorDescription: desc})
}

func isErr(err, target error) bool {
	if err == target {
		return true
	}
	type unwrapper interface{ Unwrap() error }
	if u, ok := err.(unwrapper); ok {
		return isErr(u.Unwrap(), target)
	}
	return false
}

func generateToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func jwkMapToPublicKey(raw any) (any, error) {
	b, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return jose.PublicKeyToGoKey(m)
}
