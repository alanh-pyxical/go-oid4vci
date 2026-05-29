// Package issuer implements the server side of the OID4VCI pre-authorised
// code flow. It exposes a single [Issuer] type whose [Issuer.Handler] method
// returns an [net/http.Handler] that serves all required endpoints.
//
// The issuer delegates two concerns to the caller via interfaces:
//
//   - [OfferStore]: persistence of credential offers and pre-authorised codes.
//   - [CredentialFactory]: production of the actual credential payload.
//
// This keeps the library free of any particular database or credential format.
package issuer

import (
	"context"
	"time"

	"github.com/alanh-pyxical/go-oid4vci/types"
)

// Offer is the server-side record associated with a credential offer. It is
// created by [Issuer.NewOffer] and stored by the caller's [OfferStore].
type Offer struct {
	// ID is the stable identifier for this offer.
	ID string

	// PreAuthorizedCode is the one-time code included in the offer URI
	// delivered to the wallet.
	PreAuthorizedCode string

	// CredentialConfigurationIDs are the configurations available in this
	// offer.
	CredentialConfigurationIDs []string

	// TxCode is the optional PIN that must accompany the pre-authorised code
	// at the token endpoint. Empty if no PIN is required.
	TxCode string

	// SubjectID is an opaque identifier for the credential subject — the
	// issuer's own reference for who the credential is about. The
	// CredentialFactory receives this when the credential is requested.
	SubjectID string

	// ExpiresAt is when the pre-authorised code expires.
	ExpiresAt time.Time

	// IssuedAt records when the offer was created.
	IssuedAt time.Time

	// Metadata is caller-supplied key/value pairs attached to the offer.
	// The CredentialFactory receives them, allowing issuers to pass
	// arbitrary context (e.g. application reference, approved amount)
	// through the protocol flow without a separate lookup.
	Metadata map[string]any
}

// OfferStore persists and retrieves [Offer] records. The library calls
// [OfferStore.Consume] exactly once per pre-authorised code, so the
// implementation must mark the code as used atomically.
//
// Implementations are responsible for expiry — Consume should return
// [oid4vci.ErrOfferExpired] if the offer's ExpiresAt has passed, and
// [oid4vci.ErrOfferAlreadyUsed] if the code has already been redeemed.
type OfferStore interface {
	// Save persists a new offer. Returns an error if the offer ID or
	// pre-authorised code already exists.
	Save(ctx context.Context, offer *Offer) error

	// Consume retrieves an offer by its pre-authorised code and atomically
	// marks it as used. Returns [oid4vci.ErrOfferNotFound],
	// [oid4vci.ErrOfferExpired], or [oid4vci.ErrOfferAlreadyUsed] as
	// appropriate.
	Consume(ctx context.Context, preAuthCode string) (*Offer, error)
}

// AccessTokenRecord is the server-side record associated with an issued access
// token.
type AccessTokenRecord struct {
	// Token is the opaque access token string.
	Token string

	// OfferID links back to the original offer.
	OfferID string

	// SubjectID is copied from the offer for quick lookup.
	SubjectID string

	// CredentialConfigurationIDs are the configurations this token authorises.
	CredentialConfigurationIDs []string

	// CNonce is the current server nonce the wallet must include in its
	// credential request proof.
	CNonce string

	// CNonceExpiresAt is when CNonce expires.
	CNonceExpiresAt time.Time

	// ExpiresAt is when the access token itself expires.
	ExpiresAt time.Time

	// Metadata is forwarded from the originating offer.
	Metadata map[string]any
}

// TokenStore persists and retrieves [AccessTokenRecord] values.
type TokenStore interface {
	// Save stores a newly issued access token record.
	Save(ctx context.Context, record *AccessTokenRecord) error

	// Get retrieves the record for token. Returns an error if the token is
	// unknown or expired.
	Get(ctx context.Context, token string) (*AccessTokenRecord, error)

	// RotateCNonce replaces the CNonce on an existing record and returns the
	// updated record. Called after each credential issuance to prevent
	// nonce reuse.
	RotateCNonce(ctx context.Context, token string, newNonce string, expiresAt time.Time) (*AccessTokenRecord, error)
}

// CredentialRequest carries the validated, server-side view of a credential
// request. The [CredentialFactory] receives this and must return a credential
// string.
type CredentialRequest struct {
	// ConfigurationID is the requested credential configuration.
	ConfigurationID string

	// SubjectID is the subject for whom the credential should be issued,
	// copied from the original offer.
	SubjectID string

	// HolderPublicKey is the key the wallet wants bound to the credential,
	// parsed from the proof JWT. Nil if no proof was supplied.
	HolderPublicKey any // *ecdsa.PublicKey or *rsa.PublicKey

	// Metadata is the arbitrary metadata from the originating offer.
	Metadata map[string]any
}

// CredentialFactory produces credential payloads on demand. The issuer library
// calls Issue once for each validated credential request; the factory returns
// the credential as a raw string (e.g. an SD-JWT-VC) and its format
// identifier.
//
// The factory is where callers integrate go-sd-jwt-vc or any other credential
// format library.
type CredentialFactory interface {
	Issue(ctx context.Context, req *CredentialRequest) (credential string, format string, err error)
}

// CredentialFactoryFunc adapts a plain function to [CredentialFactory].
type CredentialFactoryFunc func(ctx context.Context, req *CredentialRequest) (string, string, error)

func (f CredentialFactoryFunc) Issue(ctx context.Context, req *CredentialRequest) (string, string, error) {
	return f(ctx, req)
}

// OfferConfig carries the parameters for creating a new credential offer via
// [Issuer.NewOffer].
type OfferConfig struct {
	// SubjectID is the issuer's identifier for the credential subject.
	// Required.
	SubjectID string

	// CredentialConfigurationIDs selects which configurations to include in
	// the offer. Must be a non-empty subset of the issuer's supported
	// configurations. Required.
	CredentialConfigurationIDs []string

	// TxCode is an optional PIN that the user must supply alongside the
	// pre-authorised code. Leave empty for no PIN.
	TxCode string

	// TTL is how long the pre-authorised code remains valid.
	// Defaults to 5 minutes if zero.
	TTL time.Duration

	// Metadata is arbitrary caller-supplied data attached to the offer and
	// forwarded to the CredentialFactory at issuance time.
	Metadata map[string]any
}

// OfferResponse is returned by [Issuer.NewOffer].
type OfferResponse struct {
	// OfferURI is the openid-credential-offer:// URI to deliver to the
	// wallet (via QR code, deep link, push notification, etc.).
	OfferURI string

	// Offer is the server-side record — the caller may persist additional
	// references to it.
	Offer *Offer

	// CredentialOffer is the structured offer object, useful if the caller
	// needs to embed it in their own UI.
	CredentialOffer *types.CredentialOffer
}
