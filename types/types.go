// Package types defines the protocol types shared between the issuer and
// client sub-packages. They map directly to the JSON structures defined in
// OpenID for Verifiable Credential Issuance
// (draft-ietf-oauth-credential-issuance).
//
// All types use pointer fields for optional JSON properties so that omitempty
// correctly omits them rather than emitting zero values.
package types

// IssuerMetadata is the document served at
// <issuer>/.well-known/openid-credential-issuer.
// Defined in OID4VCI §11.2.
type IssuerMetadata struct {
	// Issuer is the credential issuer identifier — an HTTPS URI. Required.
	Issuer string `json:"issuer"`

	// CredentialEndpoint is the URL of the credential endpoint. Required.
	CredentialEndpoint string `json:"credential_endpoint"`

	// BatchCredentialEndpoint is the URL of the batch credential endpoint.
	// Optional — omit if the issuer does not support batch issuance.
	BatchCredentialEndpoint string `json:"batch_credential_endpoint,omitempty"`

	// TokenEndpoint is the URL of the OAuth 2.0 token endpoint. Required
	// when the issuer acts as its own authorisation server.
	TokenEndpoint string `json:"token_endpoint,omitempty"`

	// DeferredCredentialEndpoint is the URL for deferred credential pickup.
	DeferredCredentialEndpoint string `json:"deferred_credential_endpoint,omitempty"`

	// CredentialConfigurationsSupported describes the credential types this
	// issuer can issue, keyed by a caller-chosen configuration identifier.
	// Required.
	CredentialConfigurationsSupported map[string]CredentialConfiguration `json:"credential_configurations_supported"`

	// Display holds issuer-level display metadata (name, logo, etc.) per
	// locale.
	Display []IssuerDisplay `json:"display,omitempty"`
}

// CredentialConfiguration describes a single credential type the issuer
// supports. Included in [IssuerMetadata.CredentialConfigurationsSupported].
type CredentialConfiguration struct {
	// Format is the credential format identifier, e.g. "vc+sd-jwt",
	// "ldp_vc", "mso_mdoc". Required.
	Format string `json:"format"`

	// VCT is the Verifiable Credential Type URI used with the vc+sd-jwt
	// format. Required for SD-JWT-VC credentials.
	VCT string `json:"vct,omitempty"`

	// Scope is the OAuth 2.0 scope value associated with this configuration.
	Scope string `json:"scope,omitempty"`

	// CryptographicBindingMethodsSupported lists the binding methods the
	// issuer supports, e.g. ["jwk", "did:jwk"].
	CryptographicBindingMethodsSupported []string `json:"cryptographic_binding_methods_supported,omitempty"`

	// CredentialSigningAlgValuesSupported lists the JWA algorithm identifiers
	// the issuer uses to sign credentials of this type.
	CredentialSigningAlgValuesSupported []string `json:"credential_signing_alg_values_supported,omitempty"`

	// ProofTypesSupported describes the proof-of-possession types the issuer
	// accepts when binding a credential to a holder key.
	ProofTypesSupported map[string]ProofTypeMetadata `json:"proof_types_supported,omitempty"`

	// Claims describes the individual claims available in this credential
	// type. Keyed by claim name.
	Claims map[string]ClaimMetadata `json:"claims,omitempty"`

	// Display holds per-locale display metadata for this credential type.
	Display []CredentialDisplay `json:"display,omitempty"`
}

// ProofTypeMetadata describes a proof-of-possession mechanism the issuer
// accepts.
type ProofTypeMetadata struct {
	// ProofSigningAlgValuesSupported lists the JWA algorithms accepted for
	// this proof type.
	ProofSigningAlgValuesSupported []string `json:"proof_signing_alg_values_supported"`
}

// ClaimMetadata carries display and disclosure metadata for a single claim.
type ClaimMetadata struct {
	Mandatory bool             `json:"mandatory,omitempty"`
	ValueType string           `json:"value_type,omitempty"`
	Display   []ClaimDisplay   `json:"display,omitempty"`
}

// IssuerDisplay holds localised display metadata for the issuer itself.
type IssuerDisplay struct {
	Name            string `json:"name,omitempty"`
	Locale          string `json:"locale,omitempty"`
	LogoURI         string `json:"logo_uri,omitempty"`
	BackgroundColor string `json:"background_color,omitempty"`
	TextColor       string `json:"text_color,omitempty"`
}

// CredentialDisplay holds localised display metadata for a credential type.
type CredentialDisplay struct {
	Name            string      `json:"name,omitempty"`
	Locale          string      `json:"locale,omitempty"`
	LogoURI         string      `json:"logo_uri,omitempty"`
	Description     string      `json:"description,omitempty"`
	BackgroundColor string      `json:"background_color,omitempty"`
	TextColor       string      `json:"text_color,omitempty"`
}

// ClaimDisplay holds localised display metadata for a single claim.
type ClaimDisplay struct {
	Name   string `json:"name,omitempty"`
	Locale string `json:"locale,omitempty"`
}

// CredentialOffer is the object delivered to the wallet (via QR code, deep
// link, or redirect) to initiate credential acquisition.
// Defined in OID4VCI §4.1.
type CredentialOffer struct {
	// CredentialIssuer is the identifier of the issuer making the offer.
	CredentialIssuer string `json:"credential_issuer"`

	// CredentialConfigurationIDs lists the credential configuration IDs
	// offered. The wallet will request one or more of these.
	CredentialConfigurationIDs []string `json:"credential_configuration_ids"`

	// Grants describes how the wallet may obtain an access token.
	Grants OfferGrants `json:"grants"`
}

// OfferGrants describes the token acquisition grants available in an offer.
type OfferGrants struct {
	// PreAuthorizedCode is populated when the issuer has already
	// authenticated the user and pre-authorised the issuance.
	PreAuthorizedCode *PreAuthorizedCodeGrant `json:"urn:ietf:params:oauth:grant-type:pre-authorized_code,omitempty"`

	// AuthorizationCode is populated when the wallet must obtain
	// authorisation via a browser redirect flow.
	AuthorizationCode *AuthorizationCodeGrant `json:"authorization_code,omitempty"`
}

// PreAuthorizedCodeGrant carries the pre-authorised code grant details.
type PreAuthorizedCodeGrant struct {
	// PreAuthorizedCode is the short-lived code the wallet exchanges for an
	// access token. Required.
	PreAuthorizedCode string `json:"pre-authorized_code"`

	// TxCode describes an additional transaction code (PIN) that must be
	// supplied alongside the pre-authorised code. Optional.
	TxCode *TxCode `json:"tx_code,omitempty"`

	// Interval is the minimum number of seconds the wallet should wait
	// between polling requests when the issuer is not yet ready. Optional.
	Interval *int `json:"interval,omitempty"`
}

// TxCode describes an optional transaction code (e.g. a PIN sent out-of-band)
// that the user must supply when redeeming a pre-authorised code.
type TxCode struct {
	// InputMode is "numeric" or "text". Defaults to "numeric".
	InputMode string `json:"input_mode,omitempty"`
	// Length is the expected character count, if fixed.
	Length *int `json:"length,omitempty"`
	// Description is a human-readable hint shown to the user.
	Description string `json:"description,omitempty"`
}

// AuthorizationCodeGrant carries the authorisation code grant details.
type AuthorizationCodeGrant struct {
	// IssuerState is an opaque value the issuer wants passed back via the
	// authorisation request.
	IssuerState string `json:"issuer_state,omitempty"`

	// AuthorizationServer is the authorisation server to use if different
	// from the credential issuer.
	AuthorizationServer string `json:"authorization_server,omitempty"`
}

// TokenRequest is the body sent to the token endpoint to exchange a
// pre-authorised code for an access token.
type TokenRequest struct {
	// GrantType must be
	// "urn:ietf:params:oauth:grant-type:pre-authorized_code".
	GrantType string `json:"grant_type"`

	// PreAuthorizedCode is the code from the credential offer.
	PreAuthorizedCode string `json:"pre-authorized_code"`

	// TxCode is the optional transaction code (PIN).
	TxCode string `json:"tx_code,omitempty"`

	// ClientID identifies the wallet. Optional for public clients.
	ClientID string `json:"client_id,omitempty"`
}

// TokenResponse is the body returned by the token endpoint.
type TokenResponse struct {
	// AccessToken is the bearer token to present to the credential endpoint.
	AccessToken string `json:"access_token"`

	// TokenType is always "Bearer".
	TokenType string `json:"token_type"`

	// ExpiresIn is the access token lifetime in seconds.
	ExpiresIn int `json:"expires_in"`

	// CNonce is a server-generated nonce the wallet must include in the
	// credential request proof.
	CNonce string `json:"c_nonce,omitempty"`

	// CNonceExpiresIn is the c_nonce lifetime in seconds.
	CNonceExpiresIn int `json:"c_nonce_expires_in,omitempty"`
}

// CredentialRequest is the body sent to the credential endpoint.
type CredentialRequest struct {
	// CredentialConfigurationID selects the configuration to issue.
	// Use either this or Format+VCT, not both.
	CredentialConfigurationID string `json:"credential_configuration_id,omitempty"`

	// Format is the requested credential format. Used when
	// CredentialConfigurationID is not set.
	Format string `json:"format,omitempty"`

	// VCT is the requested credential type (SD-JWT-VC format only).
	VCT string `json:"vct,omitempty"`

	// Proof carries the holder's proof of possession of the key to bind.
	Proof *CredentialProof `json:"proof,omitempty"`

	// Proofs carries multiple proofs for batch variants.
	Proofs *CredentialProofs `json:"proofs,omitempty"`
}

// CredentialProof is a single proof-of-possession for key binding.
type CredentialProof struct {
	// ProofType is the proof mechanism; currently only "jwt" is widely
	// supported.
	ProofType string `json:"proof_type"`

	// JWT is the compact-serialised proof JWT. Required when ProofType is
	// "jwt".
	JWT string `json:"jwt,omitempty"`
}

// CredentialProofs carries multiple proofs for requesting several credentials
// in one call (batch).
type CredentialProofs struct {
	JWT []string `json:"jwt,omitempty"`
}

// CredentialResponse is the body returned by the credential endpoint on
// synchronous issuance.
type CredentialResponse struct {
	// Credential is the issued credential string (e.g. the SD-JWT-VC).
	// Present on synchronous issuance.
	Credential string `json:"credential,omitempty"`

	// Credentials is used for batch responses.
	Credentials []CredentialResponseItem `json:"credentials,omitempty"`

	// TransactionID is present when issuance is deferred — the wallet
	// polls the deferred endpoint with this value.
	TransactionID string `json:"transaction_id,omitempty"`

	// CNonce is a fresh nonce for subsequent requests.
	CNonce string `json:"c_nonce,omitempty"`

	// CNonceExpiresIn is the new c_nonce lifetime.
	CNonceExpiresIn int `json:"c_nonce_expires_in,omitempty"`

	// NotificationID is returned when the issuer supports the notification
	// endpoint.
	NotificationID string `json:"notification_id,omitempty"`
}

// CredentialResponseItem is a single item in a batch credential response.
type CredentialResponseItem struct {
	Credential    string `json:"credential,omitempty"`
	TransactionID string `json:"transaction_id,omitempty"`
}

// ErrorResponse is the body returned on protocol errors.
type ErrorResponse struct {
	// Error is the error code, e.g. "invalid_request",
	// "unsupported_credential_type".
	Error string `json:"error"`

	// ErrorDescription is a human-readable description.
	ErrorDescription string `json:"error_description,omitempty"`

	// CNonce is a fresh nonce returned on "invalid_proof" errors so the
	// wallet can retry with a valid proof.
	CNonce string `json:"c_nonce,omitempty"`

	// CNonceExpiresIn is the c_nonce lifetime in seconds.
	CNonceExpiresIn int `json:"c_nonce_expires_in,omitempty"`
}

// GrantTypePreAuthorized is the OAuth 2.0 grant type for pre-authorised code.
const GrantTypePreAuthorized = "urn:ietf:params:oauth:grant-type:pre-authorized_code"

// FormatSDJWTVC is the credential format identifier for SD-JWT-VC.
const FormatSDJWTVC = "vc+sd-jwt"
