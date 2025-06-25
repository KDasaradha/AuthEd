
import React from 'react';

function BasicAuthSetup() {
  return (
    <ol className="list-decimal space-y-2 pl-5">
      <li><strong>Client-Side:</strong> Concatenate username and password with a colon (`:`).</li>
      <li><strong>Client-Side:</strong> Base64-encode the resulting string.</li>
      <li><strong>Client-Side:</strong> For each request, construct an `Authorization` header with the value `Basic ` followed by the encoded string.</li>
      <li><strong>Server-Side:</strong> On receiving a request, check for the `Authorization` header.</li>
      <li><strong>Server-Side:</strong> Decode the Base64 string to retrieve the `username:password`.</li>
      <li><strong>Server-Side:</strong> Validate the credentials against a user store. Grant or deny access. Must be used over TLS.</li>
    </ol>
  );
}

function TokenBasedSetup() {
  return (
    <ol className="list-decimal space-y-2 pl-5">
      <li><strong>Login:</strong> User authenticates with credentials (e.g., username/password).</li>
      <li><strong>Token Generation:</strong> Server verifies credentials, generates a JWT containing user claims (e.g., `sub`, `roles`, `exp`), and signs it with a secret key.</li>
      <li><strong>Token Issuance:</strong> Server returns the JWT to the client.</li>
      <li><strong>Token Storage:</strong> Client stores the JWT securely (e.g., HttpOnly cookie is preferred over localStorage to prevent XSS).</li>
      <li><strong>Authenticated Requests:</strong> For subsequent requests, the client includes the JWT in the `Authorization: Bearer <token>` header.</li>
      <li><strong>Token Validation:</strong> The server receives the token, validates its signature and expiration, and uses its claims for authorization.</li>
    </ol>
  );
}

function OAuth2Setup() {
  return (
    <ol className="list-decimal space-y-2 pl-5">
      <li><strong>Client Registration:</strong> Register your application with the Authorization Server (e.g., Google) to get a Client ID and Client Secret.</li>
      <li><strong>Authorization Request:</strong> The user is redirected from your app to the Authorization Server with your Client ID and requested scopes.</li>
      <li><strong>User Consent:</strong> The user logs in to the Authorization Server and grants consent to your application.</li>
      <li><strong>Authorization Code:</strong> The Authorization Server redirects the user back to your app's pre-registered callback URI with a temporary Authorization Code.</li>
      <li><strong>Token Exchange:</strong> Your app's backend exchanges this code and its Client Secret for an Access Token (and optionally a Refresh Token).</li>
      <li><strong>API Access:</strong> Your app uses this Access Token in an `Authorization` header to make API calls to the Resource Server on behalf of the user.</li>
    </ol>
  );
}

function SessionBasedSetup() {
  return (
    <ol className="list-decimal space-y-2 pl-5">
      <li><strong>Login:</strong> User submits credentials to the server.</li>
      <li><strong>Session Creation:</strong> Server validates credentials, generates a unique Session ID, and stores the session data on the server, mapping it to the ID.</li>
      <li><strong>Cookie Issuance:</strong> Server responds with a `Set-Cookie` header containing the Session ID. The cookie should be marked `HttpOnly`, `Secure`, and `SameSite=Lax` or `Strict`.</li>
      <li><strong>Subsequent Requests:</strong> The browser automatically includes the session cookie in all future requests to the same domain.</li>
      <li><strong>Session Validation:</strong> On each request, the server uses the Session ID from the cookie to retrieve the user's session data from its store, confirming their identity.</li>
    </ol>
  );
}

function ApiKeySetup() {
  return (
    <ol className="list-decimal space-y-2 pl-5">
      <li><strong>Key Generation:</strong> A developer generates an API key for their application from a service's developer portal.</li>
      <li><strong>Client Configuration:</strong> The client application is configured to include this API key in every request to the service.</li>
      <li><strong>Transmission:</strong> The most common method is sending it in a custom header (e.g., `X-API-Key: <key>`). Sending in query parameters is less secure as it can be logged.</li>
      <li><strong>Server Validation:</strong> The server reads the key, validates it against a database of issued keys, and checks if the associated application has permission to perform the requested action.</li>
    </ol>
  );
}

function DigestAuthSetup() {
  return (
    <ol className="list-decimal space-y-2 pl-5">
      <li><strong>Initial Request:</strong> Client makes an unauthenticated request to a protected resource.</li>
      <li><strong>Challenge:</strong> Server responds with `401 Unauthorized` and a `WWW-Authenticate: Digest` header containing a `realm` and a unique `nonce`.</li>
      <li><strong>Client Response:</strong> Client prompts user for credentials, then computes an MD5 hash of the credentials and challenge details.</li>
      <li><strong>Authenticated Request:</strong> Client re-sends the request with an `Authorization: Digest` header containing the computed response hash and other parameters.</li>
      <li><strong>Server Validation:</strong> Server recalculates the hash using its stored password information and compares it to the client's response to authenticate.</li>
    </ol>
  );
}

function CertificateBasedSetup() {
  return (
    <ol className="list-decimal space-y-2 pl-5">
      <li><strong>Certificate Issuance:</strong> A trusted Certificate Authority (CA), either public or private, issues a client certificate to a user or device.</li>
      <li><strong>Client Installation:</strong> The certificate and its private key are securely installed on the client machine or device.</li>
      <li><strong>Server Configuration:</strong> The web server or API gateway is configured to request and validate client certificates during the TLS handshake (this is known as mTLS).</li>
      <li><strong>TLS Handshake:</strong> When the client connects, it presents its certificate. The server verifies the certificate's signature, trust chain, and validity, then grants access.</li>
    </ol>
  );
}

function OidcSetup() {
  return (
    <ol className="list-decimal space-y-2 pl-5">
      <li>Follow the standard OAuth 2.0 Authorization Code flow, but include `openid` in the list of requested scopes.</li>
      <li>After the user grants consent, the Authorization Server returns an authorization code.</li>
      <li>The client exchanges the code at the token endpoint for both an `access_token` (for API access) and an `id_token` (for authentication).</li>
      <li>The client MUST validate the `id_token`'s signature, issuer (`iss`), audience (`aud`), and expiration (`exp`).</li>
      <li>The claims inside the validated `id_token` (e.g., `sub` for subject ID, `email`) are used to identify and log in the user within the application.</li>
    </ol>
  );
}

function SamlSetup() {
  return (
    <ol className="list-decimal space-y-2 pl-5">
      <li><strong>Metadata Exchange:</strong> Establish a trust relationship by exchanging XML metadata files between the Service Provider (SP) and Identity Provider (IdP).</li>
      <li><strong>SP-Initiated Flow:</strong> User attempts to access the SP. The SP creates a SAML request and redirects the user's browser to the IdP.</li>
      <li><strong>IdP Authentication:</strong> The user authenticates with the IdP if they don't already have a session.</li>
      <li><strong>SAML Assertion:</strong> The IdP generates a signed SAML Assertion (XML) and redirects the user back to the SP's Assertion Consumer Service (ACS) URL with the assertion.</li>
      <li><strong>SP Validation:</strong> The SP validates the assertion's signature and content, then creates a local session for the user.</li>
    </ol>
  );
}

function MfaSetup() {
  return (
    <ol className="list-decimal space-y-2 pl-5">
      <li><strong>Enrollment:</strong> During setup, a user enrolls a second factor (e.g., scans a QR code for a TOTP app, registers a phone number for SMS, or registers a FIDO2 key).</li>
      <li><strong>Primary Authentication:</strong> On login, the user first provides their primary factor (usually a password).</li>
      <li><strong>Secondary Challenge:</strong> After the first factor is validated, the system prompts for the second factor.</li>
      <li><strong>Secondary Verification:</strong> User provides the second factor (e.g., enters a 6-digit code, approves a push notification, touches a security key).</li>
      <li><strong>Access Granted:</strong> The server validates this second factor and completes the authentication, creating a session.</li>
    </ol>
  );
}

function BiometricSetup() {
  return (
    <ol className="list-decimal space-y-2 pl-5">
      <li><strong>Registration (WebAuthn):</strong> User registers their device's authenticator (e.g., Touch ID, YubiKey) with the web service. The authenticator generates a new public/private key pair. The public key is stored by the server.</li>
      <li><strong>Authentication Challenge:</strong> To log in, the server sends a unique challenge to the client.</li>
      <li><strong>Local Biometric Scan:</strong> The browser prompts the user for their biometric data.</li>
      <li><strong>Challenge Signing:</strong> A successful scan unlocks the device's private key, which cryptographically signs the server's challenge.</li>
      <li><strong>Verification:</strong> The signed challenge is sent to the server, which verifies the signature using the user's stored public key.</li>
    </ol>
  );
}

function KerberosSetup() {
  return (
    <ol className="list-decimal space-y-2 pl-5">
      <li><strong>AS Exchange:</strong> A client authenticates with the Authentication Server (AS) part of the KDC and receives an encrypted TGT.</li>
      <li><strong>TGS Exchange:</strong> To access a service, the client presents the TGT to the Ticket-Granting Server (TGS) and requests a service ticket for that specific service.</li>
      <li><strong>Service Ticket:</strong> The TGS decrypts the TGT, verifies it, and provides a service ticket encrypted with the target server's secret key.</li>
      <li><strong>CS Exchange:</strong> The client presents this service ticket to the application server.</li>
      <li><strong>Access:</strong> The application server decrypts the ticket with its own key, verifies its authenticity, and grants access.</li>
    </ol>
  );
}

function SsoSetup() {
  return (
    <ol className="list-decimal space-y-2 pl-5">
      <li>An organization deploys or subscribes to a central Identity Provider (IdP) like Azure AD, Okta, or ADFS.</li>
      <li>Each application (Service Provider or SP) is configured to trust the IdP by exchanging metadata (for SAML) or client credentials (for OIDC).</li>
      <li>When an unauthenticated user tries to access an SP, the SP redirects them to the IdP.</li>
      <li>The user logs in to the IdP (if they don't have an active session).</li>
      <li>The IdP redirects the user back to the SP with a signed token or assertion, granting them access. The user can now access other connected SPs without logging in again.</li>
    </ol>
  );
}

function HmacSetup() {
  return (
    <ol className="list-decimal space-y-2 pl-5">
      <li>Provision the client application with a unique, securely generated secret key.</li>
      <li>The client creates a canonical string from the request components (e.g., HTTP method, URI, timestamp, request body).</li>
      <li>The client uses a hash function (e.g., SHA256) and the secret key to create an HMAC signature of that string.</li>
      <li>The client sends the raw signature (often Base64 encoded) in a custom request header (e.g., `X-Signature`).</li>
      <li>The server receives the request, constructs the exact same canonical string, computes its own signature with its copy of the secret key, and securely compares it to the one in the header.</li>
    </ol>
  );
}

function NtlmSetup() {
  return (
    <ol className="list-decimal space-y-2 pl-5">
      <li>Generally configured at the web server level (e.g., IIS) for 'Windows Integrated Authentication'. Not typically implemented by application developers.</li>
      <li>A browser on a domain-joined machine (like Edge or Chrome) automatically performs the three-step NTLM handshake when accessing intranet resources.</li>
      <li>Modern development should avoid NTLM entirely. Prefer modern, secure protocols like OIDC or SAML for web applications.</li>
    </ol>
  );
}

function LdapSetup() {
  return (
    <ol className="list-decimal space-y-2 pl-5">
      <li>An application is configured with the LDAP server's address and a service account with read permissions to search the directory.</li>
      <li>When a user enters their username/password, the app uses its service account to perform an LDAP search for the user's full DN (e.g., `cn=user,ou=people,dc=example,dc=com`).</li>
      <li>Once the DN is found, the app attempts a new LDAP 'bind' operation to the server using the user's full DN and the password they provided.</li>
      <li>A successful bind authenticates the user. A failed bind means incorrect credentials.</li>
    </ol>
  );
}

function AnonymousSetup() {
  return (
    <ol className="list-decimal space-y-2 pl-5">
      <li>This is a server-side configuration, not an active process.</li>
      <li>In your application's security configuration (e.g., framework middleware, web server config), define which routes or endpoints are public.</li>
      <li>For these routes, disable or bypass any authentication-checking middleware.</li>
      <li>Ensure all other routes that handle sensitive data or actions still require a valid, non-anonymous authentication context.</li>
    </ol>
  );
}

function ChallengeResponseSetup() {
  return (
    <ol className="list-decimal space-y-2 pl-5">
      <li>The client initiates an authentication request.</li>
      <li>The server generates a unique, unpredictable challenge (nonce) and sends it to the client.</li>
      <li>The client uses its secret (e.g., password hash) and the challenge to compute a response hash.</li>
      <li>The client sends the computed response back to the server.</li>
      <li>The server, knowing the secret, independently computes the expected response and compares it to what the client sent. A match proves the client knows the secret.</li>
    </ol>
  );
}

function SmartCardSetup() {
  return (
    <ol className="list-decimal space-y-2 pl-5">
      <li>Users are issued smart cards containing their digital certificates by a trusted authority.</li>
      <li>Client computers must have a physical smart card reader and appropriate middleware installed.</li>
      <li>The target server is configured for client certificate authentication (mTLS).</li>
      <li>The user inserts their card into the reader. The browser or OS prompts the user for a PIN, which unlocks the card.</li>
      <li>The certificate on the card is then made available for the TLS handshake with the server.</li>
    </ol>
  );
}

function SocialAuthSetup() {
  return (
    <ol className="list-decimal space-y-2 pl-5">
      <li>Register your app on the provider's developer portal (e.g., Google Cloud Console) to get a Client ID and Client Secret. Configure your allowed redirect URIs.</li>
      <li>Add a 'Login with [Provider]' button to your app that initiates the OAuth2/OIDC authorization code flow.</li>
      <li>Create a backend endpoint to handle the callback from the provider. This endpoint will receive an authorization code.</li>
      <li>Your backend exchanges the code for an ID Token and/or Access Token.</li>
      <li>After validating the ID Token, use the information within it (like email and name) to find an existing user account or create a new one. Log the user in.</li>
    </ol>
  );
}

function OtpSetup() {
  return (
    <ol className="list-decimal space-y-2 pl-5">
      <li><strong>TOTP Enrollment:</strong> The server generates a secret key and displays it as a QR code.</li>
      <li><strong>Client Setup:</strong> The user scans the QR code with an authenticator app (e.g., Google Authenticator, Authy).</li>
      <li><strong>Verification:</strong> The server may ask for one code to verify the setup was successful.</li>
      <li><strong>Login Challenge:</strong> When prompted (usually after password entry), the user opens their app and enters the current 6-digit code.</li>
      <li><strong>Server Validation:</strong> The server generates the code for the current and nearby time windows (to handle clock drift) and compares it with the user's input.</li>
    </ol>
  );
}

function ZeroTrustSetup() {
  return (
    <ol className="list-decimal space-y-2 pl-5">
      <li><strong>Strong Identity:</strong> Implement a strong, centralized Identity Provider (IdP) as the core source of truth for users.</li>
      <li><strong>Universal MFA:</strong> Enforce phishing-resistant MFA for all users and services.</li>
      <li><strong>Device Trust:</strong> Use device management (MDM) and endpoint detection (EDR) to assess device trust and health.</li>
      <li><strong>Conditional Access:</strong> Define granular, context-aware access policies for every application that evaluate user and device trust before granting access.</li>
    </ol>
  );
}

function WebAuthnSetup() {
  return (
    <ol className="list-decimal space-y-2 pl-5">
      <li><strong>Registration:</strong> The server sends a challenge and user information. The browser calls `navigator.credentials.create()`, which prompts the user to create a new credential with their authenticator. The resulting public key and credential ID are sent to the server for storage.</li>
      <li><strong>Authentication:</strong> The server sends a new, unique challenge. The browser calls `navigator.credentials.get()`, which prompts the user to use their authenticator. The authenticator signs the challenge with its private key. The signature and credential ID are sent to the server for verification against the stored public key.</li>
    </ol>
  );
}

function MutualTlsSetup() {
  return (
    <ol className="list-decimal space-y-2 pl-5">
      <li><strong>CA Setup:</strong> Create or use a private Certificate Authority (CA) to issue certificates for your internal services.</li>
      <li><strong>Certificate Provisioning:</strong> Issue a server certificate for the server and a unique client certificate for each client service or device.</li>
      <li><strong>Server Configuration:</strong> Configure the server (e.g., Nginx, API Gateway, service mesh sidecar) to require and verify client certificates against the trusted CA.</li>
      <li><strong>Client Configuration:</strong> Configure the client application's HTTP library to provide its certificate and private key when establishing a TLS connection to the server.</li>
    </ol>
  );
}

function DelegatedAuthSetup() {
  return (
    <ol className="list-decimal space-y-2 pl-5">
      <li><strong>Choose an IdP:</strong> Select an Identity Provider (e.g., Okta, Azure AD, Auth0, or your own).</li>
      <li><strong>Choose a Protocol:</strong> Choose a federation protocol (OIDC is common for new web apps; SAML is common in enterprise).</li>
      <li><strong>Application Registration:</strong> Register your application with the IdP to establish a trust relationship and get a client ID and configuration details.</li>
      <li><strong>Integrate:</strong> Configure your application to redirect users to the IdP for login and to receive, validate, and process the resulting token upon their return to create a local session.</li>
    </ol>
  );
}

const AuthTypeSetups = {
  BasicAuthSetup,
  TokenBasedSetup,
  OAuth2Setup,
  SessionBasedSetup,
  ApiKeySetup,
  DigestAuthSetup,
  CertificateBasedSetup,
  OidcSetup,
  SamlSetup,
  MfaSetup,
  BiometricSetup,
  KerberosSetup,
  SsoSetup,
  HmacSetup,
  NtlmSetup,
  LdapSetup,
  AnonymousSetup,
  ChallengeResponseSetup,
  SmartCardSetup,
  SocialAuthSetup,
  OtpSetup,
  ZeroTrustSetup,
  WebAuthnSetup,
  MutualTlsSetup,
  DelegatedAuthSetup,
};

export default AuthTypeSetups;
