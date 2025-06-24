
import React from 'react';
import type { AuthType } from './types';

// ====================================================================================
// Diagram Components
// ====================================================================================

const OAuth2Diagram = () => (
    <svg width="100%" viewBox="0 0 800 400" xmlns="http://www.w3.org/2000/svg" className="bg-gray-50 rounded">
        <g className="font-sans">
            <rect x="50" y="50" width="120" height="40" rx="5" fill="hsl(var(--primary))" stroke="hsl(var(--border))" />
            <text x="110" y="75" textAnchor="middle" fill="hsl(var(--primary-foreground))">User</text>
            
            <rect x="340" y="50" width="120" height="40" rx="5" fill="hsl(var(--primary))" stroke="hsl(var(--border))" />
            <text x="400" y="75" textAnchor="middle" fill="hsl(var(--primary-foreground))">Client App</text>

            <rect x="630" y="50" width="120" height="40" rx="5" fill="hsl(var(--primary))" stroke="hsl(var(--border))" />
            <text x="690" y="75" textAnchor="middle" fill="hsl(var(--primary-foreground))">Auth Server</text>

            <path d="M 110 120 V 300" stroke="hsl(var(--muted-foreground))" strokeDasharray="5,5" />
            <path d="M 400 120 V 300" stroke="hsl(var(--muted-foreground))" strokeDasharray="5,5" />
            <path d="M 690 120 V 300" stroke="hsl(var(--muted-foreground))" strokeDasharray="5,5" />

            <g transform="translate(0, 20)">
                <path d="M 110 130 H 390" stroke="hsl(var(--accent))" strokeWidth="2" markerEnd="url(#arrow-oauth)" />
                <text x="250" y="125" textAnchor="middle" fill="hsl(var(--foreground))" className="text-sm">1. Request Access</text>

                <path d="M 410 170 H 680" stroke="hsl(var(--accent))" strokeWidth="2" markerEnd="url(#arrow-oauth)" />
                <text x="545" y="165" textAnchor="middle" fill="hsl(var(--foreground))" className="text-sm">2. Redirect to Login</text>

                <path d="M 680 210 H 410" stroke="hsl(var(--accent))" strokeWidth="2" markerEnd="url(#arrow-oauth)" />
                <text x="545" y="205" textAnchor="middle" fill="hsl(var(--foreground))" className="text-sm">3. Credentials / Token</text>

                <path d="M 390 250 H 110" stroke="hsl(var(--accent))" strokeWidth="2" markerEnd="url(#arrow-oauth)" />
                <text x="250" y="245" textAnchor="middle" fill="hsl(var(--foreground))" className="text-sm">4. Access Granted</text>
            </g>
        </g>
        <defs>
            <marker id="arrow-oauth" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                <path d="M 0 0 L 10 5 L 0 10 z" fill="hsl(var(--accent))" />
            </marker>
        </defs>
    </svg>
);

const BasicAuthDiagram = () => (
    <svg width="100%" viewBox="0 0 800 300" xmlns="http://www.w3.org/2000/svg" className="bg-gray-50 rounded">
        <g className="font-sans">
            <rect x="150" y="50" width="120" height="40" rx="5" fill="hsl(var(--primary))" stroke="hsl(var(--border))" />
            <text x="210" y="75" textAnchor="middle" fill="hsl(var(--primary-foreground))">Client App</text>
            
            <rect x="530" y="50" width="120" height="40" rx="5" fill="hsl(var(--primary))" stroke="hsl(var(--border))" />
            <text x="590" y="75" textAnchor="middle" fill="hsl(var(--primary-foreground))">API Server</text>

            <path d="M 210 90 V 250" stroke="hsl(var(--muted-foreground))" strokeDasharray="5,5" />
            <path d="M 590 90 V 250" stroke="hsl(var(--muted-foreground))" strokeDasharray="5,5" />

            <g>
                <path d="M 220 130 H 580" stroke="hsl(var(--accent))" strokeWidth="2" markerEnd="url(#arrow-basic)" />
                <text x="400" y="125" textAnchor="middle" fill="hsl(var(--foreground))" className="text-sm">1. Request with Authorization Header</text>
                <text x="400" y="145" textAnchor="middle" fill="hsl(var(--muted-foreground))" className="text-xs">Authorization: Basic base64(user:pass)</text>

                <path d="M 580 190 H 220" stroke="hsl(var(--accent))" strokeWidth="2" markerEnd="url(#arrow-basic)" />
                <text x="400" y="185" textAnchor="middle" fill="hsl(var(--foreground))" className="text-sm">2. Response (200 OK or 401 Unauthorized)</text>
            </g>
        </g>
        <defs>
            <marker id="arrow-basic" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                <path d="M 0 0 L 10 5 L 0 10 z" fill="hsl(var(--accent))" />
            </marker>
        </defs>
    </svg>
);

const ApiKeyDiagram = () => (
    <svg width="100%" viewBox="0 0 800 300" xmlns="http://www.w3.org/2000/svg" className="bg-gray-50 rounded">
        <g className="font-sans">
            <rect x="150" y="50" width="120" height="40" rx="5" fill="hsl(var(--primary))" stroke="hsl(var(--border))" />
            <text x="210" y="75" textAnchor="middle" fill="hsl(var(--primary-foreground))">Client App</text>
            
            <rect x="530" y="50" width="120" height="40" rx="5" fill="hsl(var(--primary))" stroke="hsl(var(--border))" />
            <text x="590" y="75" textAnchor="middle" fill="hsl(var(--primary-foreground))">API Server</text>

            <path d="M 210 90 V 250" stroke="hsl(var(--muted-foreground))" strokeDasharray="5,5" />
            <path d="M 590 90 V 250" stroke="hsl(var(--muted-foreground))" strokeDasharray="5,5" />

            <g>
                <path d="M 220 130 H 580" stroke="hsl(var(--accent))" strokeWidth="2" markerEnd="url(#arrow-apikey)" />
                <text x="400" y="125" textAnchor="middle" fill="hsl(var(--foreground))" className="text-sm">1. Request with API Key Header</text>
                <text x="400" y="145" textAnchor="middle" fill="hsl(var(--muted-foreground))" className="text-xs">X-API-Key: your-api-key</text>

                <path d="M 580 190 H 220" stroke="hsl(var(--accent))" strokeWidth="2" markerEnd="url(#arrow-apikey)" />
                <text x="400" y="185" textAnchor="middle" fill="hsl(var(--foreground))" className="text-sm">2. Response (200 OK or 401 Unauthorized)</text>
            </g>
        </g>
        <defs>
            <marker id="arrow-apikey" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                <path d="M 0 0 L 10 5 L 0 10 z" fill="hsl(var(--accent))" />
            </marker>
        </defs>
    </svg>
);

const GenericAuthDiagram = () => (
    <svg width="100%" viewBox="0 0 800 300" xmlns="http://www.w3.org/2000/svg" className="bg-gray-50 rounded">
        <g className="font-sans">
            <rect x="150" y="50" width="120" height="40" rx="5" fill="hsl(var(--primary))" stroke="hsl(var(--border))" />
            <text x="210" y="75" textAnchor="middle" fill="hsl(var(--primary-foreground))">Client</text>
            
            <rect x="530" y="50" width="120" height="40" rx="5" fill="hsl(var(--primary))" stroke="hsl(var(--border))" />
            <text x="590" y="75" textAnchor="middle" fill="hsl(var(--primary-foreground))">Server</text>

            <path d="M 210 90 V 250" stroke="hsl(var(--muted-foreground))" strokeDasharray="5,5" />
            <path d="M 590 90 V 250" stroke="hsl(var(--muted-foreground))" strokeDasharray="5,5" />

            <g>
                <path d="M 220 130 H 580" stroke="hsl(var(--accent))" strokeWidth="2" markerEnd="url(#arrow-generic)" />
                <text x="400" y="125" textAnchor="middle" fill="hsl(var(--foreground))" className="text-sm">1. Authentication Request</text>
                <text x="400" y="145" textAnchor="middle" fill="hsl(var(--muted-foreground))" className="text-xs">(e.g., credentials, token, certificate)</text>

                <path d="M 580 190 H 220" stroke="hsl(var(--accent))" strokeWidth="2" markerEnd="url(#arrow-generic)" />
                <text x="400" y="185" textAnchor="middle" fill="hsl(var(--foreground))" className="text-sm">2. Authentication Response</text>
                <text x="400" y="205" textAnchor="middle" fill="hsl(var(--muted-foreground))" className="text-xs">(e.g., session, token, success/failure)</text>
            </g>
        </g>
        <defs>
            <marker id="arrow-generic" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                <path d="M 0 0 L 10 5 L 0 10 z" fill="hsl(var(--accent))" />
            </marker>
        </defs>
    </svg>
);


// ====================================================================================
// Setup Instruction Components
// ====================================================================================

const BasicAuthSetup = () => (
    <ol className="list-decimal space-y-2 pl-5">
      <li><strong>Client-Side:</strong> Concatenate username and password with a colon (`:`).</li>
      <li><strong>Client-Side:</strong> Base64-encode the resulting string.</li>
      <li><strong>Client-Side:</strong> For each request, construct an `Authorization` header with the value `Basic ` followed by the encoded string.</li>
      <li><strong>Server-Side:</strong> On receiving a request, check for the `Authorization` header.</li>
      <li><strong>Server-Side:</strong> Decode the Base64 string to retrieve the `username:password`.</li>
      <li><strong>Server-Side:</strong> Validate the credentials against a user store. Grant or deny access. Must be used over TLS.</li>
    </ol>
);

const TokenBasedSetup = () => (
    <ol className="list-decimal space-y-2 pl-5">
      <li><strong>Login:</strong> User authenticates with credentials (e.g., username/password).</li>
      <li><strong>Token Generation:</strong> Server verifies credentials, generates a JWT containing user claims (e.g., `sub`, `roles`, `exp`), and signs it with a secret key.</li>
      <li><strong>Token Issuance:</strong> Server returns the JWT to the client.</li>
      <li><strong>Token Storage:</strong> Client stores the JWT securely (e.g., HttpOnly cookie is preferred over localStorage to prevent XSS).</li>
      <li><strong>Authenticated Requests:</strong> For subsequent requests, the client includes the JWT in the `Authorization: Bearer <token>` header.</li>
      <li><strong>Token Validation:</strong> The server receives the token, validates its signature and expiration, and uses its claims for authorization.</li>
    </ol>
);

const OAuth2Setup = () => (
    <ol className="list-decimal space-y-2 pl-5">
      <li><strong>Client Registration:</strong> Register your application with the Authorization Server (e.g., Google) to get a Client ID and Client Secret.</li>
      <li><strong>Authorization Request:</strong> The user is redirected from your app to the Authorization Server with your Client ID and requested scopes.</li>
      <li><strong>User Consent:</strong> The user logs in to the Authorization Server and grants consent to your application.</li>
      <li><strong>Authorization Code:</strong> The Authorization Server redirects the user back to your app's pre-registered callback URI with a temporary Authorization Code.</li>
      <li><strong>Token Exchange:</strong> Your app's backend exchanges this code and its Client Secret for an Access Token (and optionally a Refresh Token).</li>
      <li><strong>API Access:</strong> Your app uses this Access Token in an `Authorization` header to make API calls to the Resource Server on behalf of the user.</li>
    </ol>
);

const SessionBasedSetup = () => (
    <ol className="list-decimal space-y-2 pl-5">
      <li><strong>Login:</strong> User submits credentials to the server.</li>
      <li><strong>Session Creation:</strong> Server validates credentials, generates a unique Session ID, and stores the session data on the server, mapping it to the ID.</li>
      <li><strong>Cookie Issuance:</strong> Server responds with a `Set-Cookie` header containing the Session ID. The cookie should be marked `HttpOnly`, `Secure`, and `SameSite=Lax` or `Strict`.</li>
      <li><strong>Subsequent Requests:</strong> The browser automatically includes the session cookie in all future requests to the same domain.</li>
      <li><strong>Session Validation:</strong> On each request, the server uses the Session ID from the cookie to retrieve the user's session data from its store, confirming their identity.</li>
    </ol>
);

const ApiKeySetup = () => (
    <ol className="list-decimal space-y-2 pl-5">
      <li><strong>Key Generation:</strong> A developer generates an API key for their application from a service's developer portal.</li>
      <li><strong>Client Configuration:</strong> The client application is configured to include this API key in every request to the service.</li>
      <li><strong>Transmission:</strong> The most common method is sending it in a custom header (e.g., `X-API-Key: <key>`). Sending in query parameters is less secure as it can be logged.</li>
      <li><strong>Server Validation:</strong> The server reads the key, validates it against a database of issued keys, and checks if the associated application has permission to perform the requested action.</li>
    </ol>
);

const DigestAuthSetup = () => (
    <ol className="list-decimal space-y-2 pl-5">
     <li><strong>Initial Request:</strong> Client makes an unauthenticated request to a protected resource.</li>
     <li><strong>Challenge:</strong> Server responds with `401 Unauthorized` and a `WWW-Authenticate: Digest` header containing a `realm` and a unique `nonce`.</li>
     <li><strong>Client Response:</strong> Client prompts user for credentials, then computes an MD5 hash of the credentials and challenge details.</li>
     <li><strong>Authenticated Request:</strong> Client re-sends the request with an `Authorization: Digest` header containing the computed response hash and other parameters.</li>
     <li><strong>Server Validation:</strong> Server recalculates the hash using its stored password information and compares it to the client's response to authenticate.</li>
   </ol>
);

const CertificateBasedSetup = () => (
    <ol className="list-decimal space-y-2 pl-5">
      <li><strong>Certificate Issuance:</strong> A trusted Certificate Authority (CA), either public or private, issues a client certificate to a user or device.</li>
      <li><strong>Client Installation:</strong> The certificate and its private key are securely installed on the client machine or device.</li>
      <li><strong>Server Configuration:</strong> The web server or API gateway is configured to request and validate client certificates during the TLS handshake (this is known as mTLS).</li>
      <li><strong>TLS Handshake:</strong> When the client connects, it presents its certificate. The server verifies the certificate's signature, trust chain, and validity, then grants access.</li>
    </ol>
);

const OidcSetup = () => (
    <ol className="list-decimal space-y-2 pl-5">
      <li>Follow the standard OAuth 2.0 Authorization Code flow, but include `openid` in the list of requested scopes.</li>
      <li>After the user grants consent, the Authorization Server returns an authorization code.</li>
      <li>The client exchanges the code at the token endpoint for both an `access_token` (for API access) and an `id_token` (for authentication).</li>
      <li>The client MUST validate the `id_token`'s signature, issuer (`iss`), audience (`aud`), and expiration (`exp`).</li>
      <li>The claims inside the validated `id_token` (e.g., `sub` for subject ID, `email`) are used to identify and log in the user within the application.</li>
    </ol>
);

const SamlSetup = () => (
    <ol className="list-decimal space-y-2 pl-5">
      <li><strong>Metadata Exchange:</strong> Establish a trust relationship by exchanging XML metadata files between the Service Provider (SP) and Identity Provider (IdP).</li>
      <li><strong>SP-Initiated Flow:</strong> User attempts to access the SP. The SP creates a SAML request and redirects the user's browser to the IdP.</li>
      <li><strong>IdP Authentication:</strong> The user authenticates with the IdP if they don't already have a session.</li>
      <li><strong>SAML Assertion:</strong> The IdP generates a signed SAML Assertion (XML) and redirects the user back to the SP's Assertion Consumer Service (ACS) URL with the assertion.</li>
      <li><strong>SP Validation:</strong> The SP validates the assertion's signature and content, then creates a local session for the user.</li>
    </ol>
);

const MfaSetup = () => (
    <ol className="list-decimal space-y-2 pl-5">
      <li><strong>Enrollment:</strong> During setup, a user enrolls a second factor (e.g., scans a QR code for a TOTP app, registers a phone number for SMS, or registers a FIDO2 key).</li>
      <li><strong>Primary Authentication:</strong> On login, the user first provides their primary factor (usually a password).</li>
      <li><strong>Secondary Challenge:</strong> After the first factor is validated, the system prompts for the second factor.</li>
      <li><strong>Secondary Verification:</strong> User provides the second factor (e.g., enters a 6-digit code, approves a push notification, touches a security key).</li>
      <li><strong>Access Granted:</strong> The server validates this second factor and completes the authentication, creating a session.</li>
    </ol>
);

const BiometricSetup = () => (
    <ol className="list-decimal space-y-2 pl-5">
      <li><strong>Registration (WebAuthn):</strong> User registers their device's authenticator (e.g., Touch ID, YubiKey) with the web service. The authenticator generates a new public/private key pair. The public key is stored by the server.</li>
      <li><strong>Authentication Challenge:</strong> To log in, the server sends a unique challenge to the client.</li>
      <li><strong>Local Biometric Scan:</strong> The browser prompts the user for their biometric data.</li>
      <li><strong>Challenge Signing:</strong> A successful scan unlocks the device's private key, which cryptographically signs the server's challenge.</li>
      <li><strong>Verification:</strong> The signed challenge is sent to the server, which verifies the signature using the user's stored public key.</li>
    </ol>
);

const KerberosSetup = () => (
    <ol className="list-decimal space-y-2 pl-5">
      <li><strong>AS Exchange:</strong> A client authenticates with the Authentication Server (AS) part of the KDC and receives an encrypted TGT.</li>
      <li><strong>TGS Exchange:</strong> To access a service, the client presents the TGT to the Ticket-Granting Server (TGS) and requests a service ticket for that specific service.</li>
      <li><strong>Service Ticket:</strong> The TGS decrypts the TGT, verifies it, and provides a service ticket encrypted with the target server's secret key.</li>
      <li><strong>CS Exchange:</strong> The client presents this service ticket to the application server.</li>
      <li><strong>Access:</strong> The application server decrypts the ticket with its own key, verifies its authenticity, and grants access.</li>
    </ol>
);

const SsoSetup = () => (
    <ol className="list-decimal space-y-2 pl-5">
      <li>An organization deploys or subscribes to a central Identity Provider (IdP) like Azure AD, Okta, or ADFS.</li>
      <li>Each application (Service Provider or SP) is configured to trust the IdP by exchanging metadata (for SAML) or client credentials (for OIDC).</li>
      <li>When an unauthenticated user tries to access an SP, the SP redirects them to the IdP.</li>
      <li>The user logs in to the IdP (if they don't have an active session).</li>
      <li>The IdP redirects the user back to the SP with a signed token or assertion, granting them access. The user can now access other connected SPs without logging in again.</li>
    </ol>
);

const HmacSetup = () => (
    <ol className="list-decimal space-y-2 pl-5">
     <li>Provision the client application with a unique, securely generated secret key.</li>
     <li>The client creates a canonical string from the request components (e.g., HTTP method, URI, timestamp, request body).</li>
     <li>The client uses a hash function (e.g., SHA256) and the secret key to create an HMAC signature of that string.</li>
     <li>The client sends the raw signature (often Base64 encoded) in a custom request header (e.g., `X-Signature`).</li>
     <li>The server receives the request, constructs the exact same canonical string, computes its own signature with its copy of the secret key, and securely compares it to the one in the header.</li>
   </ol>
);

const NtlmSetup = () => (
    <ol className="list-decimal space-y-2 pl-5">
      <li>Generally configured at the web server level (e.g., IIS) for 'Windows Integrated Authentication'. Not typically implemented by application developers.</li>
      <li>A browser on a domain-joined machine (like Edge or Chrome) automatically performs the three-step NTLM handshake when accessing intranet resources.</li>
      <li>Modern development should avoid NTLM entirely. Prefer modern, secure protocols like OIDC or SAML for web applications.</li>
    </ol>
);

const LdapSetup = () => (
    <ol className="list-decimal space-y-2 pl-5">
      <li>An application is configured with the LDAP server's address and a service account with read permissions to search the directory.</li>
      <li>When a user enters their username/password, the app uses its service account to perform an LDAP search for the user's full DN (e.g., `cn=user,ou=people,dc=example,dc=com`).</li>
      <li>Once the DN is found, the app attempts a new LDAP 'bind' operation to the server using the user's full DN and the password they provided.</li>
      <li>A successful bind authenticates the user. A failed bind means incorrect credentials.</li>
    </ol>
);

const AnonymousSetup = () => (
    <ol className="list-decimal space-y-2 pl-5">
      <li>This is a server-side configuration, not an active process.</li>
      <li>In your application's security configuration (e.g., framework middleware, web server config), define which routes or endpoints are public.</li>
      <li>For these routes, disable or bypass any authentication-checking middleware.</li>
      <li>Ensure all other routes that handle sensitive data or actions still require a valid, non-anonymous authentication context.</li>
    </ol>
);

const ChallengeResponseSetup = () => (
    <ol className="list-decimal space-y-2 pl-5">
      <li>The client initiates an authentication request.</li>
      <li>The server generates a unique, unpredictable challenge (nonce) and sends it to the client.</li>
      <li>The client uses its secret (e.g., password hash) and the challenge to compute a response hash.</li>
      <li>The client sends the computed response back to the server.</li>
      <li>The server, knowing the secret, independently computes the expected response and compares it to what the client sent. A match proves the client knows the secret.</li>
    </ol>
);

const SmartCardSetup = () => (
    <ol className="list-decimal space-y-2 pl-5">
      <li>Users are issued smart cards containing their digital certificates by a trusted authority.</li>
      <li>Client computers must have a physical smart card reader and appropriate middleware installed.</li>
      <li>The target server is configured for client certificate authentication (mTLS).</li>
      <li>The user inserts their card into the reader. The browser or OS prompts the user for a PIN, which unlocks the card.</li>
      <li>The certificate on the card is then made available for the TLS handshake with the server.</li>
    </ol>
);

const SocialAuthSetup = () => (
    <ol className="list-decimal space-y-2 pl-5">
     <li>Register your app on the provider's developer portal (e.g., Google Cloud Console) to get a Client ID and Client Secret. Configure your allowed redirect URIs.</li>
     <li>Add a 'Login with [Provider]' button to your app that initiates the OAuth2/OIDC authorization code flow.</li>
     <li>Create a backend endpoint to handle the callback from the provider. This endpoint will receive an authorization code.</li>
     <li>Your backend exchanges the code for an ID Token and/or Access Token.</li>
     <li>After validating the ID Token, use the information within it (like email and name) to find an existing user account or create a new one. Log the user in.</li>
   </ol>
);

const OtpSetup = () => (
    <ol className="list-decimal space-y-2 pl-5">
      <li><strong>TOTP Enrollment:</strong> The server generates a secret key and displays it as a QR code.</li>
      <li><strong>Client Setup:</strong> The user scans the QR code with an authenticator app (e.g., Google Authenticator, Authy).</li>
      <li><strong>Verification:</strong> The server may ask for one code to verify the setup was successful.</li>
      <li><strong>Login Challenge:</strong> When prompted (usually after password entry), the user opens their app and enters the current 6-digit code.</li>
      <li><strong>Server Validation:</strong> The server generates the code for the current and nearby time windows (to handle clock drift) and compares it with the user's input.</li>
    </ol>
);

const ZeroTrustSetup = () => (
    <ol className="list-decimal space-y-2 pl-5">
      <li><strong>Strong Identity:</strong> Implement a strong, centralized Identity Provider (IdP) as the core source of truth for users.</li>
      <li><strong>Universal MFA:</strong> Enforce phishing-resistant MFA for all users and services.</li>
      <li><strong>Device Trust:</strong> Use device management (MDM) and endpoint detection (EDR) to assess device trust and health.</li>
      <li><strong>Conditional Access:</strong> Define granular, context-aware access policies for every application that evaluate user and device trust before granting access.</li>
    </ol>
);

const WebAuthnSetup = () => (
    <ol className="list-decimal space-y-2 pl-5">
      <li><strong>Registration:</strong> The server sends a challenge and user information. The browser calls `navigator.credentials.create()`, which prompts the user to create a new credential with their authenticator. The resulting public key and credential ID are sent to the server for storage.</li>
      <li><strong>Authentication:</strong> The server sends a new, unique challenge. The browser calls `navigator.credentials.get()`, which prompts the user to use their authenticator. The authenticator signs the challenge with its private key. The signature and credential ID are sent to the server for verification against the stored public key.</li>
    </ol>
);

const MutualTlsSetup = () => (
    <ol className="list-decimal space-y-2 pl-5">
      <li><strong>CA Setup:</strong> Create or use a private Certificate Authority (CA) to issue certificates for your internal services.</li>
      <li><strong>Certificate Provisioning:</strong> Issue a server certificate for the server and a unique client certificate for each client service or device.</li>
      <li><strong>Server Configuration:</strong> Configure the server (e.g., Nginx, API Gateway, service mesh sidecar) to require and verify client certificates against the trusted CA.</li>
      <li><strong>Client Configuration:</strong> Configure the client application's HTTP library to provide its certificate and private key when establishing a TLS connection to the server.</li>
    </ol>
);

const DelegatedAuthSetup = () => (
    <ol className="list-decimal space-y-2 pl-5">
      <li><strong>Choose an IdP:</strong> Select an Identity Provider (e.g., Okta, Azure AD, Auth0, or your own).</li>
      <li><strong>Choose a Protocol:</strong> Choose a federation protocol (OIDC is common for new web apps; SAML is common in enterprise).</li>
      <li><strong>Application Registration:</strong> Register your application with the IdP to establish a trust relationship and get a client ID and configuration details.</li>
      <li><strong>Integrate:</strong> Configure your application to redirect users to the IdP for login and to receive, validate, and process the resulting token upon their return to create a local session.</li>
    </ol>
);


// ====================================================================================
// Data Definitions (Plain Objects)
// ====================================================================================

type AuthTypeStrings = Omit<AuthType, 'setupInstructions' | 'diagram'>;

const authTypeData: AuthTypeStrings[] = [
  {
    slug: "basic-authentication",
    name: "Basic Authentication",
    description: "A simple method using a username and password encoded in Base64.",
    useCase: "Internal APIs, simple services where transport is secured by TLS.",
    security: "Low",
    complexity: "Low",
    protocols: "HTTP",
    technicalExplanation: "HTTP Basic Authentication is a simple challenge-response mechanism where a user agent provides a username and password. These credentials are combined into a 'username:password' string, encoded using Base64, and sent in the `Authorization` header of every HTTP request. Example: `Authorization: Basic dXNlcjpwYXNz`. Critically, Base64 is an encoding, not encryption, so credentials are sent in a reversible format. Without HTTPS (TLS) to encrypt the entire request, this method is highly insecure and vulnerable to sniffing. It is stateless, requiring credentials to be sent with each request.",
  },
  {
    slug: "token-based-authentication",
    name: "Token-Based (JWT)",
    description: "Uses a signed token (JWT) to verify user identity and claims.",
    useCase: "SPAs, Mobile Apps, APIs, server-to-server communication.",
    security: "Medium",
    complexity: "Medium",
    protocols: "HTTP, WebSocket",
    technicalExplanation: "After a user logs in with credentials, the server creates a JSON Web Token (JWT) and sends it to the client. A JWT is a self-contained, stateless token with three parts: a header, a payload (containing user data or 'claims' like user ID and roles), and a cryptographic signature. The signature, created with a secret key known only to the server, ensures the token's integrity. The client stores this token (e.g., in localStorage or a secure cookie) and sends it with every protected request in the `Authorization: Bearer <token>` header. The server can then validate the token without needing to look up session data.",
  },
  {
    slug: "oauth2-authentication",
    name: "OAuth2 Authentication",
    description: "A delegation protocol for third-party access to user resources.",
    useCase: "Third-party services (e.g., 'Log in with Google'), granting limited API access.",
    security: "High",
    complexity: "High",
    protocols: "HTTP",
    technicalExplanation: "OAuth2 is an authorization framework, not an authentication protocol. It enables an application (the Client) to obtain limited, delegated access to a user's resources on another service (the Resource Server), without exposing their credentials. It defines roles (Resource Owner, Client, Authorization Server, Resource Server) and various 'grant types' (flows) like Authorization Code for web apps, which is considered the most secure for that context. The outcome is an Access Token, which is a key that grants specific, scoped permissions.",
  },
  {
    slug: "session-based-authentication",
    name: "Session-Based Authentication",
    description: "Server stores session data and provides a session ID to the client.",
    useCase: "Traditional monolithic web applications, server-rendered pages.",
    security: "Medium",
    complexity: "Low",
    protocols: "HTTP (Cookies)",
    technicalExplanation: "In this stateful model, the server creates and maintains a session for a user upon successful login. It stores session information (like user ID) on the server-side (in memory, a database, or a cache like Redis) and sends a unique Session ID to the client. This ID is typically sent in a secure, `HttpOnly` cookie. The browser automatically sends this cookie with every subsequent request, allowing the server to look up the session data, identify the user, and maintain their authenticated state across multiple page views.",
  },
  {
    slug: "api-key-authentication",
    name: "API Key Authentication",
    description: "A unique key is assigned to each application to access the API.",
    useCase: "Public APIs, usage tracking, server-to-server identification.",
    security: "Low",
    complexity: "Low",
    protocols: "HTTP",
    technicalExplanation: "API keys are used to identify the consuming application or project making a request, not a specific end-user. It's a simple way to control access, track usage for billing, and apply rate limiting. The key is a long, unique string that the client sends with each request, typically in a custom HTTP header like `X-API-Key`, a query parameter, or the request body. Because the key is static and often long-lived, it should be treated like a secret and protected accordingly. It does not provide user-level authentication.",
  },
  {
    slug: "digest-authentication",
    name: "Digest Authentication",
    description: "A challenge-response method that hashes credentials before sending.",
    useCase: "Situations requiring more security than Basic Auth without implementing TLS.",
    security: "Medium",
    complexity: "Medium",
    protocols: "HTTP",
    technicalExplanation: "As a challenge-response protocol, Digest Auth improves on Basic Auth by never sending the password in cleartext. The server sends a 'nonce' (a random value). The client creates an MD5 hash of the username, password, nonce, URI, and HTTP method. This hash is sent to the server, which performs the same calculation to verify. While better than Basic, it is still vulnerable to man-in-the-middle attacks (without TLS) and uses the outdated MD5 algorithm. It is largely considered obsolete in favor of modern protocols.",
  },
  {
    slug: "certificate-based-authentication",
    name: "Certificate-Based Auth",
    description: "Uses client-side digital certificates to verify identity.",
    useCase: "High-security corporate environments, B2B, and IoT devices.",
    security: "High",
    complexity: "High",
    protocols: "TLS/SSL",
    technicalExplanation: "This method, also known as Mutual TLS (mTLS), uses X.509 digital certificates for strong authentication. The client presents its own certificate to the server during the TLS handshake. The server verifies that the certificate was issued by a trusted Certificate Authority (CA) and has not been revoked. This provides strong, passwordless authentication for a user or device, as possession of the certificate and its corresponding private key proves identity. It is a cornerstone of Zero Trust architectures for service-to-service communication.",
  },
  {
    slug: "openid-connect",
    name: "OpenID Connect (OIDC)",
    description: "An identity layer on top of OAuth2 for user authentication.",
    useCase: "SSO, federated identity, modern consumer and enterprise applications.",
    security: "High",
    complexity: "High",
    protocols: "HTTP, OAuth2",
    technicalExplanation: "OIDC is a thin identity layer built on top of OAuth 2.0. While OAuth 2.0 provides authorization ('what a user can do'), OIDC provides authentication ('who a user is'). It introduces the `ID Token`, a specially formatted JSON Web Token (JWT) that contains user profile information (claims like name, email, etc.). It standardizes how clients can verify the identity of the end-user based on the authentication performed by an Authorization Server, as well as to obtain basic profile information about the end-user in an interoperable and REST-like manner.",
  },
  {
    slug: "saml",
    name: "SAML",
    description: "An XML-based standard for exchanging authentication and authorization data.",
    useCase: "Enterprise SSO, federated identity between different organizations.",
    security: "High",
    complexity: "High",
    protocols: "HTTP, SOAP",
    technicalExplanation: "Security Assertion Markup Language (SAML) is an XML-based open standard for exchanging authentication and authorization data between an Identity Provider (IdP) and a Service Provider (SP). It enables web-based Single Sign-On (SSO) by allowing the IdP, which holds the user's identity, to send a signed XML document, called a SAML Assertion, to the SP. The SP trusts this assertion to authenticate and authorize the user without needing direct access to the user's credentials.",
  },
  {
    slug: "multi-factor-authentication",
    name: "Multi-Factor (MFA)",
    description: "Requires two or more verification factors to gain access.",
    useCase: "Securing sensitive accounts, regulatory compliance (e.g., PCI DSS).",
    security: "High",
    complexity: "Medium",
    protocols: "Varies",
    technicalExplanation: "MFA provides layered security by requiring users to present at least two pieces of evidence (factors) to an authentication mechanism. These factors fall into three categories: Knowledge (something you know, like a password or PIN), Possession (something you have, like a phone app, SMS code, or hardware token), and Inherence (something you are, like a fingerprint or face scan). Requiring multiple factors makes it significantly harder for an unauthorized person to gain access.",
  },
  {
    slug: "biometric-authentication",
    name: "Biometric Authentication",
    description: "Uses unique biological characteristics (fingerprint, face).",
    useCase: "Mobile devices, high-security access, passwordless login.",
    security: "High",
    complexity: "High",
    protocols: "Varies (FIDO/WebAuthn)",
    technicalExplanation: "Biometric authentication verifies identity using unique physical traits. In modern secure systems (like FIDO2/WebAuthn), the biometric data (e.g., fingerprint scan) never leaves the user's device. Instead, it is used locally to unlock a cryptographic private key stored in a secure element on the device. This private key then signs a challenge from the server, proving both possession of the device and the user's presence in a highly secure, private, and phishing-resistant manner.",
  },
  {
    slug: "kerberos-authentication",
    name: "Kerberos Authentication",
    description: "A network authentication protocol using tickets to prove identity.",
    useCase: "Windows Active Directory, large corporate networks, Unix systems.",
    security: "High",
    complexity: "High",
    protocols: "TCP/UDP",
    technicalExplanation: "Kerberos is a ticket-based protocol that uses a trusted third party, a Key Distribution Center (KDC), to provide strong, mutual authentication. A client authenticates once to the KDC to get a Ticket-Granting Ticket (TGT). The client then uses this TGT to request service tickets for specific applications without re-entering a password. This avoids sending passwords over the network and is the default authentication protocol in Windows Active Directory.",
  },
  {
    slug: "single-sign-on",
    name: "Single Sign-On (SSO)",
    description: "Log in once to access multiple independent software systems.",
    useCase: "Corporate environments, large platforms with multiple services (e.g., Google Suite).",
    security: "High",
    complexity: "High",
    protocols: "SAML, OIDC",
    technicalExplanation: "SSO is an authentication scheme, not a specific protocol itself. It allows a user to log in once with a single set of credentials to a central Identity Provider (IdP) and gain access to multiple, separate applications without re-authenticating. This is achieved through federation protocols like SAML or OIDC. Applications (Service Providers) are configured to trust the IdP. When a user tries to access an SP, the SP redirects them to the IdP for authentication. After a successful login, the IdP sends a secure assertion back to the SP, which then grants the user access.",
  },
  {
    slug: "hmac-authentication",
    name: "HMAC Authentication",
    description: "Uses a cryptographic hash function and a secret key for message authentication.",
    useCase: "Securing webhook endpoints, server-to-server API calls.",
    security: "Medium",
    complexity: "Medium",
    protocols: "HTTP",
    technicalExplanation: "HMAC (Hash-based Message Authentication Code) verifies both the integrity and authenticity of a request. The client and server share a secret key. To make a request, the client creates a signature by hashing the request content (and often other parts like the URI and a timestamp) with the secret key using an algorithm like SHA256. The server performs the same calculation on the received message and compares its result to the signature sent by the client. If they match, the server knows the request is from a trusted source and hasn't been tampered with in transit.",
  },
  {
    slug: "ntlm-authentication",
    name: "NTLM Authentication",
    description: "A suite of Microsoft security protocols for challenge-response authentication.",
    useCase: "Legacy Windows environments, backward compatibility within intranets.",
    security: "Low",
    complexity: "High",
    protocols: "Varies",
    technicalExplanation: "NTLM (New Technology LAN Manager) is a legacy challenge-response protocol common in older Windows networks. It's known to be vulnerable to relay attacks and pass-the-hash attacks, and is not recommended for modern applications or use over the internet. It has been largely superseded by Kerberos in Active Directory environments. Its continued use is typically for backward compatibility with old applications or devices that do not support Kerberos.",
  },
  {
    slug: "ldap-authentication",
    name: "LDAP Authentication",
    description: "Validates user credentials against an LDAP directory service.",
    useCase: "Centralized user management in corporate networks (e.g., Active Directory).",
    security: "Medium",
    complexity: "Medium",
    protocols: "LDAP",
    technicalExplanation: "Lightweight Directory Access Protocol (LDAP) is a protocol for accessing and maintaining distributed directory information services like Active Directory. For authentication, an application performs a 'bind' operation to the LDAP server. A simple bind with a user's Distinguished Name (DN) and password will succeed if the credentials are correct. This allows applications to centralize user management without storing passwords themselves. All communication must be encrypted via LDAPS (LDAP over SSL) or STARTTLS.",
  },
  {
    slug: "anonymous-authentication",
    name: "Anonymous Authentication",
    description: "Grants access to public resources without verifying identity.",
    useCase: "Public websites, guest access, read-only content.",
    security: "Low",
    complexity: "Low",
    protocols: "HTTP",
    technicalExplanation: "This isn't a form of authentication as much as a deliberate lack of it. The server is configured to allow access to specific resources without requiring any credentials. On the backend, the user might be assigned a generic, low-privilege 'anonymous' identity to standardize authorization checks. It's essential for any public-facing content and is the default state for most websites before a user logs in.",
  },
  {
    slug: "challenge-response-authentication",
    name: "Challenge-Response Auth",
    description: "Server sends a challenge, client responds with a computed value.",
    useCase: "Secure passwordless systems, preventing replay attacks.",
    security: "Medium",
    complexity: "Medium",
    protocols: "Varies",
    technicalExplanation: "This is a family of protocols where a secret (like a password or key) is never transmitted directly over the network. The verifier sends a random, single-use value (the challenge or 'nonce'). The claimant uses a shared secret to perform a cryptographic calculation with the nonce and sends the result (the response). The verifier performs the same calculation to validate the response. This prevents replay attacks, as a new challenge is used for each authentication attempt. Examples include Digest, NTLM, and parts of the Kerberos and WebAuthn flows.",
  },
  {
    slug: "smart-card-authentication",
    name: "Smart Card Authentication",
    description: "Uses a physical smart card with an embedded certificate.",
    useCase: "Government (e.g., PIV/CAC cards), military, finance.",
    security: "High",
    complexity: "High",
    protocols: "PKI",
    technicalExplanation: "A form of certificate-based authentication where the certificate and its private key are stored on a secure, tamper-resistant cryptographic chip in a physical card. This provides strong two-factor authentication: something you have (the card) and something you know (a PIN to unlock the card for use). The private key never leaves the card; instead, cryptographic operations like signing are performed on the card itself. This makes it extremely resistant to theft or malware on the host computer.",
  },
  {
    slug: "social-authentication",
    name: "Social Authentication",
    description: "Uses existing login information from social networks.",
    useCase: "Consumer applications, reducing friction for user signup.",
    security: "High",
    complexity: "Medium",
    protocols: "OAuth2, OIDC",
    technicalExplanation: "This is a user-friendly application of the OAuth 2.0 and OIDC protocols. Instead of creating a new account with a password for your site, users can log in using their existing credentials from a social provider like Google, GitHub, or Facebook. This simplifies registration, offloads password management to the trusted social provider, and can allow your application to request basic profile information (with user consent).",
  },
  {
    slug: "one-time-password",
    name: "One-Time Password (OTP)",
    description: "A password that is valid for only one login session or transaction.",
    useCase: "As a second factor in MFA, verifying transactions.",
    security: "Medium",
    complexity: "Low",
    protocols: "Varies (SMS, App)",
    technicalExplanation: "An OTP is a temporary, dynamic code used for authentication. Common types include HOTP (counter-based) and TOTP (Time-based), which is used by apps like Google Authenticator. During setup, a shared secret is established between the server and the user's app (or device). Both then use this secret and a moving factor (the current time for TOTP, a counter for HOTP) to independently generate the same short-lived code. OTPs sent via SMS are also common but are less secure due to risks of SIM swapping.",
  },
  {
    slug: "zero-trust-authentication",
    name: "Zero Trust Authentication",
    description: "Assumes no implicit trust and continuously verifies every access attempt.",
    useCase: "Modern cloud-native environments, protecting against lateral movement.",
    security: "High",
    complexity: "High",
    protocols: "Varies",
    technicalExplanation: "Zero Trust is a security architecture, not a single technology. It's built on the principle of 'never trust, always verify.' It assumes that any access request could be a threat, regardless of its origin (inside or outside the corporate network). Authentication and authorization are not one-time events but are re-evaluated continuously based on a rich set of signals, including user identity, device health and posture, location, and the sensitivity of the requested data. It moves security from the network perimeter to individual resources.",
  },
  {
    slug: "webauthn",
    name: "WebAuthn",
    description: "A web standard for secure, passwordless authentication using public-key cryptography.",
    useCase: "Modern web applications, passwordless login, phishing-resistant MFA.",
    security: "High",
    complexity: "High",
    protocols: "WebAuthn API",
    technicalExplanation: "WebAuthn is a W3C standard that enables passwordless and phishing-resistant authentication. It allows websites to use built-in authenticators (like Touch ID, Face ID, Windows Hello) or external security keys (like YubiKeys) for login. It uses public-key cryptography where a private key, securely stored on the user's authenticator, is used to sign a challenge from the server. The server verifies this signature with the corresponding public key. This proves user possession of the authenticator and is scoped per-origin, preventing phishing.",
  },
  {
    slug: "mutual-tls",
    name: "Mutual TLS (mTLS)",
    description: "Both client and server authenticate each other using TLS certificates.",
    useCase: "Server-to-server APIs (microservices), IoT devices, Zero Trust networks.",
    security: "High",
    complexity: "High",
    protocols: "TLS",
    technicalExplanation: "In standard TLS (used in HTTPS), only the client verifies the server's certificate to ensure it's talking to the right server. In mTLS, this verification is bidirectional. The server also requests and validates the client's certificate during the initial TLS handshake. This provides strong, cryptographic proof of identity for both parties in a connection before any application data (like HTTP requests) is exchanged. It is ideal for non-interactive systems like microservices or IoT devices.",
  },
  {
    slug: "delegated-authentication",
    name: "Delegated Authentication",
    description: "Delegates the authentication process to a trusted external service or identity provider.",
    useCase: "Integrating with enterprise IdPs, using third-party login services.",
    security: "High",
    complexity: "High",
    protocols: "SAML, OAuth2, OIDC",
    technicalExplanation: "This is a broad architectural pattern that underpins SSO, social logins, and enterprise federation. An application (the Service Provider) chooses not to manage user credentials itself. Instead, it delegates the entire authentication process to a dedicated, trusted Identity Provider (IdP). The application establishes a trust relationship with the IdP (via a protocol like SAML or OIDC) and consumes security tokens (like SAML assertions or OIDC ID tokens) to log users in. This centralizes identity management and improves security.",
  }
];

// ====================================================================================
// Component Mapping
// ====================================================================================

const setupInstructionsMap: Record<string, React.ComponentType> = {
  "basic-authentication": BasicAuthSetup,
  "token-based-authentication": TokenBasedSetup,
  "oauth2-authentication": OAuth2Setup,
  "session-based-authentication": SessionBasedSetup,
  "api-key-authentication": ApiKeySetup,
  "digest-authentication": DigestAuthSetup,
  "certificate-based-authentication": CertificateBasedSetup,
  "openid-connect": OidcSetup,
  "saml": SamlSetup,
  "multi-factor-authentication": MfaSetup,
  "biometric-authentication": BiometricSetup,
  "kerberos-authentication": KerberosSetup,
  "single-sign-on": SsoSetup,
  "hmac-authentication": HmacSetup,
  "ntlm-authentication": NtlmSetup,
  "ldap-authentication": LdapSetup,
  "anonymous-authentication": AnonymousSetup,
  "challenge-response-authentication": ChallengeResponseSetup,
  "smart-card-authentication": SmartCardSetup,
  "social-authentication": SocialAuthSetup,
  "one-time-password": OtpSetup,
  "zero-trust-authentication": ZeroTrustSetup,
  "webauthn": WebAuthnSetup,
  "mutual-tls": MutualTlsSetup,
  "delegated-authentication": DelegatedAuthSetup,
};

const diagramMap: Record<string, React.ComponentType> = {
  "oauth2-authentication": OAuth2Diagram,
  "basic-authentication": BasicAuthDiagram,
  "api-key-authentication": ApiKeyDiagram,
  "token-based-authentication": GenericAuthDiagram,
  "session-based-authentication": GenericAuthDiagram,
  "digest-authentication": GenericAuthDiagram,
  "certificate-based-authentication": GenericAuthDiagram,
  "openid-connect": OAuth2Diagram,
  "saml": OAuth2Diagram,
  "multi-factor-authentication": GenericAuthDiagram,
  "biometric-authentication": GenericAuthDiagram,
  "kerberos-authentication": OAuth2Diagram,
  "single-sign-on": OAuth2Diagram,
  "hmac-authentication": GenericAuthDiagram,
  "ntlm-authentication": GenericAuthDiagram,
  "ldap-authentication": GenericAuthDiagram,
  "anonymous-authentication": GenericAuthDiagram,
  "challenge-response-authentication": GenericAuthDiagram,
  "smart-card-authentication": GenericAuthDiagram,
  "social-authentication": OAuth2Diagram,
  "one-time-password": GenericAuthDiagram,
  "zero-trust-authentication": GenericAuthDiagram,
  "webauthn": GenericAuthDiagram,
  "mutual-tls": GenericAuthDiagram,
  "delegated-authentication": OAuth2Diagram,
};

// ====================================================================================
// Final Export
// ====================================================================================

export const authTypes: AuthType[] = authTypeData.map(data => {
  const SetupComponent = setupInstructionsMap[data.slug];
  const DiagramComponent = diagramMap[data.slug];
  
  return {
    ...data,
    setupInstructions: SetupComponent ? <SetupComponent /> : <></>,
    diagram: DiagramComponent ? <DiagramComponent /> : <></>,
  };
});
