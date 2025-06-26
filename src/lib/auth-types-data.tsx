
import type { AuthType } from './types';
import { 
    ApiKeyDiagram, 
    BasicAuthDiagram, 
    GenericAuthDiagram, 
    OAuth2Diagram 
} from '@/components/auth/AuthTypeDiagrams';
import { PlaceholderSetup } from '@/components/auth/PlaceholderSetup';
import { BasicAuthSetup } from '@/components/auth/AuthTypeSetups';
import React from 'react';

export const authTypes: AuthType[] = [
  {
    slug: "basic-authentication",
    name: "Basic Authentication",
    category: "Basic",
    description: "A simple method using a username and password encoded in Base64.",
    useCase: "Internal APIs, simple services where transport is secured by TLS.",
    security: "Low",
    complexity: "Low",
    protocols: "HTTP",
    phishingResistance: 'Low',
    ux: 'Medium Friction',
    credentialType: 'Password',
    standardization: 'IETF RFC 7617',
    technicalExplanation: "HTTP Basic Authentication is one of the simplest methods for enforcing access control to web resources. It's a stateless, challenge-response mechanism defined in RFC 7617. When a client requests a protected resource for the first time, the server responds with a `401 Unauthorized` status and a `WWW-Authenticate: Basic realm=\"...\"` header. The 'realm' is a string that identifies the protected area.\n\nUpon receiving this challenge, the browser prompts the user for a username and password. The client then combines these into a `username:password` string, encodes it using Base64, and resubmits the request with an `Authorization` header. For example, `admin:password` becomes `YWRtaW46cGFzc3dvcmQ=`, and the header would be `Authorization: Basic YWRtaW46cGFzc3dvcmQ=`.\n\n**Crucially, Base64 is an encoding scheme, not encryption.** It is trivial to reverse, meaning the credentials are sent in cleartext unless the entire connection is encrypted with HTTPS (TLS). Because it's stateless, these credentials must be sent with every single request to the protected realm, which increases the risk of exposure if not properly secured.",
    setupInstructions: BasicAuthSetup,
    diagram: BasicAuthDiagram,
    pros: ["Extremely simple to implement", "Universally supported by browsers and clients"],
    cons: ["Insecure without TLS", "Sends credentials with every request", "No mechanism for logout"],
    ssoCapability: 'Not Suited',
    developerExperience: 'Easy',
    httpExamples: {
      request: `GET /resource HTTP/1.1
Host: api.example.com
Authorization: Basic dXNlcjpwYXNz`,
      successResponse: `HTTP/1.1 200 OK
Content-Type: application/json

{
  "message": "Access granted to protected resource"
}`,
      errorResponse: `HTTP/1.1 401 Unauthorized
WWW-Authenticate: Basic realm="User Visible Realm"`,
    },
    securityNotes: (
      <>
        <p>
          <strong>Crucial Warning:</strong> Basic Authentication is only secure when used over a transport layer that is itself encrypted, such as HTTPS (using TLS/SSL).
        </p>
        <p className="mt-2">
          Without TLS, the Base64-encoded credentials can be easily intercepted and decoded by anyone monitoring the network traffic. Never use Basic Auth over an unencrypted HTTP connection in a production environment.
        </p>
      </>
    ),
  },
  {
    slug: "token-based-authentication",
    name: "Token-Based (JWT)",
    category: "Token-Based",
    description: "Uses a signed token (JWT) to verify user identity and claims.",
    useCase: "SPAs, Mobile Apps, APIs, server-to-server communication.",
    security: "Medium",
    complexity: "Medium",
    protocols: "HTTP, WebSocket",
    phishingResistance: 'Low',
    ux: 'Low Friction',
    credentialType: 'Bearer Token',
    standardization: 'IETF RFC 7519',
    technicalExplanation: "Token-based authentication is a stateless protocol. After a user logs in with credentials, the server creates a JSON Web Token (JWT) and sends it to the client. A JWT is a compact, self-contained token with three parts: a header (specifying the algorithm), a payload (containing user data or 'claims' like user ID, roles, and expiration time), and a cryptographic signature. The signature, created with a secret key known only to the server, ensures the token's integrity and authenticity. The client stores this token (e.g., in localStorage or a secure cookie) and sends it with every protected request in the `Authorization: Bearer <token>` header. The server can then validate the token's signature and claims without needing to look up session data in a database, making it highly scalable.",
    setupInstructions: PlaceholderSetup,
    diagram: GenericAuthDiagram,
    pros: ["Stateless and scalable", "Good for SPAs and mobile apps", "Decouples client and server", "Transmits claims securely"],
    cons: ["Token revocation is complex", "Tokens can grow large", "Secret management is critical", "Data in token is readable (not encrypted)"],
    ssoCapability: 'Possible',
    developerExperience: 'Moderate',
    httpExamples: {
      request: `GET /api/profile HTTP/1.1
Host: api.example.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...`,
      successResponse: `HTTP/1.1 200 OK
Content-Type: application/json

{
  "user": { "id": "123", "email": "user@example.com" }
}`,
    },
    securityNotes: (
      <>
        <p>The JWT payload is Base64Url encoded, not encrypted. Do not store sensitive information in the payload unless it is also encrypted. The security of the token relies on the signature, so use a strong secret and algorithm (e.g., HS256 or RS256). Avoid the 'none' algorithm at all costs.</p>
      </>
    ),
  },
  {
    slug: "oauth2-authentication",
    name: "OAuth2 Authentication",
    category: "OAuth/OIDC",
    description: "A delegation protocol for third-party access to user resources.",
    useCase: "Third-party services (e.g., 'Log in with Google'), granting limited API access.",
    security: "High",
    complexity: "High",
    protocols: "HTTP",
    phishingResistance: 'Medium',
    ux: 'Low Friction',
    credentialType: 'Access Token',
    standardization: 'IETF RFC 6749',
    technicalExplanation: "OAuth2 is an authorization framework, not an authentication protocol. It enables an application (the Client) to obtain limited, delegated access to a user's resources on another service (the Resource Server), without exposing the user's credentials. It defines roles (Resource Owner, Client, Authorization Server, Resource Server) and various 'grant types' (flows). The most common and secure flow for web applications is the 'Authorization Code' grant, which involves redirecting the user to the Authorization Server to grant consent. The outcome is an Access Token, a credential that grants specific, scoped permissions to the client application.",
    setupInstructions: PlaceholderSetup,
    diagram: OAuth2Diagram,
    pros: ["Delegated access model", "Granular scopes and permissions", "Wide industry adoption", "Separates user credentials from client app"],
    cons: ["Complex specification with multiple flows", "Not an authentication protocol by itself (needs OIDC for that)", "Vulnerable if redirect URIs are not properly managed"],
    ssoCapability: 'Possible',
    developerExperience: 'Complex',
    securityNotes: (
      <>
        <p>For Single-Page Applications and mobile apps, the Authorization Code grant with PKCE (Proof Key for Code Exchange) is essential to prevent authorization code interception attacks. Always use a strict, pre-registered allowlist for redirect URIs.</p>
      </>
    ),
  },
  {
    slug: "session-based-authentication",
    name: "Session-Based Authentication",
    category: "Session-Based",
    description: "Server stores session data and provides a session ID to the client.",
    useCase: "Traditional monolithic web applications, server-rendered pages.",
    security: "Medium",
    complexity: "Low",
    protocols: "HTTP (Cookies)",
    phishingResistance: 'Low',
    ux: 'Low Friction',
    credentialType: 'Session ID (Cookie)',
    standardization: 'De facto',
    technicalExplanation: "In this stateful model, the server creates and maintains a session for a user upon successful login. It stores session information (like user ID) on the server-side (in memory, a database, or a cache like Redis) and sends a unique, randomly generated Session ID to the client. This ID is typically sent in an `HttpOnly` cookie. The `HttpOnly` flag prevents JavaScript from accessing the cookie, mitigating XSS attacks. The browser automatically sends this cookie with every subsequent request to the same domain, allowing the server to look up the session data, identify the user, and maintain their authenticated state across multiple page views.",
    setupInstructions: PlaceholderSetup,
    diagram: GenericAuthDiagram,
    pros: ["Simple to understand and implement", "Mature and well-understood", "Easy to revoke sessions on the server"],
    cons: ["Requires server-side storage (stateful)", "Doesn't scale well horizontally without a shared session store", "Vulnerable to CSRF without protection"],
    ssoCapability: 'Not Suited',
    developerExperience: 'Easy',
    httpExamples: {
      successResponse: `HTTP/1.1 200 OK
Set-Cookie: session_id=abc123xyz; HttpOnly; Secure; SameSite=Lax`,
      request: `GET /profile HTTP/1.1
Host: app.example.com
Cookie: session_id=abc123xyz`
    },
    securityNotes: (
      <>
        <p>Always use the `HttpOnly`, `Secure`, and `SameSite` attributes on session cookies. `HttpOnly` prevents client-side script access, `Secure` ensures the cookie is only sent over HTTPS, and `SameSite` (`Lax` or `Strict`) is a critical defense against Cross-Site Request Forgery (CSRF) attacks.</p>
      </>
    ),
  },
  {
    slug: "api-key-authentication",
    name: "API Key Authentication",
    category: "Token-Based",
    description: "A unique key is assigned to each application to access the API.",
    useCase: "Public APIs, usage tracking, server-to-server identification.",
    security: "Low",
    complexity: "Low",
    protocols: "HTTP",
    phishingResistance: 'Low',
    ux: 'N/A',
    credentialType: 'Static Key',
    standardization: 'De facto',
    technicalExplanation: "API keys are used to identify the consuming application or project making a request, not a specific end-user. It's a simple way to control access, track usage for billing, and apply rate limiting. The key is a long, unique string that the client sends with each request, typically in a custom HTTP header like `X-API-Key`, a query parameter, or the request body. Because the key is static and often long-lived, it should be treated like a secret and protected accordingly. It does not provide user-level authentication but rather project-level identification.",
    setupInstructions: PlaceholderSetup,
    diagram: ApiKeyDiagram,
    pros: ["Simple to generate and use", "Good for identifying applications and tracking usage"],
    cons: ["Not for user authentication", "Vulnerable if exposed on the client-side", "No standard for key placement in requests"],
    ssoCapability: 'Not Suited',
    developerExperience: 'Easy',
    httpExamples: {
      request: `GET /v1/data HTTP/1.1
Host: api.service.com
X-API-Key: a1b2c3d4-e5f6-7890-a1b2-c3d4e5f67890`
    },
    securityNotes: (
      <>
        <p>API keys should never be embedded in client-side code (like JavaScript in a browser) as they can be easily extracted. They are best suited for server-to-server communication where the key can be stored securely as an environment variable.</p>
      </>
    )
  },
  {
    slug: "digest-authentication",
    name: "Digest Authentication",
    category: "Basic",
    description: "A challenge-response method that hashes credentials before sending.",
    useCase: "Situations requiring more security than Basic Auth without implementing TLS.",
    security: "Low",
    complexity: "Medium",
    protocols: "HTTP",
    phishingResistance: 'Low',
    ux: 'Medium Friction',
    credentialType: 'Password (hashed)',
    standardization: 'IETF RFC 7616',
    technicalExplanation: "As a challenge-response protocol, Digest Auth improves on Basic Auth by never sending the password in cleartext. The server sends a 'nonce' (a random, single-use value) in its `WWW-Authenticate` header. The client creates an MD5 hash of the username, password, nonce, URI, and HTTP method. This hash is sent back to the server in the `Authorization` header. The server, knowing the user's password, performs the same calculation to verify the hash. While better than Basic, it is still vulnerable to man-in-the-middle attacks (without TLS) and uses the outdated and cryptographically broken MD5 algorithm. It is largely considered obsolete.",
    setupInstructions: PlaceholderSetup,
    diagram: GenericAuthDiagram,
    pros: ["Doesn't send password in cleartext"],
    cons: ["Considered obsolete and insecure", "Uses weak MD5 hashing", "Vulnerable to Man-in-the-Middle attacks without TLS", "Complex for little security gain"],
    ssoCapability: 'Not Suited',
    developerExperience: 'Moderate',
    securityNotes: (
      <>
        <p>Digest Authentication should not be used in modern applications. Its reliance on MD5 and vulnerability to MITM attacks make it a poor choice compared to token-based or other modern protocols over TLS.</p>
      </>
    )
  },
  {
    slug: "certificate-based-authentication",
    name: "Certificate-Based Auth",
    category: "Assertion-Based",
    description: "Uses client-side digital certificates to verify identity.",
    useCase: "High-security corporate environments, B2B, and IoT devices.",
    security: "High",
    complexity: "High",
    protocols: "TLS/SSL",
    phishingResistance: 'High',
    ux: 'Low Friction',
    credentialType: 'Private Key',
    standardization: 'X.509 (IETF)',
    technicalExplanation: "This method, also known as Mutual TLS (mTLS), uses X.509 digital certificates for strong authentication. The client presents its own certificate to the server during the TLS handshake. The server verifies that the certificate was issued by a trusted Certificate Authority (CA) and has not been revoked. This provides strong, passwordless authentication for a user or device, as possession of the certificate and its corresponding private key proves identity. It is a cornerstone of Zero Trust architectures for service-to-service communication.",
    setupInstructions: PlaceholderSetup,
    diagram: GenericAuthDiagram,
    pros: ["Very high security", "Phishing resistant", "Passwordless", "Authenticates at the network layer"],
    cons: ["Complex certificate management (issuance, revocation)", "High implementation overhead", "Poor user experience for browser-based apps"],
    ssoCapability: 'Possible',
    developerExperience: 'Complex',
    securityNotes: (
       <>
        <p>The primary challenge is managing the Public Key Infrastructure (PKI), including securely issuing, rotating, and revoking certificates. Improper management can undermine the entire security model.</p>
      </>
    )
  },
  {
    slug: "openid-connect",
    name: "OpenID Connect (OIDC)",
    category: "OAuth/OIDC",
    description: "An identity layer on top of OAuth2 for user authentication.",
    useCase: "SSO, federated identity, modern consumer and enterprise applications.",
    security: "High",
    complexity: "High",
    protocols: "HTTP, OAuth2",
    phishingResistance: 'Medium',
    ux: 'Low Friction',
    credentialType: 'ID Token (JWT)',
    standardization: 'OpenID Foundation',
    technicalExplanation: "OIDC is a thin identity layer built on top of OAuth 2.0. While OAuth 2.0 provides authorization ('what a user can do'), OIDC provides authentication ('who a user is'). It introduces the `ID Token`, a specially formatted JSON Web Token (JWT) that contains user profile information (claims like name, email, etc.). It standardizes how clients can verify the identity of the end-user based on the authentication performed by an Authorization Server, as well as to obtain basic profile information about the end-user in an interoperable and REST-like manner.",
    setupInstructions: PlaceholderSetup,
    diagram: OAuth2Diagram,
    pros: ["Standardized identity layer", "Enables Single Sign-On (SSO)", "Built on modern standards (OAuth2, JWT)"],
    cons: ["Inherits complexity of OAuth2", "Requires understanding of various flows and claims"],
    ssoCapability: 'Native',
    developerExperience: 'Complex',
    httpExamples: {
      successResponse: `Decoded ID Token Payload:
{
  "iss": "https://server.example.com",
  "sub": "248289761001",
  "aud": "s6BhdRkqt3",
  "exp": 1311281970,
  "iat": 1311280970,
  "name": "Jane Doe",
  "email": "jane.doe@example.com"
}`
    },
    securityNotes: (
      <>
        <p>A client application MUST validate the ID Token before using it. This includes verifying the signature, checking the issuer (`iss`), the audience (`aud`), the expiration time (`exp`), and the nonce to mitigate replay attacks.</p>
      </>
    )
  },
  {
    slug: "saml",
    name: "SAML",
    category: "Assertion-Based",
    description: "An XML-based standard for exchanging authentication and authorization data.",
    useCase: "Enterprise SSO, federated identity between different organizations.",
    security: "High",
    complexity: "High",
    protocols: "HTTP, SOAP",
    phishingResistance: 'Medium',
    ux: 'Low Friction',
    credentialType: 'SAML Assertion (XML)',
    standardization: 'OASIS',
    technicalExplanation: "Security Assertion Markup Language (SAML) is an XML-based open standard for exchanging authentication and authorization data between an Identity Provider (IdP) and a Service Provider (SP). It enables web-based Single Sign-On (SSO) by allowing the IdP, which holds the user's identity, to send a signed XML document, called a SAML Assertion, to the SP. The SP trusts this assertion to authenticate and authorize the user without needing direct access to the user's credentials.",
    setupInstructions: PlaceholderSetup,
    diagram: OAuth2Diagram,
    pros: ["Mature standard for enterprise SSO", "Robust and feature-rich", "Widely supported in corporate environments"],
    cons: ["XML-based (verbose and complex)", "Considered legacy compared to OIDC", "Complex to debug due to redirects and XML parsing"],
    ssoCapability: 'Native',
    developerExperience: 'Complex',
     securityNotes: (
      <>
        <p>SAML is vulnerable to XML Signature Wrapping attacks if the assertion is not validated correctly. Always use a trusted, well-maintained library for parsing and validating SAML assertions. Also, ensure the recipient endpoint is protected against unsolicited assertions.</p>
      </>
    )
  },
  {
    slug: "multi-factor-authentication",
    name: "Multi-Factor (MFA)",
    category: "Passwordless/MFA",
    description: "Requires two or more verification factors to gain access.",
    useCase: "Securing sensitive accounts, regulatory compliance (e.g., PCI DSS).",
    security: "High",
    complexity: "Medium",
    protocols: "Varies",
    phishingResistance: 'High',
    ux: 'High Friction',
    credentialType: 'Multiple Factors',
    standardization: 'Varies',
    technicalExplanation: "MFA provides layered security by requiring users to present at least two pieces of evidence (factors) to an authentication mechanism. These factors fall into three categories: Knowledge (something you know, like a password or PIN), Possession (something you have, like a phone app, SMS code, or hardware token), and Inherence (something you are, like a fingerprint or face scan). Requiring multiple factors makes it significantly harder for an unauthorized person to gain access even if one factor (like the password) is compromised.",
    setupInstructions: PlaceholderSetup,
    diagram: GenericAuthDiagram,
    pros: ["Dramatically increases security", "Protects against credential stuffing and phishing"],
    cons: ["Adds friction to user experience", "Can be complex to implement correctly", "Some factors are more secure than others"],
    ssoCapability: 'Possible',
    developerExperience: 'Moderate',
    securityNotes: (
      <>
        <p>The strength of MFA depends on the factors used. Phishing-resistant factors like FIDO2/WebAuthn are the gold standard. SMS-based MFA is better than nothing but is vulnerable to SIM-swapping attacks. Authenticator apps (TOTP) are a good middle ground.</p>
      </>
    )
  },
  {
    slug: "biometric-authentication",
    name: "Biometric Authentication",
    category: "Biometric/Hardware",
    description: "Uses unique biological characteristics (fingerprint, face).",
    useCase: "Mobile devices, high-security access, passwordless login.",
    security: "High",
    complexity: "High",
    protocols: "Varies (FIDO/WebAuthn)",
    phishingResistance: 'High',
    ux: 'Low Friction',
    credentialType: 'Biometric',
    standardization: 'FIDO Alliance',
    technicalExplanation: "Biometric authentication verifies identity using unique physical traits. In modern secure systems (like FIDO2/WebAuthn), the raw biometric data (e.g., fingerprint scan) never leaves the user's device. Instead, it is used locally to unlock a cryptographic private key stored in a secure element on the device. This private key then signs a challenge from the server, proving both possession of the device and the user's presence in a highly secure, private, and phishing-resistant manner.",
    setupInstructions: PlaceholderSetup,
    diagram: GenericAuthDiagram,
    pros: ["Highly convenient for users", "Strong phishing resistance (with FIDO)", "Passwordless"],
    cons: ["Biometric data cannot be changed if compromised", "High implementation complexity", "Privacy concerns if not implemented correctly"],
    ssoCapability: 'Possible',
    developerExperience: 'Complex',
    securityNotes: (
      <>
        <p>The key security principle is that the biometric data should only be used to unlock a local secret on the device and should never be transmitted to a server. This is the model used by FIDO/WebAuthn and is critical for both security and privacy.</p>
      </>
    )
  },
  {
    slug: "kerberos-authentication",
    name: "Kerberos Authentication",
    category: "Secure Enterprise Flow",
    description: "A network authentication protocol using tickets to prove identity.",
    useCase: "Windows Active Directory, large corporate networks, Unix systems.",
    security: "High",
    complexity: "High",
    protocols: "TCP/UDP",
    phishingResistance: 'High',
    ux: 'Low Friction',
    credentialType: 'Kerberos Ticket',
    standardization: 'IETF RFC 4120',
    technicalExplanation: "Kerberos is a ticket-based protocol that uses a trusted third party, a Key Distribution Center (KDC), to provide strong, mutual authentication. A client authenticates once to the KDC to get a Ticket-Granting Ticket (TGT). The client then uses this TGT to request service tickets for specific applications without re-entering a password. This avoids sending passwords over the network and is the default authentication protocol in Windows Active Directory.",
    setupInstructions: PlaceholderSetup,
    diagram: OAuth2Diagram,
    pros: ["Very strong security for internal networks", "Enables SSO within a domain", "Protects against replay attacks"],
    cons: ["Complex to set up and manage", "Not designed for internet/web use", "Single point of failure (KDC)", "Sensitive to time synchronization"],
    ssoCapability: 'Native',
    developerExperience: 'Complex',
    securityNotes: (
      <>
        <p>Kerberos is highly dependent on all machines in the network having synchronized clocks. If clocks drift too far apart, ticket validation will fail. The KDC is also a critical piece of infrastructure; if it goes down, no one can authenticate.</p>
      </>
    )
  },
  {
    slug: "single-sign-on",
    name: "Single Sign-On (SSO)",
    category: "Secure Enterprise Flow",
    description: "Log in once to access multiple independent software systems.",
    useCase: "Corporate environments, large platforms with multiple services (e.g., Google Suite).",
    security: "High",
    complexity: "High",
    protocols: "SAML, OIDC",
    phishingResistance: 'Medium',
    ux: 'Low Friction',
    credentialType: 'Varies (Token/Assertion)',
    standardization: 'SAML, OIDC',
    technicalExplanation: "SSO is an authentication scheme, not a specific protocol itself. It allows a user to log in once with a single set of credentials to a central Identity Provider (IdP) and gain access to multiple, separate applications without re-authenticating. This is achieved through federation protocols like SAML or OIDC. Applications (Service Providers) are configured to trust the IdP. When a user tries to access an SP, the SP redirects them to the IdP for authentication. After a successful login, the IdP sends a secure assertion back to the SP, which then grants the user access.",
    setupInstructions: PlaceholderSetup,
    diagram: OAuth2Diagram,
    pros: ["Greatly improved user experience", "Centralized access control and auditing", "Reduces password fatigue"],
    cons: ["IdP is a single point of failure and a high-value target", "Complex to configure trust relationships", "Session management can be tricky"],
    ssoCapability: 'Native',
    developerExperience: 'Complex',
     securityNotes: (
      <>
        <p>The Identity Provider (IdP) becomes the "keys to the kingdom." It must be protected with the highest level of security, including strong MFA for all administrative access. Misconfiguration of the trust relationship between the Service Provider and IdP can lead to serious vulnerabilities.</p>
      </>
    )
  },
  {
    slug: "hmac-authentication",
    name: "HMAC Authentication",
    category: "Token-Based",
    description: "Uses a cryptographic hash function and a secret key for message authentication.",
    useCase: "Securing webhook endpoints, server-to-server API calls.",
    security: "Medium",
    complexity: "Medium",
    protocols: "HTTP",
    phishingResistance: 'Medium',
    ux: 'N/A',
    credentialType: 'Shared Secret',
    standardization: 'IETF RFC 2104',
    technicalExplanation: "HMAC (Hash-based Message Authentication Code) verifies both the integrity and authenticity of a request. The client and server share a secret key. To make a request, the client creates a signature by hashing the request content (and often other parts like the URI and a timestamp) with an algorithm like SHA256 and the shared secret. This signature is sent in a header (e.g., `X-Hub-Signature-256`). The server performs the same calculation on the received message and compares its result to the signature sent by the client. If they match, the server knows the request is from a trusted source and hasn't been tampered with.",
    setupInstructions: PlaceholderSetup,
    diagram: GenericAuthDiagram,
    pros: ["Protects against message tampering", "Prevents replay attacks (with nonce/timestamp)", "Verifies sender authenticity"],
    cons: ["Requires secure shared secret distribution", "Can be complex to implement correctly", "Does not encrypt the message body"],
    ssoCapability: 'Not Suited',
    developerExperience: 'Moderate',
    httpExamples: {
      request: `POST /webhook HTTP/1.1
Host: api.example.com
X-Hub-Signature-256: sha256=7ddb8c1a...
Content-Type: application/json

{"event": "new_commit"}`
    },
    securityNotes: (
      <>
        <p>The signature must cover the entire request body and other key headers to prevent tampering. Including a timestamp or nonce in the signed content is crucial to prevent replay attacks, where an attacker re-sends a valid, captured request.</p>
      </>
    )
  },
  {
    slug: "ntlm-authentication",
    name: "NTLM Authentication",
    category: "Session-Based",
    description: "A suite of Microsoft security protocols for challenge-response authentication.",
    useCase: "Legacy Windows environments, backward compatibility within intranets.",
    security: "Low",
    complexity: "High",
    protocols: "Varies",
    phishingResistance: 'Low',
    ux: 'Low Friction',
    credentialType: 'Password Hash',
    standardization: 'Proprietary (Microsoft)',
    technicalExplanation: "NTLM (New Technology LAN Manager) is a legacy challenge-response protocol common in older Windows networks. It's known to be vulnerable to relay attacks and pass-the-hash attacks, and is not recommended for modern applications or use over the internet. It has been largely superseded by Kerberos in Active Directory environments. Its continued use is typically for backward compatibility with old applications or devices that do not support Kerberos.",
    setupInstructions: PlaceholderSetup,
    diagram: GenericAuthDiagram,
    pros: ["Backward compatibility in Windows environments"],
    cons: ["Many known vulnerabilities", "Superseded by Kerberos", "Not for internet use", "Weak cryptography"],
    ssoCapability: 'Possible',
    developerExperience: 'Complex',
    securityNotes: (
       <>
        <p>NTLM is considered insecure by modern standards. It should be disabled wherever possible in favor of Kerberos. Its continued use poses a significant security risk in any network.</p>
      </>
    )
  },
  {
    slug: "ldap-authentication",
    name: "LDAP Authentication",
    category: "Session-Based",
    description: "Validates user credentials against an LDAP directory service.",
    useCase: "Centralized user management in corporate networks (e.g., Active Directory).",
    security: "Medium",
    complexity: "Medium",
    protocols: "LDAP",
    phishingResistance: 'Low',
    ux: 'Medium Friction',
    credentialType: 'Password',
    standardization: 'IETF RFC 4511',
    technicalExplanation: "Lightweight Directory Access Protocol (LDAP) is a protocol for accessing and maintaining distributed directory information services like Active Directory. For authentication, an application performs a 'bind' operation to the LDAP server. A simple bind with a user's Distinguished Name (DN) and password will succeed if the credentials are correct. This allows applications to centralize user management without storing passwords themselves. All communication must be encrypted via LDAPS (LDAP over SSL) or STARTTLS.",
    setupInstructions: PlaceholderSetup,
    diagram: GenericAuthDiagram,
    pros: ["Centralizes user directory", "Standard protocol for directory services", "Mature and widely supported"],
    cons: ["Insecure without LDAPS/TLS (sends passwords in cleartext)", "Can be complex to manage directory structure (DNs)", "Chatty protocol"],
    ssoCapability: 'Possible',
    developerExperience: 'Moderate',
    securityNotes: (
       <>
        <p>Never use LDAP over an unencrypted connection. Always use LDAPS (port 636) or STARTTLS to encrypt the entire session, otherwise credentials will be sent in cleartext over the network. Bind with a service account with limited privileges for searching, and only perform the user credential bind for authentication.</p>
      </>
    )
  },
  {
    slug: "anonymous-authentication",
    name: "Anonymous Authentication",
    category: "Basic",
    description: "Grants access to public resources without verifying identity.",
    useCase: "Public websites, guest access, read-only content.",
    security: "Low",
    complexity: "Low",
    protocols: "HTTP",
    phishingResistance: 'N/A',
    ux: 'Low Friction',
    credentialType: 'None',
    standardization: 'N/A',
    technicalExplanation: "This isn't a form of authentication as much as a deliberate lack of it. The server is configured to allow access to specific resources without requiring any credentials. On the backend, the user might be assigned a generic, low-privilege 'anonymous' identity to standardize authorization checks. It's essential for any public-facing content and is the default state for most websites before a user logs in.",
    setupInstructions: PlaceholderSetup,
    diagram: GenericAuthDiagram,
    pros: ["No friction for users", "Simple for public content"],
    cons: ["Provides no user identity", "Not suitable for protected resources", "Can make usage tracking difficult"],
    ssoCapability: 'Not Suited',
    developerExperience: 'Easy',
     securityNotes: (
      <>
        <p>Ensure that anonymous access is strictly limited to public resources. Authorization rules must be robust to prevent an anonymous user from accessing any sensitive data or performing privileged actions.</p>
      </>
    )
  },
  {
    slug: "challenge-response-authentication",
    name: "Challenge-Response Auth",
    category: "Advanced Concepts",
    description: "Server sends a challenge, client responds with a computed value.",
    useCase: "Secure passwordless systems, preventing replay attacks.",
    security: "Medium",
    complexity: "Medium",
    protocols: "Varies",
    phishingResistance: 'Medium',
    ux: 'Medium Friction',
    credentialType: 'Varies (Secret)',
    standardization: 'Varies',
    technicalExplanation: "This is a family of protocols where a secret (like a password or key) is never transmitted directly over the network. The verifier sends a random, single-use value (the challenge or 'nonce'). The claimant uses a shared secret to perform a cryptographic calculation with the nonce and sends the result (the response). The verifier performs the same calculation to validate the response. This prevents replay attacks, as a new challenge is used for each authentication attempt. Examples include Digest, NTLM, and parts of the Kerberos and WebAuthn flows.",
    setupInstructions: PlaceholderSetup,
    diagram: GenericAuthDiagram,
    pros: ["Secrets are not sent over the network", "Resistant to replay attacks"],
    cons: ["Can be complex to design", "Strength depends on the underlying cryptographic algorithm"],
    ssoCapability: 'Not Suited',
    developerExperience: 'Moderate',
    securityNotes: (
      <>
        <p>The security of a challenge-response system is entirely dependent on the strength of the cryptographic algorithm used and the randomness and uniqueness of the challenge (nonce). A predictable nonce can lead to replay attacks.</p>
      </>
    )
  },
  {
    slug: "smart-card-authentication",
    name: "Smart Card Authentication",
    category: "Biometric/Hardware",
    description: "Uses a physical smart card with an embedded certificate.",
    useCase: "Government (e.g., PIV/CAC cards), military, finance.",
    security: "High",
    complexity: "High",
    protocols: "PKI",
    phishingResistance: 'High',
    ux: 'High Friction',
    credentialType: 'Private Key (Hardware)',
    standardization: 'ISO/IEC 7816, PKI',
    technicalExplanation: "A form of certificate-based authentication where the certificate and its private key are stored on a secure, tamper-resistant cryptographic chip in a physical card. This provides strong two-factor authentication: something you have (the card) and something you know (a PIN to unlock the card for use). The private key never leaves the card; instead, cryptographic operations like signing are performed on the card itself. This makes it extremely resistant to theft or malware on the host computer.",
    setupInstructions: PlaceholderSetup,
    diagram: GenericAuthDiagram,
    pros: ["Extremely high security", "Tamper-resistant hardware", "Strong, phishing-resistant MFA"],
    cons: ["Requires physical hardware and readers", "High cost and infrastructure overhead", "Poor user experience"],
    ssoCapability: 'Possible',
    developerExperience: 'Complex',
    securityNotes: (
      <>
        <p>The PIN used to unlock the card is a critical security component. The card should have a mechanism to lock itself after a certain number of incorrect PIN attempts to prevent brute-force attacks.</p>
      </>
    )
  },
  {
    slug: "social-authentication",
    name: "Social Authentication",
    category: "OAuth/OIDC",
    description: "Uses existing login information from social networks.",
    useCase: "Consumer applications, reducing friction for user signup.",
    security: "High",
    complexity: "Medium",
    protocols: "OAuth2, OIDC",
    phishingResistance: 'Medium',
    ux: 'Low Friction',
    credentialType: 'Social Account',
    standardization: 'OAuth2, OIDC',
    technicalExplanation: "This is a user-friendly application of the OAuth 2.0 and OIDC protocols. Instead of creating a new account with a password for your site, users can log in using their existing credentials from a social provider like Google, GitHub, or Facebook. This simplifies registration, offloads password management to the trusted social provider, and can allow your application to request basic profile information (with user consent) via defined scopes.",
    setupInstructions: PlaceholderSetup,
    diagram: OAuth2Diagram,
    pros: ["Reduces signup friction", "No need to store user passwords", "Leverages trusted providers' security"],
    cons: ["Dependency on third-party providers", "Privacy concerns for users", "Account linking can be complex"],
    ssoCapability: 'Native',
    developerExperience: 'Moderate',
    securityNotes: (
      <>
        <p>Your application is now dependent on the security of the social provider. It's crucial to handle cases where a user revokes access from the provider's side. Also, be mindful of the data you request; only ask for the scopes you absolutely need.</p>
      </>
    )
  },
  {
    slug: "one-time-password",
    name: "One-Time Password (OTP)",
    category: "Passwordless/MFA",
    description: "A password that is valid for only one login session or transaction.",
    useCase: "As a second factor in MFA, verifying transactions.",
    security: "Medium",
    complexity: "Low",
    protocols: "Varies (SMS, App)",
    phishingResistance: 'Medium',
    ux: 'Medium Friction',
    credentialType: 'Single-use Code',
    standardization: 'IETF RFC 4226/6238',
    technicalExplanation: "An OTP is a temporary, dynamic code used for authentication. Common types include HOTP (counter-based) and TOTP (Time-based), which is used by apps like Google Authenticator. During setup, a shared secret is established between the server and the user's app (or device). Both then use this secret and a moving factor (the current time for TOTP, a counter for HOTP) to independently generate the same short-lived code. OTPs sent via SMS are also common but are less secure due to risks of SIM swapping.",
    setupInstructions: PlaceholderSetup,
    diagram: GenericAuthDiagram,
    pros: ["Good second factor for MFA", "Protects against password reuse attacks"],
    cons: ["Can be phished (user tricked into entering code on fake site)", "SMS-based OTP is vulnerable to SIM-swapping", "Adds user friction"],
    ssoCapability: 'Not Suited',
    developerExperience: 'Easy',
    securityNotes: (
      <>
        <p>To protect against brute-force attacks, the server must implement rate limiting on OTP validation attempts. TOTP (Time-based) is generally preferred over HOTP (counter-based) as it is self-synchronizing.</p>
      </>
    )
  },
  {
    slug: "zero-trust-authentication",
    name: "Zero Trust Authentication",
    category: "Advanced Concepts",
    description: "Assumes no implicit trust and continuously verifies every access attempt.",
    useCase: "Modern cloud-native environments, protecting against lateral movement.",
    security: "High",
    complexity: "High",
    protocols: "Varies",
    phishingResistance: 'High',
    ux: 'Varies',
    credentialType: 'Varies (Contextual)',
    standardization: 'NIST Framework',
    technicalExplanation: "Zero Trust is a security architecture, not a single technology. It's built on the principle of 'never trust, always verify.' It assumes that any access request could be a threat, regardless of its origin (inside or outside the corporate network). Authentication and authorization are not one-time events but are re-evaluated continuously based on a rich set of signals, including user identity, device health and posture, location, and the sensitivity of the requested data. It moves security from the network perimeter to individual resources.",
    setupInstructions: PlaceholderSetup,
    diagram: GenericAuthDiagram,
    pros: ["Strong security posture", "Protects against lateral movement", "Adapts to modern infrastructure"],
    cons: ["Very complex to design and implement", "Can impact user experience if not tuned", "Requires significant investment"],
    ssoCapability: 'Native',
    developerExperience: 'Complex',
    securityNotes: (
      <>
        <p>Implementing Zero Trust requires a mature understanding of your organization's assets, users, and data flows. It's an incremental journey, not a single product you can buy. Start by enforcing strong identity verification (MFA) and device health checks everywhere.</p>
      </>
    )
  },
  {
    slug: "webauthn",
    name: "WebAuthn",
    category: "Biometric/Hardware",
    description: "A web standard for secure, passwordless authentication using public-key cryptography.",
    useCase: "Modern web applications, passwordless login, phishing-resistant MFA.",
    security: "High",
    complexity: "High",
    protocols: "WebAuthn API",
    phishingResistance: 'High',
    ux: 'Low Friction',
    credentialType: 'Private Key (Device)',
    standardization: 'W3C/FIDO',
    technicalExplanation: "WebAuthn is a W3C standard that enables passwordless and phishing-resistant authentication. It allows websites to use built-in authenticators (like Touch ID, Face ID, Windows Hello) or external security keys (like YubiKeys) for login. It uses public-key cryptography where a private key, securely stored on the user's authenticator, is used to sign a challenge from the server. The server verifies this signature with the corresponding public key. This proves user possession of the authenticator and is scoped per-origin, preventing phishing.",
    setupInstructions: PlaceholderSetup,
    diagram: GenericAuthDiagram,
    pros: ["Highest phishing resistance available", "Passwordless and convenient", "Standardized web API"],
    cons: ["Requires browser/device support", "Users need to understand the new flow", "Account recovery can be complex"],
    ssoCapability: 'Possible',
    developerExperience: 'Complex',
    securityNotes: (
      <>
        <p>A robust account recovery process is critical for WebAuthn. Since a user might lose their device (authenticator), you must provide secure alternative methods for them to regain access, such as recovery codes or a verified email address, without undermining the security of the system.</p>
      </>
    )
  },
  {
    slug: "mutual-tls",
    name: "Mutual TLS (mTLS)",
    category: "Assertion-Based",
    description: "Both client and server authenticate each other using TLS certificates.",
    useCase: "Server-to-server APIs (microservices), IoT devices, Zero Trust networks.",
    security: "High",
    complexity: "High",
    protocols: "TLS",
    phishingResistance: 'High',
    ux: 'N/A',
    credentialType: 'Private Key',
    standardization: 'IETF RFC 8446',
    technicalExplanation: "In standard TLS (used in HTTPS), only the client verifies the server's certificate to ensure it's talking to the right server. In mTLS, this verification is bidirectional. The server also requests and validates the client's certificate during the initial TLS handshake. This provides strong, cryptographic proof of identity for both parties in a connection before any application data (like HTTP requests) is exchanged. It is ideal for non-interactive systems like microservices or IoT devices.",
    setupInstructions: PlaceholderSetup,
    diagram: GenericAuthDiagram,
    pros: ["Strong, cryptographic identity for services", "Authenticates at the transport layer", "Language and application agnostic"],
    cons: ["Certificate management at scale is complex", "Not suited for user-facing applications", "Adds latency to initial connection"],
    ssoCapability: 'Not Suited',
    developerExperience: 'Complex',
    securityNotes: (
      <>
        <p>mTLS provides authentication but not authorization. After a successful mTLS handshake, the application layer must still perform authorization checks based on the identity presented in the client certificate (e.g., by checking the Common Name or Subject Alternative Name).</p>
      </>
    )
  },
  {
    slug: "delegated-authentication",
    name: "Delegated Authentication",
    category: "Advanced Concepts",
    description: "Delegates the authentication process to a trusted external service or identity provider.",
    useCase: "Integrating with enterprise IdPs, using third-party login services.",
    security: "High",
    complexity: "High",
    protocols: "SAML, OAuth2, OIDC",
    phishingResistance: 'Medium',
    ux: 'Low Friction',
    credentialType: 'Varies (Token/Assertion)',
    standardization: 'SAML, OAuth2, OIDC',
    technicalExplanation: "This is a broad architectural pattern that underpins SSO, social logins, and enterprise federation. An application (the Service Provider) chooses not to manage user credentials itself. Instead, it delegates the entire authentication process to a dedicated, trusted Identity Provider (IdP). The application establishes a trust relationship with the IdP (via a protocol like SAML or OIDC) and consumes security tokens (like SAML assertions or OIDC ID tokens) to log users in. This centralizes identity management and improves security.",
    setupInstructions: PlaceholderSetup,
    diagram: OAuth2Diagram,
    pros: ["Reduces security burden on application", "Enables SSO and federation", "Leverages specialized identity services"],
    cons: ["Creates dependency on IdP", "Requires understanding of federation protocols", "Initial configuration can be complex"],
    ssoCapability: 'Native',
    developerExperience: 'Complex',
    securityNotes: (
      <>
        <p>The trust relationship between your application and the Identity Provider is paramount. Your application must rigorously validate all incoming tokens/assertions to ensure they are from the expected issuer and intended for your application.</p>
      </>
    )
  },
  {
    slug: "device-fingerprint-authentication",
    name: "Device Fingerprint Auth",
    category: "Advanced Concepts",
    description: "Identifies devices by collecting a unique set of browser and hardware attributes.",
    useCase: "Fraud detection, bot prevention, and as a factor in risk-based authentication.",
    security: "Medium",
    complexity: "High",
    protocols: "Proprietary",
    phishingResistance: 'Low',
    ux: 'Low Friction',
    credentialType: 'Device Attributes',
    standardization: 'De facto',
    technicalExplanation: "Device fingerprinting involves collecting a wide array of data points from a user's device, such as browser version, installed fonts, screen resolution, operating system, and hardware specifics. These attributes are combined to create a unique 'fingerprint' or hash. While not infallible, this fingerprint can be used to identify a returning device with a high degree of probability, serving as a passive authentication factor to detect anomalies or add confidence to a session. It is typically used as one signal among many in a risk-based authentication system.",
    setupInstructions: PlaceholderSetup,
    diagram: GenericAuthDiagram,
    pros: ["Passive and frictionless for the user", "Effective for fraud and bot detection"],
    cons: ["Raises privacy concerns (e.g., GDPR)", "Can be spoofed", "Fingerprints can change with software updates", "Not a primary authentication method"],
    ssoCapability: 'Not Suited',
    developerExperience: 'Complex',
    securityNotes: (
       <>
        <p>Device fingerprinting should never be used as the sole method of authentication. It is a probabilistic signal, not a deterministic proof of identity. Its use must be balanced with user privacy considerations and relevant regulations.</p>
      </>
    )
  },
];
