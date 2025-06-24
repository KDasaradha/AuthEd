import type { AuthType } from './types';

const PlaceholderDiagram = () => (
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
                <path d="M 110 130 H 390" stroke="hsl(var(--accent))" strokeWidth="2" markerEnd="url(#arrow)" />
                <text x="250" y="125" textAnchor="middle" fill="hsl(var(--foreground))" className="text-sm">1. Request Access</text>

                <path d="M 410 170 H 680" stroke="hsl(var(--accent))" strokeWidth="2" markerEnd="url(#arrow)" />
                <text x="545" y="165" textAnchor="middle" fill="hsl(var(--foreground))" className="text-sm">2. Redirect to Login</text>

                <path d="M 680 210 H 410" stroke="hsl(var(--accent))" strokeWidth="2" markerEnd="url(#arrow)" />
                <text x="545" y="205" textAnchor="middle" fill="hsl(var(--foreground))" className="text-sm">3. Credentials / Token</text>

                <path d="M 390 250 H 110" stroke="hsl(var(--accent))" strokeWidth="2" markerEnd="url(#arrow)" />
                <text x="250" y="245" textAnchor="middle" fill="hsl(var(--foreground))" className="text-sm">4. Access Granted</text>
            </g>
        </g>
        <defs>
            <marker id="arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                <path d="M 0 0 L 10 5 L 0 10 z" fill="hsl(var(--accent))" />
            </marker>
        </defs>
    </svg>
);


const genericSetup = (
  <ol className="list-decimal space-y-2 pl-5">
    <li>Configure the corresponding FastAPI backend application for this authentication type.</li>
    <li>Use the interactive demo on this page to send requests.</li>
    <li>For login, provide the required credentials (e.g., username/password).</li>
    <li>Use the received token, cookie, or header in subsequent requests to the protected endpoint.</li>
    <li>Observe the responses to understand the authentication flow.</li>
  </ol>
);

export const authTypes: AuthType[] = [
  {
    slug: "basic-authentication",
    name: "Basic Authentication",
    description: "A simple method using a username and password encoded in Base64.",
    useCase: "Internal APIs, simple services",
    security: "Low",
    complexity: "Low",
    protocols: "HTTP",
    technicalExplanation: "HTTP Basic Authentication sends a Base64-encoded string of 'username:password' in the Authorization header. It is not secure over HTTP as it can be easily decoded.",
    setupInstructions: genericSetup,
    diagram: <PlaceholderDiagram />
  },
  {
    slug: "token-based-authentication",
    name: "Token-Based (JWT)",
    description: "Uses a signed token (JWT) to verify user identity and claims.",
    useCase: "SPAs, Mobile Apps, APIs",
    security: "Medium",
    complexity: "Medium",
    protocols: "HTTP, WebSocket",
    technicalExplanation: "JSON Web Tokens (JWT) are self-contained tokens that can be used to securely transmit information between parties. The server generates a token that certifies the user identity, and the client sends this token with every request.",
    setupInstructions: genericSetup,
    diagram: <PlaceholderDiagram />
  },
  {
    slug: "oauth2-authentication",
    name: "OAuth2 Authentication",
    description: "A delegation protocol for third-party access to user resources.",
    useCase: "Third-party services, social logins",
    security: "High",
    complexity: "High",
    protocols: "HTTP",
    technicalExplanation: "OAuth2 allows applications to obtain limited access to user accounts on an HTTP service. It delegates user authentication to the service that hosts the user account, and authorizes third-party applications to access the user account.",
    setupInstructions: genericSetup,
    diagram: <PlaceholderDiagram />
  },
  {
    slug: "session-based-authentication",
    name: "Session-Based Authentication",
    description: "Server stores session data and provides a session ID to the client.",
    useCase: "Traditional web applications",
    security: "Medium",
    complexity: "Low",
    protocols: "HTTP (Cookies)",
    technicalExplanation: "The server creates a session for the user upon login, stores session-specific data, and sends a session ID back to the client as a cookie. The client sends this cookie with each request to identify itself.",
    setupInstructions: genericSetup,
    diagram: <PlaceholderDiagram />
  },
  {
    slug: "api-key-authentication",
    name: "API Key Authentication",
    description: "A unique key is assigned to each application to access the API.",
    useCase: "Public APIs, server-to-server",
    security: "Low",
    complexity: "Low",
    protocols: "HTTP",
    technicalExplanation: "The client sends a unique API key, typically in a request header (e.g., X-API-Key), to identify the calling application. It's simple but less secure as the key can be compromised.",
    setupInstructions: genericSetup,
    diagram: <PlaceholderDiagram />
  },
  {
    slug: "digest-authentication",
    name: "Digest Authentication",
    description: "A challenge-response method that hashes credentials before sending.",
    useCase: "More secure than Basic Auth",
    security: "Medium",
    complexity: "Medium",
    protocols: "HTTP",
    technicalExplanation: "An improvement on Basic Auth, Digest Authentication sends a hash of the password combined with a server-provided nonce over the network, avoiding sending the password in cleartext.",
    setupInstructions: genericSetup,
    diagram: <PlaceholderDiagram />
  },
  {
    slug: "certificate-based-authentication",
    name: "Certificate-Based Auth",
    description: "Uses client-side digital certificates to verify identity.",
    useCase: "High-security corporate environments",
    security: "High",
    complexity: "High",
    protocols: "TLS/SSL",
    technicalExplanation: "The client presents a digital certificate to the server during the TLS handshake. The server verifies the certificate's validity and issuer to authenticate the client, enabling strong, passwordless authentication.",
    setupInstructions: genericSetup,
    diagram: <PlaceholderDiagram />
  },
  {
    slug: "openid-connect",
    name: "OpenID Connect (OIDC)",
    description: "An identity layer on top of OAuth2 for user authentication.",
    useCase: "SSO, federated identity",
    security: "High",
    complexity: "High",
    protocols: "HTTP, OAuth2",
    technicalExplanation: "OIDC is a simple identity layer built on top of the OAuth 2.0 protocol. It allows clients to verify the identity of the end-user based on the authentication performed by an Authorization Server, and obtain basic profile information.",
    setupInstructions: genericSetup,
    diagram: <PlaceholderDiagram />
  },
  {
    slug: "saml",
    name: "SAML",
    description: "An XML-based standard for exchanging authentication and authorization data.",
    useCase: "Enterprise SSO, federated identity",
    security: "High",
    complexity: "High",
    protocols: "HTTP, SOAP",
    technicalExplanation: "Security Assertion Markup Language (SAML) is an open standard that enables identity providers (IdP) to pass authorization credentials to service providers (SP). This allows for single sign-on (SSO) across different domains.",
    setupInstructions: genericSetup,
    diagram: <PlaceholderDiagram />
  },
  {
    slug: "multi-factor-authentication",
    name: "Multi-Factor (MFA)",
    description: "Requires two or more verification factors to gain access.",
    useCase: "Securing sensitive accounts",
    security: "High",
    complexity: "Medium",
    protocols: "Varies",
    technicalExplanation: "MFA enhances security by requiring users to provide multiple forms of verification, such as something they know (password), something they have (phone), and something they are (biometric).",
    setupInstructions: genericSetup,
    diagram: <PlaceholderDiagram />
  },
  {
    slug: "biometric-authentication",
    name: "Biometric Authentication",
    description: "Uses unique biological characteristics (fingerprint, face).",
    useCase: "Mobile devices, high-security access",
    security: "High",
    complexity: "High",
    protocols: "Varies (FIDO/WebAuthn)",
    technicalExplanation: "Biometric authentication verifies a user's identity through unique biological traits. This demo uses a mock implementation to simulate the flow.",
    setupInstructions: genericSetup,
    diagram: <PlaceholderDiagram />
  },
  {
    slug: "kerberos-authentication",
    name: "Kerberos Authentication",
    description: "A network authentication protocol using tickets to prove identity.",
    useCase: "Windows Active Directory, large networks",
    security: "High",
    complexity: "High",
    protocols: "TCP/UDP",
    technicalExplanation: "Kerberos uses a trusted third party, called a Key Distribution Center (KDC), to issue 'tickets' to clients. Clients then use these tickets to prove their identity to servers without sending passwords over the network.",
    setupInstructions: genericSetup,
    diagram: <PlaceholderDiagram />
  },
  {
    slug: "single-sign-on",
    name: "Single Sign-On (SSO)",
    description: "Log in once to access multiple independent software systems.",
    useCase: "Corporate environments, large platforms",
    security: "High",
    complexity: "High",
    protocols: "SAML, OIDC",
    technicalExplanation: "SSO allows a user to log in with a single ID and password to gain access to a connected system or systems of systems without being prompted for different usernames or passwords.",
    setupInstructions: genericSetup,
    diagram: <PlaceholderDiagram />
  },
  {
    slug: "hmac-authentication",
    name: "HMAC Authentication",
    description: "Uses a cryptographic hash function and a secret key for message authentication.",
    useCase: "Securing API requests",
    security: "Medium",
    complexity: "Medium",
    protocols: "HTTP",
    technicalExplanation: "Hash-based Message Authentication Code (HMAC) is a type of message authentication code (MAC) involving a cryptographic hash function in combination with a secret cryptographic key.",
    setupInstructions: genericSetup,
    diagram: <PlaceholderDiagram />
  },
  {
    slug: "ntlm-authentication",
    name: "NTLM Authentication",
    description: "A suite of Microsoft security protocols for challenge-response authentication.",
    useCase: "Legacy Windows environments",
    security: "Low",
    complexity: "High",
    protocols: "Varies",
    technicalExplanation: "NTLM is a challenge-response authentication protocol used in Windows networks. It is now considered insecure and has been largely replaced by Kerberos.",
    setupInstructions: genericSetup,
    diagram: <PlaceholderDiagram />
  },
  {
    slug: "ldap-authentication",
    name: "LDAP Authentication",
    description: "Validates user credentials against an LDAP directory service.",
    useCase: "Centralized user management",
    security: "Medium",
    complexity: "Medium",
    protocols: "LDAP",
    technicalExplanation: "Lightweight Directory Access Protocol (LDAP) is used to look up user information in a central directory. Authentication is done by binding to the LDAP server with the user's credentials.",
    setupInstructions: genericSetup,
    diagram: <PlaceholderDiagram />
  },
  {
    slug: "anonymous-authentication",
    name: "Anonymous Authentication",
    description: "Grants access to public resources without verifying identity.",
    useCase: "Public websites, guest access",
    security: "Low",
    complexity: "Low",
    protocols: "HTTP",
    technicalExplanation: "Allows users to access resources without providing any credentials. It's suitable for public content where user identity is not required.",
    setupInstructions: genericSetup,
    diagram: <PlaceholderDiagram />
  },
  {
    slug: "challenge-response-authentication",
    name: "Challenge-Response Auth",
    description: "Server sends a challenge, client responds with a computed value.",
    useCase: "Secure passwordless systems",
    security: "Medium",
    complexity: "Medium",
    protocols: "Varies",
    technicalExplanation: "The server sends a random piece of data (the challenge) to the client. The client combines this with a secret (like a password) and hashes it to produce a response, which is sent back for verification.",
    setupInstructions: genericSetup,
    diagram: <PlaceholderDiagram />
  },
  {
    slug: "smart-card-authentication",
    name: "Smart Card Authentication",
    description: "Uses a physical smart card with an embedded certificate.",
    useCase: "Government, military, finance",
    security: "High",
    complexity: "High",
    protocols: "PKI",
    technicalExplanation: "A user inserts a smart card into a reader and may enter a PIN. The card contains a digital certificate that is used to authenticate the user. This demo uses a mock implementation.",
    setupInstructions: genericSetup,
    diagram: <PlaceholderDiagram />
  },
  {
    slug: "social-authentication",
    name: "Social Authentication",
    description: "Uses existing login information from social networks.",
    useCase: "Consumer applications",
    security: "High",
    complexity: "Medium",
    protocols: "OAuth2, OIDC",
    technicalExplanation: "A form of single sign-on using existing information from a social networking service like Facebook, Google, or Twitter to sign into a third-party website, instead of creating a new login account specifically for that website.",
    setupInstructions: genericSetup,
    diagram: <PlaceholderDiagram />
  },
  {
    slug: "one-time-password",
    name: "One-Time Password (OTP)",
    description: "A password that is valid for only one login session or transaction.",
    useCase: "MFA, transaction verification",
    security: "Medium",
    complexity: "Low",
    protocols: "Varies (SMS, App)",
    technicalExplanation: "An OTP is a password that is automatically generated to be used for a single access attempt. It's a common factor in MFA systems and can be delivered via SMS, email, or an authenticator app.",
    setupInstructions: genericSetup,
    diagram: <PlaceholderDiagram />
  },
  {
    slug: "zero-trust-authentication",
    name: "Zero Trust Authentication",
    description: "Assumes no implicit trust and continuously verifies every access attempt.",
    useCase: "Modern cloud-native environments",
    security: "High",
    complexity: "High",
    protocols: "Varies",
    technicalExplanation: "A security model based on the principle of 'never trust, always verify.' It requires strict identity verification for every person and device trying to access resources on a private network, regardless of whether they are sitting within or outside of the network perimeter.",
    setupInstructions: genericSetup,
    diagram: <PlaceholderDiagram />
  },
  {
    slug: "webauthn",
    name: "WebAuthn",
    description: "A web standard for secure, passwordless authentication using public-key cryptography.",
    useCase: "Modern web applications, passwordless login",
    security: "High",
    complexity: "High",
    protocols: "WebAuthn API",
    technicalExplanation: "WebAuthn allows servers to register and authenticate users using public-key cryptography instead of a password. It is supported by major browsers and platforms and can use authenticators like security keys or biometrics.",
    setupInstructions: genericSetup,
    diagram: <PlaceholderDiagram />
  },
  {
    slug: "mutual-tls",
    name: "Mutual TLS (mTLS)",
    description: "Both client and server authenticate each other using TLS certificates.",
    useCase: "Server-to-server, IoT, Zero Trust",
    security: "High",
    complexity: "High",
    protocols: "TLS",
    technicalExplanation: "In standard TLS, only the client verifies the server. In Mutual TLS, the server also verifies the client's identity by requesting a client certificate during the handshake, ensuring both parties are who they claim to be.",
    setupInstructions: genericSetup,
    diagram: <PlaceholderDiagram />
  },
  {
    slug: "delegated-authentication",
    name: "Delegated Authentication",
    description: "Delegates the authentication process to a trusted external service or identity provider.",
    useCase: "Integrating with external IdPs",
    security: "High",
    complexity: "High",
    protocols: "SAML, OAuth2, OIDC",
    technicalExplanation: "Instead of managing user credentials, an application delegates the authentication process to a centralized, trusted Identity Provider (IdP). This is the core principle behind protocols like SAML and OpenID Connect.",
    setupInstructions: genericSetup,
    diagram: <PlaceholderDiagram />
  }
];
