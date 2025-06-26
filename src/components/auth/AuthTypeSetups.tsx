
'use client';

import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Button } from '@/components/ui/button';
import { Copy, Check } from 'lucide-react';
import { useState } from 'react';

const CodeBlock = ({ code, lang }: { code: string; lang: string }) => {
  const [hasCopied, setHasCopied] = useState(false);

  const copyToClipboard = () => {
    navigator.clipboard.writeText(code.trim());
    setHasCopied(true);
    setTimeout(() => {
      setHasCopied(false);
    }, 2000);
  };

  return (
    <div className="relative group">
      <pre className="p-4 pr-12 bg-muted rounded-md text-sm overflow-x-auto font-code w-full">
        <code className={`language-${lang}`}>{code.trim()}</code>
      </pre>
      <Button
        size="icon"
        variant="ghost"
        className="absolute top-2 right-2 h-8 w-8 opacity-0 group-hover:opacity-100 transition-opacity"
        onClick={copyToClipboard}
      >
        {hasCopied ? <Check className="w-4 h-4 text-green-500" /> : <Copy className="w-4 h-4" />}
        <span className="sr-only">Copy code</span>
      </Button>
    </div>
  );
};

const InfoBlock = ({children}: {children: React.ReactNode}) => (
  <div className="p-4 border border-dashed rounded-lg bg-secondary/30 text-sm">
    {children}
  </div>
);


// --- Basic Auth ---
const basicClientCode = `
const username = 'admin';
const password = 'password';

// Base64 encode the credentials
const encodedCredentials = btoa(\`\${username}:\${password}\`);

// The header should look like: "Authorization: Basic YWRtaW46cGFzc3dvcmQ="
const headers = {
  'Authorization': \`Basic \${encodedCredentials}\`
};

fetch('https://api.example.com/protected-resource', {
  method: 'GET',
  headers: headers
})
.then(response => {
  if (response.status === 401) {
    throw new Error('Authentication failed!');
  }
  if (!response.ok) {
    throw new Error('Network response was not ok');
  }
  return response.json();
})
.then(data => {
  console.log('Access granted:', data);
})
.catch(error => {
  console.error('Error:', error);
});
`;

const basicServerCode = `
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import secrets

app = FastAPI()
security = HTTPBasic()

def get_current_username(credentials: HTTPBasicCredentials = Depends(security)):
    """A dependency to verify username and password."""
    # In a real app, you'd fetch user from a database and hash/verify passwords
    correct_username = "admin"
    correct_password = "password"

    # Use secrets.compare_digest to prevent timing attacks
    is_correct_username = secrets.compare_digest(credentials.username, correct_username)
    is_correct_password = secrets.compare_digest(credentials.password, correct_password)

    if not (is_correct_username and is_correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

@app.get("/protected-resource")
def get_protected_resource(username: str = Depends(get_current_username)):
    """An example protected endpoint."""
    return {"message": f"Welcome {username}! You have access to this resource."}
`;


export function BasicAuthSetup() {
  return (
    <div className="space-y-4">
      <p>
        Here’s how you can implement Basic Authentication on the server with Python's FastAPI and how to make a request from a JavaScript client.
      </p>
      <Tabs defaultValue="client" className="w-full">
        <TabsList className="grid w-full grid-cols-2">
          <TabsTrigger value="client">Client (JavaScript)</TabsTrigger>
          <TabsTrigger value="server">Server (FastAPI)</TabsTrigger>
        </TabsList>
        <TabsContent value="client">
          <CodeBlock code={basicClientCode} lang="javascript" />
        </TabsContent>
        <TabsContent value="server">
          <CodeBlock code={basicServerCode} lang="python" />
        </TabsContent>
      </Tabs>
    </div>
  );
}

// --- API Key Auth ---

const apiKeyClientCode = `
const API_KEY = 'your_super_secret_api_key';

const headers = {
  'X-API-Key': API_KEY
};

fetch('https://api.example.com/items', {
  method: 'GET',
  headers: headers
})
.then(response => {
  if (response.status === 401 || response.status === 403) {
    throw new Error('API Key is invalid or missing!');
  }
  return response.json();
})
.then(data => {
  console.log('Successfully fetched data:', data);
})
.catch(error => {
  console.error('Error:', error);
});
`;

const apiKeyServerCode = `
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import APIKeyHeader
import secrets

app = FastAPI()

API_KEY_NAME = "X-API-Key"
# In a real app, this would be a dictionary of valid keys and owners
VALID_API_KEYS = {"your_super_secret_api_key": "owner1"}

api_key_header_scheme = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

async def get_api_key(api_key_header: str = Depends(api_key_header_scheme)):
    """Dependency to validate the API Key."""
    if not api_key_header or not secrets.compare_digest(api_key_header, list(VALID_API_KEYS.keys())[0]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
        )
    return api_key_header

@app.get("/items", dependencies=[Depends(get_api_key)])
async def read_items():
    """An endpoint protected by an API Key."""
    return [{"name": "Item Foo"}, {"name": "Item Bar"}]
`;

export function ApiKeyAuthSetup() {
  return (
    <div className="space-y-4">
      <p>
        API Key authentication identifies the client application, not a specific user. The client sends a key in a header, which the server validates.
      </p>
      <Tabs defaultValue="client" className="w-full">
        <TabsList className="grid w-full grid-cols-2">
          <TabsTrigger value="client">Client (JavaScript)</TabsTrigger>
          <TabsTrigger value="server">Server (FastAPI)</TabsTrigger>
        </TabsList>
        <TabsContent value="client">
          <CodeBlock code={apiKeyClientCode} lang="javascript" />
        </TabsContent>
        <TabsContent value="server">
          <CodeBlock code={apiKeyServerCode} lang="python" />
        </TabsContent>
      </Tabs>
    </div>
  );
}

// --- JWT Auth ---

const jwtClientCode = `
// Step 1: Client authenticates (e.g., with username/password) to get a token.
// This is usually done once per session.
async function loginAndGetToken(username, password) {
  const response = await fetch('https://api.example.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    // FastAPI's OAuth2PasswordRequestForm expects form data
    body: new URLSearchParams({
        'username': username,
        'password': password
    })
  });
  if (!response.ok) {
      throw new Error('Login failed');
  }
  const data = await response.json();
  return data.access_token;
}

// Step 2: Client uses the received token to access protected resources.
async function getProtectedData(token) {
  const headers = {
    'Authorization': \`Bearer \${token}\`
  };

  const response = await fetch('https://api.example.com/users/me', {
    method: 'GET',
    headers: headers
  });
  
  const data = await response.json();
  console.log('Protected data:', data);
  return data;
}

// Example usage:
loginAndGetToken('testuser', 'testpass').then(token => {
  if (token) {
    getProtectedData(token);
  }
}).catch(console.error);
`;

const jwtServerCode = `
# You would need to install python-jose, passlib, and python-multipart
# pip install "python-jose[cryptography]" "passlib[bcrypt]" "python-multipart"
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from datetime import datetime, timedelta, timezone
from passlib.context import CryptContext

# --- Configuration ---
# In a real app, load from environment variables
SECRET_KEY = "a_very_secret_key_for_jwt"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI()

# --- Hashing & User DB ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
# Fake user database
fake_users_db = {
    "testuser": {
        "username": "testuser",
        "full_name": "Test User",
        "email": "test@example.com",
        "hashed_password": pwd_context.hash("testpass"),
        "disabled": False,
    }
}

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# --- Helper Functions ---
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# --- Dependencies ---
async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = fake_users_db.get(username)
    if user is None or user["disabled"]:
        raise credentials_exception
    return user

# --- Endpoints ---
@app.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = fake_users_db.get(form_data.username)
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["username"]}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/users/me")
async def read_users_me(current_user: dict = Depends(get_current_user)):
    return {"username": current_user["username"], "email": current_user["email"]}
`;

export function JwtAuthSetup() {
  return (
    <div className="space-y-4">
      <p>
        JWT authentication is a stateless process. The client first authenticates to get a token, then includes that token in the `Authorization` header for all subsequent protected requests.
      </p>
      <Tabs defaultValue="client" className="w-full">
        <TabsList className="grid w-full grid-cols-2">
          <TabsTrigger value="client">Client (JavaScript)</TabsTrigger>
          <TabsTrigger value="server">Server (FastAPI)</TabsTrigger>
        </TabsList>
        <TabsContent value="client">
          <CodeBlock code={jwtClientCode} lang="javascript" />
        </TabsContent>
        <TabsContent value="server">
          <CodeBlock code={jwtServerCode} lang="python" />
        </TabsContent>
      </Tabs>
    </div>
  );
}

// --- Bearer Token Auth ---

const bearerClientCode = `
const bearerToken = 'your_retrieved_bearer_token'; // e.g., from a login endpoint

const headers = {
  'Authorization': \`Bearer \${bearerToken}\`
};

fetch('https://api.example.com/protected-data', {
  method: 'GET',
  headers: headers
})
.then(response => {
  if (response.status === 401) {
    throw new Error('Token is invalid or expired!');
  }
  return response.json();
})
.then(data => {
  console.log('Successfully accessed data:', data);
})
.catch(error => {
  console.error('Error:', error);
});
`;

const bearerServerCode = `
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

app = FastAPI()

# This is a simplified dependency, often paired with another function
# that decodes the token (if JWT) or looks it up in a database.
security = HTTPBearer()

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """A dependency to validate the Bearer Token."""
    # In a real app, you would validate the token.
    # 1. If it's a JWT, decode and verify its signature and claims.
    # 2. If it's an opaque token, look it up in a database/cache.
    
    # For this demo, we'll accept any token that isn't "invalid".
    if credentials.scheme != "Bearer" or credentials.credentials == "invalid_token":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    # In a real app, you would return the user object associated with the token.
    return {"user_id": "user123"}

@app.get("/protected-data")
async def read_protected_data(current_user: dict = Depends(get_current_user)):
    """An endpoint protected by a Bearer Token."""
    return {"message": f"Welcome, you have access!", "user_info": current_user}
`;

export function BearerTokenAuthSetup() {
  return (
    <div className="space-y-4">
      <p>
        Bearer Token authentication is a common HTTP authentication scheme. The client sends a token in the `Authorization` header with the `Bearer` prefix. This example shows the basic structure. The token itself could be a JWT or an opaque string.
      </p>
      <Tabs defaultValue="client" className="w-full">
        <TabsList className="grid w-full grid-cols-2">
          <TabsTrigger value="client">Client (JavaScript)</TabsTrigger>
          <TabsTrigger value="server">Server (FastAPI)</TabsTrigger>
        </TabsList>
        <TabsContent value="client">
          <CodeBlock code={bearerClientCode} lang="javascript" />
        </TabsContent>
        <TabsContent value="server">
          <CodeBlock code={bearerServerCode} lang="python" />
        </TabsContent>
      </Tabs>
    </div>
  );
}


// --- Session-Based Auth ---

const sessionClientCode = `
// Client-side code for session-based auth is often simple, as the browser handles cookies automatically.

// 1. Login request (sends username/password, receives a session cookie in response)
fetch('/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ username: 'user', password: 'password' })
}).then(res => {
  if (res.ok) {
    console.log('Login successful, session cookie set by browser.');
    // The browser will now automatically send the session cookie on subsequent requests to the same domain.
  }
});

// 2. Subsequent request to a protected route
fetch('/profile').then(async res => {
  if (res.ok) {
    const data = await res.json();
    console.log('Profile data:', data);
  } else {
    console.error('Access denied. Not logged in?');
  }
});
`;

const sessionServerCode = `
from fastapi import FastAPI, Response, Request, Depends, HTTPException, status
import uuid

app = FastAPI()

# In a real application, use a persistent store like Redis or a database.
# This is a simple in-memory dictionary for demonstration purposes.
sessions = {}
users = {"user": {"password": "password", "name": "Test User"}}

@app.post("/login")
async def login(response: Response, request: Request):
    form = await request.json()
    username = form.get("username")
    password = form.get("password")
    
    user = users.get(username)
    if not user or user["password"] != password:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
        
    session_id = str(uuid.uuid4())
    sessions[session_id] = username # Store user identifier in session
    
    # Set the session ID in an HttpOnly cookie
    response.set_cookie(key="session_id", value=session_id, httponly=True)
    return {"message": "Login successful"}

async def get_current_user(request: Request):
    session_id = request.cookies.get("session_id")
    if not session_id or session_id not in sessions:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    
    username = sessions[session_id]
    return users.get(username)

@app.get("/profile")
async def read_profile(current_user: dict = Depends(get_current_user)):
    return {"user": current_user}
`;


export function SessionAuthSetup() {
  return (
    <div className="space-y-4">
      <p>
        Session-based authentication is stateful. The server creates a session on login, stores it, and gives the client a cookie with a session ID. The browser automatically sends this cookie on subsequent requests.
      </p>
      <Tabs defaultValue="server" className="w-full">
        <TabsList className="grid w-full grid-cols-2">
          <TabsTrigger value="client">Client (JavaScript)</TabsTrigger>
          <TabsTrigger value="server">Server (FastAPI)</TabsTrigger>
        </TabsList>
        <TabsContent value="client">
           <InfoBlock>
            <p>On the client-side, there's very little to do for basic session authentication. The browser automatically manages sending and receiving cookies for the same domain.</p>
          </InfoBlock>
          <CodeBlock code={sessionClientCode} lang="javascript" />
        </TabsContent>
        <TabsContent value="server">
          <CodeBlock code={sessionServerCode} lang="python" />
        </TabsContent>
      </Tabs>
    </div>
  );
}

// --- HMAC Auth ---

const hmacClientCode = `
# This client example is in Python, as HMAC is common for server-to-server calls.
import hmac
import hashlib
import time
import requests
import json

SECRET_KEY = b'your-shared-secret'
API_URL = 'http://127.0.0.1:8000/webhook'

def generate_signature(body, timestamp):
    message = f"{timestamp}.{body}".encode('utf-8')
    signature = hmac.new(SECRET_KEY, message, hashlib.sha256).hexdigest()
    return signature

def send_request():
    payload = {"event": "user.created", "user_id": "12345"}
    body_str = json.dumps(payload, separators=(',', ':')) # Compact JSON
    timestamp = str(int(time.time()))
    
    signature = generate_signature(body_str, timestamp)
    
    headers = {
        'Content-Type': 'application/json',
        'X-Signature-Timestamp': timestamp,
        'X-Signature-SHA256': f"sha256={signature}"
    }
    
    response = requests.post(API_URL, data=body_str, headers=headers)
    
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.json()}")

if __name__ == "__main__":
    send_request()
`;

const hmacServerCode = `
from fastapi import FastAPI, Request, Header, HTTPException, status
import hmac
import hashlib
import time

app = FastAPI()

# This should be a securely stored secret, shared with the client.
SECRET_KEY = b'your-shared-secret'
# Set a tolerance for how old a request can be (in seconds)
TIMESTAMP_TOLERANCE = 300 # 5 minutes

async def verify_signature(request: Request, x_signature_timestamp: str = Header(None), x_signature_sha256: str = Header(None)):
    if not x_signature_timestamp or not x_signature_sha256:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing signature headers")

    # 1. Check the timestamp to prevent replay attacks
    try:
        timestamp = int(x_signature_timestamp)
        if time.time() - timestamp > TIMESTAMP_TOLERANCE:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Timestamp expired")
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid timestamp")

    # 2. Verify the signature
    body = await request.body()
    message = f"{x_signature_timestamp}.".encode('utf-8') + body
    
    expected_signature_bytes = hmac.new(SECRET_KEY, message, hashlib.sha256).digest()
    
    try:
        # header format is "sha256=..."
        received_signature_bytes = bytes.fromhex(x_signature_sha256.split('=')[1])
    except (ValueError, IndexError):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid signature format")

    if not hmac.compare_digest(expected_signature_bytes, received_signature_bytes):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid signature")

@app.post("/webhook")
async def handle_webhook(request: Request):
    # The dependency implicitly calls verify_signature
    await verify_signature(request, request.headers.get('x-signature-timestamp'), request.headers.get('x-signature-sha256'))
    
    payload = await request.json()
    # Process the valid webhook payload
    print("Received valid webhook:", payload)
    return {"status": "success", "received": payload}
`;

export function HmacAuthSetup() {
  return (
    <div className="space-y-4">
      <p>
        HMAC is used to verify message integrity and authenticity, common for securing webhooks. A shared secret is used to create a signature for the request body, which the server then verifies.
      </p>
      <Tabs defaultValue="server" className="w-full">
        <TabsList className="grid w-full grid-cols-2">
          <TabsTrigger value="client">Client (Python)</TabsTrigger>
          <TabsTrigger value="server">Server (FastAPI)</TabsTrigger>
        </TabsList>
        <TabsContent value="client">
          <CodeBlock code={hmacClientCode} lang="python" />
        </TabsContent>
        <TabsContent value="server">
          <CodeBlock code={hmacServerCode} lang="python" />
        </TabsContent>
      </Tabs>
    </div>
  );
}

// --- OTP/TOTP Auth ---

const otpServerCode = `
# You would need to install pyotp and qrcode
# pip install pyotp qrcode
import pyotp
import qrcode
import io
from starlette.responses import StreamingResponse
from fastapi import FastAPI

app = FastAPI()

# In a real app, store this secret per-user in your database
# and associate it with the user's account.
# For demo, we use a fixed secret.
USER_SECRET = pyotp.random_base32()

@app.get("/generate-otp-setup")
def generate_otp_setup():
    """
    Generates a provisioning URI and a QR code for setting up an authenticator app.
    """
    # The provisioning URI includes the issuer name, account name, and the secret
    provisioning_uri = pyotp.totp.TOTP(USER_SECRET).provisioning_uri(
        name='user@example.com', 
        issuer_name='AuthShowcase App'
    )
    
    return {"secret": USER_SECRET, "provisioning_uri": provisioning_uri}

@app.get("/generate-qr-code")
def generate_qr_code():
    provisioning_uri = pyotp.totp.TOTP(USER_SECRET).provisioning_uri(name='user@example.com', issuer_name='AuthShowcase App')
    
    img = qrcode.make(provisioning_uri)
    buf = io.BytesIO()
    img.save(buf)
    buf.seek(0)
    
    return StreamingResponse(buf, media_type="image/png")


@app.post("/verify-otp")
def verify_otp(otp_code: str):
    """
    Verifies a Time-based One-Time Password (TOTP).
    """
    totp = pyotp.TOTP(USER_SECRET)
    
    # Verify the code. The for_time parameter can be used to check against previous intervals.
    is_valid = totp.verify(otp_code)
    
    if is_valid:
        return {"status": "success", "message": "OTP is valid."}
    else:
        return {"status": "error", "message": "OTP is invalid."}

`;

export function OtpAuthSetup() {
  return (
    <div className="space-y-4">
      <p>
        Time-based One-Time Passwords (TOTP) are a common second factor for MFA. A shared secret is used by the client (authenticator app) and server to generate a short-lived code.
      </p>
       <InfoBlock>
        <p>The client for OTP is typically a mobile authenticator app (like Google Authenticator or Authy). The user scans a QR code provided by the server to set it up. There is no special JavaScript client code needed other than a simple form to submit the 6-digit code.</p>
      </InfoBlock>
      <CodeBlock code={otpServerCode} lang="python" />
    </div>
  );
}


// --- WebAuthn Auth ---

const webauthnClientCode = `
// --- 1. Registration ---
async function register() {
    // Get challenge from the server
    const createOptions = await fetch('/register-begin').then(r => r.json());

    // Need to decode base64url fields for the API
    createOptions.challenge = base64url.decode(createOptions.challenge);
    createOptions.user.id = base64url.decode(createOptions.user.id);
    
    // Prompt browser/OS to create a new credential
    const credential = await navigator.credentials.create({ publicKey: createOptions });
    
    // Send the new credential back to the server to be stored
    await fetch('/register-finish', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            id: credential.id,
            rawId: base64url.encode(credential.rawId),
            response: {
                clientDataJSON: base64url.encode(credential.response.clientDataJSON),
                attestationObject: base64url.encode(credential.response.attestationObject),
            },
            type: credential.type
        })
    });
}

// --- 2. Login ---
async function login() {
    // Get challenge from the server
    const getOptions = await fetch('/login-begin').then(r => r.json());

    getOptions.challenge = base64url.decode(getOptions.challenge);
    
    // Prompt to use an existing credential
    const assertion = await navigator.credentials.get({ publicKey: getOptions });

    // Send assertion to the server for verification
    await fetch('/login-finish', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            id: assertion.id,
            rawId: base64url.encode(assertion.rawId),
            response: {
                clientDataJSON: base64url.encode(assertion.response.clientDataJSON),
                authenticatorData: base64url.encode(assertion.response.authenticatorData),
                signature: base64url.encode(assertion.response.signature),
                userHandle: assertion.response.userHandle ? base64url.encode(assertion.response.userHandle) : null,
            },
            type: assertion.type
        })
    });
}

// (Note: base64url is a helper library to handle encoding, not shown here)
`;

const webauthnServerCode = `
# You would need a library to handle the complexity of WebAuthn
# pip install webauthn
from fastapi import FastAPI, Request
from webauthn import generate_registration_options, verify_registration_response, \
    generate_authentication_options, verify_authentication_response
from webauthn.helpers.structs import RegistrationCredential, AuthenticationCredential

app = FastAPI()

# In a real app, these would be in your database
users = {} # { username: { id, credentials } }
RP_ID = "localhost" # Relying Party ID (your domain)
RP_NAME = "AuthShowcase"
ORIGIN = "http://localhost:3000"

@app.get("/register-begin")
async def register_begin(username: str):
    if username in users:
        # Handle user already exists
        pass

    user_id = f"user_{username}"
    
    options = generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_id=user_id,
        user_name=username,
    )
    
    # Store challenge temporarily, e.g. in session
    # session['challenge'] = options.challenge
    return options

@app.post("/register-finish")
async def register_finish(request: Request):
    body = await request.json()
    # challenge = session.pop('challenge') # retrieve challenge
    
    # verification = verify_registration_response(
    #     credential=RegistrationCredential.parse_raw(body),
    #     expected_challenge=challenge,
    #     expected_origin=ORIGIN,
    #     expected_rp_id=RP_ID,
    # )
    
    # Store verification.credential_public_key and verification.credential_id in your user DB
    return {"verified": True} # Simplified

@app.get("/login-begin")
async def login_begin(username: str):
    # user_credentials = users[username]['credentials']
    options = generate_authentication_options(
        rp_id=RP_ID,
        # allow_credentials=user_credentials
    )
    # session['challenge'] = options.challenge
    return options

@app.post("/login-finish")
async def login_finish(request: Request):
    body = await request.json()
    # challenge = session.pop('challenge')
    # user_handle = users[username]['id']
    # user_credentials = users[username]['credentials']

    # verification = verify_authentication_response(
    #    credential=AuthenticationCredential.parse_raw(body),
    #    expected_challenge=challenge,
    #    expected_rp_id=RP_ID,
    #    expected_origin=ORIGIN,
    #    credential_public_key=..., # From DB
    #    credential_current_sign_count=... # From DB
    # )
    
    # Update sign count in DB
    return {"verified": True} # Simplified
`;

export function WebAuthnSetup() {
  return (
    <div className="space-y-4">
      <p>
        WebAuthn provides strong, passwordless, and phishing-resistant authentication using public-key cryptography. The user's private key never leaves their device.
      </p>
      <InfoBlock>
        WebAuthn is a complex protocol. The code snippets below are illustrative of the main API calls and server-side steps. A production implementation requires careful handling of challenges, credential storage, and various edge cases.
      </InfoBlock>
      <Tabs defaultValue="client" className="w-full">
        <TabsList className="grid w-full grid-cols-2">
          <TabsTrigger value="client">Client (JavaScript)</TabsTrigger>
          <TabsTrigger value="server">Server (FastAPI)</TabsTrigger>
        </TabsList>
        <TabsContent value="client">
          <CodeBlock code={webauthnClientCode} lang="javascript" />
        </TabsContent>
        <TabsContent value="server">
          <CodeBlock code={webauthnServerCode} lang="python" />
        </TabsContent>
      </Tabs>
    </div>
  );
}

// --- LDAP Auth ---

const ldapServerCode = `
# You would need to install python-ldap
# pip install python-ldap
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import ldap

app = FastAPI()
security = HTTPBasic()

# --- LDAP Configuration ---
# In a real app, load from environment variables
LDAP_SERVER = "ldap://your-ldap-server.com"
# The DN pattern for your users. {username} will be replaced.
USER_DN_PATTERN = "uid={username},ou=people,dc=example,dc=org"

def authenticate_ldap_user(credentials: HTTPBasicCredentials = Depends(security)):
    """A dependency to authenticate a user against an LDAP server."""
    username = credentials.username
    password = credentials.password
    
    user_dn = USER_DN_PATTERN.format(username=username)
    
    try:
        # Initialize connection to LDAP server. 
        # Use ldap.initialize("ldaps://...") for LDAP over SSL
        conn = ldap.initialize(LDAP_SERVER)
        # Set protocol version
        conn.protocol_version = ldap.VERSION3
        
        # Attempt to bind (authenticate) with the user's credentials.
        # This will raise an exception if credentials are invalid.
        conn.simple_bind_s(user_dn, password)
        
        print(f"Successfully authenticated user: {username}")
        # You could optionally search for user attributes here
        
    except ldap.INVALID_CREDENTIALS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    except ldap.SERVER_DOWN:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="LDAP server is not reachable",
        )
    finally:
        # Always unbind to close the connection
        if 'conn' in locals() and conn:
            conn.unbind_s()
            
    return username

@app.get("/corporate-resource")
def get_corporate_resource(username: str = Depends(authenticate_ldap_user)):
    return {"message": f"Welcome {username}, you have accessed the resource via LDAP."}
`;

export function LdapAuthSetup() {
  return (
    <div className="space-y-4">
      <p>
        LDAP authentication validates credentials against a central directory service like Active Directory. This is a server-side integration. The client typically uses a simple method like Basic Auth to send credentials to the application server, which then performs the LDAP `bind` operation.
      </p>
      <InfoBlock>
        There is no special client-side JavaScript code for LDAP itself. The client communicates with your application server, not the LDAP server. The example below shows a FastAPI server that uses LDAP as its authentication backend.
      </InfoBlock>
      <CodeBlock code={ldapServerCode} lang="python" />
    </div>
  );
}

// --- Informative Setups (OAuth2, OIDC, SAML, etc.) ---

export function OAuth2Setup() {
  return (
    <InfoBlock>
      <div className="space-y-3">
        <p className="font-semibold">OAuth2 is a complex authorization framework, not a simple implementation.</p>
        <p>A full code example requires setting up an application with a specific provider (like Google, GitHub, etc.), handling redirects, managing client secrets, and exchanging authorization codes for tokens.</p>
        <p>The core flow for a web app is:</p>
        <ol className="list-decimal list-inside space-y-2 pl-2">
          <li><strong>Redirect:</strong> Your app redirects the user to the OAuth provider's login page with your client ID and requested scopes.</li>
          <li><strong>Consent:</strong> The user logs in and grants your application permission.</li>
          <li><strong>Callback:</strong> The provider redirects the user back to your app with a temporary authorization code.</li>
          <li><strong>Token Exchange:</strong> Your server sends the authorization code and your client secret to the provider to get an access token.</li>
          <li><strong>API Calls:</strong> Your server uses the access token to make API calls on behalf of the user.</li>
        </ol>
        <p>For a complete implementation, it is highly recommended to use a trusted library like <code className="font-code bg-muted p-1 rounded">Authlib</code> for Python or <code className="font-code bg-muted p-1 rounded">next-auth</code> for Next.js.</p>
      </div>
    </InfoBlock>
  );
}

export function OidcSetup() {
  return (
    <InfoBlock>
      <div className="space-y-3">
        <p className="font-semibold">OpenID Connect is an identity layer built on top of OAuth2.</p>
        <p>The implementation follows the same flow as OAuth2, but with a key difference: you request the <code className="font-code bg-muted p-1 rounded">openid</code> scope. In return for the authorization code, the provider gives you both an <code className="font-code bg-muted p-1 rounded">access_token</code> (for API access) and an <code className="font-code bg-muted p-1 rounded">id_token</code> (a JWT containing user identity information).</p>
        <p>Your application's most critical task is to <strong className="text-destructive">rigorously validate the ID token's signature, issuer, audience, and expiration</strong> before trusting its contents to log the user in.</p>
        <p>Due to its complexity, using a certified OIDC library for your language/framework is essential for security.</p>
      </div>
    </InfoBlock>
  );
}

export function SamlSetup() {
  return (
    <InfoBlock>
      <div className="space-y-3">
        <p className="font-semibold">SAML is a complex XML-based standard for enterprise SSO.</p>
        <p>A typical SAML flow involves three parties: the user, a Service Provider (SP, your app), and an Identity Provider (IdP, e.g., Okta, ADFS). The flow is redirect-based and results in the IdP sending a digitally signed XML document (a SAML Assertion) to your application.</p>
        <p>Implementing SAML from scratch is not recommended. You must use a robust, well-maintained library (like <code className="font-code bg-muted p-1 rounded">python3-saml</code> for Python) to handle the parsing and, most importantly, the security validation of the XML assertion. Misconfiguration can lead to severe vulnerabilities.</p>
      </div>
    </InfoBlock>
  );
}

export function CertificateAuthSetup() {
  return (
    <InfoBlock>
      <div className="space-y-3">
        <p className="font-semibold">Client-side Certificate (mTLS) authentication is configured at the web server/load balancer level, not directly in the application code.</p>
        <p>You would configure your web server (like Nginx, Apache) or API Gateway to:</p>
        <ol className="list-decimal list-inside space-y-2 pl-2">
          <li>Request a client certificate during the TLS handshake.</li>
          <li>Verify that the client certificate is signed by a trusted Certificate Authority (CA).</li>
          <li>(Optional) Pass the details of the validated certificate (like the subject or distinguished name) to the backend application via HTTP headers.</li>
        </ol>
        <p>The FastAPI application would then trust these headers (from the secure proxy) to identify the client, rather than implementing the TLS handshake itself.</p>
      </div>
    </InfoBlock>
  );
}

export function MfaSetup() {
  return (
    <InfoBlock>
      <div className="space-y-3">
        <p className="font-semibold">Multi-Factor Authentication (MFA) is a process, not a single protocol.</p>
        <p>It involves combining two or more different authentication methods. A common implementation is:</p>
        <ol className="list-decimal list-inside space-y-2 pl-2">
            <li><strong>Factor 1:</strong> The user provides something they know, like a password.</li>
            <li><strong>Factor 2:</strong> After the first factor is verified, the user must provide something they have, like an OTP from an authenticator app.</li>
        </ol>
        <p>The code for MFA is therefore a combination of other authentication methods. See the <strong>One-Time Password (OTP)</strong> guide for an example of a common second factor.</p>
      </div>
    </InfoBlock>
  );
}
