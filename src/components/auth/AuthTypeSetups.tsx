
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
