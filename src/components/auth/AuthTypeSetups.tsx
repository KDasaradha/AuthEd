
'use client';

import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';

const CodeBlock = ({ code, lang }: { code: string; lang: string }) => (
  <pre className="p-4 bg-muted rounded-md text-sm overflow-x-auto font-code w-full">
    <code className={`language-${lang}`}>{code.trim()}</code>
  </pre>
);

const clientCode = `
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

const serverCode = `
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
          <CodeBlock code={clientCode} lang="javascript" />
        </TabsContent>
        <TabsContent value="server">
          <CodeBlock code={serverCode} lang="python" />
        </TabsContent>
      </Tabs>
    </div>
  );
}
