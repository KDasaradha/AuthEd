'use client'
import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert, AlertDescription, AlertTitle } from '../ui/alert';
import { Loader2 } from 'lucide-react';

export function InteractiveDemo() {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [token, setToken] = useState('');
    const [protectedData, setProtectedData] = useState('');
    const [error, setError] = useState('');
    const [isLoading, setIsLoading] = useState(false);

    const handleLogin = () => {
        setIsLoading(true);
        setError('');
        setProtectedData('');
        setToken('');
        setTimeout(() => {
            if (username.toLowerCase() === 'admin' && password === 'password') {
                setToken('mock_jwt_token_for_demo.' + Math.random().toString(36).substring(2));
            } else {
                setError('Invalid credentials. Try username "admin" and password "password".');
            }
            setIsLoading(false);
        }, 500);
    };

    const handleProtected = () => {
        setIsLoading(true);
        setError('');
        setProtectedData('');
        setTimeout(() => {
            if (token) {
                setProtectedData('Access Granted: Welcome, Admin! Here is your protected data.');
            } else {
                setError('Access Denied: You must log in to get a token first.');
            }
            setIsLoading(false);
        }, 500);
    }

    return (
        <Card>
            <CardHeader>
                <CardTitle>Interactive Demo</CardTitle>
                <CardDescription>This is a mock demo. No real API calls are made.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
                 <div className="space-y-2">
                    <Input placeholder="Username (try 'admin')" value={username} onChange={e => setUsername(e.target.value)} disabled={isLoading} />
                    <Input type="password" placeholder="Password (try 'password')" value={password} onChange={e => setPassword(e.target.value)} disabled={isLoading} />
                    <Button onClick={handleLogin} disabled={isLoading}>
                      {isLoading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                      Log in
                    </Button>
                 </div>
                 
                 <div>
                    <Button onClick={handleProtected} disabled={isLoading}>
                      {isLoading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                      Access Protected Resource
                    </Button>
                 </div>
                 
                {token && (
                    <Alert>
                        <AlertTitle className="text-primary">Token Received</AlertTitle>
                        <AlertDescription className="break-all text-xs text-muted-foreground">{token}</AlertDescription>
                    </Alert>
                )}
                {protectedData && (
                    <Alert>
                        <AlertTitle className='text-primary'>Success!</AlertTitle>
                        <AlertDescription className="text-muted-foreground">{protectedData}</AlertDescription>
                    </Alert>
                )}
                 {error && (
                    <Alert variant="destructive">
                        <AlertTitle>Error</AlertTitle>
                        <AlertDescription>{error}</AlertDescription>
                    </Alert>
                )}
            </CardContent>
        </Card>
    );
};
