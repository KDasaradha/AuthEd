'use client'
import { useState, useRef, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardDescription, CardHeader, CardTitle, CardFooter } from '@/components/ui/card';
import { Alert, AlertDescription, AlertTitle } from '../ui/alert';
import { Loader2, Terminal } from 'lucide-react';
import { ScrollArea } from '../ui/scroll-area';

export function InteractiveDemo() {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [token, setToken] = useState('');
    const [protectedData, setProtectedData] = useState('');
    const [error, setError] = useState('');
    const [log, setLog] = useState<string[]>([]);
    const [isLoading, setIsLoading] = useState(false);
    const logContainerRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (logContainerRef.current) {
            logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight;
        }
    }, [log]);

    const clearState = () => {
        setToken('');
        setProtectedData('');
        setError('');
        setLog([]);
    }

    const addLog = (message: string) => {
        setLog(prev => [...prev, `[${new Date().toLocaleTimeString()}] ${message}`]);
    }

    const handleLogin = () => {
        setIsLoading(true);
        clearState();
        
        addLog("▶️ Starting authentication attempt...");
        setTimeout(() => {
            addLog(`Attempting login with user: '${username}'...`);
            if (username.toLowerCase() === 'admin' && password === 'password') {
                setTimeout(() => {
                    addLog("✅ Server: Credentials validated successfully.");
                    const mockToken = 'mock_jwt_token_for_demo.' + Math.random().toString(36).substring(2);
                    setTimeout(() => {
                        addLog("✅ Server: Generated new token.");
                        setToken(mockToken);
                        setIsLoading(false);
                    }, 500);
                }, 800);
            } else {
                setTimeout(() => {
                    addLog("❌ Server: Invalid credentials provided.");
                    setError('Invalid credentials. Try username "admin" and password "password".');
                    setIsLoading(false);
                }, 800);
            }
        }, 500);
    };

    const handleProtected = () => {
        setIsLoading(true);
        setProtectedData('');
        setError('');

        addLog("▶️ Attempting to access protected resource...");
        setTimeout(() => {
            if (token) {
                addLog(`Sending request with token: ${token.substring(0, 30)}...`);
                setTimeout(() => {
                    addLog("✅ Server: Token is valid. Granting access.");
                    setTimeout(() => {
                         addLog("✅ Server: Sending protected data to client.");
                        setProtectedData('Access Granted: Welcome, Admin! This is your top-secret data.');
                        setIsLoading(false);
                    }, 500)
                }, 800);
            } else {
                 addLog("❌ Client: No token found. Aborting request.");
                setError('Access Denied: You must log in to get a token first.');
                setIsLoading(false);
            }
        }, 500);
    }

    return (
        <Card>
            <CardHeader>
                <CardTitle>Interactive Demo</CardTitle>
                <CardDescription>
                    Experience a simulated authentication flow. Use the mock credentials below and watch the log to see how the client and server interact.
                </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
                 <div className="p-4 border rounded-lg bg-secondary/30 space-y-2">
                    <p className="text-sm text-muted-foreground">Try these mock credentials:</p>
                    <Input placeholder="Username (use 'admin')" value={username} onChange={e => setUsername(e.target.value)} disabled={isLoading} />
                    <Input type="password" placeholder="Password (use 'password')" value={password} onChange={e => setPassword(e.target.value)} disabled={isLoading} />
                 </div>
                 
                 <div className="flex gap-2">
                    <Button onClick={handleLogin} disabled={isLoading} className="w-full">
                      {isLoading && !token ? <Loader2 className="animate-spin" /> : '1. Get Token'}
                    </Button>
                    <Button onClick={handleProtected} disabled={isLoading || !token} variant="outline" className="w-full">
                      {isLoading && token ? <Loader2 className="animate-spin" /> : '2. Access Resource'}
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
                        <AlertTitle className='text-primary'>Protected Data</AlertTitle>
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
            <CardFooter className="flex-col items-start gap-2 pt-4 border-t">
                <div className="flex items-center gap-2 text-sm font-semibold">
                    <Terminal className="w-4 h-4" />
                    <span>Live Log</span>
                </div>
                <ScrollArea className="h-40 w-full rounded-md bg-muted/50 p-2">
                    <div ref={logContainerRef} className="text-xs text-muted-foreground space-y-1">
                        {log.length > 0 ? log.map((entry, i) => <p key={i} className="font-mono">{entry}</p>) : <p className="font-mono">Log is empty. Click a button to start.</p>}
                    </div>
                </ScrollArea>
            </CardFooter>
        </Card>
    );
};