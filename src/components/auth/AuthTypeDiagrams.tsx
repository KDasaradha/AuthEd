import React from 'react';

export function OAuth2Diagram() {
    return (
    <svg width="100%" viewBox="0 0 800 400" xmlns="http://www.w3.org/2000/svg" className="bg-gray-50 rounded dark:bg-card">
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
}

export function BasicAuthDiagram() {
    return (
    <svg width="100%" viewBox="0 0 800 300" xmlns="http://www.w3.org/2000/svg" className="bg-gray-50 rounded dark:bg-card">
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
}

export function ApiKeyDiagram() {
    return (
    <svg width="100%" viewBox="0 0 800 300" xmlns="http://www.w3.org/2000/svg" className="bg-gray-50 rounded dark:bg-card">
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
}

export function GenericAuthDiagram() {
    return (
    <svg width="100%" viewBox="0 0 800 300" xmlns="http://www.w3.org/2000/svg" className="bg-gray-50 rounded dark:bg-card">
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
}
