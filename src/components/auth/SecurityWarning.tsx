import { AlertTriangle } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "../ui/alert";

export function SecurityWarning({ children }: { children: React.ReactNode }) {
    return (
        <Alert variant="destructive">
            <AlertTriangle className="h-4 w-4" />
            <AlertTitle>Security Warning</AlertTitle>
            <AlertDescription>
                {children}
            </AlertDescription>
        </Alert>
    );
}
