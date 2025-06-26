import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { AuthFlowDiagram } from "@/components/auth/AuthFlowDiagram";
import { InteractiveDemo } from "@/components/auth/InteractiveDemo";
import type { AuthType } from "@/lib/types";
import { CheckCircle2, XCircle } from "lucide-react";
import { HttpExamples } from "@/components/auth/HttpExamples";
import { SecurityWarning } from "@/components/auth/SecurityWarning";

type AuthTypeDetailPageProps = {
  authType: AuthType;
};

export function AuthTypeDetailPage({ authType }: AuthTypeDetailPageProps) {
  const SetupComponent = authType.setupInstructions;
  const DiagramComponent = authType.diagram;

  return (
    <div className="space-y-8">
      <header>
        <h1 className="text-4xl md:text-5xl font-bold tracking-tighter mb-2">{authType.name}</h1>
        <p className="text-lg text-muted-foreground">{authType.description}</p>
        <div className="mt-4 flex flex-wrap gap-2">
            <Badge variant={authType.security === 'High' ? 'destructive' : authType.security === 'Medium' ? 'default' : 'secondary'}>
              Security: {authType.security}
            </Badge>
            <Badge variant="outline">Complexity: {authType.complexity}</Badge>
            <Badge variant="secondary">Protocols: {authType.protocols}</Badge>
        </div>
      </header>

      {authType.securityNotes && (
        <SecurityWarning>{authType.securityNotes}</SecurityWarning>
      )}
      
      <div className="grid lg:grid-cols-3 gap-8">
        <div className="lg:col-span-2 space-y-8">
            <Card>
                <CardHeader>
                    <CardTitle>Technical Explanation</CardTitle>
                </CardHeader>
                <CardContent className="prose dark:prose-invert max-w-none">
                    <p>{authType.technicalExplanation}</p>
                </CardContent>
            </Card>

            {authType.httpExamples && <HttpExamples examples={authType.httpExamples} />}

            <Card>
                <CardHeader>
                    <CardTitle>Common Use Cases</CardTitle>
                </CardHeader>
                <CardContent>
                    <p className="text-muted-foreground">{authType.useCase}</p>
                </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Pros & Cons</CardTitle>
              </CardHeader>
              <CardContent className="grid gap-6 md:grid-cols-2">
                <div>
                  <h4 className="mb-3 flex items-center gap-2 font-semibold">
                    <CheckCircle2 className="h-5 w-5 text-green-500" />
                    Pros
                  </h4>
                  <ul className="list-disc space-y-2 pl-5 text-muted-foreground">
                    {authType.pros.map((pro) => (
                      <li key={pro}>{pro}</li>
                    ))}
                  </ul>
                </div>
                <div>
                  <h4 className="mb-3 flex items-center gap-2 font-semibold">
                    <XCircle className="h-5 w-5 text-red-500" />
                    Cons
                  </h4>
                  <ul className="list-disc space-y-2 pl-5 text-muted-foreground">
                    {authType.cons.map((con) => (
                      <li key={con}>{con}</li>
                    ))}
                  </ul>
                </div>
              </CardContent>
            </Card>
            
            <AuthFlowDiagram diagram={<DiagramComponent />} />
        </div>

        <div className="lg:col-span-1 space-y-8">
            <Card>
                <CardHeader>
                    <CardTitle>Setup Instructions</CardTitle>
                </CardHeader>
                <CardContent className="text-sm space-y-2 text-muted-foreground">
                   <SetupComponent />
                </CardContent>
            </Card>
            
            <InteractiveDemo />
        </div>
      </div>
    </div>
  );
}
