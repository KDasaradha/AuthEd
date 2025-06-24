import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { AuthFlowDiagram } from "@/components/auth/AuthFlowDiagram";
import { InteractiveDemo } from "@/components/auth/InteractiveDemo";
import type { AuthType } from "@/lib/types";

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

            <Card>
                <CardHeader>
                    <CardTitle>Common Use Cases</CardTitle>
                </CardHeader>
                <CardContent>
                    <p className="text-muted-foreground">{authType.useCase}</p>
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
