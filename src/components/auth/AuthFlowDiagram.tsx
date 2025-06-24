import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";

export function AuthFlowDiagram({ diagram }: { diagram: React.ReactNode }) {
  return (
    <Card>
        <CardHeader>
            <CardTitle>Authentication Flow</CardTitle>
        </CardHeader>
        <CardContent>
            <div className="p-4 border rounded-lg bg-secondary/30 my-4 overflow-x-auto">
                {diagram}
            </div>
        </CardContent>
    </Card>
  );
};
