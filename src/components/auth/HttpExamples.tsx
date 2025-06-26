import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

type HttpExamplesProps = {
  examples: {
    request?: string;
    successResponse?: string;
    errorResponse?: string;
  }
};

const CodeBlock = ({ code }: { code: string }) => (
  <pre className="p-4 bg-muted rounded-md text-sm overflow-x-auto font-code">
    <code>{code}</code>
  </pre>
);

export function HttpExamples({ examples }: HttpExamplesProps) {
  const { request, successResponse, errorResponse } = examples;
  
  return (
    <Card>
      <CardHeader>
        <CardTitle>HTTP Message Examples</CardTitle>
        <CardDescription>
            See what the client and server exchange during this flow.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        {request && (
          <div>
            <h4 className="font-semibold mb-2 text-muted-foreground">Example Request</h4>
            <CodeBlock code={request} />
          </div>
        )}
        {successResponse && (
          <div>
            <h4 className="font-semibold mb-2 text-muted-foreground">Example Success Response (200 OK)</h4>
            <CodeBlock code={successResponse} />
          </div>
        )}
        {errorResponse && (
          <div>
            <h4 className="font-semibold mb-2 text-muted-foreground">Example Error Response (401 Unauthorized)</h4>
            <CodeBlock code={errorResponse} />
          </div>
        )}
      </CardContent>
    </Card>
  );
};
