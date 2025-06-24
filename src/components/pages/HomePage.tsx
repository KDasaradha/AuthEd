import { AuthVsAuthzDiagram } from "@/components/auth/AuthVsAuthzDiagram";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ArrowRight } from "lucide-react";
import Link from "next/link";

export function HomePage() {
  return (
    <div className="space-y-8">
      <section className="text-center">
        <h1 className="text-4xl md:text-5xl font-bold tracking-tighter mb-4">
          Authentication vs. Authorization
        </h1>
        <p className="max-w-3xl mx-auto text-lg text-muted-foreground">
          A deep dive into securing applications. Understand the crucial
          difference and explore 25 methods to protect your services.
        </p>
      </section>

      <AuthVsAuthzDiagram />

      <section className="grid md:grid-cols-2 gap-8 items-start">
        <Card>
          <CardHeader>
            <CardTitle>Authentication (AuthN)</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <p className="text-muted-foreground">
              Authentication is the process of verifying who a user is. It's the
              gateway to your application, ensuring that only legitimate users
              can gain access. Think of it as showing your ID at a security
              checkpoint.
            </p>
            <ul className="list-disc pl-5 space-y-1 text-sm">
              <li>Verifies identity.</li>
              <li>Answers the question: "Who are you?"</li>
              <li>Examples: Passwords, Biometrics, MFA.</li>
            </ul>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Authorization (AuthZ)</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <p className="text-muted-foreground">
              Once a user is authenticated, authorization determines what they
              are allowed to do. It defines permissions and access levels for
              different resources within the application. It's what you're
              allowed to do after you've passed the security checkpoint.
            </p>
            <ul className="list-disc pl-5 space-y-1 text-sm">
              <li>Determines permissions.</li>
              <li>Answers the question: "What are you allowed to do?"</li>
              <li>Examples: User Roles (Admin vs. User), Permissions.</li>
            </ul>
          </CardContent>
        </Card>
      </section>

      <section className="text-center py-8">
        <h2 className="text-3xl font-bold mb-4">Ready to Dive Deeper?</h2>
        <p className="max-w-2xl mx-auto text-muted-foreground mb-6">
          Explore our comprehensive guides and interactive demos on 25 different
          authentication methods.
        </p>
        <Button asChild size="lg">
          <Link href="/auth-types">
            Explore Auth Types <ArrowRight className="ml-2" />
          </Link>
        </Button>
      </section>
    </div>
  );
}
