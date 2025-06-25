import { AuthVsAuthzDiagram } from "@/components/auth/AuthVsAuthzDiagram";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { ArrowRight, KeyRound, ShieldCheck, PlayCircle, GitFork, ListChecks } from "lucide-react";
import Link from "next/link";

const features = [
  {
    icon: <ListChecks className="w-8 h-8 text-primary" />,
    title: "25+ Auth Types",
    description: "From Basic Auth to WebAuthn, get detailed guides on a wide range of authentication methods.",
    href: "/auth-types"
  },
  {
    icon: <PlayCircle className="w-8 h-8 text-primary" />,
    title: "Interactive Demos",
    description: "Experience authentication flows firsthand with our mock interactive demonstrations for each type.",
    href: "/auth-types"
  },
  {
    icon: <GitFork className="w-8 h-8 text-primary" />,
    title: "Visual Flow Diagrams",
    description: "Understand complex protocols like OAuth2 and SAML with clear, easy-to-follow diagrams.",
    href: "/comparison"
  }
];

export function HomePage() {
  return (
    <div className="space-y-16">
      <section className="text-center py-8">
        <h1 className="text-4xl md:text-5xl font-bold tracking-tighter mb-4">
          Mastering Digital Security
        </h1>
        <p className="max-w-3xl mx-auto text-lg text-muted-foreground">
          A deep dive into securing applications. Understand the crucial
          difference between Authentication and Authorization, and explore 25 methods to protect your services.
        </p>
        <div className="mt-6 flex justify-center gap-4">
           <Button asChild size="lg">
              <Link href="/auth-types">
                Get Started <ArrowRight className="ml-2" />
              </Link>
            </Button>
            <Button asChild size="lg" variant="outline">
              <Link href="/comparison">
                Compare Methods
              </Link>
            </Button>
        </div>
      </section>

      <section className="space-y-8">
        <div className="text-center">
          <h2 className="text-3xl font-bold">What You'll Learn</h2>
          <p className="text-muted-foreground mt-2">Core concepts and tools to build secure applications.</p>
        </div>
        <div className="grid md:grid-cols-3 gap-6">
          {features.map((feature) => (
            <Card key={feature.title} className="text-center flex flex-col items-center pt-6">
              <div className="bg-primary/10 p-3 rounded-full mb-4 inline-flex">
                {feature.icon}
              </div>
              <CardHeader>
                <CardTitle>{feature.title}</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-muted-foreground text-sm">{feature.description}</p>
              </CardContent>
            </Card>
          ))}
        </div>
      </section>

      <section className="space-y-8">
        <div className="text-center">
          <h2 className="text-3xl font-bold">Authentication vs. Authorization</h2>
          <p className="text-muted-foreground mt-2">The two pillars of access control.</p>
        </div>
        <AuthVsAuthzDiagram />
        <div className="grid md:grid-cols-2 gap-8 items-start">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <KeyRound className="text-primary"/>
                Authentication (AuthN)
              </CardTitle>
              <CardDescription>"Who are you?"</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <p className="text-muted-foreground">
                The process of verifying a user's identity. It's the front door, ensuring only legitimate users get in.
              </p>
              <ul className="list-disc pl-5 space-y-1 text-sm text-muted-foreground">
                <li>Verifies identity</li>
                <li>First step in access control</li>
                <li>Examples: Passwords, Biometrics, MFA</li>
              </ul>
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
               <CardTitle className="flex items-center gap-2">
                <ShieldCheck className="text-accent"/>
                Authorization (AuthZ)
              </CardTitle>
              <CardDescription>"What can you do?"</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <p className="text-muted-foreground">
                The process of determining what an authenticated user is allowed to do. It defines permissions and access levels.
              </p>
              <ul className="list-disc pl-5 space-y-1 text-sm text-muted-foreground">
                <li>Determines permissions</li>
                <li>Happens after successful authentication</li>
                <li>Examples: Admin vs. User roles, access rights</li>
              </ul>
            </CardContent>
          </Card>
        </div>
      </section>
    </div>
  );
}
