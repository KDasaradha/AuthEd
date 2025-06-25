import React from 'react';
import { AuthVsAuthzDiagram } from "@/components/auth/AuthVsAuthzDiagram";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { ArrowRight, KeyRound, ShieldCheck, PlayCircle, GitFork, ListChecks } from "lucide-react";
import Link from "next/link";

const features = [
  {
    icon: <ListChecks className="w-8 h-8 text-primary" />,
    title: "25+ In-Depth Guides",
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
    <div className="space-y-20 md:space-y-28">
      <section className="text-center pt-16 pb-12">
        <h1 className="text-4xl md:text-6xl font-bold tracking-tighter mb-4">
          Mastering Digital Security
        </h1>
        <p className="max-w-3xl mx-auto text-lg text-muted-foreground">
          An educational platform to learn about 25 authentication types, understand the difference between authentication and authorization, with interactive demos and technical deep dives.
        </p>
        <div className="mt-8 flex justify-center gap-4">
           <Button asChild size="lg">
              <Link href="/auth-types">
                Get Started <ArrowRight className="ml-2 h-5 w-5" />
              </Link>
            </Button>
            <Button asChild size="lg" variant="outline">
              <Link href="/comparison">
                Compare All Methods
              </Link>
            </Button>
        </div>
      </section>

      <section className="space-y-12">
        <div className="text-center">
          <h2 className="text-3xl md:text-4xl font-bold">Authentication vs. Authorization</h2>
          <p className="text-muted-foreground mt-2">Understanding the two pillars of access control is the first step.</p>
        </div>
        <AuthVsAuthzDiagram />
        <div className="grid md:grid-cols-2 gap-8 items-start">
          <Card className="border-primary/30 shadow-sm hover:shadow-primary/10 hover:border-primary/70 transition-all">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <KeyRound className="text-primary"/>
                Authentication (AuthN)
              </CardTitle>
              <CardDescription>"Who are you?"</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <p className="text-muted-foreground">
                The process of verifying a user's identity. It's the front door of your application, ensuring only legitimate users can get in.
              </p>
              <ul className="list-disc pl-5 space-y-1 text-sm text-muted-foreground">
                <li>Verifies identity</li>
                <li>The first step in any secure process</li>
                <li>Examples: Passwords, Biometrics, MFA</li>
              </ul>
            </CardContent>
          </Card>
          <Card className="border-accent/30 shadow-sm hover:shadow-accent/10 hover:border-accent/70 transition-all">
            <CardHeader>
               <CardTitle className="flex items-center gap-2">
                <ShieldCheck className="text-accent"/>
                Authorization (AuthZ)
              </CardTitle>
              <CardDescription>"What are you allowed to do?"</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <p className="text-muted-foreground">
                The process of determining what an authenticated user is permitted to do. It defines their permissions and access levels.
              </p>
              <ul className="list-disc pl-5 space-y-1 text-sm text-muted-foreground">
                <li>Determines permissions and rights</li>
                <li>Happens after successful authentication</li>
                <li>Examples: Admin vs. User roles, file access</li>
              </ul>
            </CardContent>
          </Card>
        </div>
      </section>

      <section className="space-y-12">
        <div className="text-center">
          <h2 className="text-3xl md:text-4xl font-bold">A Comprehensive Learning Platform</h2>
          <p className="text-muted-foreground mt-2 max-w-2xl mx-auto">Core concepts and tools to help you build secure, modern applications with confidence.</p>
        </div>
        <div className="grid md:grid-cols-3 gap-8">
          {features.map((feature) => (
            <Link href={feature.href} key={feature.title} className="group block">
              <Card className="text-center flex flex-col items-center p-6 h-full transition-all duration-300 group-hover:border-primary group-hover:shadow-xl group-hover:-translate-y-2">
                <div className="bg-primary/10 p-4 rounded-full mb-4 inline-flex transition-colors duration-300 group-hover:bg-primary/20">
                  {feature.icon}
                </div>
                <CardHeader className="p-0">
                  <CardTitle>{feature.title}</CardTitle>
                </CardHeader>
                <CardContent className="p-0 mt-2">
                  <p className="text-muted-foreground text-sm">{feature.description}</p>
                </CardContent>
              </Card>
            </Link>
          ))}
        </div>
      </section>

      <section className="text-center bg-card border rounded-lg p-10 md:p-16">
        <h2 className="text-3xl md:text-4xl font-bold tracking-tight">Ready to Become an Expert?</h2>
        <p className="max-w-2xl mx-auto mt-4 text-lg text-muted-foreground">
          Your journey into the world of authentication starts here. Explore our comprehensive library and build your knowledge.
        </p>
        <div className="mt-8">
          <Button asChild size="lg">
            <Link href="/auth-types">
              Explore All Authentication Types <ArrowRight className="ml-2 h-5 w-5" />
            </Link>
          </Button>
        </div>
      </section>

    </div>
  );
}
