import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { BookOpen, Code, Component, GitFork, Layers, ListChecks, PlayCircle, Wind } from "lucide-react";

const features = [
    {
      icon: <BookOpen className="w-6 h-6 text-primary" />,
      title: "AuthN vs. AuthZ",
      description: "Clear, detailed explanations of the core concepts of Authentication and Authorization.",
    },
    {
      icon: <ListChecks className="w-6 h-6 text-primary" />,
      title: "25+ Auth Guides",
      description: "In-depth guides for a wide range of authentication methods, from basic to advanced.",
    },
    {
      icon: <PlayCircle className="w-6 h-6 text-primary" />,
      title: "Interactive Demos",
      description: "Hands-on demos to experience authentication flows in a safe, mock environment.",
    },
    {
      icon: <GitFork className="w-6 h-6 text-primary" />,
      title: "Visual Diagrams",
      description: "Easy-to-understand diagrams illustrating complex protocols like OAuth2 and SAML.",
    },
];

const techStack = [
    {
        icon: <Layers className="w-5 h-5 text-accent" />,
        name: "Next.js",
        description: "App Router & Server Components"
    },
    {
        icon: <Code className="w-5 h-5 text-accent" />,
        name: "TypeScript",
        description: "For type safety"
    },
    {
        icon: <Wind className="w-5 h-5 text-accent" />,
        name: "Tailwind CSS",
        description: "For modern styling"
    },
    {
        icon: <Component className="w-5 h-5 text-accent" />,
        name: "Shadcn/UI",
        description: "For UI components"
    }
]

export function AboutPage() {
  return (
    <div className="space-y-12">
      <header className="text-center">
        <h1 className="text-4xl md:text-5xl font-bold tracking-tighter">About AuthEd</h1>
        <p className="max-w-3xl mx-auto mt-3 text-lg text-muted-foreground">
          An educational platform designed to demystify the complex world of digital authentication and authorization.
        </p>
      </header>
      
      <Card>
        <CardHeader>
          <CardTitle>Project Purpose</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4 text-muted-foreground">
          <p>
            AuthEd's primary objective is to provide developers, students, and security enthusiasts with a clear, comprehensive, and interactive resource to understand critical security concepts. We aim to bridge the gap between theory and practice.
          </p>
          <p>
            This project serves as a functional frontend companion to a FastAPI backend project, demonstrating 25 distinct authentication types in a practical, hands-on manner. It's built to be both an educational tool and a reference guide.
          </p>
        </CardContent>
      </Card>

      <section className="space-y-6">
        <div className="text-center">
            <h2 className="text-3xl font-bold">Features at a Glance</h2>
            <p className="text-muted-foreground mt-2">Everything you need to master authentication.</p>
        </div>
        <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6">
          {features.map((feature) => (
            <Card key={feature.title} className="flex flex-col items-start p-6">
                <div className="bg-primary/10 p-3 rounded-full mb-4">
                    {feature.icon}
                </div>
                <h3 className="font-semibold text-lg">{feature.title}</h3>
                <p className="text-muted-foreground text-sm mt-1">{feature.description}</p>
            </Card>
          ))}
        </div>
      </section>
      
      <div className="grid md:grid-cols-2 gap-8">
        <Card>
            <CardHeader>
                <CardTitle>Technology Stack</CardTitle>
            </CardHeader>
            <CardContent>
                <ul className="space-y-4">
                {techStack.map((tech) => (
                    <li key={tech.name} className="flex items-start gap-4">
                        <div className="bg-accent/10 p-2 rounded-lg mt-1">
                            {tech.icon}
                        </div>
                        <div>
                            <p className="font-semibold">{tech.name}</p>
                            <p className="text-sm text-muted-foreground">{tech.description}</p>
                        </div>
                    </li>
                ))}
                </ul>
            </CardContent>
        </Card>
        
        <Card>
            <CardHeader>
                <CardTitle>Project Resources</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4 text-muted-foreground">
                <p>
                    This frontend application is designed to work with a corresponding backend implementation. For more details on the backend, please refer to the project's repository.
                </p>
                <p>
                    The complete source code for both the frontend and backend is available for you to explore, learn from, and adapt.
                </p>
            </CardContent>
        </Card>
      </div>

    </div>
  )
}
