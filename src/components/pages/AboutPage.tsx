'use client'

import { Card, CardContent, CardDescription, CardHeader, CardTitle, CardFooter } from "@/components/ui/card";
import { BookOpen, Layers3, GitCompare, PlayCircle, Layers, Code, Wind, Component, BrainCircuit, GraduationCap, Github } from "lucide-react";
import { motion } from 'framer-motion';
import { Button } from "../ui/button";
import Link from "next/link";

const features = [
    {
      icon: <Layers3 className="w-8 h-8 text-primary" />,
      title: "25+ Auth Guides",
      description: "In-depth guides for a wide range of authentication methods, from basic to advanced.",
    },
    {
      icon: <GitCompare className="w-8 h-8 text-primary" />,
      title: "Visual Flow Diagrams",
      description: "Easy-to-understand diagrams illustrating complex protocols like OAuth2 and SAML.",
    },
    {
      icon: <PlayCircle className="w-8 h-8 text-primary" />,
      title: "Interactive Demos",
      description: "Hands-on demos to experience authentication flows in a safe, mock environment.",
    },
    {
        icon: <BookOpen className="w-8 h-8 text-primary" />,
        title: "Advanced Comparison",
        description: "Filter and sort methods by security, complexity, and use case to find the perfect fit.",
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
        description: "For robust, type-safe code"
    },
    {
        icon: <Wind className="w-5 h-5 text-accent" />,
        name: "Tailwind CSS",
        description: "For modern, utility-first styling"
    },
    {
        icon: <Component className="w-5 h-5 text-accent" />,
        name: "Shadcn/UI & Framer Motion",
        description: "For components and animations"
    }
];

const educationalPrinciples = [
    {
      icon: <GraduationCap className="w-6 h-6 text-primary" />,
      title: "Bloom’s Taxonomy",
      description: "Structuring content to guide you from basic knowledge to advanced analysis and evaluation.",
    },
    {
      icon: <PlayCircle className="w-6 h-6 text-primary" />,
      title: "Visual & Experiential Learning",
      description: "Using interactive diagrams and hands-on demos that allow you to 'learn by doing'.",
    },
     {
      icon: <BrainCircuit className="w-6 h-6 text-primary" />,
      title: "Real-World Context",
      description: "Connecting abstract protocols to concrete use cases and security implications.",
    },
]

const sectionVariants = {
  hidden: { opacity: 0, y: 50 },
  visible: { opacity: 1, y: 0, transition: { duration: 0.6, ease: "easeOut" } },
};

const cardVariants = {
    hidden: { opacity: 0, scale: 0.95 },
    visible: { opacity: 1, scale: 1 },
};

export function AboutPage() {
  return (
    <motion.div 
        className="space-y-20"
        initial="hidden"
        animate="visible"
        transition={{ staggerChildren: 0.2 }}
    >
      <motion.header 
        className="text-center"
        variants={sectionVariants}
      >
        <h1 className="text-4xl md:text-5xl font-bold tracking-tighter">About AuthShowcase</h1>
        <p className="max-w-3xl mx-auto mt-3 text-lg text-muted-foreground">
          A developer-centric platform to learn, visualize & experiment with 25+ authentication types.
        </p>
      </motion.header>
      
      <motion.section variants={sectionVariants}>
        <Card className="bg-card/80 backdrop-blur-sm">
            <CardHeader>
            <CardTitle className="text-2xl">Our Mission</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4 text-muted-foreground">
            <p>
                AuthShowcase is a developer-centric educational platform designed to demystify the complex world of digital security. Our mission is to bridge the gap between abstract theory and practical implementation, empowering developers to build safer, more secure applications.
            </p>
            <p>
                We believe that by providing clear, interactive, and accessible resources, we can foster a deeper understanding of authentication and authorization principles across the tech community.
            </p>
            </CardContent>
        </Card>
      </motion.section>

      <motion.section 
        className="space-y-8"
        variants={sectionVariants}
      >
        <div className="text-center">
            <h2 className="text-3xl font-bold">Features at a Glance</h2>
            <p className="text-muted-foreground mt-2">Everything you need to master authentication.</p>
        </div>
        <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6">
          {features.map((feature, i) => (
            <motion.div
                key={feature.title}
                variants={cardVariants}
                transition={{ duration: 0.5, delay: i * 0.1 }}
            >
                <Card className="flex flex-col items-start p-6 text-left h-full transition-all duration-300 hover:shadow-primary/20 hover:shadow-lg hover:-translate-y-1">
                    <div className="bg-primary/10 p-3 rounded-full mb-4">
                        {feature.icon}
                    </div>
                    <h3 className="font-semibold text-lg">{feature.title}</h3>
                    <p className="text-muted-foreground text-sm mt-1 flex-grow">{feature.description}</p>
                </Card>
            </motion.div>
          ))}
        </div>
      </motion.section>
      
      <div className="grid lg:grid-cols-5 gap-8">
        <motion.section className="lg:col-span-3" variants={sectionVariants}>
            <Card className="h-full">
                <CardHeader>
                    <CardTitle>Our Educational Philosophy</CardTitle>
                    <CardDescription>We use proven learning frameworks to maximize understanding.</CardDescription>
                </CardHeader>
                <CardContent>
                    <ul className="space-y-6">
                        {educationalPrinciples.map((principle) => (
                            <li key={principle.title} className="flex items-start gap-4">
                                <div className="bg-primary/10 p-2 rounded-lg mt-1">
                                    {principle.icon}
                                </div>
                                <div>
                                    <p className="font-semibold">{principle.title}</p>
                                    <p className="text-sm text-muted-foreground">{principle.description}</p>
                                </div>
                            </li>
                        ))}
                    </ul>
                </CardContent>
            </Card>
        </motion.section>
        <motion.section className="lg:col-span-2" variants={sectionVariants}>
             <Card className="h-full">
                <CardHeader>
                    <CardTitle>Technology Stack</CardTitle>
                    <CardDescription>Built with modern, robust technologies.</CardDescription>
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
        </motion.section>
      </div>

      <motion.section variants={sectionVariants}>
        <Card>
            <CardHeader className="text-center">
                <CardTitle>Explore The Project</CardTitle>
                <CardDescription>The complete source code is available for you to explore, learn from, and adapt.</CardDescription>
            </CardHeader>
            <CardFooter className="flex flex-col md:flex-row gap-4 justify-center">
                <Button asChild size="lg" className="w-full md:w-auto">
                    <Link href="#" target="_blank" rel="noopener noreferrer"><Github className="mr-2"/>Frontend Repository</Link>
                </Button>
                <Button asChild size="lg" variant="outline" className="w-full md:w-auto">
                    <Link href="#" target="_blank" rel="noopener noreferrer"><Github className="mr-2"/>Backend Repository (FastAPI)</Link>
                </Button>
            </CardFooter>
        </Card>
      </motion.section>

    </motion.div>
  )
}
