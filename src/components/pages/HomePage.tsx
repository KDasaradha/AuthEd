'use client';

import React from 'react';
import Link from 'next/link';
import { ArrowRight, BookOpen, GitCompare, Code } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { TypeAnimation } from 'react-type-animation';
import { Tilt } from 'react-tilt';
import { AuthVsAuthzDiagram } from "@/components/auth/AuthVsAuthzDiagram";
import { motion } from 'framer-motion';

const featureCards = [
  {
    icon: <BookOpen className="w-8 h-8 text-primary" />,
    title: 'Explore Protocols',
    description: 'Dive into 25+ detailed authentication guides with visual diagrams and code examples.',
    href: '/auth-types',
    cta: 'Start Learning',
  },
  {
    icon: <GitCompare className="w-8 h-8 text-primary" />,
    title: 'Compare Auth Types',
    description: 'Use our advanced matrix to compare protocols on security, complexity, and use cases.',
    href: '/comparison',
    cta: 'Compare Now',
  },
  {
    icon: <Code className="w-8 h-8 text-primary" />,
    title: 'Try a Live Demo',
    description: 'Experience authentication flows with our interactive demos for each protocol.',
    href: '/auth-types',
    cta: 'Launch Demo',
  },
];

const tiltOptions = {
  max: 20,
  perspective: 1000,
  scale: 1.05,
  speed: 400,
  transition: true,
  easing: 'cubic-bezier(.03,.98,.52,.99)',
};

export function HomePage() {
  const sectionVariants = {
    hidden: { opacity: 0, y: 50 },
    visible: { opacity: 1, y: 0, transition: { duration: 0.6, ease: "easeOut" } },
  };

  return (
    <div className="space-y-24 md:space-y-32">
      {/* Hero Section */}
      <section className="relative text-center pt-20 pb-16 overflow-hidden">
        <div className="absolute inset-0 -z-10 bg-grid-pattern" style={{ maskImage: 'linear-gradient(to bottom, transparent, black 80%, transparent)' }}></div>
        <div className="container mx-auto">
          <h1 className="text-4xl md:text-6xl font-bold tracking-tighter bg-clip-text text-transparent bg-gradient-to-b from-neutral-700 to-neutral-900 dark:from-neutral-200 dark:to-neutral-500 pb-4">
            AuthShowcase: Unlock Modern Security
          </h1>
          <TypeAnimation
            sequence={[
              'Visualize 25+ authentication protocols.',
              1500,
              'Experiment with live, hands-on demos.',
              1500,
              'Compare methods with an advanced matrix.',
              1500,
              'Master authentication, from basic to biometric.',
              1500,
            ]}
            wrapper="p"
            speed={50}
            className="max-w-3xl mx-auto text-lg text-muted-foreground mt-4"
            repeat={Infinity}
          />
          <div className="mt-8 flex justify-center gap-4">
            <Button asChild size="lg">
              <Link href="/auth-types">
                Get Started <ArrowRight className="ml-2 h-5 w-5" />
              </Link>
            </Button>
          </div>
        </div>
      </section>

      {/* Auth vs AuthZ Section */}
      <motion.section 
        className="space-y-12"
        initial="hidden"
        whileInView="visible"
        viewport={{ once: true, amount: 0.2 }}
        variants={sectionVariants}
      >
        <div className="text-center">
          <h2 className="text-3xl md:text-4xl font-bold">Authentication vs. Authorization</h2>
          <p className="text-muted-foreground mt-2">The two pillars of secure access control, demystified.</p>
        </div>
        <AuthVsAuthzDiagram />
      </motion.section>

      {/* Features Section */}
      <motion.section 
        className="space-y-12"
        initial="hidden"
        whileInView="visible"
        viewport={{ once: true, amount: 0.2 }}
        variants={sectionVariants}
      >
        <div className="text-center">
          <h2 className="text-3xl md:text-4xl font-bold">A Developer-Centric Learning Platform</h2>
          <p className="text-muted-foreground mt-2 max-w-2xl mx-auto">
            Tools and guides designed to help you build secure, modern applications with confidence.
          </p>
        </div>
        <div className="grid md:grid-cols-3 gap-8">
          {featureCards.map((card, index) => (
            <motion.div
              key={card.title}
              initial={{ opacity: 0, y: 50 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, amount: 0.5 }}
              transition={{ duration: 0.5, delay: index * 0.2, ease: "easeOut" }}
            >
              <Tilt options={tiltOptions}>
                <Link href={card.href} className="group block h-full">
                  <Card className="h-full bg-white/40 dark:bg-black/40 backdrop-blur-lg border-white/20 dark:border-black/20 shadow-lg hover:shadow-2xl transition-all duration-300 transform hover:-translate-y-2">
                    <CardHeader className="items-center text-center">
                      <div className="bg-primary/10 p-4 rounded-full mb-4 inline-flex">
                        {card.icon}
                      </div>
                      <CardTitle>{card.title}</CardTitle>
                    </CardHeader>
                    <CardContent className="text-center">
                      <p className="text-muted-foreground text-sm">{card.description}</p>
                      <Button variant="link" className="mt-4">
                        {card.cta} <ArrowRight className="ml-2 h-4 w-4" />
                      </Button>
                    </CardContent>
                  </Card>
                </Link>
              </Tilt>
            </motion.div>
          ))}
        </div>
      </motion.section>

      {/* CTA Section */}
      <motion.section 
        className="text-center bg-card border rounded-lg p-10 md:p-16"
        initial="hidden"
        whileInView="visible"
        viewport={{ once: true, amount: 0.5 }}
        variants={sectionVariants}
      >
        <h2 className="text-3xl md:text-4xl font-bold tracking-tight">Ready to Become an Auth Expert?</h2>
        <p className="max-w-2xl mx-auto mt-4 text-lg text-muted-foreground">
          Your journey starts here. Explore our comprehensive library and build your knowledge.
        </p>
        <div className="mt-8">
          <Button asChild size="lg" className="bg-gradient-to-r from-primary to-accent text-primary-foreground">
            <Link href="/comparison">
              Compare All Authentication Types <ArrowRight className="ml-2 h-5 w-5" />
            </Link>
          </Button>
        </div>
      </motion.section>
    </div>
  );
}
