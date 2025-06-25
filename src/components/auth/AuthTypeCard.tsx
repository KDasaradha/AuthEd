'use client';

import type { AuthType } from "@/lib/types";
import Link from "next/link";
import { Card, CardHeader, CardTitle, CardDescription, CardFooter } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ArrowRight } from "lucide-react";
import { Tilt } from 'react-tilt';

const tiltOptions = {
  max: 15,
  perspective: 1000,
  scale: 1.05,
  speed: 400,
  transition: true,
  easing: 'cubic-bezier(.03,.98,.52,.99)',
};

export function AuthTypeCard({ authType }: { authType: AuthType }) {
  return (
    <Tilt options={tiltOptions}>
      <Link href={`/auth-types/${authType.slug}`} className="group block h-full">
        <Card className="h-full flex flex-col transition-all duration-300 bg-card/60 dark:bg-card/40 backdrop-blur-sm border-border/50 hover:border-primary/80 hover:shadow-primary/20 hover:shadow-lg">
          <CardHeader>
            <CardTitle>{authType.name}</CardTitle>
            <CardDescription className="line-clamp-2 h-10">{authType.description}</CardDescription>
          </CardHeader>
          <div className="flex-grow" />
          <CardFooter className="flex justify-between items-center">
            <div className="flex flex-wrap gap-2">
              <Badge variant={authType.security === 'High' ? 'destructive' : authType.security === 'Medium' ? 'default' : 'secondary'}>
                {authType.security}
              </Badge>
              <Badge variant="outline">{authType.complexity}</Badge>
            </div>
            <ArrowRight className="w-4 h-4 text-muted-foreground group-hover:text-primary transition-colors flex-shrink-0" />
          </CardFooter>
        </Card>
      </Link>
    </Tilt>
  )
}
