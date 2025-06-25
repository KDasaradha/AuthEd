import type { AuthType } from "@/lib/types";
import Link from "next/link";
import { Card, CardHeader, CardTitle, CardDescription, CardFooter } from "../ui/card";
import { Badge } from "../ui/badge";
import { ArrowRight } from "lucide-react";

export function AuthTypeCard({ authType }: { authType: AuthType }) {
  return (
    <Link href={`/auth-types/${authType.slug}`} className="group">
      <Card className="h-full flex flex-col transition-all duration-300 group-hover:border-primary group-hover:shadow-lg group-hover:-translate-y-1">
        <CardHeader>
          <CardTitle>{authType.name}</CardTitle>
          <CardDescription>{authType.description}</CardDescription>
        </CardHeader>
        <div className="flex-grow" />
        <CardFooter className="flex justify-between items-center">
          <div className="flex gap-2">
            <Badge variant={authType.security === 'High' ? 'destructive' : authType.security === 'Medium' ? 'default' : 'secondary'}>
              {authType.security}
            </Badge>
            <Badge variant="outline">{authType.complexity}</Badge>
          </div>
          <ArrowRight className="w-4 h-4 text-muted-foreground group-hover:text-primary transition-colors" />
        </CardFooter>
      </Card>
    </Link>
  )
}
