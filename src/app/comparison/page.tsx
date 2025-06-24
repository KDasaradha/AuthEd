import { authTypes } from "@/lib/auth-types-data";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Comparison of Authentication Types',
};

export default function ComparisonPage() {
  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-4xl font-bold tracking-tight">Comparison Table</h1>
        <p className="mt-2 text-lg text-muted-foreground">
          Compare all 25 authentication types by their security level, complexity, and common use cases.
        </p>
      </div>
      <div className="border rounded-lg w-full">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="font-headline">Auth Type</TableHead>
              <TableHead className="font-headline">Security Level</TableHead>
              <TableHead className="font-headline">Complexity</TableHead>
              <TableHead className="font-headline hidden md:table-cell">Common Use Case</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {authTypes.map((type) => (
              <TableRow key={type.slug}>
                <TableCell className="font-medium">
                  <Button variant="link" asChild className="p-0 h-auto">
                    <Link href={`/auth-types/${type.slug}`}>{type.name}</Link>
                  </Button>
                </TableCell>
                <TableCell>
                  <Badge variant={type.security === 'High' ? 'destructive' : type.security === 'Medium' ? 'default' : 'secondary'}>
                    {type.security}
                  </Badge>
                </TableCell>
                <TableCell>
                  <Badge variant="outline">{type.complexity}</Badge>
                </TableCell>
                <TableCell className="hidden md:table-cell text-muted-foreground">{type.useCase}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}
