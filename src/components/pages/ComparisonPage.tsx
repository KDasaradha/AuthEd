'use client';

import { useState, useMemo } from 'react';
import { authTypes } from "@/lib/auth-types-data";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { ArrowUpDown, ArrowUp, ArrowDown } from "lucide-react";

type SortableKeys = 'name' | 'security' | 'complexity' | 'statefulness';
type SortDirection = 'ascending' | 'descending';

type SortConfig = {
  key: SortableKeys;
  direction: SortDirection;
} | null;

const statefulnessMap: Record<string, string> = {
  'session-based-authentication': 'Stateful',
  'kerberos-authentication': 'Stateful',
  'ntlm-authentication': 'Stateful',
  'multi-factor-authentication': 'Varies',
  'single-sign-on': 'Varies',
  'one-time-password': 'Varies',
  'zero-trust-authentication': 'Varies',
  'delegated-authentication': 'Varies',
};

const securityOrder: Record<string, number> = { 'Low': 1, 'Medium': 2, 'High': 3 };
const complexityOrder: Record<string, number> = { 'Low': 1, 'Medium': 2, 'High': 3 };

export function ComparisonPage() {
  const [sortConfig, setSortConfig] = useState<SortConfig>({ key: 'name', direction: 'ascending' });

  const extendedAuthTypes = useMemo(() => {
    return authTypes.map(type => ({
      ...type,
      statefulness: statefulnessMap[type.slug] || 'Stateless'
    }));
  }, []);

  const sortedAuthTypes = useMemo(() => {
    let sortableItems = [...extendedAuthTypes];
    if (sortConfig !== null) {
      sortableItems.sort((a, b) => {
        const key = sortConfig.key;
        let aValue, bValue;

        if (key === 'security') {
          aValue = securityOrder[a.security];
          bValue = securityOrder[b.security];
        } else if (key === 'complexity') {
          aValue = complexityOrder[a.complexity];
          bValue = complexityOrder[b.complexity];
        } else {
          aValue = a[key].toLowerCase();
          bValue = b[key].toLowerCase();
        }

        if (aValue < bValue) {
          return sortConfig.direction === 'ascending' ? -1 : 1;
        }
        if (aValue > bValue) {
          return sortConfig.direction === 'ascending' ? 1 : -1;
        }
        return 0;
      });
    }
    return sortableItems;
  }, [extendedAuthTypes, sortConfig]);

  const requestSort = (key: SortableKeys) => {
    let direction: SortDirection = 'ascending';
    if (sortConfig && sortConfig.key === key && sortConfig.direction === 'ascending') {
      direction = 'descending';
    }
    setSortConfig({ key, direction });
  };

  const getSortIcon = (key: SortableKeys) => {
    if (!sortConfig || sortConfig.key !== key) {
      return <ArrowUpDown className="ml-2 h-4 w-4 opacity-30" />;
    }
    return sortConfig.direction === 'ascending' ? <ArrowUp className="ml-2 h-4 w-4" /> : <ArrowDown className="ml-2 h-4 w-4" />;
  };
  
  const headers: { key: SortableKeys; label: string; tooltip: string; className?: string }[] = [
      { key: 'name', label: 'Auth Type', tooltip: 'Name of the authentication method.' },
      { key: 'security', label: 'Security', tooltip: 'General security level provided.' },
      { key: 'complexity', label: 'Complexity', tooltip: 'Typical implementation and maintenance complexity.' },
      { key: 'statefulness', label: 'Statefulness', tooltip: 'Whether the server needs to store session state.', className: 'hidden lg:table-cell' },
  ];

  return (
    <TooltipProvider>
      <div className="space-y-8">
        <div>
          <h1 className="text-4xl font-bold tracking-tight">Advanced Comparison</h1>
          <p className="mt-2 text-lg text-muted-foreground">
            Sort and compare authentication types by security, complexity, and other key characteristics.
          </p>
        </div>
        <div className="border rounded-lg w-full">
          <Table>
            <TableHeader>
              <TableRow>
                {headers.map(header => (
                    <TableHead key={header.key} className={header.className}>
                      <Button variant="ghost" onClick={() => requestSort(header.key)} className="px-0 hover:bg-transparent -ml-4">
                          <Tooltip>
                              <TooltipTrigger asChild>
                                  <span className="flex items-center">{header.label} {getSortIcon(header.key)}</span>
                              </TooltipTrigger>
                              <TooltipContent>
                                  <p>{header.tooltip}</p>
                              </TooltipContent>
                          </Tooltip>
                      </Button>
                    </TableHead>
                ))}
                <TableHead className="font-headline hidden md:table-cell">Protocols</TableHead>
                <TableHead className="font-headline hidden xl:table-cell">Common Use Case</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {sortedAuthTypes.map((type) => (
                <TableRow key={type.slug}>
                  <TableCell className="font-medium">
                    <Button variant="link" asChild className="p-0 h-auto text-left whitespace-normal">
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
                  <TableCell className="hidden lg:table-cell">{type.statefulness}</TableCell>
                  <TableCell className="hidden md:table-cell text-sm text-muted-foreground">{type.protocols}</TableCell>
                  <TableCell className="hidden xl:table-cell text-sm text-muted-foreground">{type.useCase}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </div>
    </TooltipProvider>
  );
}
