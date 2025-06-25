'use client';

import { useState, useMemo } from 'react';
import type { AuthType } from '@/lib/types';
import { authTypes } from "@/lib/auth-types-data";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { ArrowUpDown, ArrowUp, ArrowDown } from "lucide-react";

type SortableKeys = 'name' | 'security' | 'complexity' | 'statefulness' | 'phishingResistance' | 'ux';
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
const phishingResistanceOrder: Record<string, number> = { 'N/A': 0, 'Low': 1, 'Medium': 2, 'High': 3 };
const uxOrder: Record<string, number> = { 'N/A': 0, 'High Friction': 1, 'Medium Friction': 2, 'Low Friction': 3 };


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
        let aValue: string | number, bValue: string | number;

        if (key === 'security') {
          aValue = securityOrder[a.security];
          bValue = securityOrder[b.security];
        } else if (key === 'complexity') {
          aValue = complexityOrder[a.complexity];
          bValue = complexityOrder[b.complexity];
        } else if (key === 'phishingResistance') {
            aValue = phishingResistanceOrder[a.phishingResistance];
            bValue = phishingResistanceOrder[b.phishingResistance];
        } else if (key === 'ux') {
            aValue = uxOrder[a.ux];
            bValue = uxOrder[b.ux];
        } else {
          aValue = a[key].toString().toLowerCase();
          bValue = b[key].toString().toLowerCase();
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
      { key: 'security', label: 'Security', tooltip: 'General security level provided against attacks.' },
      { key: 'phishingResistance', label: 'Phishing Resistance', tooltip: 'How well the method protects against phishing attacks.', className: 'hidden md:table-cell' },
      { key: 'ux', label: 'User Experience', tooltip: 'Typical friction for the end-user during authentication.', className: 'hidden md:table-cell' },
      { key: 'complexity', label: 'Complexity', tooltip: 'Typical implementation and maintenance complexity.' },
      { key: 'statefulness', label: 'Statefulness', tooltip: 'Whether the server needs to store session state.', className: 'hidden lg:table-cell' },
  ];

  const getPhishingBadgeVariant = (resistance: AuthType['phishingResistance']) => {
    switch (resistance) {
      case 'High': return 'destructive';
      case 'Medium': return 'default';
      default: return 'secondary';
    }
  };

  const getUxBadgeVariant = (ux: AuthType['ux']) => {
    switch (ux) {
      case 'Low Friction': return 'default';
      case 'Medium Friction': return 'secondary';
      case 'High Friction': return 'destructive';
      default: return 'outline';
    }
  }

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
                <TableHead className="hidden lg:table-cell">Credential Type</TableHead>
                <TableHead className="hidden xl:table-cell">Standardization</TableHead>
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
                  <TableCell className="hidden md:table-cell">
                    <Badge variant={getPhishingBadgeVariant(type.phishingResistance)}>
                      {type.phishingResistance}
                    </Badge>
                  </TableCell>
                  <TableCell className="hidden md:table-cell">
                     <Badge variant={getUxBadgeVariant(type.ux)}>
                        {type.ux}
                      </Badge>
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline">{type.complexity}</Badge>
                  </TableCell>
                  <TableCell className="hidden lg:table-cell">{type.statefulness}</TableCell>
                  <TableCell className="hidden lg:table-cell text-sm text-muted-foreground">{type.credentialType}</TableCell>
                  <TableCell className="hidden xl:table-cell text-sm text-muted-foreground">{type.standardization}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </div>
    </TooltipProvider>
  );
}
