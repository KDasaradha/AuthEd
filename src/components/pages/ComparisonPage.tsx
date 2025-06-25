'use client';

import { useState, useMemo } from 'react';
import { authTypes } from "@/lib/auth-types-data";
import { Badge } from "@/components/ui/badge";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { CheckCircle2, XCircle, Search, SlidersHorizontal, ArrowUpDown } from 'lucide-react';
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '../ui/dropdown-menu';

const initialFilters = {
    security: 'all',
    complexity: 'all',
    developerExperience: 'all'
};

export function ComparisonPage() {
    const [searchTerm, setSearchTerm] = useState('');
    const [filters, setFilters] = useState(initialFilters);
    const [sortConfig, setSortConfig] = useState({ key: 'name', direction: 'asc' });

    const filteredAndSortedTypes = useMemo(() => {
        let filtered = authTypes.filter(type =>
            type.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
            type.description.toLowerCase().includes(searchTerm.toLowerCase())
        );

        filtered = filtered.filter(type => {
            return (filters.security === 'all' || type.security === filters.security) &&
                   (filters.complexity === 'all' || type.complexity === filters.complexity) &&
                   (filters.developerExperience === 'all' || type.developerExperience === filters.developerExperience);
        });

        filtered.sort((a, b) => {
            const key = sortConfig.key as keyof typeof a;
            let valA = a[key];
            let valB = b[key];
            
            if (typeof valA === 'string' && typeof valB === 'string') {
              const comparison = valA.localeCompare(valB);
              return sortConfig.direction === 'asc' ? comparison : -comparison;
            }
            return 0;
        });

        return filtered;
    }, [searchTerm, filters, sortConfig]);

    const handleFilterChange = (filterName: string, value: string) => {
        setFilters(prev => ({ ...prev, [filterName]: value }));
    };

    const resetFilters = () => {
        setSearchTerm('');
        setFilters(initialFilters);
        setSortConfig({ key: 'name', direction: 'asc' });
    };

    const handleSort = (key: string) => {
      setSortConfig(prev => ({
        key,
        direction: prev.key === key && prev.direction === 'asc' ? 'desc' : 'asc'
      }));
    }

    const getBadgeVariant = (level: 'Low' | 'Medium' | 'High' | 'Easy' | 'Moderate' | 'Complex') => {
        switch (level) {
            case 'High': case 'Easy': return 'default';
            case 'Medium': case 'Moderate': return 'secondary';
            case 'Low': case 'Complex': return 'destructive';
            default: return 'outline';
        }
    };

    return (
        <div className="space-y-8">
            <header className="space-y-2">
                <h1 className="text-4xl font-bold tracking-tight">Advanced Comparison</h1>
                <p className="text-lg text-muted-foreground">
                    Interactively filter and sort authentication methods to find the perfect fit for your needs.
                </p>
            </header>

            <Card>
                <CardHeader className="flex flex-row items-center justify-between">
                    <div className="flex items-center gap-2">
                        <SlidersHorizontal className="w-5 h-5 text-muted-foreground" />
                        <CardTitle className="text-2xl">Filter & Sort</CardTitle>
                    </div>
                    <Button variant="ghost" onClick={resetFilters}>Reset All</Button>
                </CardHeader>
                <CardContent className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                    <div className="space-y-2">
                        <Label htmlFor="search">Search</Label>
                        <div className="relative">
                            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                            <Input
                                id="search"
                                placeholder="Search by name or description..."
                                value={searchTerm}
                                onChange={(e) => setSearchTerm(e.target.value)}
                                className="pl-10"
                            />
                        </div>
                    </div>
                    <div className="space-y-2">
                        <Label htmlFor="security">Security Level</Label>
                        <Select value={filters.security} onValueChange={(value) => handleFilterChange('security', value)}>
                            <SelectTrigger id="security"><SelectValue /></SelectTrigger>
                            <SelectContent>
                                <SelectItem value="all">All Security Levels</SelectItem>
                                <SelectItem value="High">High</SelectItem>
                                <SelectItem value="Medium">Medium</SelectItem>
                                <SelectItem value="Low">Low</SelectItem>
                            </SelectContent>
                        </Select>
                    </div>
                    <div className="space-y-2">
                        <Label htmlFor="complexity">Implementation Complexity</Label>
                        <Select value={filters.complexity} onValueChange={(value) => handleFilterChange('complexity', value)}>
                            <SelectTrigger id="complexity"><SelectValue /></SelectTrigger>
                            <SelectContent>
                                <SelectItem value="all">All Complexities</SelectItem>
                                <SelectItem value="High">High</SelectItem>
                                <SelectItem value="Medium">Medium</SelectItem>
                                <SelectItem value="Low">Low</SelectItem>
                            </SelectContent>
                        </Select>
                    </div>
                    <div className="space-y-2">
                        <Label htmlFor="dev-exp">Developer Experience</Label>
                         <Select value={filters.developerExperience} onValueChange={(value) => handleFilterChange('developerExperience', value)}>
                            <SelectTrigger id="dev-exp"><SelectValue /></SelectTrigger>
                            <SelectContent>
                                <SelectItem value="all">All Dev Experiences</SelectItem>
                                <SelectItem value="Complex">Complex</SelectItem>
                                <SelectItem value="Moderate">Moderate</SelectItem>
                                <SelectItem value="Easy">Easy</SelectItem>
                            </SelectContent>
                        </Select>
                    </div>
                </CardContent>
            </Card>
            
            <div className="flex items-center justify-between">
                <p className="text-sm text-muted-foreground">Showing <span className="font-bold text-foreground">{filteredAndSortedTypes.length}</span> of {authTypes.length} methods.</p>
                <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                        <Button variant="outline">
                            <ArrowUpDown className="mr-2 h-4 w-4" />
                            Sort by: {sortConfig.key.charAt(0).toUpperCase() + sortConfig.key.slice(1)} ({sortConfig.direction})
                        </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end">
                        <DropdownMenuItem onClick={() => handleSort('name')}>Name</DropdownMenuItem>
                        <DropdownMenuItem onClick={() => handleSort('security')}>Security</DropdownMenuItem>
                        <DropdownMenuItem onClick={() => handleSort('complexity')}>Complexity</DropdownMenuItem>
                    </DropdownMenuContent>
                </DropdownMenu>
            </div>

            {filteredAndSortedTypes.length > 0 ? (
                <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6">
                    {filteredAndSortedTypes.map((type) => (
                        <Card key={type.slug} className="flex flex-col h-full hover:border-primary/80 hover:shadow-lg transition-all duration-300">
                            <CardHeader>
                                <CardTitle>{type.name}</CardTitle>
                                <CardDescription>{type.description}</CardDescription>
                            </CardHeader>
                            <CardContent className="flex-grow space-y-4">
                                <div className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
                                    <div className="flex justify-between items-center"><span>Security</span> <Badge variant={getBadgeVariant(type.security)}>{type.security}</Badge></div>
                                    <div className="flex justify-between items-center"><span>Complexity</span> <Badge variant={getBadgeVariant(type.complexity)}>{type.complexity}</Badge></div>
                                    <div className="flex justify-between items-center"><span>Dev Experience</span> <Badge variant={getBadgeVariant(type.developerExperience)}>{type.developerExperience}</Badge></div>
                                    <div className="flex justify-between items-center"><span>SSO</span> <Badge variant={type.ssoCapability === 'Native' ? 'default' : type.ssoCapability === 'Possible' ? 'secondary' : 'outline'}>{type.ssoCapability}</Badge></div>
                                </div>
                                <Separator />
                                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                                    <div>
                                        <h4 className="font-semibold mb-2 flex items-center gap-2"><CheckCircle2 className="w-4 h-4 text-green-500" /> Pros</h4>
                                        <ul className="list-inside space-y-1 text-xs text-muted-foreground">
                                            {type.pros.map(pro => <li key={pro}>- {pro}</li>)}
                                        </ul>
                                    </div>
                                    <div>
                                        <h4 className="font-semibold mb-2 flex items-center gap-2"><XCircle className="w-4 h-4 text-red-500" /> Cons</h4>
                                        <ul className="list-inside space-y-1 text-xs text-muted-foreground">
                                            {type.cons.map(con => <li key={con}>- {con}</li>)}
                                        </ul>
                                    </div>
                                </div>
                            </CardContent>
                            <CardFooter>
                                <Button asChild className="w-full">
                                    <Link href={`/auth-types/${type.slug}`}>View Details</Link>
                                </Button>
                            </CardFooter>
                        </Card>
                    ))}
                </div>
            ) : (
                <div className="text-center py-16 border-2 border-dashed rounded-lg">
                    <p className="font-semibold">No authentication types match your criteria.</p>
                    <p className="text-muted-foreground mt-1">Try adjusting your filters or search term.</p>
                    <Button variant="outline" className="mt-4" onClick={resetFilters}>Reset Filters</Button>
                </div>
            )}
        </div>
    );
}
