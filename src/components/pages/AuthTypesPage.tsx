'use client';

import { useState, useMemo } from 'react';
import { authTypes } from "@/lib/auth-types-data";
import { AuthTypeCard } from "@/components/auth/AuthTypeCard";
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { motion } from 'framer-motion';
import { Search } from 'lucide-react';
import { Label } from '@/components/ui/label';

const initialFilters = {
    security: 'all',
    complexity: 'all',
};

export function AuthTypesPage() {
    const [searchTerm, setSearchTerm] = useState('');
    const [filters, setFilters] = useState(initialFilters);

    const filteredTypes = useMemo(() => {
        return authTypes.filter(type => {
            const matchesSearch = type.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                                  type.description.toLowerCase().includes(searchTerm.toLowerCase());
            
            const matchesSecurity = filters.security === 'all' || type.security === filters.security;
            const matchesComplexity = filters.complexity === 'all' || type.complexity === filters.complexity;

            return matchesSearch && matchesSecurity && matchesComplexity;
        });
    }, [searchTerm, filters]);

    const handleFilterChange = (filterName: string, value: string) => {
        setFilters(prev => ({ ...prev, [filterName]: value }));
    };

    const containerVariants = {
        hidden: { opacity: 0 },
        visible: {
            opacity: 1,
            transition: {
                staggerChildren: 0.05,
            },
        },
    };

    const itemVariants = {
        hidden: { y: 20, opacity: 0 },
        visible: {
            y: 0,
            opacity: 1,
        },
    };

    return (
    <div className="space-y-8">
        <header className="space-y-2">
            <h1 className="text-4xl font-bold tracking-tight">Authentication Types</h1>
            <p className="mt-2 text-lg text-muted-foreground">
                Explore our comprehensive library of 25 authentication methods. Use the filters to find the right solution for your needs.
            </p>
        </header>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="md:col-span-1">
                <Label htmlFor="search" className="sr-only">Search</Label>
                <div className="relative">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                    <Input
                        id="search"
                        placeholder="Search by name..."
                        value={searchTerm}
                        onChange={(e) => setSearchTerm(e.target.value)}
                        className="pl-10"
                    />
                </div>
            </div>
            <div>
                <Label htmlFor="security" className="sr-only">Security Level</Label>
                <Select value={filters.security} onValueChange={(value) => handleFilterChange('security', value)}>
                    <SelectTrigger id="security"><SelectValue placeholder="Filter by security" /></SelectTrigger>
                    <SelectContent>
                        <SelectItem value="all">All Security Levels</SelectItem>
                        <SelectItem value="High">High</SelectItem>
                        <SelectItem value="Medium">Medium</SelectItem>
                        <SelectItem value="Low">Low</SelectItem>
                    </SelectContent>
                </Select>
            </div>
            <div>
                <Label htmlFor="complexity" className="sr-only">Complexity</Label>
                <Select value={filters.complexity} onValueChange={(value) => handleFilterChange('complexity', value)}>
                    <SelectTrigger id="complexity"><SelectValue placeholder="Filter by complexity" /></SelectTrigger>
                    <SelectContent>
                        <SelectItem value="all">All Complexities</SelectItem>
                        <SelectItem value="High">High</SelectItem>
                        <SelectItem value="Medium">Medium</SelectItem>
                        <SelectItem value="Low">Low</SelectItem>
                    </SelectContent>
                </Select>
            </div>
        </div>

        {filteredTypes.length > 0 ? (
            <motion.div 
                className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6"
                variants={containerVariants}
                initial="hidden"
                animate="visible"
            >
                {filteredTypes.map((authType) => (
                    <motion.div key={authType.slug} variants={itemVariants}>
                        <AuthTypeCard authType={authType} />
                    </motion.div>
                ))}
            </motion.div>
        ) : (
            <div className="text-center py-16 border-2 border-dashed rounded-lg bg-card/50">
                <p className="text-2xl font-semibold tracking-tight">No Results Found</p>
                <p className="text-muted-foreground mt-2">Try adjusting your search or filter criteria.</p>
            </div>
        )}
    </div>
    );
}
