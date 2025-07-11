
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
    category: 'all',
};

export function AuthTypesPage() {
    const [searchTerm, setSearchTerm] = useState('');
    const [filters, setFilters] = useState(initialFilters);

    const categories = useMemo(() => {
        const allCategories = authTypes.map(type => type.category);
        return [...new Set(allCategories)].sort();
    }, []);

    const filteredTypes = useMemo(() => {
        return authTypes.filter(type => {
            const matchesSearch = type.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                                  type.description.toLowerCase().includes(searchTerm.toLowerCase());
            
            const matchesSecurity = filters.security === 'all' || type.security === filters.security;
            const matchesComplexity = filters.complexity === 'all' || type.complexity === filters.complexity;
            const matchesCategory = filters.category === 'all' || type.category === filters.category;

            return matchesSearch && matchesSecurity && matchesComplexity && matchesCategory;
        });
    }, [searchTerm, filters]);

    const groupedTypes = useMemo(() => {
        return filteredTypes.reduce((acc, type) => {
            const category = type.category || 'Uncategorized';
            if (!acc[category]) {
                acc[category] = [];
            }
            acc[category].push(type);
            return acc;
        }, {} as Record<string, typeof filteredTypes>);
    }, [filteredTypes]);

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
                Explore our comprehensive library of {authTypes.length} authentication methods, organized by category. Use the filters to find the right solution.
            </p>
        </header>

        <div className="border rounded-lg p-4 bg-card/50">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            <div className="space-y-2">
              <Label htmlFor="search">Search by Keyword</Label>
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                  id="search"
                  placeholder="e.g. OAuth, Token..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="pl-10"
                />
              </div>
            </div>
            <div className="space-y-2">
              <Label htmlFor="category">Category</Label>
              <Select value={filters.category} onValueChange={(value) => handleFilterChange('category', value)}>
                <SelectTrigger id="category"><SelectValue placeholder="All Categories" /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Categories</SelectItem>
                  {categories.map(cat => <SelectItem key={cat} value={cat}>{cat}</SelectItem>)}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label htmlFor="security">Security Level</Label>
              <Select value={filters.security} onValueChange={(value) => handleFilterChange('security', value)}>
                <SelectTrigger id="security"><SelectValue placeholder="All Security Levels" /></SelectTrigger>
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
                <SelectTrigger id="complexity"><SelectValue placeholder="All Complexities" /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Complexities</SelectItem>
                  <SelectItem value="High">High</SelectItem>
                  <SelectItem value="Medium">Medium</SelectItem>
                  <SelectItem value="Low">Low</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
        </div>
        
        <p className="text-sm text-muted-foreground">
            Showing <span className="font-bold text-foreground">{filteredTypes.length}</span> of {authTypes.length} authentication methods.
        </p>

        <div className="space-y-12">
            {Object.keys(groupedTypes).length > 0 ? (
                Object.entries(groupedTypes).map(([category, types]) => (
                    <section key={category} className="space-y-6">
                        <h2 className="text-2xl font-bold tracking-tight border-b pb-2">{category}</h2>
                        <motion.div 
                            className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6"
                            variants={containerVariants}
                            initial="hidden"
                            animate="visible"
                        >
                            {types.map((authType) => (
                                <motion.div key={authType.slug} variants={itemVariants}>
                                    <AuthTypeCard authType={authType} />
                                </motion.div>
                            ))}
                        </motion.div>
                    </section>
                ))
            ) : (
                <div className="text-center py-16 border-2 border-dashed rounded-lg bg-card/50">
                    <p className="text-2xl font-semibold tracking-tight">No Results Found</p>
                    <p className="text-muted-foreground mt-2">Try adjusting your search or filter criteria.</p>
                </div>
            )}
        </div>
    </div>
    );
}
