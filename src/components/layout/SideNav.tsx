'use client';

import { authTypes } from '@/lib/auth-types-data';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { SidebarMenu, SidebarMenuItem, SidebarMenuButton, SidebarContent, SidebarHeader, SidebarInput, SidebarGroup, SidebarGroupLabel } from '../ui/sidebar';
import { ScrollArea } from '../ui/scroll-area';
import { KeyRound } from 'lucide-react';
import { useSidebar } from '../ui/sidebar';
import { useState, useMemo } from 'react';
import { SheetTitle } from '../ui/sheet';

export function SideNav({ isMobile = false }: { isMobile?: boolean }) {
  const pathname = usePathname();
  const { setOpenMobile } = useSidebar();
  const [search, setSearch] = useState('');

  const filteredAuthTypes = useMemo(() => authTypes.filter(type => 
    type.name.toLowerCase().includes(search.toLowerCase()) || 
    type.description.toLowerCase().includes(search.toLowerCase())
  ), [search]);

  const handleLinkClick = () => {
    if (isMobile) {
      setOpenMobile(false);
    }
  };

  const mainLinks = [
    { href: '/auth-types', label: 'All Auth Types' },
    { href: '/comparison', label: 'Comparison Table' },
    { href: '/about', label: 'About Project' },
  ];

  return (
    <div className="flex flex-col h-full">
      {isMobile && (
        <SidebarHeader className='p-4 border-b'>
          <Link href="/" className="flex items-center space-x-2">
            <KeyRound className="h-6 w-6 text-primary" />
            <SheetTitle className="font-bold font-headline text-lg p-0 m-0">AuthEd</SheetTitle>
          </Link>
        </SidebarHeader>
      )}
      <SidebarHeader className="p-2">
         <SidebarInput placeholder="Search types..." value={search} onChange={(e) => setSearch(e.target.value)} />
      </SidebarHeader>
      <ScrollArea className="flex-1">
        <SidebarContent className="w-full p-0">
          {isMobile && (
            <SidebarGroup>
                <SidebarGroupLabel>Menu</SidebarGroupLabel>
                <SidebarMenu>
                  {mainLinks.map((link) => (
                    <SidebarMenuItem key={link.href}>
                      <SidebarMenuButton
                        asChild
                        onClick={handleLinkClick}
                        isActive={pathname === link.href}
                      >
                        <Link href={link.href}>{link.label}</Link>
                      </SidebarMenuButton>
                    </SidebarMenuItem>
                  ))}
                </SidebarMenu>
            </SidebarGroup>
          )}

          <SidebarGroup>
            <SidebarGroupLabel>Authentication Types</SidebarGroupLabel>
            <SidebarMenu>
              {filteredAuthTypes.map((type) => (
                <SidebarMenuItem key={type.slug}>
                  <SidebarMenuButton
                    asChild
                    onClick={handleLinkClick}
                    isActive={pathname === `/auth-types/${type.slug}`}
                    className="justify-start"
                    tooltip={type.name}
                  >
                    <Link href={`/auth-types/${type.slug}`}>
                      <span className="truncate">{type.name}</span>
                    </Link>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              ))}
               {filteredAuthTypes.length === 0 && (
                <p className='p-4 text-sm text-muted-foreground'>No types found.</p>
               )}
            </SidebarMenu>
          </SidebarGroup>
        </SidebarContent>
      </ScrollArea>
    </div>
  );
}
