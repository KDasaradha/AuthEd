import type { Metadata } from 'next';
import './globals.css';
import { SidebarProvider, Sidebar, SidebarInset } from '@/components/ui/sidebar';
import { Toaster } from '@/components/ui/toaster';
import { Header } from '@/components/layout/Header';
import { SideNav } from '@/components/layout/SideNav';
import { cn } from '@/lib/utils';

export const metadata: Metadata = {
  title: {
    default: 'AuthEd: Authentication & Authorization Explained',
    template: '%s | AuthEd',
  },
  description: 'An educational platform to learn about 25 authentication types, understand the difference between authentication and authorization, with interactive demos and technical deep dives.',
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="light" suppressHydrationWarning>
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link href="https://fonts.googleapis.com/css2?family=PT+Sans:ital,wght@0,400;0,700;1,400;1,700&display=swap" rel="stylesheet" />
        <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300..700&display=swap" rel="stylesheet" />
      </head>
      <body className={cn('font-body antialiased min-h-screen')}>
        <SidebarProvider>
            <div className="flex min-h-screen flex-col">
              <Header />
              <div className="flex flex-1">
                <Sidebar className="hidden md:flex md:flex-col md:w-64" variant="sidebar" side="left" collapsible="icon">
                  <SideNav />
                </Sidebar>
                <SidebarInset className="flex-1">
                  <main className="p-4 md:p-6 lg:p-8">
                    {children}
                  </main>
                </SidebarInset>
              </div>
            </div>
        </SidebarProvider>
        <Toaster />
      </body>
    </html>
  );
}
