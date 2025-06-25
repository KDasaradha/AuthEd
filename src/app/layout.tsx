import type { Metadata } from 'next';
import './globals.css';
import { SidebarProvider, Sidebar, SidebarInset } from '@/components/ui/sidebar';
import { Toaster } from '@/components/ui/toaster';
import { Header } from '@/components/layout/Header';
import { SideNav } from '@/components/layout/SideNav';
import { cn } from '@/lib/utils';
import { ThemeProvider } from '@/components/ThemeProvider';

export const metadata: Metadata = {
  title: {
    default: 'AuthShowcase: Learn, Visualize & Experiment with Authentication',
    template: '%s | AuthShowcase',
  },
  description: 'A developer-centric platform to learn, visualize, and experiment with 25+ authentication types, featuring interactive demos and modern design.',
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link href="https://fonts.googleapis.com/css2?family=PT+Sans:wght@400;700&display=swap" rel="stylesheet" />
        <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300..700&display=swap" rel="stylesheet" />
      </head>
      <body className={cn('font-body antialiased min-h-screen')}>
        <ThemeProvider
          attribute="class"
          defaultTheme="system"
          enableSystem
          disableTransitionOnChange
        >
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
        </ThemeProvider>
      </body>
    </html>
  );
}
