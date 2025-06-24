import { authTypes } from "@/lib/auth-types-data";
import { AuthTypeCard } from "@/components/auth/AuthTypeCard";
import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Authentication Types',
  description: 'Explore 25 different methods of authentication, from basic to advanced.',
};

export default function AuthTypesPage() {
  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-4xl font-bold tracking-tight">Authentication Types</h1>
        <p className="mt-2 text-lg text-muted-foreground">
          Explore our comprehensive library of 25 authentication methods. Click on any card to see a detailed explanation, use cases, and an interactive demo.
        </p>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {authTypes.map((authType) => (
          <AuthTypeCard key={authType.slug} authType={authType} />
        ))}
      </div>
    </div>
  );
}
