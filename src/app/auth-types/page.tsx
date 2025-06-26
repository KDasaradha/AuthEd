import type { Metadata } from 'next';
import { AuthTypesPage } from '@/components/pages/AuthTypesPage';

export const metadata: Metadata = {
  title: 'Authentication Types',
  description: 'Explore our comprehensive library of 26 authentication methods, organized by category. Use the filters to find the right solution.',
};

export default function AuthTypes() {
  return <AuthTypesPage />;
}
