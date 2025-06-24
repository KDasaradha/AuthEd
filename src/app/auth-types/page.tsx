import type { Metadata } from 'next';
import { AuthTypesPage } from '@/components/pages/AuthTypesPage';

export const metadata: Metadata = {
  title: 'Authentication Types',
  description: 'Explore 25 different methods of authentication, from basic to advanced.',
};

export default function AuthTypes() {
  return <AuthTypesPage />;
}
