import { ComparisonPage } from "@/components/pages/ComparisonPage";
import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Comparison of Authentication Types',
};

export default function Comparison() {
  return <ComparisonPage />;
}
