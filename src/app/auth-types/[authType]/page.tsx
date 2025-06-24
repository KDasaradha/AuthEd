import { authTypes } from "@/lib/auth-types-data";
import { notFound } from "next/navigation";
import type { Metadata } from "next";
import { AuthTypeDetailPage } from "@/components/pages/AuthTypeDetailPage";

type Props = {
  params: { authType: string };
};

export async function generateStaticParams() {
  return authTypes.map((type) => ({
    authType: type.slug,
  }));
}

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const authType = authTypes.find((type) => type.slug === params.authType);
  if (!authType) {
    return {};
  }
  return {
    title: authType.name,
    description: authType.description,
  };
}

export default function AuthTypeDetail({ params }: Props) {
  const authType = authTypes.find((type) => type.slug === params.authType);

  if (!authType) {
    notFound();
  }

  return <AuthTypeDetailPage authType={authType} />;
}
