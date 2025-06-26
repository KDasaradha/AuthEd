import type { ComponentType } from 'react';

export type AuthType = {
  slug: string;
  name: string;
  description: string;
  category: string;
  useCase: string;
  security: 'Low' | 'Medium' | 'High';
  complexity: 'Low' | 'Medium' | 'High';
  protocols: string;
  technicalExplanation: string;
  setupInstructions: ComponentType;
  diagram: ComponentType;
  phishingResistance: 'Low' | 'Medium' | 'High' | 'N/A';
  ux: 'Low Friction' | 'Medium Friction' | 'High Friction' | 'N/A';
  credentialType: string;
  standardization: string;
  pros: string[];
  cons: string[];
  ssoCapability: 'Native' | 'Possible' | 'Not Suited';
  developerExperience: 'Easy' | 'Moderate' | 'Complex';
};
