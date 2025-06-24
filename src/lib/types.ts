export type AuthType = {
  slug: string;
  name: string;
  description: string;
  useCase: string;
  security: 'Low' | 'Medium' | 'High';
  complexity: 'Low' | 'Medium' | 'High';
  protocols: string;
  technicalExplanation: string;
  setupInstructions: React.ComponentType;
  diagram: React.ComponentType;
};
