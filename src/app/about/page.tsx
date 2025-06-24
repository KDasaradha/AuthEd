import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'About',
};

export default function AboutPage() {
  return (
    <div className="space-y-8">
      <h1 className="text-4xl font-bold tracking-tight">About AuthEd</h1>
      
      <Card>
        <CardHeader>
          <CardTitle>Project Purpose</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4 text-muted-foreground">
          <p>
            AuthEd is an educational platform designed to demystify the complex world of digital authentication and authorization. 
            Our primary objective is to provide developers, students, and security enthusiasts with a clear, comprehensive, and interactive resource to understand these critical security concepts.
          </p>
          <p>
            This project serves as a functional frontend companion to a FastAPI backend project, demonstrating 25 distinct authentication types in a practical, hands-on manner.
          </p>
        </CardContent>
      </Card>

      <div className="grid md:grid-cols-2 gap-8">
        <Card>
          <CardHeader>
            <CardTitle>Core Features</CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="list-disc pl-5 space-y-2 text-muted-foreground">
              <li>In-depth explanation of Authentication vs. Authorization.</li>
              <li>Detailed guides for 25 different authentication methods.</li>
              <li>Interactive demos to see authentication flows in action.</li>
              <li>Visual diagrams illustrating complex protocols.</li>
              <li>A comparison table to evaluate methods side-by-side.</li>
            </ul>
          </CardContent>
        </Card>
        
        <Card>
          <CardHeader>
            <CardTitle>Technology Stack</CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="list-disc pl-5 space-y-2 text-muted-foreground">
              <li><strong>Framework:</strong> Next.js (App Router)</li>
              <li><strong>Language:</strong> TypeScript</li>
              <li><strong>Styling:</strong> Tailwind CSS</li>
              <li><strong>UI Components:</strong> Shadcn/UI</li>
              <li><strong>Diagrams:</strong> Custom SVG & placeholder components</li>
            </ul>
          </CardContent>
        </Card>
      </div>
      
      <Card>
        <CardHeader>
          <CardTitle>Project Resources</CardTitle>
        </CardHeader>
        <CardContent className="text-muted-foreground">
            <p>
                This frontend application is designed to work with a corresponding backend implementation. For more details on the backend, please refer to the project's repository (link to be added).
            </p>
        </CardContent>
      </Card>
    </div>
  )
}
