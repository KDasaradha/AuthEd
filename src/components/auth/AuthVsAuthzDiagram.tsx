import { Card, CardContent } from "@/components/ui/card"
import { KeyRound, ShieldCheck } from "lucide-react"

export function AuthVsAuthzDiagram() {
  return (
    <Card className="w-full">
      <CardContent className="p-6">
        <div className="flex flex-col md:flex-row justify-around items-center gap-8 text-center">
          
          <div className="flex flex-col items-center space-y-3">
            <div className="rounded-full bg-primary/10 p-4">
              <KeyRound className="w-10 h-10 text-primary" />
            </div>
            <h3 className="text-xl font-semibold">Step 1: Authentication</h3>
            <p className="text-muted-foreground text-sm max-w-xs">Verifying your identity to gain access.</p>
            <p className="font-bold font-headline text-primary">"Who are you?"</p>
          </div>

          <div className="text-muted-foreground hidden md:block">
            <svg width="100" height="24" viewBox="0 0 100 24" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path d="M5 12H95" stroke="currentColor" strokeWidth="2" strokeDasharray="4 4"/>
              <path d="M90 7L95 12L90 17" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
          </div>
           <div className="text-muted-foreground md:hidden rotate-90 my-4">
            <svg width="24" height="100" viewBox="0 0 24 100" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path d="M12 5V95" stroke="currentColor" strokeWidth="2" strokeDasharray="4 4"/>
              <path d="M7 90L12 95L17 90" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
          </div>

          <div className="flex flex-col items-center space-y-3">
            <div className="rounded-full bg-accent/10 p-4">
              <ShieldCheck className="w-10 h-10 text-accent" />
            </div>
            <h3 className="text-xl font-semibold">Step 2: Authorization</h3>
            <p className="text-muted-foreground text-sm max-w-xs">Determining your permissions and access rights.</p>
            <p className="font-bold font-headline text-accent">"What can you do?"</p>
          </div>
          
        </div>
      </CardContent>
    </Card>
  )
}
