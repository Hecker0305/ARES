import { Link } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Home } from "lucide-react";

export function NotFoundPage() {
  return (
    <div className="flex flex-col items-center justify-center h-full p-6">
      <h1 className="text-6xl font-bold text-muted-foreground">404</h1>
      <p className="mt-4 text-lg text-muted-foreground">Page not found</p>
      <Button asChild className="mt-6">
        <Link to="/">
          <Home className="h-4 w-4" />
          Back to Overview
        </Link>
      </Button>
    </div>
  );
}
