import { useState } from "react";
import { useStartCloudScan } from "@/api/queries";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/input";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Search, FileText } from "lucide-react";

export function CloudScannerPage() {
  const startCloudScan = useStartCloudScan();
  const [path, setPath] = useState("");
  const [scanResults, setScanResults] = useState<string | null>(null);

  const handleScan = async () => {
    if (!path.trim()) return;
    const result = await startCloudScan.mutateAsync(path.trim());
    setScanResults(JSON.stringify(result, null, 2));
  };

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Cloud Scanner</h1>
        <p className="text-muted-foreground mt-1">Terraform and CloudFormation misconfiguration detection.</p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Search className="h-5 w-5" />
            Scan Infrastructure Config
          </CardTitle>
          <CardDescription>Provide the path to your Terraform or CloudFormation files.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label>File/Directory Path</Label>
            <Input
              placeholder="/path/to/terraform/main.tf"
              value={path}
              onChange={(e) => setPath(e.target.value)}
            />
          </div>
          <Button onClick={handleScan} disabled={startCloudScan.isPending || !path.trim()}>
            {startCloudScan.isPending ? "Scanning..." : "Start Scan"}
          </Button>
        </CardContent>
      </Card>

      {startCloudScan.isPending && (
        <Card>
          <CardContent className="pt-6">
            <div className="space-y-3">
              <Skeleton className="h-4 w-3/4" />
              <Skeleton className="h-4 w-1/2" />
              <Skeleton className="h-4 w-2/3" />
            </div>
          </CardContent>
        </Card>
      )}

      {scanResults && (
        <Card>
          <CardHeader><CardTitle>Scan Results</CardTitle></CardHeader>
          <CardContent><pre className="rounded bg-muted/50 p-4 text-sm font-mono overflow-x-auto">{scanResults}</pre></CardContent>
        </Card>
      )}

      {/* Validation */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <FileText className="h-5 w-5" />
            Validate Config Line
          </CardTitle>
          <CardDescription>Check a single configuration line for issues.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <Textarea placeholder='resource "aws_s3_bucket" "example" {' className="min-h-20 font-mono text-sm" />
          <Button variant="outline">Validate</Button>
        </CardContent>
      </Card>
    </div>
  );
}
