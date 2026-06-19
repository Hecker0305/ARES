import { useQuery } from "@tanstack/react-query";
import { api } from "@/api/client";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Users, Shield } from "lucide-react";

export function EnterpriseIdentityPage() {
  const { data: ssoConfigs, isLoading } = useQuery({
    queryKey: ["ssoConfigs"],
    queryFn: api.getSSOConfigs,
  });

  const { data: scimData } = useQuery({
    queryKey: ["scimUsers"],
    queryFn: api.listSCIMUsers,
  });

  if (isLoading) return <Skeleton className="h-96" />;

  return (
    <div className="space-y-6 p-6">
      <div>
        <h1 className="text-2xl font-bold">Enterprise Identity</h1>
        <p className="text-muted-foreground">
          SAML SSO, SCIM provisioning, and identity provider integration
        </p>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <Card className="p-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Shield className="h-5 w-5" />
              <h2 className="font-medium">SSO Providers</h2>
            </div>
          </div>
          <div className="mt-3 space-y-2">
            {(!ssoConfigs || ssoConfigs.length === 0) && (
              <p className="text-sm text-muted-foreground">
                No SSO providers configured
              </p>
            )}
            {ssoConfigs?.map((cfg, i) => (
              <div
                key={i}
                className="rounded bg-muted/50 p-3 text-sm"
              >
                <div className="flex items-center gap-2">
                  <Badge variant="outline">{cfg.provider}</Badge>
                  <span className="font-medium">{cfg.entity_id}</span>
                </div>
                <p className="mt-1 text-xs text-muted-foreground">
                  SSO URL: {cfg.sso_url}
                </p>
              </div>
            ))}
          </div>
        </Card>

        <Card className="p-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Users className="h-5 w-5" />
              <h2 className="font-medium">SCIM Users</h2>
            </div>
            <Badge variant="outline">
              {scimData?.totalResults ?? 0} users
            </Badge>
          </div>
          <div className="mt-3 space-y-2">
            {(!scimData?.Resources || scimData.Resources.length === 0) && (
              <p className="text-sm text-muted-foreground">
                No SCIM users provisioned
              </p>
            )}
            {scimData?.Resources?.map((user) => (
              <div
                key={user.id}
                className="flex items-center justify-between rounded bg-muted/50 p-2"
              >
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium">{user.userName}</span>
                  <span className="text-xs text-muted-foreground">
                    {user.email}
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <Badge variant="outline" className="text-xs">
                    {user.role || "user"}
                  </Badge>
                  {user.active ? (
                    <Badge
                      variant="default"
                      className="h-2 w-2 rounded-full p-0"
                    />
                  ) : (
                    <Badge
                      variant="destructive"
                      className="h-2 w-2 rounded-full p-0"
                    />
                  )}
                </div>
              </div>
            ))}
          </div>
        </Card>
      </div>
    </div>
  );
}
