import { LiveFeed } from "@/components/live-feed";

export function LivePage() {
  return (
    <div className="flex flex-col h-[calc(100vh-3.5rem)]">
      <div className="flex items-center justify-between px-6 py-3 border-b">
        <h1 className="text-xl font-bold">Live Feed</h1>
      </div>
      <div className="flex-1">
        <LiveFeed />
      </div>
    </div>
  );
}
