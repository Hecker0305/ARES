import { create } from "zustand";
import type { WSEvent } from "@/api/types";

type WSStatus = "idle" | "connecting" | "connected" | "disconnected" | "reconnecting";

interface WSStore {
  status: WSStatus;
  events: WSEvent[];
  paused: boolean;
  subscribedInstance: string | null;
  connect: () => void;
  disconnect: () => void;
  pushEvent: (event: WSEvent) => void;
  subscribe: (instanceId: string) => void;
  unsubscribe: () => void;
  sendStatusRequest: () => void;
  pause: () => void;
  resume: () => void;
  clear: () => void;
}

const MAX_EVENTS = 1000;
const DEDUP_WINDOW = 200;

function eventKey(e: WSEvent): string {
  return `${e.timestamp || ""}|${e.instance_id || ""}|${e.type}|${e.tool_name || ""}|${(e.content || e.output || "").substring(0, 80)}`;
}

const seenKeys = new Set<string>();

function isDuplicate(event: WSEvent): boolean {
  const key = eventKey(event);
  if (seenKeys.has(key)) return true;
  seenKeys.add(key);
  if (seenKeys.size > DEDUP_WINDOW * 2) {
    const arr = Array.from(seenKeys);
    seenKeys.clear();
    arr.slice(-DEDUP_WINDOW).forEach((k) => seenKeys.add(k));
  }
  return false;
}

let ws: WebSocket | null = null;
let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
let reconnectDelay = 1000;
let keepAliveTimer: ReturnType<typeof setInterval> | null = null;
const MAX_RECONNECT_DELAY = 30000;

function createWSConnection() {
  if (ws) return;

  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  if (window.location.protocol === "http:" && import.meta.env.PROD) {
    console.warn("[WS] Insecure WebSocket connection in production. Use HTTPS.");
  }
  const wsUrl = `${protocol}//${window.location.host}/ws`;

  useWSStore.setState({ status: "connecting" });

  try {
    ws = new WebSocket(wsUrl);
  } catch {
    scheduleReconnect();
    return;
  }

  ws.onopen = () => {
    reconnectDelay = 1000;
    useWSStore.setState({ status: "connected" });

    keepAliveTimer = setInterval(() => {
      if (ws?.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: "ping" }));
      }
    }, 25000);

    const sub = useWSStore.getState().subscribedInstance;
    if (sub && ws?.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ scan_id: sub, type: "get_status" }));
    }
  };

  ws.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data) as WSEvent;
      if (!useWSStore.getState().paused && !isDuplicate(data)) {
        useWSStore.getState().pushEvent(data);
      }
    } catch {
      console.warn("[WS] Failed to parse message", event.data);
    }
  };

  ws.onclose = () => {
    if (keepAliveTimer) {
      clearInterval(keepAliveTimer);
      keepAliveTimer = null;
    }
    ws = null;
    useWSStore.setState({ status: "disconnected" });
    scheduleReconnect();
  };

  ws.onerror = () => {
    ws?.close();
  };
}

function scheduleReconnect() {
  if (reconnectTimer) return;

  // Debounce: only show "reconnecting" if still disconnected after 1.5 s
  const debounce = setTimeout(() => {
    useWSStore.setState({ status: "reconnecting" });
  }, 1500);

  reconnectTimer = setTimeout(() => {
    reconnectTimer = null;
    clearTimeout(debounce);
    reconnectDelay = Math.min(reconnectDelay * 2, MAX_RECONNECT_DELAY);
    createWSConnection();
  }, reconnectDelay);
}

export const useWSStore = create<WSStore>((set, get) => ({
  status: "idle",
  events: [],
  paused: false,
  subscribedInstance: null,

  connect: () => {
    createWSConnection();
  },

  disconnect: () => {
    if (reconnectTimer) {
      clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }
    if (ws) {
      ws.close();
      ws = null;
    }
    set({ status: "idle" });
  },

  pushEvent: (event: WSEvent) => {
    set((state) => {
      const events = [...state.events, event];
      if (events.length > MAX_EVENTS) {
        events.splice(0, events.length - MAX_EVENTS);
      }
      return { events };
    });
  },

  subscribe: (instanceId: string) => {
    set({ subscribedInstance: instanceId });
    if (ws?.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ scan_id: instanceId, type: "get_status" }));
    }
  },

  sendStatusRequest: () => {
    const instanceId = get().subscribedInstance;
    if (instanceId && ws?.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ scan_id: instanceId, type: "get_status" }));
    }
  },

  unsubscribe: () => {
    set({ subscribedInstance: null });
  },

  pause: () => set({ paused: true }),
  resume: () => set({ paused: false }),
  clear: () => {
    seenKeys.clear();
    set({ events: [] });
  },
}));

export async function fetchEventHistory(instanceId: string): Promise<WSEvent[]> {
  const res = await fetch(`/api/instances/${instanceId}/events`);
  if (!res.ok) {
    throw new Error(`Failed to fetch event history: ${res.statusText}`);
  }
  return res.json() as Promise<WSEvent[]>;
}
