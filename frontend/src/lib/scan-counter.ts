import { useSyncExternalStore } from "react";

const STORAGE_KEY = "ares:scan_count";
const MAX_SCANS = 10;

function getCount(): number {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : MAX_SCANS;
  } catch {
    return MAX_SCANS;
  }
}

function setCount(count: number) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(count));
}

function subscribe(cb: () => void) {
  window.addEventListener("storage", cb);
  return () => window.removeEventListener("storage", cb);
}

export function useScanCount() {
  const remaining = useSyncExternalStore(subscribe, getCount);

  const decrement = () => {
    if (remaining <= 0) return;
    setCount(remaining - 1);
    window.dispatchEvent(new Event("storage"));
  };

  const reset = () => {
    setCount(MAX_SCANS);
    window.dispatchEvent(new Event("storage"));
  };

  return { remaining, max: MAX_SCANS, decrement, reset, exhausted: remaining <= 0 };
}
