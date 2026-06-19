import { create } from "zustand";

export type AuthState = "authed";

interface AuthStore {
  state: AuthState;
  username: string | null;
  role: string | null;
  refresh: () => Promise<void>;
}

export const useAuth = create<AuthStore>(() => ({
  state: "authed",
  username: "admin",
  role: "admin",

  refresh: async () => {},
}));
