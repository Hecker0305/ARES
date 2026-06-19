import { create } from "zustand";

interface SettingsState {
  adminUsername: string;
  setAdminUsername: (username: string) => void;
}

export const useSettings = create<SettingsState>((set) => ({
  adminUsername: "admin",
  setAdminUsername: (username) => set({ adminUsername: username }),
}));