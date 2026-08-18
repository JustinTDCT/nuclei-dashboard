import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { api } from "./api";

interface TimezoneState {
  defaultTimezone: string;
}

const TimezoneContext = createContext<TimezoneState>({ defaultTimezone: "UTC" });

export function TimezoneProvider({ children }: { children: ReactNode }) {
  const [defaultTimezone, setDefaultTimezone] = useState("UTC");
  useEffect(() => {
    api<{ default_timezone: string }>("/api/display-settings")
      .then((data) => setDefaultTimezone(data.default_timezone || "UTC"))
      .catch(() => setDefaultTimezone("UTC"));
  }, []);
  return <TimezoneContext.Provider value={{ defaultTimezone }}>{children}</TimezoneContext.Provider>;
}

export function useTimezone() {
  return useContext(TimezoneContext);
}

export function formatUtc(value: string | null | undefined, timeZone = "UTC") {
  if (!value) return "—";
  try {
    return new Date(value).toLocaleString(undefined, { timeZone });
  } catch {
    return new Date(value).toLocaleString();
  }
}
