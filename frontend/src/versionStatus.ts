export const VERSION_STATUS_LABELS: Record<string, string> = {
  match: "Matches approved",
  mismatch: "Mismatch",
  not_reported: "Not reported",
  not_configured: "No approved version configured",
};

export function versionStatusLabel(status: string | undefined | null): string {
  if (!status) return VERSION_STATUS_LABELS.not_reported;
  return VERSION_STATUS_LABELS[status] || status.replaceAll("_", " ");
}

export function recordedVersion(
  provenance: Record<string, unknown> | null | undefined,
  key: string,
  ...aliases: string[]
): string {
  for (const candidate of [key, ...aliases]) {
    const value = provenance?.[candidate];
    if (typeof value === "string" && value.trim()) return value;
  }
  return "Not Recorded";
}
