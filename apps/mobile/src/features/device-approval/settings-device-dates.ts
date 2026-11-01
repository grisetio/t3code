const DAY_MS = 24 * 60 * 60 * 1000;

const startOfDay = (epochMilliseconds: number) => {
  const date = new Date(epochMilliseconds);
  return new Date(date.getFullYear(), date.getMonth(), date.getDate()).getTime();
};

/** "today", "yesterday", "Oct 31", or "Oct 31, 2025" outside the current year, in local time. */
export function formatDeviceDay(epochMilliseconds: number, now: number, locale?: string): string {
  // Rounding absorbs the hour a daylight-saving change adds or removes between the two days.
  const daysAgo = Math.round((startOfDay(now) - startOfDay(epochMilliseconds)) / DAY_MS);
  if (daysAgo === 0) return "today";
  if (daysAgo === 1) return "yesterday";
  const date = new Date(epochMilliseconds);
  return date.toLocaleDateString(locale, {
    month: "short",
    day: "numeric",
    ...(date.getFullYear() === new Date(now).getFullYear() ? {} : { year: "numeric" }),
  });
}

export function formatDeviceUse(
  device: {
    readonly enrolledAt: { readonly epochMilliseconds: number };
    readonly lastUsedAt: { readonly epochMilliseconds: number } | null;
  },
  now: number,
  locale?: string,
): string {
  const added = `Added ${formatDeviceDay(device.enrolledAt.epochMilliseconds, now, locale)}`;
  return device.lastUsedAt === null
    ? added
    : `${added} · Used ${formatDeviceDay(device.lastUsedAt.epochMilliseconds, now, locale)}`;
}
