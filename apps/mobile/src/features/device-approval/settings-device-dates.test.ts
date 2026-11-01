import { describe, expect, it } from "vite-plus/test";

import { formatDeviceDay, formatDeviceUse } from "./settings-device-dates";

// Local-time constructors keep the calendar-day comparisons independent of the test machine's zone.
const NOW = new Date(2026, 10, 1, 0, 30).getTime();
const at = (month: number, day: number, hour = 12, year = 2026) => ({
  epochMilliseconds: new Date(year, month, day, hour).getTime(),
});

describe("formatDeviceDay", () => {
  it("names recent calendar days, not 24-hour spans", () => {
    expect(formatDeviceDay(new Date(2026, 10, 1, 0, 5).getTime(), NOW, "en-US")).toBe("today");
    expect(formatDeviceDay(new Date(2026, 9, 31, 23, 50).getTime(), NOW, "en-US")).toBe(
      "yesterday",
    );
    expect(formatDeviceDay(at(9, 30).epochMilliseconds, NOW, "en-US")).toBe("Oct 30");
  });

  it("adds the year only outside the current one", () => {
    expect(formatDeviceDay(at(11, 30, 12, 2025).epochMilliseconds, NOW, "en-US")).toBe(
      "Dec 30, 2025",
    );
  });
});

describe("formatDeviceUse", () => {
  it("reads as a short added/used line", () => {
    expect(formatDeviceUse({ enrolledAt: at(9, 30), lastUsedAt: at(10, 1) }, NOW, "en-US")).toBe(
      "Added Oct 30 · Used today",
    );
    expect(formatDeviceUse({ enrolledAt: at(9, 30), lastUsedAt: null }, NOW, "en-US")).toBe(
      "Added Oct 30",
    );
  });
});
