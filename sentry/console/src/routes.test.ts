import { describe, expect, it } from "vitest";

import { AREAS, areaForPath, SURFACES, surfacesForArea } from "./routes";

describe("console information architecture", () => {
  it("keeps all routes under exactly five operator tasks", () => {
    expect(AREAS).toHaveLength(5);
    expect(SURFACES).toHaveLength(16);
    expect(new Set(SURFACES.map((surface) => surface.path)).size).toBe(16);
    for (const surface of SURFACES) {
      expect(areaForPath(surface.path)?.id).toBe(surface.area);
      expect(surface.aliases.length).toBeGreaterThan(0);
    }
  });

  it("gives every task a valid landing view", () => {
    for (const area of AREAS) {
      expect(surfacesForArea(area.id).some((surface) => surface.path === area.landing)).toBe(true);
    }
  });
});
