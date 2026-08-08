import { fireEvent, render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { CommandPalette } from "./CommandPalette";
import { Nav } from "./Nav";

describe("Nav", () => {
  it("shows the fifteen requested destinations as one flat set of tabs", () => {
    render(<Nav path="/forecast" />);
    const navigation = screen.getByRole("navigation", { name: "Primary" });

    expect(within(navigation).getAllByRole("link").slice(1).map((link) => link.textContent)).toEqual([
      "Triage",
      "Command Centre",
      "Estate Register",
      "Classification",
      "Sensor Grid",
      "Behaviour",
      "Risk Register",
      "Forecast",
      "Findings",
      "Remediation",
      "Decommission",
      "Zero-Trust",
      "Threat",
      "Operations",
      "Audit",
    ]);
    expect(within(navigation).queryByRole("link", { name: "Correlation" })).toBeNull();
    expect(within(navigation).queryByText("Posture")).toBeNull();
    expect(within(navigation).getByRole("link", { name: "Forecast" }).getAttribute("aria-current")).toBe("page");
  });

  it("keeps the command palette available from its original keyboard shortcut", () => {
    render(
      <>
        <Nav path="/" />
        <CommandPalette />
      </>,
    );
    fireEvent.keyDown(window, { key: "k", metaKey: true });
    expect(screen.getByRole("dialog", { name: "Command palette" })).toBeTruthy();
    expect(screen.getByPlaceholderText("Search all views…")).toBeTruthy();
    expect(screen.getByRole("option", { name: /Findings/ })).toBeTruthy();

    fireEvent.change(screen.getByPlaceholderText("Search all views…"), {
      target: { value: "Data sources" },
    });
    expect(screen.getByRole("option", { name: /Sensor Grid/ })).toBeTruthy();
  });
});
