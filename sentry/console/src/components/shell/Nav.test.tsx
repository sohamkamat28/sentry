import { fireEvent, render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { CommandPalette } from "./CommandPalette";
import { Nav } from "./Nav";

describe("Nav", () => {
  // Asserted on `href` rather than `textContent`: the active entry also renders
  // its plain-English description, so the text of one link is no longer just
  // its label. Hrefs pin the same flat set and the same order, and additionally
  // pin the landing surface — `/` is Command Centre, with Triage at `/triage`.
  it("shows the fifteen requested destinations as one flat set of tabs", () => {
    render(<Nav path="/forecast" />);
    const navigation = screen.getByRole("navigation", { name: "Primary" });

    expect(within(navigation).getAllByRole("link").slice(1).map((link) => link.getAttribute("href"))).toEqual([
      "#/triage",
      "#/",
      "#/estate",
      "#/classification",
      "#/sensor",
      "#/behaviour",
      "#/risk",
      "#/forecast",
      "#/findings",
      "#/remediation",
      "#/decommission",
      "#/zerotrust",
      "#/threat",
      "#/operations",
      "#/audit",
    ]);
    expect(within(navigation).queryByRole("link", { name: /Correlation/ })).toBeNull();
    expect(within(navigation).queryByText("Posture")).toBeNull();

    const current = within(navigation).getByRole("link", { name: /Forecast/ });
    expect(current.getAttribute("aria-current")).toBe("page");
    // Every destination carries a plain-English line on hover, so a reader who
    // does not know the domain can tell the sixteen apart before clicking.
    expect(current.getAttribute("title")).toBe("Which APIs are dying, and how soon");
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
