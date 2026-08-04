import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { Metric } from "./Metric";

describe("Metric", () => {
  it("renders an em dash while loading, never a zero", () => {
    // Showing 0 before results arrive reads as "none found" — a different claim
    // from "not yet known". This shipped once.
    render(<Metric loading value={undefined} label="Resurrection alerts" />);
    expect(screen.getByText("—")).toBeTruthy();
    expect(screen.queryByText("0")).toBeNull();
  });

  it("renders a real zero once the value has arrived", () => {
    render(<Metric value={0} label="Resurrection alerts" />);
    expect(screen.getByText("0")).toBeTruthy();
    expect(screen.queryByText("—")).toBeNull();
  });

  it("treats null as pending, not as zero", () => {
    render(<Metric value={null} label="Probes" />);
    expect(screen.getByText("—")).toBeTruthy();
  });

  it("marks a count derived from a degraded source", () => {
    render(<Metric value={126} label="Endpoints" degraded />);
    expect(screen.getByText(/degraded/i)).toBeTruthy();
  });

  it("shows the sub-label only when not pending", () => {
    const { rerender } = render(<Metric loading label="X" sub="threshold 0.85" />);
    expect(screen.queryByText("threshold 0.85")).toBeNull();
    rerender(<Metric value={1} label="X" sub="threshold 0.85" />);
    expect(screen.getByText("threshold 0.85")).toBeTruthy();
  });
});
