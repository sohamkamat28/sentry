import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { Table } from "./Table";

describe("Table", () => {
  it.each(["Enter", " "])("activates an interactive row with %s", (key) => {
    const open = vi.fn();
    render(
      <Table
        columns={[{ key: "name", header: "name", render: (row) => row.name }]}
        rows={[{ id: "ep_1", name: "GET /orders" }]}
        rowKey={(row) => row.id}
        rowLabel={(row) => `Open ${row.name}`}
        onRowClick={open}
      />,
    );

    fireEvent.keyDown(screen.getByRole("row", { name: "Open GET /orders" }), { key });
    expect(open).toHaveBeenCalledWith({ id: "ep_1", name: "GET /orders" });
  });
});
