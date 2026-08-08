import type { ReactNode } from "react";

export interface Column<T> {
  key: string;
  /**
   * A node, not just a string, so a header can carry the count that would
   * otherwise be repeated in every cell beneath it — "ratelimit · 39 gaps"
   * said once instead of a chip on all 44 rows.
   */
  header: ReactNode;
  render: (row: T) => ReactNode;
  align?: "left" | "right";
  width?: string;
}

interface Props<T> {
  columns: Column<T>[];
  rows: T[] | undefined;
  rowKey: (row: T) => string;
  loading?: boolean;
  error?: Error | null;
  /** Shown only when the request succeeded and returned nothing. */
  empty?: string;
  onRowClick?: (row: T) => void;
  rowLabel?: (row: T) => string;
  /**
   * Draw the surrounding panel. Off when the table is already inside a `Card`,
   * which otherwise nests a bordered box in a bordered box and reads as two
   * frames competing for the same edge.
   */
  framed?: boolean;
}

/**
 * The console's one table.
 *
 * Loading, failed and empty are three states and this renders three different
 * things. A table showing "no rows" while a request is in flight — or after it
 * failed — asserts the estate is clean on evidence it does not have, which is
 * the same defect the Metric tile exists to prevent, one level up.
 */
export function Table<T>({
  columns,
  rows,
  rowKey,
  loading,
  error,
  empty = "no rows",
  onRowClick,
  rowLabel,
  framed = true,
}: Props<T>) {
  const span = columns.length;
  return (
    <div className={`overflow-x-auto ${framed ? "panel" : ""}`}>
      <table className="w-full border-collapse">
        <thead>
          <tr>
            {columns.map((c) => (
              <th key={c.key} className="th" style={c.width ? { width: c.width } : undefined}>
                {c.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {loading && (
            <tr>
              <td className="cell text-tx4" colSpan={span} aria-busy>
                loading…
              </td>
            </tr>
          )}

          {!loading && error && (
            <tr>
              <td className="cell text-crit" colSpan={span}>
                {error.message}
              </td>
            </tr>
          )}

          {!loading && !error && rows && rows.length === 0 && (
            <tr>
              <td className="cell text-tx4" colSpan={span}>
                {empty}
              </td>
            </tr>
          )}

          {!loading &&
            !error &&
            rows?.map((row) => (
              <tr
                key={rowKey(row)}
                onClick={onRowClick ? () => onRowClick(row) : undefined}
                onKeyDown={
                  onRowClick
                    ? (event) => {
                        if (event.target !== event.currentTarget) return;
                        if (event.key === "Enter" || event.key === " ") {
                          event.preventDefault();
                          onRowClick(row);
                        }
                      }
                    : undefined
                }
                tabIndex={onRowClick ? 0 : undefined}
                aria-label={rowLabel?.(row)}
                className={onRowClick ? "cursor-pointer hover:bg-line/40" : undefined}
              >
                {columns.map((c) => (
                  <td
                    key={c.key}
                    className={`cell ${c.align === "right" ? "text-right num" : ""}`}
                  >
                    {c.render(row)}
                  </td>
                ))}
              </tr>
            ))}
        </tbody>
      </table>
    </div>
  );
}
