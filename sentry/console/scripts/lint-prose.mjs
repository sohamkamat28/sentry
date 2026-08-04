// The console explains nothing.
//
// An operator opening this tool is a security analyst or compliance officer at
// the institution that deployed it. They do not need to be told what a blast
// radius is; they need to know which endpoint has one, how big, and what happens
// if they press the button.
//
// This lint fails the build on explanatory copy in rendered strings.

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, extname } from "node:path";

const PATTERNS = [
  /\bis a\b/i,
  /\bstands for\b/i,
  /\bthink of it as\b/i,
  /\bin other words\b/i,
  /\bwhy this matters\b/i,
  /\bthis means that\b/i,
  /\bwhat is\b/i,
];

// Only text that reaches a user. Comments explaining the code to a developer are
// exactly what should be there, so they are excluded.
const STRING_LITERAL = /(?:"([^"\\]*(?:\\.[^"\\]*)*)"|'([^'\\]*(?:\\.[^'\\]*)*)'|>([^<>{}]{12,})<)/g;

// Test names are read by whoever runs the suite, never by an operator, and a
// test asserting that a class "is a real palette colour" is describing the
// property under test rather than explaining a term to a user. Scanning them
// blocks accurate test names to enforce a rule about UI copy.
const IS_TEST = /\.(test|spec)\.tsx?$/;

function walk(dir) {
  const out = [];
  for (const e of readdirSync(dir)) {
    const p = join(dir, e);
    if (statSync(p).isDirectory()) out.push(...walk(p));
    else if ([".tsx", ".ts"].includes(extname(p)) && !IS_TEST.test(p)) out.push(p);
  }
  return out;
}

let violations = 0;

for (const file of walk("src")) {
  const lines = readFileSync(file, "utf8").split("\n");
  lines.forEach((line, i) => {
    const code = line.replace(/\/\/.*$/, "").replace(/\/\*.*?\*\//g, "");
    if (!code.trim() || code.trim().startsWith("*")) return;

    for (const m of code.matchAll(STRING_LITERAL)) {
      const text = m[1] ?? m[2] ?? m[3] ?? "";
      if (text.length < 12) continue;
      for (const p of PATTERNS) {
        if (p.test(text)) {
          console.error(`${file}:${i + 1}  explanatory copy: ${text.trim().slice(0, 80)}`);
          violations++;
          break;
        }
      }
    }
  });
}

if (violations > 0) {
  console.error(`\n${violations} explanatory string(s) found. The console is a tool, not a lesson.`);
  process.exit(1);
}
console.log("prose lint clean: no explanatory copy in rendered strings");
