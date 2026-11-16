const HIDDEN = /[­​-‏‪-‮⁠-⁤﻿]|[\u{E0000}-\u{E007F}]/u;
const HIDDEN_ALL = new RegExp(HIDDEN.source, "gu");

function tokens(text) {
  return text.match(new RegExp(`${HIDDEN.source}|\\s+|[^\\s\\u00AD\\u200B-\\u200F\\u202A-\\u202E\\u2060-\\u2064\\uFEFF]+`, "gu")) || [];
}

function codePoint(character) {
  return `U+${character.codePointAt(0).toString(16).toUpperCase().padStart(4, "0")}`;
}

function push(out, kind, text) {
  if (!text) return;
  const last = out[out.length - 1];
  if (last && last.kind === kind && kind !== "hidden") last.text += text;
  else out.push({ kind, text });
}

function pushAdded(out, token) {
  if (HIDDEN.test(token) && [...token].length === 1) out.push({ kind: "hidden", text: codePoint(token) });
  else push(out, "added", token);
}

export function hiddenCharacters(text) {
  return (text.match(HIDDEN_ALL) || []).map(codePoint);
}

export function compareTexts(published, observed) {
  const a = tokens(published || "");
  const b = tokens(observed || "");
  const rows = a.length + 1;
  const cols = b.length + 1;
  const table = new Uint32Array(rows * cols);
  for (let i = a.length - 1; i >= 0; i -= 1) {
    for (let j = b.length - 1; j >= 0; j -= 1) {
      table[i * cols + j] = a[i] === b[j]
        ? table[(i + 1) * cols + j + 1] + 1
        : Math.max(table[(i + 1) * cols + j], table[i * cols + j + 1]);
    }
  }
  const out = [];
  let i = 0;
  let j = 0;
  while (i < a.length && j < b.length) {
    if (a[i] === b[j]) {
      push(out, "same", b[j]);
      i += 1;
      j += 1;
    } else if (table[(i + 1) * cols + j] >= table[i * cols + j + 1]) {
      push(out, "removed", a[i]);
      i += 1;
    } else {
      pushAdded(out, b[j]);
      j += 1;
    }
  }
  while (i < a.length) push(out, "removed", a[i++]);
  while (j < b.length) pushAdded(out, b[j++]);
  return out;
}
