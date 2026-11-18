#!/usr/bin/env node
/**
 * cws-source-proof — Zero-Code-Upload Source-Proof Manifest Generator & CLI
 *
 * MIT License | Zero npm dependencies (Node.js >= 20 built-ins only).
 *
 * Generates a cryptographic SHA-256 file & relative module-graph manifest locally
 * so Chrome Web Store and web-app authors can attest source-tree structure without
 * uploading proprietary source code, literals, or secrets.
 */

import { createHash } from "node:crypto";
import {
  appendFileSync,
  existsSync,
  lstatSync,
  readdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { extname, join, posix, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const PACKAGE_VERSION = "1.0.0";

export const DEFAULT_ATTESTATION_API_URL =
  "https://b2b-audit-dropzone-production.up.railway.app";

export const MAX_SOURCE_PROOF_FILES = 25_000;
export const MAX_SINGLE_FILE_BYTES = 52_428_800; // 50 MB

export const DEFAULT_EXCLUDED_DIRS = Object.freeze([
  ".git",
  "node_modules",
  "dist",
  "build",
  "out",
  ".output",
  ".plasmo",
  "extension",
  ".next",
  ".turbo",
  "coverage",
  "__pycache__",
]);

export const DEFAULT_EXCLUDED_FILE_PATTERNS = Object.freeze([
  ".env",
  ".env.*",
  ".env*",
  ".npmrc",
  "*.pem",
  "*.key",
  "*.pfx",
  "*.p12",
  "payment-config.json",
  "*.sqlite*",
  "*.db*",
]);

const PARSEABLE_CODE_EXTENSIONS = new Set([
  ".js",
  ".mjs",
  ".cjs",
  ".jsx",
  ".ts",
  ".tsx",
  ".mts",
  ".cts",
]);

const PRE_BUILD_SOURCE_EXTENSIONS = new Set([
  ".ts",
  ".tsx",
  ".jsx",
  ".mts",
  ".cts",
  ".vue",
  ".svelte",
]);

const CODE_CLASSIFICATION_EXTENSIONS = new Set([
  "js",
  "mjs",
  "cjs",
  "jsx",
  "ts",
  "tsx",
  "mts",
  "cts",
  "py",
  "rs",
  "go",
  "java",
  "kt",
  "kts",
  "c",
  "h",
  "cpp",
  "hpp",
  "cc",
  "cxx",
  "swift",
  "cs",
  "php",
  "sh",
  "vue",
  "svelte",
]);

const LANGUAGE_BY_EXTENSION = new Map([
  ["js", "JavaScript"],
  ["mjs", "JavaScript"],
  ["cjs", "JavaScript"],
  ["jsx", "JSX"],
  ["ts", "TypeScript"],
  ["tsx", "TSX"],
  ["mts", "TypeScript"],
  ["cts", "TypeScript"],
  ["vue", "Vue"],
  ["svelte", "Svelte"],
  ["py", "Python"],
  ["rs", "Rust"],
  ["go", "Go"],
  ["java", "Java"],
  ["kt", "Kotlin"],
  ["kts", "Kotlin"],
  ["c", "C"],
  ["h", "C"],
  ["cpp", "C++"],
  ["hpp", "C++"],
  ["cc", "C++"],
  ["cxx", "C++"],
  ["swift", "Swift"],
  ["cs", "C#"],
  ["php", "PHP"],
  ["sh", "Shell"],
  ["json", "JSON"],
  ["jsonc", "JSON"],
  ["yaml", "YAML"],
  ["yml", "YAML"],
  ["toml", "TOML"],
  ["ini", "INI"],
  ["cfg", "INI"],
  ["conf", "INI"],
  ["md", "Markdown"],
  ["markdown", "Markdown"],
  ["mdx", "Markdown"],
  ["txt", "Text"],
  ["html", "HTML"],
  ["htm", "HTML"],
  ["css", "CSS"],
  ["scss", "SCSS"],
  ["sass", "Sass"],
  ["less", "Less"],
  ["xml", "XML"],
  ["svg", "SVG"],
]);

const MANIFEST_FILENAMES = new Set([
  "package.json",
  "manifest.json",
  "package-lock.json",
  "yarn.lock",
  "pnpm-lock.yaml",
  "npm-shrinkwrap.json",
  "cargo.toml",
  "cargo.lock",
  "go.mod",
  "go.sum",
  "pyproject.toml",
  "requirements.txt",
]);

const CONFIG_FILENAMES = new Set([
  ".gitignore",
  ".gitattributes",
  ".editorconfig",
  ".nvmrc",
  ".yarnrc",
  ".yarnrc.yml",
  "eslint.config.js",
  "eslint.config.mjs",
  "eslint.config.ts",
  ".prettierrc",
  ".prettierrc.json",
  "tsconfig.json",
  "tsconfig.build.json",
  "jsconfig.json",
  "vite.config.ts",
  "vite.config.js",
  "vite.config.mjs",
  "vitest.config.ts",
  "webpack.config.js",
  "rollup.config.js",
  "wxt.config.ts",
]);

const DOCUMENTATION_EXTENSIONS = new Set([
  "md",
  "markdown",
  "mdx",
  "rst",
  "txt",
  "adoc",
]);

const DOCUMENTATION_FILENAMES = new Set([
  "readme",
  "readme.md",
  "readme.txt",
  "changelog",
  "changelog.md",
  "license",
  "license.md",
  "license.txt",
  "copying",
  "contributing.md",
  "security.md",
]);

const SOURCE_DIRECTORY_NAMES = new Set([
  "src",
  "source",
  "lib",
  "packages",
  "app",
  "apps",
  "bin",
  "scripts",
  "components",
  "entrypoints",
  "background",
  "content",
  "popup",
  "options",
  "test",
  "tests",
  "__tests__",
  "spec",
]);

const TEST_DIRECTORY_NAMES = new Set([
  "test",
  "tests",
  "__tests__",
  "spec",
  "specs",
]);

const DOCUMENTATION_DIRECTORY_NAMES = new Set([
  "docs",
  "doc",
  "documentation",
  "guides",
  "examples",
]);

const GENERATED_DIRECTORY_NAMES = new Set([
  "dist",
  "build",
  "out",
  "coverage",
  ".next",
  ".nuxt",
  "__pycache__",
]);

const VENDOR_DIRECTORY_NAMES = new Set([
  "node_modules",
  "vendor",
  "third_party",
  "third-party",
]);

/**
 * Strict Unicode code-point string comparator (never localeCompare).
 */
export function compareUnicodeCodePoints(a, b) {
  return a < b ? -1 : a > b ? 1 : 0;
}

function globPatternToRegExp(pattern) {
  const escaped = String(pattern)
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*/g, ".*")
    .replace(/\?/g, ".");
  return new RegExp(`^${escaped}$`, "i");
}

function compileFileExclusionMatchers(patterns) {
  return patterns.map((p) => globPatternToRegExp(p));
}

function matchesAnyPattern(fileName, compiledMatchers) {
  return compiledMatchers.some((re) => re.test(fileName));
}

function splitBasename(filename) {
  const idx = filename.lastIndexOf(".");
  if (idx <= 0) return { stem: filename, ext: "" };
  return { stem: filename.slice(0, idx), ext: filename.slice(idx + 1) };
}

function detectLanguage(relPosixPath) {
  const base = posix.basename(relPosixPath);
  const lower = base.toLowerCase();
  if (lower === "dockerfile" || lower.startsWith("dockerfile.")) {
    return "Dockerfile";
  }
  if (lower.endsWith(".d.ts") || lower.endsWith(".d.mts") || lower.endsWith(".d.cts")) {
    return "TypeScript";
  }
  const { ext } = splitBasename(lower);
  return LANGUAGE_BY_EXTENSION.get(ext) ?? null;
}

function classifyPath(relPosixPath, isDirectory = false) {
  const classes = new Set();
  const segments = relPosixPath
    .toLowerCase()
    .split("/")
    .filter(Boolean);
  const filename = segments[segments.length - 1] ?? "";
  const { stem, ext } = splitBasename(filename);

  if (segments.some((s) => TEST_DIRECTORY_NAMES.has(s))) classes.add("test");
  if (segments.some((s) => DOCUMENTATION_DIRECTORY_NAMES.has(s))) classes.add("documentation");
  if (segments.some((s) => VENDOR_DIRECTORY_NAMES.has(s))) classes.add("vendor");
  if (segments.some((s) => GENERATED_DIRECTORY_NAMES.has(s))) classes.add("generated");

  if (!isDirectory) {
    if (
      filename.includes(".test.") ||
      filename.includes(".spec.") ||
      filename.startsWith("test_") ||
      stem.endsWith("_test") ||
      stem.endsWith("_spec")
    ) {
      classes.add("test");
    }
    if (
      filename.endsWith(".min.js") ||
      filename.endsWith(".min.css") ||
      filename.endsWith(".map") ||
      filename.endsWith(".lock") ||
      filename.endsWith(".d.ts") ||
      filename.endsWith(".d.mts") ||
      filename.endsWith(".d.cts")
    ) {
      classes.add("generated");
    }
    if (MANIFEST_FILENAMES.has(filename)) classes.add("manifest");
    if (CONFIG_FILENAMES.has(filename)) classes.add("config");
    if (DOCUMENTATION_EXTENSIONS.has(ext) || DOCUMENTATION_FILENAMES.has(filename)) {
      classes.add("documentation");
    }
    if (CODE_CLASSIFICATION_EXTENSIONS.has(ext)) {
      classes.add("source");
    }
    if (
      (filename.endsWith(".json") || filename.endsWith(".yaml") || filename.endsWith(".yml")) &&
      !classes.has("manifest") &&
      !classes.has("config")
    ) {
      classes.add("config");
    }
  }

  if (segments.some((s) => SOURCE_DIRECTORY_NAMES.has(s))) {
    if (!classes.has("vendor") && !classes.has("generated")) {
      classes.add("source");
    }
  }

  if (classes.size === 0) {
    classes.add(isDirectory ? "source" : "unknown");
  }

  return [...classes].sort(compareUnicodeCodePoints);
}

/**
 * Lexical JS/TS comment stripper that preserves single/double/template strings
 * and regex literals so `https://...` or `'import "./fake.js"'` inside literals
 * are never corrupted while `// ...` and `/* ... *\/` comments are replaced by whitespace.
 */
export function stripCodeComments(codeText) {
  const src = String(codeText || "");
  const len = src.length;
  const out = [];
  let state = "CODE";
  let inRegexClass = false;
  let prevNonSpaceChar = "";
  let prevWord = "";
  const templateBraceDepth = [];

  const REGEX_PRECEDING_KEYWORDS = new Set([
    "return",
    "throw",
    "case",
    "typeof",
    "void",
    "delete",
    "in",
    "of",
    "instanceof",
    "new",
    "await",
    "yield",
  ]);
  const REGEX_PRECEDING_PUNCT = new Set([
    "",
    "(",
    ",",
    "=",
    ":",
    "[",
    "!",
    "&",
    "|",
    "?",
    "{",
    "}",
    ";",
    "+",
    "-",
    "~",
    "*",
    "%",
    "^",
    "<",
    ">",
  ]);

  let i = 0;
  while (i < len) {
    const ch = src[i];
    const next = i + 1 < len ? src[i + 1] : "";

    if (state === "LINE_COMMENT") {
      if (ch === "\n" || ch === "\r") {
        out.push(ch);
        state = "CODE";
      } else {
        out.push(" ");
      }
      i += 1;
      continue;
    }

    if (state === "BLOCK_COMMENT") {
      if (ch === "*" && next === "/") {
        out.push("  ");
        state = "CODE";
        i += 2;
      } else {
        out.push(ch === "\n" || ch === "\r" ? ch : " ");
        i += 1;
      }
      continue;
    }

    if (state === "SINGLE_QUOTE") {
      out.push(ch);
      if (ch === "\\" && i + 1 < len) {
        out.push(next);
        i += 2;
        continue;
      }
      if (ch === "'" || ch === "\n" || ch === "\r") {
        state = "CODE";
        prevNonSpaceChar = "'";
        prevWord = "";
      }
      i += 1;
      continue;
    }

    if (state === "DOUBLE_QUOTE") {
      out.push(ch);
      if (ch === "\\" && i + 1 < len) {
        out.push(next);
        i += 2;
        continue;
      }
      if (ch === '"' || ch === "\n" || ch === "\r") {
        state = "CODE";
        prevNonSpaceChar = '"';
        prevWord = "";
      }
      i += 1;
      continue;
    }

    if (state === "TEMPLATE") {
      if (ch === "\\" && i + 1 < len) {
        out.push(ch, next);
        i += 2;
        continue;
      }
      if (ch === "$" && next === "{") {
        out.push("${");
        templateBraceDepth.push(1);
        state = "CODE";
        prevNonSpaceChar = "{";
        prevWord = "";
        i += 2;
        continue;
      }
      out.push(ch);
      if (ch === "`") {
        state = "CODE";
        prevNonSpaceChar = "`";
        prevWord = "";
      }
      i += 1;
      continue;
    }

    if (state === "REGEX") {
      out.push(ch);
      if (ch === "\\" && i + 1 < len && next !== "\n" && next !== "\r") {
        out.push(next);
        i += 2;
        continue;
      }
      if (ch === "\n" || ch === "\r") {
        state = "CODE";
        inRegexClass = false;
        i += 1;
        continue;
      }
      if (ch === "[" && !inRegexClass) {
        inRegexClass = true;
      } else if (ch === "]" && inRegexClass) {
        inRegexClass = false;
      } else if (ch === "/" && !inRegexClass) {
        state = "CODE";
        prevNonSpaceChar = "/";
        prevWord = "";
      }
      i += 1;
      continue;
    }

    // state === "CODE"
    if (ch === "/" && next === "/") {
      out.push("  ");
      state = "LINE_COMMENT";
      i += 2;
      continue;
    }
    if (ch === "/" && next === "*") {
      out.push("  ");
      state = "BLOCK_COMMENT";
      i += 2;
      continue;
    }
    if (ch === "'") {
      out.push(ch);
      state = "SINGLE_QUOTE";
      i += 1;
      continue;
    }
    if (ch === '"') {
      out.push(ch);
      state = "DOUBLE_QUOTE";
      i += 1;
      continue;
    }
    if (ch === "`") {
      out.push(ch);
      state = "TEMPLATE";
      i += 1;
      continue;
    }
    if (ch === "/") {
      const canStartRegex =
        REGEX_PRECEDING_PUNCT.has(prevNonSpaceChar) || REGEX_PRECEDING_KEYWORDS.has(prevWord);
      out.push(ch);
      if (canStartRegex) {
        state = "REGEX";
        inRegexClass = false;
      } else {
        prevNonSpaceChar = "/";
        prevWord = "";
      }
      i += 1;
      continue;
    }

    if (templateBraceDepth.length > 0) {
      if (ch === "{") {
        templateBraceDepth[templateBraceDepth.length - 1] += 1;
      } else if (ch === "}") {
        templateBraceDepth[templateBraceDepth.length - 1] -= 1;
        if (templateBraceDepth[templateBraceDepth.length - 1] === 0) {
          templateBraceDepth.pop();
          out.push(ch);
          state = "TEMPLATE";
          i += 1;
          continue;
        }
      }
    }

    out.push(ch);
    if (/[A-Za-z0-9_$]/.test(ch)) {
      if (/[A-Za-z0-9_$]/.test(prevNonSpaceChar)) {
        prevWord += ch;
      } else {
        prevWord = ch;
      }
      prevNonSpaceChar = ch;
    } else if (!/\s/.test(ch)) {
      prevNonSpaceChar = ch;
      prevWord = "";
    }
    i += 1;
  }

  return out.join("");
}

function extractRelativeSpecifiers(codeText) {
  const cleaned = stripCodeComments(codeText);
  const found = [];

  const fromRe =
    /\b(?:import|export)\s+(?:type\s+)?(?:[\w*$]+|\{[^}]*\}|\*\s+as\s+[\w$]+)(?:\s*,\s*(?:[\w*$]+|\{[^}]*\}|\*\s+as\s+[\w$]+))?\s*from\s*["'](\.\.?\/[^"'\r\n]+)["']/g;
  const sideEffectImportRe = /\bimport\s*["'](\.\.?\/[^"'\r\n]+)["']/g;
  const dynamicImportRe = /\bimport\s*\(\s*["'`](\.\.?\/[^"'`$\r\n]+)["'`]\s*\)/g;
  const requireRe = /\brequire\s*\(\s*["'`](\.\.?\/[^"'`$\r\n]+)["'`]\s*\)/g;

  let m;
  while ((m = fromRe.exec(cleaned)) !== null) {
    found.push({ specifier: m[1], kind: "imports" });
  }
  while ((m = sideEffectImportRe.exec(cleaned)) !== null) {
    found.push({ specifier: m[1], kind: "imports" });
  }
  while ((m = dynamicImportRe.exec(cleaned)) !== null) {
    found.push({ specifier: m[1], kind: "imports" });
  }
  while ((m = requireRe.exec(cleaned)) !== null) {
    found.push({ specifier: m[1], kind: "requires" });
  }

  return found;
}

function resolveInventoriedRelativeImport(fromRelPath, specifier, inventoriedFiles) {
  const cleanSpec = String(specifier || "").split(/[?#]/)[0];
  if (!cleanSpec.startsWith("./") && !cleanSpec.startsWith("../")) {
    return null;
  }
  const fromDir = posix.dirname(fromRelPath);
  const normalized = posix.normalize(posix.join(fromDir, cleanSpec));
  if (
    !normalized ||
    normalized === "." ||
    normalized === ".." ||
    normalized.startsWith("../") ||
    normalized.startsWith("/")
  ) {
    return null;
  }

  const candidates = [normalized];

  // TypeScript NodeNext / Bundler extension remapping (.js -> .ts/.tsx, .mjs -> .mts, .cjs -> .cts)
  if (normalized.endsWith(".js")) {
    const stem = normalized.slice(0, -3);
    candidates.push(`${stem}.ts`, `${stem}.tsx`, `${stem}.jsx`);
  } else if (normalized.endsWith(".mjs")) {
    const stem = normalized.slice(0, -4);
    candidates.push(`${stem}.mts`);
  } else if (normalized.endsWith(".cjs")) {
    const stem = normalized.slice(0, -4);
    candidates.push(`${stem}.cts`);
  } else if (normalized.endsWith(".jsx")) {
    const stem = normalized.slice(0, -4);
    candidates.push(`${stem}.tsx`);
  }

  candidates.push(
    `${normalized}.ts`,
    `${normalized}.tsx`,
    `${normalized}.js`,
    `${normalized}.jsx`,
    `${normalized}.mjs`,
    `${normalized}.cjs`,
    `${normalized}.mts`,
    `${normalized}.cts`,
    `${normalized}.json`,
    `${normalized}.css`,
    `${normalized}/index.ts`,
    `${normalized}/index.tsx`,
    `${normalized}/index.js`,
    `${normalized}/index.jsx`,
    `${normalized}/index.mjs`,
    `${normalized}/index.cjs`
  );

  for (const cand of candidates) {
    if (inventoriedFiles.has(cand)) {
      return cand;
    }
  }
  return null;
}

/**
 * RFC 8785 / canonical JSON SHA-256 digester matching HistoricalSourceGraph root commitments.
 */
function digestCanonicalJson(value) {
  const hash = createHash("sha256");
  let buffer = "";

  function emit(chunk) {
    buffer += chunk;
    if (buffer.length >= 8192) {
      hash.update(buffer);
      buffer = "";
    }
  }

  function walk(val) {
    if (val === null || typeof val !== "object") {
      emit(JSON.stringify(val));
      return;
    }
    if (Array.isArray(val)) {
      emit("[");
      for (let i = 0; i < val.length; i += 1) {
        if (i > 0) emit(",");
        const item = val[i];
        walk(item === undefined || typeof item === "symbol" ? null : item);
      }
      emit("]");
      return;
    }
    emit("{");
    let first = true;
    for (const key of Object.keys(val).sort()) {
      const prop = val[key];
      if (prop === undefined || typeof prop === "symbol") continue;
      if (!first) emit(",");
      first = false;
      emit(JSON.stringify(key));
      emit(":");
      walk(prop);
    }
    emit("}");
  }

  walk(value);
  if (buffer.length > 0) {
    hash.update(buffer);
  }
  return hash.digest("hex");
}

function computeHistoricalRootSha256(entries, exclusions) {
  const commitment = {
    entries: entries.map((entry) => {
      if (entry.kind === "file") {
        return {
          kind: entry.kind,
          path: entry.path,
          sha256: entry.sha256,
          size: entry.size,
          content_state: entry.content_state,
        };
      }
      return {
        kind: entry.kind,
        path: entry.path,
        tree_state: entry.tree_state,
      };
    }),
    exclusions,
  };
  return digestCanonicalJson(commitment);
}

/**
 * Walk a repository directory safely (skipping symlinks, secrets, and build outputs)
 * and generate a zero-code Source-Proof Manifest envelope.
 */
export function generateSourceProofManifest(repoDir, options = {}) {
  if (!repoDir) {
    throw new Error("generateSourceProofManifest requires a target repository directory");
  }
  const resolvedRepo = resolve(String(repoDir));
  if (!existsSync(resolvedRepo) || !statSync(resolvedRepo).isDirectory()) {
    throw new Error(`Repository directory does not exist: ${resolvedRepo}`);
  }

  const maxFiles = Number.isInteger(options.maxFiles) ? options.maxFiles : MAX_SOURCE_PROOF_FILES;
  const maxSingleFileBytes = Number.isInteger(options.maxSingleFileBytes)
    ? options.maxSingleFileBytes
    : MAX_SINGLE_FILE_BYTES;
  const lstatFn = typeof options.lstatImpl === "function" ? options.lstatImpl : lstatSync;
  const caller =
    typeof options.caller === "string" && /^[\w .:@/+-]+$/u.test(options.caller)
      ? options.caller
      : "cws-source-proof-cli";

  const excludedDirs = new Set([
    ...DEFAULT_EXCLUDED_DIRS,
    ...(Array.isArray(options.extraIgnoredDirs) ? options.extraIgnoredDirs : []),
  ]);
  const excludedFileMatchers = compileFileExclusionMatchers([
    ...DEFAULT_EXCLUDED_FILE_PATTERNS,
    ...(Array.isArray(options.extraIgnoredFilePatterns) ? options.extraIgnoredFilePatterns : []),
  ]);

  const entries = [];
  const inventoriedFiles = new Set();
  const codeFilesToParse = [];
  let skippedSymlinkCount = 0;
  let excludedItemCount = 0;
  let fileCount = 0;
  let preBuildSourceFileCount = 0;

  function walkDirectory(currentDir) {
    const names = readdirSync(currentDir).sort(compareUnicodeCodePoints);
    for (const name of names) {
      const fullPath = join(currentDir, name);
      const relPath = relative(resolvedRepo, fullPath).split("\\").join("/");
      if (!relPath || relPath.startsWith("..") || relPath.includes("\0")) {
        continue;
      }

      const st = lstatFn(fullPath);
      if (st.isSymbolicLink()) {
        skippedSymlinkCount += 1;
        continue;
      }

      if (st.isDirectory()) {
        if (excludedDirs.has(name) || excludedDirs.has(relPath)) {
          excludedItemCount += 1;
          continue;
        }
        const classifications = classifyPath(relPath, true);
        entries.push({
          path: relPath,
          kind: "directory",
          tree_state: "enumerated",
          classifications,
          limitations: [],
        });
        walkDirectory(fullPath);
        continue;
      }

      if (st.isFile()) {
        if (matchesAnyPattern(name, excludedFileMatchers)) {
          excludedItemCount += 1;
          continue;
        }
        fileCount += 1;
        if (fileCount > maxFiles) {
          throw new Error(
            `Repository exceeds maximum Source-Proof file count (${maxFiles} files)`
          );
        }
        if (st.size > maxSingleFileBytes) {
          throw new Error(
            `File '${relPath}' (${st.size} bytes) exceeds maximum single-file limit (${maxSingleFileBytes} bytes)`
          );
        }

        const rawBuf = readFileSync(fullPath);
        const sha256 = createHash("sha256").update(rawBuf).digest("hex");
        const ext = extname(relPath).toLowerCase();
        const detectedLang = detectLanguage(relPath);
        const baseLower = posix.basename(relPath).toLowerCase();
        const isPrimaryManifest = baseLower === "package.json" || baseLower === "manifest.json";

        let classifications = classifyPath(relPath, false);
        if (isPrimaryManifest) {
          classifications = ["manifest"];
        } else if (PARSEABLE_CODE_EXTENSIONS.has(ext) && !classifications.includes("source")) {
          classifications = [
            ...new Set([...classifications.filter((c) => c !== "unknown"), "source"]),
          ].sort(compareUnicodeCodePoints);
        }

        entries.push({
          path: relPath,
          kind: "file",
          language: detectedLang || (ext === ".json" ? "JSON" : "Text"),
          sha256,
          size: st.size,
          content_state: "hashed",
          classifications,
          limitations: [],
        });
        inventoriedFiles.add(relPath);

        if (
          PRE_BUILD_SOURCE_EXTENSIONS.has(ext) ||
          (PARSEABLE_CODE_EXTENSIONS.has(ext) &&
            (relPath.startsWith("src/") || relPath.includes("/src/")))
        ) {
          preBuildSourceFileCount += 1;
        }

        if (PARSEABLE_CODE_EXTENSIONS.has(ext)) {
          codeFilesToParse.push({ relPath, content: rawBuf.toString("utf8") });
        }
      }
    }
  }

  walkDirectory(resolvedRepo);

  const relationshipMap = new Map();
  for (const { relPath, content } of codeFilesToParse) {
    const specs = extractRelativeSpecifiers(content);
    for (const { specifier, kind } of specs) {
      const target = resolveInventoriedRelativeImport(relPath, specifier, inventoriedFiles);
      if (!target) continue;
      const relObj = {
        from_path: relPath,
        to: target,
        kind,
        resolution: "internal",
        parse_state: "parsed",
      };
      const key = `${relObj.from_path}\0${relObj.to}\0${relObj.kind}\0${relObj.resolution}\0${relObj.parse_state}`;
      relationshipMap.set(key, relObj);
    }
  }

  entries.sort((a, b) => compareUnicodeCodePoints(a.path, b.path));
  const relationships = [...relationshipMap.entries()]
    .sort(([ka], [kb]) => compareUnicodeCodePoints(ka, kb))
    .map(([, val]) => val);

  const fileEntries = entries.filter((e) => e.kind === "file");
  const sourceModuleEntries = fileEntries.filter((e) => e.classifications.includes("source"));
  const languages = [
    ...new Set(fileEntries.filter((e) => e.language !== null).map((e) => e.language)),
  ].sort(compareUnicodeCodePoints);
  const manifests = fileEntries
    .filter((e) => e.classifications.includes("manifest"))
    .map((e) => e.path)
    .sort(compareUnicodeCodePoints);

  const exclusions = [];
  const rootSha256 = computeHistoricalRootSha256(entries, exclusions);

  const historicalSourceGraph = {
    schema: "HistoricalSourceGraph",
    authority: "historical-reference",
    root_alias: "$REFERENCE_ROOT",
    root_sha256: rootSha256,
    inventory_state: "complete",
    entries,
    relationships,
    parse_failures: [],
    exclusions,
    languages,
    manifests,
    vcs: null,
    provenance: {
      importer: "cws-source-proof",
      importer_version: PACKAGE_VERSION,
      caller,
    },
    limitations: [],
  };

  return {
    schema: "CwsSourceProofEnvelope",
    schemaVersion: "1.0",
    kind: "SourceProofManifest",
    attestationNotice: "Self-Attested Hash Manifest (Zero Code Uploaded)",
    generatedAtUtc: new Date().toISOString(),
    zeroSourceCodeUploaded: true,
    rootSha256,
    fileCount: fileEntries.length,
    moduleCount: sourceModuleEntries.length,
    preBuildSourceFileCount,
    hasPackageJson: inventoriedFiles.has("package.json"),
    relationshipCount: relationships.length,
    skippedSymlinkCount,
    excludedItemCount,
    languages,
    manifests,
    historicalSourceGraph,
  };
}

/**
 * Request an ambient GitHub Actions OIDC JWT when running in a workflow with `id-token: write`.
 * Returns `null` cleanly when OIDC environment variables are absent.
 */
export async function fetchGitHubActionsOidcToken(options = {}) {
  const requestUrl = options.requestUrl ?? process.env.ACTIONS_ID_TOKEN_REQUEST_URL ?? "";
  const requestToken = options.requestToken ?? process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN ?? "";
  const audience = options.audience || "cws-source-proof";
  const fetchImpl = options.fetchImpl || globalThis.fetch;
  const timeoutMs = Number.isInteger(options.timeoutMs) ? options.timeoutMs : 10_000;

  if (!requestUrl || !requestToken || typeof fetchImpl !== "function") {
    return null;
  }

  const targetUrl = new URL(requestUrl);
  targetUrl.searchParams.set("audience", audience);

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetchImpl(targetUrl.toString(), {
      method: "GET",
      headers: {
        Authorization: `bearer ${requestToken}`,
        Accept: "application/json; api-version=2.0",
        "User-Agent": `cws-source-proof/${PACKAGE_VERSION}`,
      },
      signal: controller.signal,
    });

    if (!res.ok) {
      throw new Error(`GitHub Actions OIDC token request failed with HTTP ${res.status}`);
    }
    const data = await res.json();
    return typeof data?.value === "string" && data.value.length > 0 ? data.value : null;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Submit a zero-code Source-Proof Manifest to the public attestation endpoint.
 */
export async function submitSourceProofAttestation(options = {}) {
  const {
    manifest,
    extensionId,
    apiBaseUrl = DEFAULT_ATTESTATION_API_URL,
    oidcToken = "",
    repoLabel = "",
    fetchImpl = globalThis.fetch,
    timeoutMs = 30_000,
  } = options;

  const normalizedExtId = String(extensionId || "")
    .trim()
    .toLowerCase();
  if (!/^[a-p]{32}$/.test(normalizedExtId)) {
    throw new Error(
      `Invalid 32-character Chrome Web Store extension ID: '${extensionId || ""}' (expected [a-p]{32})`
    );
  }
  if (!manifest || typeof manifest !== "object" || !manifest.historicalSourceGraph) {
    throw new Error("submitSourceProofAttestation requires a valid SourceProofManifest object");
  }
  if (typeof fetchImpl !== "function") {
    throw new Error("Global fetch is unavailable; Node.js >= 20 is required");
  }

  const endpoint = `${String(apiBaseUrl).replace(/\/+$/, "")}/api/source-proof/attest`;
  const headers = {
    "Content-Type": "application/json",
    Accept: "application/json",
    "User-Agent": `cws-source-proof/${PACKAGE_VERSION}`,
  };
  if (oidcToken && String(oidcToken).trim().length > 0) {
    headers.Authorization = `Bearer ${String(oidcToken).trim()}`;
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetchImpl(endpoint, {
      method: "POST",
      headers,
      body: JSON.stringify({
        extensionId: normalizedExtId,
        repoLabel: String(repoLabel || "").trim(),
        manifest,
      }),
      signal: controller.signal,
    });

    const text = await res.text();
    let parsed = null;
    try {
      parsed = text ? JSON.parse(text) : {};
    } catch {
      parsed = { raw: text };
    }

    if (!res.ok) {
      const err = new Error(
        parsed?.error ||
          parsed?.message ||
          `Attestation endpoint returned HTTP ${res.status}`
      );
      err.statusCode = res.status;
      throw err;
    }
    return parsed;
  } finally {
    clearTimeout(timer);
  }
}

function writeGitHubActionOutput(ghOutputPath, key, value) {
  if (!ghOutputPath) return;
  const cleanVal = String(value ?? "").replace(/[\r\n]+/g, " ");
  appendFileSync(ghOutputPath, `${key}=${cleanVal}\n`, "utf8");
}

function parseCliArgs(argv, env) {
  const opts = {
    repoDir: env.INPUT_REPO_DIR || "",
    outPath: env.INPUT_OUT_FILE || "",
    extraIgnoredDirs: env.INPUT_IGNORE_DIRS
      ? env.INPUT_IGNORE_DIRS.split(",")
          .map((s) => s.trim())
          .filter(Boolean)
      : [],
    attestExtId: "",
    apiBaseUrl: env.INPUT_API_URL || DEFAULT_ATTESTATION_API_URL,
    repoLabel: env.GITHUB_REPOSITORY || "",
    oidcToken: env.CWS_SOURCE_PROOF_OIDC_TOKEN || "",
    oidcAudience: env.INPUT_OIDC_AUDIENCE || "cws-source-proof",
    help: false,
  };

  if (
    String(env.INPUT_PUBLISH_ATTESTATION || "").toLowerCase() === "true" &&
    env.INPUT_EXTENSION_ID
  ) {
    opts.attestExtId = env.INPUT_EXTENSION_ID.trim();
  }

  const positional = [];
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") {
      opts.help = true;
    } else if (arg === "--out" && argv[i + 1]) {
      opts.outPath = argv[++i];
    } else if (arg === "--ignore" && argv[i + 1]) {
      const extra = argv[++i]
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
      opts.extraIgnoredDirs.push(...extra);
    } else if (arg === "--attest-ext-id" && argv[i + 1]) {
      opts.attestExtId = argv[++i].trim();
    } else if (arg === "--api-url" && argv[i + 1]) {
      opts.apiBaseUrl = argv[++i].trim();
    } else if (arg === "--repo-label" && argv[i + 1]) {
      opts.repoLabel = argv[++i].trim();
    } else if (arg === "--oidc-token" && argv[i + 1]) {
      opts.oidcToken = argv[++i].trim();
    } else if (arg === "--oidc-audience" && argv[i + 1]) {
      opts.oidcAudience = argv[++i].trim();
    } else if (!arg.startsWith("-")) {
      positional.push(arg);
    }
  }

  if (positional[0]) {
    opts.repoDir = positional[0];
  }
  if (!opts.repoDir) {
    opts.repoDir = ".";
  }
  return opts;
}

export async function runSourceProofCli(argv = process.argv.slice(2), env = process.env) {
  const opts = parseCliArgs(argv, env);

  if (opts.help) {
    process.stdout.write(
      [
        "Usage: cws-source-proof [repoDir] [options]",
        "",
        "Options:",
        "  --out <file>             Write Source-Proof Manifest JSON to file",
        "  --ignore <dir1,dir2>     Additional directory names to exclude",
        "  --attest-ext-id <id>     Publish attestation against a 32-char CWS extension ID",
        "  --api-url <url>          Attestation hub base URL",
        "  --repo-label <owner/repo> Optional public repository label",
        "  --oidc-token <jwt>       Optional GitHub Actions OIDC bearer token",
        "  --help, -h               Show usage instructions",
        "",
      ].join("\n")
    );
    return 0;
  }

  const manifest = generateSourceProofManifest(opts.repoDir, {
    extraIgnoredDirs: opts.extraIgnoredDirs,
  });
  const jsonText = JSON.stringify(manifest, null, 2);

  let resolvedOut = "";
  if (opts.outPath) {
    resolvedOut = resolve(opts.outPath);
    writeFileSync(resolvedOut, `${jsonText}\n`, "utf8");
    console.log(
      `[cws-source-proof] Wrote zero-code Source-Proof Manifest (${manifest.moduleCount} source modules, root SHA-256 ${manifest.rootSha256.slice(0, 16)}...) to ${resolvedOut}`
    );
  } else if (!opts.attestExtId) {
    process.stdout.write(`${jsonText}\n`);
  }

  const cleanBaseUrl = String(opts.apiBaseUrl || DEFAULT_ATTESTATION_API_URL).replace(/\/+$/, "");
  const badgeExtId =
    opts.attestExtId && /^[a-p]{32}$/i.test(opts.attestExtId)
      ? opts.attestExtId.toLowerCase()
      : "<32-char-extension-id>";
  const badgeMarkdown = `[![Self-Attested Source-Proof](${cleanBaseUrl}/badge/source-proof/${badgeExtId}.svg)](${cleanBaseUrl}/source-proof/${badgeExtId})`;

  if (opts.attestExtId) {
    let oidcToken = opts.oidcToken;
    if (!oidcToken) {
      try {
        oidcToken =
          (await fetchGitHubActionsOidcToken({
            audience: opts.oidcAudience,
            requestUrl: env.ACTIONS_ID_TOKEN_REQUEST_URL,
            requestToken: env.ACTIONS_ID_TOKEN_REQUEST_TOKEN,
          })) || "";
      } catch (oidcErr) {
        console.warn(
          `[cws-source-proof] OIDC token unavailable (${oidcErr.message}); continuing as unauthenticated self-attestation.`
        );
      }
    }

    const attestRes = await submitSourceProofAttestation({
      manifest,
      extensionId: opts.attestExtId,
      apiBaseUrl: cleanBaseUrl,
      oidcToken,
      repoLabel: opts.repoLabel,
    });
    console.log(
      `[cws-source-proof] Published Self-Attested Hash Manifest for ${opts.attestExtId}: ${cleanBaseUrl}/source-proof/${opts.attestExtId.toLowerCase()}`
    );
    if (attestRes?.attestationId) {
      writeGitHubActionOutput(env.GITHUB_OUTPUT, "attestation-id", attestRes.attestationId);
    }
  }

  if (env.GITHUB_OUTPUT) {
    writeGitHubActionOutput(env.GITHUB_OUTPUT, "manifest-path", resolvedOut);
    writeGitHubActionOutput(env.GITHUB_OUTPUT, "root-sha256", manifest.rootSha256);
    writeGitHubActionOutput(env.GITHUB_OUTPUT, "badge-markdown", badgeMarkdown);
  }

  return 0;
}

const isMainModule =
  Boolean(process.argv[1]) && resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isMainModule) {
  runSourceProofCli().then(
    (code) => process.exit(code),
    (err) => {
      console.error("[cws-source-proof] Error:", err?.message || err);
      process.exit(1);
    }
  );
}
