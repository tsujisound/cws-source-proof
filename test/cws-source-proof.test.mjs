import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { execFile } from "node:child_process";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

import {
  DEFAULT_ATTESTATION_API_URL,
  DEFAULT_EXCLUDED_DIRS,
  DEFAULT_EXCLUDED_FILE_PATTERNS,
  fetchGitHubActionsOidcToken,
  generateSourceProofManifest,
  stripCodeComments,
  submitSourceProofAttestation,
} from "../src/index.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const pkgRoot = path.resolve(__dirname, "..");

test("1. generates zero-code Source-Proof Manifest with strict HistoricalSourceGraph and zero leaked source literals", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "cws-source-proof-unit-"));
  try {
    const repoDir = path.join(tmpDir, "ext-repo");
    fs.mkdirSync(path.join(repoDir, "src", "utils"), { recursive: true });

    const secretAlgo = "ULTRA_PRIVATE_PRICING_FORMULA_88421";
    const inlineApiKey = ["sk", "live", "NEVER_LEAVE_LAPTOP_9988776655"].join("_");

    fs.writeFileSync(
      path.join(repoDir, "package.json"),
      JSON.stringify({ name: "sample-cws-ext", version: "2.1.0" }, null, 2)
    );
    fs.writeFileSync(
      path.join(repoDir, "manifest.json"),
      JSON.stringify({ manifest_version: 3, name: "Sample CWS Ext", version: "2.1.0" }, null, 2)
    );
    fs.writeFileSync(
      path.join(repoDir, "src", "utils", "math.ts"),
      [
        `export const SECRET = "${secretAlgo}";`,
        `const KEY = "${inlineApiKey}";`,
        `export function computeScore(v: number): number { return v * 2.5; }`,
      ].join("\n")
    );
    fs.writeFileSync(
      path.join(repoDir, "src", "background.ts"),
      [
        `// Commented fake import that MUST NOT appear:`,
        `// import { bad } from "./nonexistent.js";`,
        `/*`,
        ` * Multi-line comment with fake edge:`,
        ` * import "./utils/fake-edge.js";`,
        ` * require("./utils/fake-require.js");`,
        ` */`,
        `const DOC_URL = "https://example.com//not-a-comment";`,
        `import { computeScore } from "./utils/math.js"; // TS NodeNext .js -> .ts remap!`,
        `console.log(DOC_URL, computeScore(10));`,
      ].join("\n")
    );

    const envelope = generateSourceProofManifest(repoDir);
    const serialized = JSON.stringify(envelope);

    assert.equal(envelope.schema, "CwsSourceProofEnvelope");
    assert.equal(envelope.schemaVersion, "1.0");
    assert.equal(envelope.kind, "SourceProofManifest");
    assert.equal(envelope.zeroSourceCodeUploaded, true);
    assert.match(envelope.attestationNotice, /Self-Attested Hash Manifest \(Zero Code Uploaded\)/);
    assert.match(envelope.rootSha256, /^[0-9a-f]{64}$/);
    assert.equal(envelope.hasPackageJson, true);
    assert.ok(envelope.preBuildSourceFileCount >= 2);
    assert.equal(envelope.fileCount, 4);
    assert.equal(envelope.relationshipCount, 1);

    // Zero raw source code or constants leaked
    assert.equal(serialized.includes(secretAlgo), false);
    assert.equal(serialized.includes(inlineApiKey), false);
    assert.equal(serialized.includes("computeScore"), false);
    assert.equal(serialized.includes("example.com"), false);

    // Strict HistoricalSourceGraph checks (no extra top-level CLI keys inside historicalSourceGraph)
    const graph = envelope.historicalSourceGraph;
    assert.equal(graph.schema, "HistoricalSourceGraph");
    assert.equal(graph.authority, "historical-reference");
    assert.equal(graph.root_alias, "$REFERENCE_ROOT");
    assert.equal(graph.inventory_state, "complete");
    assert.equal(graph.root_sha256, envelope.rootSha256);
    assert.deepEqual(graph.provenance, {
      importer: "cws-source-proof",
      importer_version: "1.0.0",
      caller: "cws-source-proof-cli",
    });
    assert.equal("zeroSourceCodeUploaded" in graph, false);
    assert.equal("fileCount" in graph, false);

    // Verify TS NodeNext .js -> .ts resolution & comment-stripping accuracy
    assert.equal(graph.relationships.length, 1);
    assert.deepEqual(graph.relationships[0], {
      from_path: "src/background.ts",
      to: "src/utils/math.ts",
      kind: "imports",
      resolution: "internal",
      parse_state: "parsed",
    });

    // Strict Unicode code-point ordering check on entries, languages, manifests
    const entryPaths = graph.entries.map((e) => e.path);
    const sortedPaths = [...entryPaths].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    assert.deepEqual(entryPaths, sortedPaths);
    assert.deepEqual(graph.manifests, ["manifest.json", "package.json"]);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("2. excludes all sensitive files, build/bundle folders, and skips symlinks safely via lstatSync", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "cws-source-proof-excl-"));
  try {
    const repoDir = path.join(tmpDir, "repo");
    const outsideSecretFile = path.join(tmpDir, "outside-secret.ts");
    fs.writeFileSync(outsideSecretFile, `export const OUTSIDE = "SHOULD_NEVER_BE_HASHED";\n`);

    fs.mkdirSync(path.join(repoDir, "src"), { recursive: true });
    fs.writeFileSync(path.join(repoDir, "src", "index.tsx"), `export const App = () => null;\n`);

    // Create every excluded directory with a dummy file inside
    for (const dirName of DEFAULT_EXCLUDED_DIRS) {
      const excludedSubdir = path.join(repoDir, dirName);
      fs.mkdirSync(excludedSubdir, { recursive: true });
      fs.writeFileSync(path.join(excludedSubdir, "ignored.js"), `console.log("${dirName}");\n`);
    }

    // Create every excluded secret/database file pattern
    const secretFiles = [
      ".env",
      ".env.local",
      ".env.production",
      ".npmrc",
      "server.pem",
      "private.key",
      "signing.pfx",
      "cert.p12",
      "payment-config.json",
      "cache.sqlite",
      "cache.sqlite-wal",
      "local.db",
      "local.db-shm",
    ];
    for (const fileName of secretFiles) {
      fs.writeFileSync(path.join(repoDir, fileName), "TOP_SECRET_CREDENTIAL=12345\n");
    }

    // Attempt symlink creation (supported on Linux/macOS CI and privileged/Dev-Mode Windows;
    // also test custom lstatSync injection if Windows throws EPERM)
    let nativeSymlinkCreated = false;
    try {
      fs.symlinkSync(outsideSecretFile, path.join(repoDir, "src", "escape-link.ts"), "file");
      nativeSymlinkCreated = true;
    } catch (err) {
      if (err && err.code !== "EPERM" && err.code !== "ENOSYS") {
        throw err;
      }
    }

    const envelope = generateSourceProofManifest(repoDir);
    const allPaths = envelope.historicalSourceGraph.entries.map((e) => e.path);

    assert.deepEqual(allPaths, ["src", "src/index.tsx"]);
    assert.equal(envelope.hasPackageJson, false);
    assert.equal(envelope.preBuildSourceFileCount, 1);
    if (nativeSymlinkCreated) {
      assert.equal(envelope.skippedSymlinkCount, 1);
    }

    // Deterministic mock lstat hook test so symlink skipping is verified 100% even on unprivileged Windows
    let lstatCalls = 0;
    const realLstat = fs.lstatSync;
    const simulated = generateSourceProofManifest(repoDir, {
      lstatImpl: (targetPath) => {
        lstatCalls++;
        const st = realLstat(targetPath);
        if (targetPath.endsWith(`index.tsx`)) {
          return {
            isSymbolicLink: () => true,
            isDirectory: () => false,
            isFile: () => false,
            size: 0,
          };
        }
        return st;
      },
    });
    assert.ok(lstatCalls >= 2);
    assert.equal(simulated.fileCount, 0);
    assert.ok(simulated.skippedSymlinkCount >= 1);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("3. stripCodeComments preserves URLs, regex classes, and import-like text inside strings/templates while stripping comments", () => {
  const sample = [
    `const re = /[/*]/g;`,
    `const url = "https://cdn.example.com//v1/*keep*/";`,
    `const single = 'import "./not-real.js"; // keep string';`,
    "const tpl = `prefix https://x.test//path ${/* inline comment */ './real-dyn.js'}`;",
    `// import "./commented-line.js";`,
    `/* export * from "./commented-block.js"; */`,
    `import realDefault from "./actual.js";`,
  ].join("\n");

  const stripped = stripCodeComments(sample);
  assert.equal(stripped.includes("commented-line.js"), false);
  assert.equal(stripped.includes("commented-block.js"), false);
  assert.equal(stripped.includes("inline comment"), false);
  assert.equal(stripped.includes("https://cdn.example.com//v1/*keep*/"), true);
  assert.equal(stripped.includes("./actual.js"), true);
  assert.equal(stripped.includes("./real-dyn.js"), true);
});

test("4. CLI writes --out JSON, supports GitHub Action env mode + GITHUB_OUTPUT, and submits mocked OIDC HTTP attestation", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "cws-source-proof-cli-"));
  let receivedRequests = [];

  const srv = http.createServer((req, res) => {
    let body = "";
    req.setEncoding("utf8");
    req.on("data", (chunk) => {
      body += chunk;
    });
    req.on("end", () => {
      receivedRequests.push({
        method: req.method,
        url: req.url,
        headers: req.headers,
        body: body ? JSON.parse(body) : null,
      });

      if (req.url.startsWith("/oidc-token")) {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ value: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.mock.sig" }));
        return;
      }

      if (req.method === "POST" && req.url === "/api/source-proof/attest") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            ok: true,
            attestationId: "spa_mock_12345",
            extensionId: JSON.parse(body).extensionId,
            tier: "Self-Attested Hash Manifest (Zero Code Uploaded)",
            certificateUrl: `http://127.0.0.1/source-proof/${JSON.parse(body).extensionId}`,
            badgeUrl: `http://127.0.0.1/badge/source-proof/${JSON.parse(body).extensionId}.svg`,
          })
        );
        return;
      }

      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "not found" }));
    });
  });

  await new Promise((resolve) => srv.listen(0, "127.0.0.1", resolve));
  const { port } = srv.address();
  const baseUrl = `http://127.0.0.1:${port}`;

  try {
    const repoDir = path.join(tmpDir, "ext");
    fs.mkdirSync(path.join(repoDir, "src"), { recursive: true });
    fs.writeFileSync(path.join(repoDir, "package.json"), JSON.stringify({ name: "cli-ext", version: "1.0.0" }));
    fs.writeFileSync(path.join(repoDir, "src", "bg.mjs"), `import "./helper.mjs";\n`);
    fs.writeFileSync(path.join(repoDir, "src", "helper.mjs"), `export const x = 1;\n`);

    // Direct API test for OIDC token fetch + attestation submission
    const oidcJwt = await fetchGitHubActionsOidcToken({
      audience: "cws-source-proof",
      requestUrl: `${baseUrl}/oidc-token`,
      requestToken: "gha-runtime-token-xyz",
    });
    assert.equal(oidcJwt, "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.mock.sig");

    const extId = "abcdefghijklmnopabcdefghijklmnop";
    const manifest = generateSourceProofManifest(repoDir);
    const apiRes = await submitSourceProofAttestation({
      manifest,
      extensionId: extId,
      apiBaseUrl: baseUrl,
      oidcToken: oidcJwt,
      repoLabel: "owner/cli-ext",
    });
    assert.equal(apiRes.ok, true);
    assert.equal(apiRes.extensionId, extId);

    // Rejects invalid 32-char extension ID
    await assert.rejects(
      () =>
        submitSourceProofAttestation({
          manifest,
          extensionId: "not-a-valid-32-char-cws-id-99999",
          apiBaseUrl: baseUrl,
        }),
      /32-character Chrome Web Store extension ID/i
    );

    // CLI invocation with --out, --attest-ext-id, --api-url, and GitHub Action GITHUB_OUTPUT
    const outPath = path.join(tmpDir, "cli-proof.json");
    const ghOutputPath = path.join(tmpDir, "github_output.txt");
    fs.writeFileSync(ghOutputPath, "", "utf8");

    await execFileAsync(
      process.execPath,
      [
        path.join(pkgRoot, "bin", "cws-source-proof.mjs"),
        repoDir,
        "--out",
        outPath,
        "--attest-ext-id",
        extId,
        "--api-url",
        baseUrl,
        "--repo-label",
        "owner/cli-ext",
      ],
      {
        encoding: "utf8",
        env: {
          ...process.env,
          ACTIONS_ID_TOKEN_REQUEST_URL: `${baseUrl}/oidc-token`,
          ACTIONS_ID_TOKEN_REQUEST_TOKEN: "gha-runtime-token-cli",
          GITHUB_OUTPUT: ghOutputPath,
        },
      }
    );

    const written = JSON.parse(fs.readFileSync(outPath, "utf8"));
    assert.equal(written.rootSha256, manifest.rootSha256);

    const ghOut = fs.readFileSync(ghOutputPath, "utf8");
    assert.match(ghOut, /root-sha256=[0-9a-f]{64}/);
    assert.match(ghOut, /manifest-path=/);
    assert.match(ghOut, /badge-markdown=/);

    const attestCalls = receivedRequests.filter((r) => r.url === "/api/source-proof/attest");
    assert.equal(attestCalls.length, 2);
    assert.equal(
      attestCalls[1].headers.authorization,
      "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.mock.sig"
    );
    assert.equal(attestCalls[1].body.extensionId, extId);
    assert.equal(attestCalls[1].body.repoLabel, "owner/cli-ext");
  } finally {
    await new Promise((resolve) => srv.close(resolve));
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("5. forensic package hygiene: zero external dependencies, injection-safe action.yml, MIT LICENSE, .gitignore, and zero forbidden internal tokens", () => {
  assert.equal(
    DEFAULT_ATTESTATION_API_URL,
    "https://b2b-audit-dropzone-production.up.railway.app"
  );
  assert.ok(DEFAULT_EXCLUDED_FILE_PATTERNS.length >= 8);

  const pkgJson = JSON.parse(fs.readFileSync(path.join(pkgRoot, "package.json"), "utf8"));
  assert.equal(pkgJson.license, "MIT");
  assert.equal(pkgJson.type, "module");
  assert.deepEqual(pkgJson.dependencies, {});
  assert.equal("devDependencies" in pkgJson, false);

  const gitignore = fs.readFileSync(path.join(pkgRoot, ".gitignore"), "utf8");
  assert.match(gitignore, /^\.env$/m);
  assert.match(gitignore, /^\.env\.\*$/m);

  const license = fs.readFileSync(path.join(pkgRoot, "LICENSE"), "utf8");
  assert.match(license, /MIT License/);

  const actionYml = fs.readFileSync(path.join(pkgRoot, "action.yml"), "utf8");
  // Inspect action.yml run: blocks to verify workflow input expressions never appear on shell lines
  const lines = actionYml.split(/\r?\n/);
  let inRunBlock = false;
  let runIndent = 0;
  for (const line of lines) {
    const runMatch = line.match(/^(\s*)run:\s*\|?\s*(.*)$/);
    if (runMatch) {
      inRunBlock = true;
      runIndent = runMatch[1].length;
      assert.equal(
        /\$\{\{\s*inputs\./.test(runMatch[2]),
        false,
        `Forbidden inline inputs interpolation on run line: ${line}`
      );
      continue;
    }
    if (inRunBlock) {
      const currentIndent = (line.match(/^(\s*)/) || ["", ""])[1].length;
      if (line.trim() !== "" && currentIndent <= runIndent) {
        inRunBlock = false;
      } else {
        assert.equal(
          /\$\{\{\s*inputs\./.test(line),
          false,
          `Forbidden inline inputs interpolation inside run block: ${line}`
        );
      }
    }
  }

  const readme = fs.readFileSync(path.join(pkgRoot, "README.md"), "utf8");
  assert.match(readme, /Self-Attested Hash Manifest \(Zero Code Uploaded\)/);
  assert.match(readme, /\$1,500/);
  assert.match(readme, /https:\/\/b2b-audit-dropzone-production\.up\.railway\.app\/open-source\/cws-source-proof/);
  assert.match(readme, /https:\/\/b2b-audit-dropzone-production\.up\.railway\.app\/directory/);

  // Scan every file in packages/cws-source-proof/ for forbidden internal tokens, Windows paths, or GitHub Push-Protection secret prefixes
  const stripeLivePrefix = ["sk", "live", ""].join("_");
  const openAiPrefix = ["sk", "proj", ""].join("-");
  const awsPrefix = "AK" + "IA";
  const ghpPrefix = "ghp" + "_";
  const slackPrefix = "xoxb" + "-";
  const forbiddenWord = new RegExp(
    `\\b${"R" + "EA"}\\b|${"rev" + "erse"}[-\\s]?engineer|${"Id" + "ea"}-[1-5]|c:\\\\Users|${stripeLivePrefix}|${openAiPrefix}|${awsPrefix}[0-9A-Z]{8,}|${ghpPrefix}|${slackPrefix}`,
    "i"
  );
  function walkPkg(dir) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (entry.name === "node_modules" || entry.name === ".git") continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        walkPkg(full);
      } else if (entry.isFile()) {
        const text = fs.readFileSync(full, "utf8");
        assert.equal(
          forbiddenWord.test(text),
          false,
          `Forbidden internal token detected in ${path.relative(pkgRoot, full)}`
        );
      }
    }
  }
  walkPkg(pkgRoot);
});
