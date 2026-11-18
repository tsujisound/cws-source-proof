#!/usr/bin/env node
import { runSourceProofCli } from "../src/index.mjs";

runSourceProofCli().then(
  (code) => process.exit(code),
  (err) => {
    console.error("[cws-source-proof] Error:", err?.message || err);
    process.exit(1);
  }
);
