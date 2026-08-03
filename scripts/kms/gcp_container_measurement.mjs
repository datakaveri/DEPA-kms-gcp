#!/usr/bin/env node
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

/**
 * Computes the GCP Confidential Space "container measurement" — the compact,
 * hostdata-style SHA-256 that the Gate 2 key release policy pins for each image.
 *
 * This is the WRITE-side counterpart of the KMS's READ-side check in
 * src/attestation/containerMeasurement.ts + GcpAttestationValidation.ts. The
 * canonical string below is byte-for-byte identical to that module (locked by
 * `--self-test` here and the golden unit test in the KMS), so the value this
 * prints is exactly what the KMS recomputes from the running workload's token.
 *
 * Usage (the workflow uses the explicit-fields form, after `docker inspect`):
 *   node gcp_container_measurement.mjs \
 *     --image-digest sha256:... --image-id sha256:... \
 *     --restart-policy Never --args '["sh","/server/bin/init_server_basic"]'
 *
 *   # verify-once against a real token (decodes; does NOT verify the signature):
 *   node gcp_container_measurement.mjs --token "<jwt>"
 *
 *   # drift guard: assert the canonical format still matches the golden value:
 *   node gcp_container_measurement.mjs --self-test
 *
 * Prints the measurement hex to stdout; the canonical string goes to stderr so
 * it can be eyeballed without polluting the value captured by the workflow.
 */

import { createHash } from "node:crypto";

export const CONTAINER_MEASUREMENT_VERSION = "depa-gcp-container-measurement/v1";

// MUST stay identical to src/attestation/containerMeasurement.ts.
export function canonicalContainerString(container) {
  const args = Array.isArray(container.args) ? container.args : [];
  return [
    CONTAINER_MEASUREMENT_VERSION,
    `image_digest=${container.image_digest ?? ""}`,
    `image_id=${container.image_id ?? ""}`,
    `restart_policy=${container.restart_policy ?? ""}`,
    `args=${JSON.stringify(args)}`,
  ].join("\n");
}

export function computeMeasurement(container) {
  return createHash("sha256")
    .update(canonicalContainerString(container), "utf8")
    .digest("hex");
}

// The golden anchor — identical to the KMS unit test (GcpAttestation.test.ts).
const GOLDEN_SAMPLE = {
  image_digest: "sha256:aaaa",
  image_id: "sha256:bbbb",
  restart_policy: "Never",
  args: ["sh", "/server/bin/init_server_basic"],
};
const GOLDEN_HASH =
  "e6a1ee6787055ddd7aba43c23d6a9daffd540e0031d27900930ce116f60b2cdd";

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--")) out[a.slice(2)] = argv[++i];
  }
  return out;
}

function containerFromToken(jwt) {
  const parts = jwt.split(".");
  if (parts.length < 2) throw new Error("not a JWT");
  const payload = JSON.parse(
    Buffer.from(parts[1], "base64url").toString("utf8"),
  );
  const c = payload?.submods?.container;
  if (!c) throw new Error("token has no submods.container");
  return c;
}

function main() {
  const opts = parseArgs(process.argv.slice(2));

  if ("self-test" in opts) {
    const got = computeMeasurement(GOLDEN_SAMPLE);
    if (got !== GOLDEN_HASH) {
      console.error(
        `SELF-TEST FAILED: canonical format drifted.\n  expected ${GOLDEN_HASH}\n  got      ${got}`,
      );
      process.exit(1);
    }
    console.error("self-test OK (canonical format matches golden)");
    console.log(got);
    return;
  }

  let container;
  if (opts.token) {
    container = containerFromToken(opts.token);
  } else if (opts["image-digest"]) {
    container = {
      image_digest: opts["image-digest"],
      image_id: opts["image-id"],
      restart_policy: opts["restart-policy"] ?? "Never",
      args: opts.args ? JSON.parse(opts.args) : [],
    };
  } else {
    console.error(
      "Provide --token <jwt>, or --image-digest/--image-id/--restart-policy/--args, or --self-test",
    );
    process.exit(2);
  }

  console.error(
    "canonical string:\n" + canonicalContainerString(container) + "\n",
  );
  console.log(computeMeasurement(container));
}

// Run as a CLI only when invoked directly (so tests can import the functions).
if (process.argv[1] && import.meta.url === `file://${process.argv[1]}`) {
  main();
}
