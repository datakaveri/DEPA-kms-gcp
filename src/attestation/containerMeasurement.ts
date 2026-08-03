// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

/**
 * GCP Confidential Space "container measurement" — a compact, hostdata-style
 * fingerprint of a workload's container identity, used by the Gate 2 key
 * release policy.
 *
 * Azure pins the code with `x-ms-sevsnpvm-hostdata` = SHA-256 of the confcom
 * CCE-policy string. GCP's equivalent is SHA-256 of the canonical string built
 * below from the STABLE, code-identifying subset of the Confidential Space
 * token's `submods.container`:
 *   - image_digest   (the image manifest digest, "sha256:...")
 *   - image_id       (the image config digest, "sha256:...")
 *   - restart_policy (e.g. "Never")
 *   - args           (the container command)
 *
 * Volatile / deployment-specific fields (`env`, `env_override`) are
 * DELIBERATELY excluded: they carry per-VM IP addresses, instance hostnames and
 * per-deployment KMS URLs, so hashing them would make the measurement change on
 * every deployment/restart. This mirrors how Azure's CCE policy pins the code +
 * command rather than runtime-assigned values.
 *
 * IMPORTANT — this string is the EXACT input that is SHA-256'd on BOTH sides:
 *   1. the KMS (Gate 2 validation, GcpAttestationValidation), and
 *   2. the offline registration CLI that computes the value to register.
 * Both import THIS function so their bytes can never disagree. The format is
 * canonical: a version tag, a fixed field order, one `key=value` line each, and
 * a compact JSON encoding of `args`. If you ever change the format, bump
 * CONTAINER_MEASUREMENT_VERSION and re-register every measurement.
 */

export interface GcpContainerClaims {
  image_digest?: string;
  image_id?: string;
  restart_policy?: string;
  args?: string[];
}

export const CONTAINER_MEASUREMENT_VERSION =
  "depa-gcp-container-measurement/v1";

/**
 * Builds the canonical string that is hashed to produce the container
 * measurement. Deterministic across the CCF JS runtime (KMS) and Node (CLI):
 * identical field order, no incidental whitespace, and `args` JSON-encoded
 * compactly (ECMA-262 JSON.stringify is identical in both engines for a string
 * array). Missing fields are encoded as empty so the output is always defined.
 */
export function canonicalContainerString(
  container: GcpContainerClaims,
): string {
  const args = Array.isArray(container.args) ? container.args : [];
  return [
    CONTAINER_MEASUREMENT_VERSION,
    `image_digest=${container.image_digest ?? ""}`,
    `image_id=${container.image_id ?? ""}`,
    `restart_policy=${container.restart_policy ?? ""}`,
    `args=${JSON.stringify(args)}`,
  ].join("\n");
}
