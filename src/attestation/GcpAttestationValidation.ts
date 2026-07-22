// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { ServiceResult } from "../utils/ServiceResult";
import { IAttestationReport } from "./ISnpAttestationReport";
import { gcpKeyReleasePolicyMap } from "../repositories/Maps";
import { KeyReleasePolicy } from "../policies/KeyReleasePolicy";
import { Logger, LogContext } from "../utils/Logger";

/**
 * Validates a GCP Confidential Space workload against the GCP key release policy.
 *
 * Unlike Azure Confidential VMs, GCP Confidential Space does NOT expose a raw
 * AMD SEV-SNP report (with endorsements / uvm_endorsements) to the workload.
 * The hardware-rooted attestation is delivered as the
 * `confidentialcomputing.googleapis.com` OIDC JWT. That token is already
 * cryptographically validated by the CCF `jwt` auth policy before this code runs.
 *
 * Gate split (mirrors Azure):
 *  - Gate 1 (authentication, jwt_validation): the caller IDENTITY - the GCP IAM
 *    `google_service_accounts` - is authorized here by `JwtValidator`, exactly
 *    as the Azure managed-identity `sub`/`oid` is. It is NOT re-checked below.
 *  - Gate 2 (authorization, this function): the code MEASUREMENT - the container
 *    `image_digest` - is checked against `gcpKeyReleasePolicyMap` (the GCP analog
 *    of the Azure `x-ms-sevsnpvm-hostdata` allowlist), populated via the
 *    `set_gcp_key_release_policy` governance action.
 *
 * Image pinning is being rolled out incrementally: until an `image_digest`
 * allowlist has been registered, the GCP key release policy is empty and Gate 2
 * is a pass-through (any image accepted) - authorization then rests entirely on
 * the Gate 1 service-account allowlist. Once image_digest entries exist, they
 * are enforced.
 */
const extractGcpClaims = (payload: {
  [key: string]: any;
}): IAttestationReport => {
  const claims: IAttestationReport = {};
  const set = (key: string, value: any) => {
    if (value === undefined || value === null) return;
    // Policy comparison is string/number based; collapse arrays to a scalar.
    claims[key] = Array.isArray(value) ? value.join(",") : value;
  };

  // Top-level Confidential Space token claims (environmental; the identity
  // claim `google_service_accounts` is deliberately NOT surfaced here - it is
  // authorized at Gate 1 by JwtValidator, not in the Gate 2 key release policy).
  set("iss", payload.iss);
  set("swname", payload.swname); // "CONFIDENTIAL_SPACE"
  set(
    "swversion",
    Array.isArray(payload.swversion) ? payload.swversion[0] : payload.swversion,
  );
  set("hwmodel", payload.hwmodel); // e.g. "GCP_INTEL_TDX"
  set("oemid", payload.oemid);
  set("dbgstat", payload.dbgstat); // e.g. "disabled-since-boot"
  set("secboot", payload.secboot);

  // Workload container claims (submods.container). `image_digest` is the code
  // MEASUREMENT the Gate 2 key release policy allowlists - the GCP analog of
  // Azure `x-ms-sevsnpvm-hostdata`.
  const container = payload.submods?.container;
  if (container) {
    set("image_digest", container.image_digest); // "sha256:..."
    set("image_reference", container.image_reference);
    set("restart_policy", container.restart_policy);
  }

  // Confidential Space support attributes (submods.confidential_space).
  const cs = payload.submods?.confidential_space;
  if (cs) {
    set("support_attributes", cs.support_attributes);
  }

  return claims;
};

export const validateGcpAttestation = (
  jwtClaims: { [key: string]: any } | undefined,
  logContextIn?: LogContext,
): ServiceResult<string | IAttestationReport> => {
  const logContext = (
    logContextIn?.clone() || new LogContext()
  ).appendScope("validateGcpAttestation");
  Logger.debug(
    `Start GCP (Confidential Space JWT) attestation validation`,
    logContext,
  );

  if (!jwtClaims || typeof jwtClaims !== "object") {
    return ServiceResult.Failed<string>(
      { errorMessage: "missing GCP Confidential Space JWT claims" },
      400,
      logContext,
    );
  }

  try {
    const attestationClaims = extractGcpClaims(jwtClaims);
    Logger.debug(`GCP attestation claims: `, logContext, attestationClaims);

    // Gate 2 image-digest pinning is incremental. Until an image_digest
    // allowlist is registered the GCP key release map is empty; treat that as
    // "any image allowed" and let authorization rest on the Gate 1
    // service-account allowlist. Checked BEFORE getKeyReleasePolicyFromMap,
    // which throws when the mandatory `claims` entry is absent.
    if (gcpKeyReleasePolicyMap.size === 0) {
      Logger.info(
        `GCP key release policy is empty (image pinning not enabled); skipping ` +
          `Gate 2 image check - authorization enforced at Gate 1 (service account).`,
        logContext,
      );
      return ServiceResult.Succeeded<IAttestationReport>(
        attestationClaims,
        logContext,
      );
    }

    const keyReleasePolicy = KeyReleasePolicy.getKeyReleasePolicyFromMap(
      gcpKeyReleasePolicyMap,
      logContext,
    );
    Logger.debug(
      `GCP key release policy: ${JSON.stringify(keyReleasePolicy)}`,
      logContext,
    );

    // A policy whose `claims` were all removed leaves an empty object; also a
    // pass-through until image_digest entries are (re)added.
    if (Object.keys(keyReleasePolicy.claims).length === 0) {
      Logger.info(
        `GCP key release policy has no claims (image pinning not enabled); ` +
          `skipping Gate 2 image check.`,
        logContext,
      );
      return ServiceResult.Succeeded<IAttestationReport>(
        attestationClaims,
        logContext,
      );
    }

    return KeyReleasePolicy.validateKeyReleasePolicy(
      keyReleasePolicy,
      attestationClaims,
      logContext,
    );
  } catch (exception: any) {
    return ServiceResult.Failed<string>(
      { errorMessage: `GCP attestation error: ${exception.message}` },
      500,
      logContext,
    );
  }
};
