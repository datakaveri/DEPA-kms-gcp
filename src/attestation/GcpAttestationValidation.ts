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
 * cryptographically validated by the CCF `jwt` auth policy (issuer + signing
 * key registered at the governance level) before this code runs, so we
 * authorize key release on the JWT claims rather than on
 * `snp_attestation.verifySnpAttestation()`.
 *
 * The relevant Confidential Space claims are flattened into the same flat
 * claim dictionary consumed by `KeyReleasePolicy.validateKeyReleasePolicy`,
 * and checked against `gcpKeyReleasePolicyMap` (populated via the
 * `set_gcp_key_release_policy` governance action with Confidential Space claim
 * keys, not `x-ms-sevsnpvm-*`).
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
  // Membership-style claims are kept as arrays so the key release policy can
  // check "any value in the token is in the allowlist" (see
  // KeyReleasePolicy.validateKeyReleasePolicyClaims). Do NOT collapse these.
  const setRaw = (key: string, value: any) => {
    if (value === undefined || value === null) return;
    claims[key] = value;
  };

  // Top-level Confidential Space token claims.
  set("iss", payload.iss);
  set("swname", payload.swname); // "CONFIDENTIAL_SPACE"
  set(
    "swversion",
    Array.isArray(payload.swversion) ? payload.swversion[0] : payload.swversion,
  );
  set("hwmodel", payload.hwmodel); // e.g. "GCP_AMD_SEV"
  set("oemid", payload.oemid);
  set("dbgstat", payload.dbgstat); // e.g. "disabled-since-boot"
  set("secboot", payload.secboot);

  // GCP IAM service account(s) the Confidential Space VM runs as. This is the
  // identity the key release policy allowlists (analogous to Azure hostdata).
  // Kept as the raw array: a token may carry more than one, and the policy
  // passes if ANY of them is in the trusted allowlist.
  setRaw("google_service_accounts", payload.google_service_accounts);

  // Workload container claims (submods.container).
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

    const keyReleasePolicy = KeyReleasePolicy.getKeyReleasePolicyFromMap(
      gcpKeyReleasePolicyMap,
      logContext,
    );
    Logger.debug(
      `GCP key release policy: ${JSON.stringify(keyReleasePolicy)}`,
      logContext,
    );

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
