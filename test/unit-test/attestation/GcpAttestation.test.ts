// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Use the CCF polyfill to mock-up all key-value map functionality for unit-test
import "@microsoft/ccf-app/polyfill.js";
import * as ccfapp from "@microsoft/ccf-app";
import { ccf } from "@microsoft/ccf-app/global";
import { beforeAll, beforeEach, describe, expect, test } from "@jest/globals";
import { Logger, LogLevel } from "../../../src/utils/Logger";
import { validateGcpAttestation } from "../../../src/attestation/GcpAttestationValidation";
import { validateAttestation } from "../../../src/attestation/AttestationValidation";
import { gcpKeyReleaseMapName } from "../../../src/repositories/Maps";
import { ISnpAttestation } from "../../../src/attestation/ISnpAttestation";
import { JwtValidator } from "../../../src/authorization/jwt/JwtValidator";
import { validationPolicyMapName } from "../../../src/authorization/jwt/JwtValidationPolicyMap";
import {
  canonicalContainerString,
  CONTAINER_MEASUREMENT_VERSION,
} from "../../../src/attestation/containerMeasurement";
import { createHash } from "crypto";

// GCP Confidential Space authorization is split across two gates, mirroring
// Azure:
//   * Gate 1 (authentication, jwt_validation): the workload IDENTITY -
//     google_service_accounts - like the Azure managed-identity sub/oid.
//   * Gate 2 (authorization, gcp_key_release): the code MEASUREMENT -
//     image_digest - like the Azure x-ms-sevsnpvm-hostdata.
// These tests exercise each gate at its enforcement point.

const GCP_ISS = "https://confidentialcomputing.googleapis.com";

// Minimal stub used in routing-confirmation tests where we only need to
// distinguish which code path was taken (not whether attestation succeeds).
const DUMMY_ATTESTATION: ISnpAttestation = {
  evidence: "dGVzdA==",
  endorsements: "dGVzdA==",
  uvm_endorsements: "dGVzdA==",
  endorsed_tcb: "test",
};

// --------------------------------------------------------------------------
// Helpers: seed the Gate 1 (jwt_validation) and Gate 2 (gcp_key_release) maps
// --------------------------------------------------------------------------
const setValidationPolicy = (policy: Record<string, unknown>) => {
  ccf.kv[validationPolicyMapName].set(
    ccf.strToBuf(GCP_ISS),
    ccf.strToBuf(JSON.stringify(policy)),
  );
};

const clearValidationPolicy = () => {
  const keyBuf = ccf.strToBuf(GCP_ISS);
  if (ccf.kv[validationPolicyMapName].has(keyBuf)) {
    ccf.kv[validationPolicyMapName].delete(keyBuf);
  }
};

const setGcpClaims = (claims: Record<string, string[]>) => {
  ccf.kv[gcpKeyReleaseMapName].set(
    ccf.strToBuf("claims"),
    ccf.strToBuf(JSON.stringify(claims)),
  );
};

const clearGcpPolicy = () => {
  for (const k of ["claims", "gte", "gt"]) {
    const keyBuf = ccf.strToBuf(k);
    if (ccf.kv[gcpKeyReleaseMapName].has(keyBuf)) {
      ccf.kv[gcpKeyReleaseMapName].delete(keyBuf);
    }
  }
};

// A fake CCF JWT-authenticated request carrying the given token payload.
const jwtRequest = (payload: { [k: string]: any }): ccfapp.Request<any> =>
  ({
    caller: { jwt: { keyIssuer: payload.iss, payload } },
  }) as unknown as ccfapp.Request<any>;

// A Confidential Space token payload. image_digest lives under submods.container.
const gcpToken = (overrides: { [k: string]: any } = {}) => ({
  iss: GCP_ISS,
  swname: "CONFIDENTIAL_SPACE",
  submods: { container: { image_digest: "sha256:aaaa" } },
  ...overrides,
});

// A CS token carrying a full container object (+ optional top-level claims such
// as dbgstat / secboot), for the container_measurement / posture tests.
const gcpTokenWithContainer = (
  container: { [k: string]: any },
  top: { [k: string]: any } = {},
) => ({
  iss: GCP_ISS,
  swname: "CONFIDENTIAL_SPACE",
  submods: { container },
  ...top,
});

// Independent (Node-side) recomputation of the measurement — mirrors exactly
// what the offline registration CLI does: SHA-256 over the shared canonical
// string. If this and the KMS ever disagree, canonicalisation has drifted.
const measurementOf = (container: { [k: string]: any }): string =>
  createHash("sha256")
    .update(canonicalContainerString(container), "utf8")
    .digest("hex");

beforeAll(() => {
  Logger.setLogLevel(LogLevel.ERROR); // keep test output clean
});

beforeEach(() => {
  clearGcpPolicy();
  clearValidationPolicy();
});

// ==========================================================================
// Gate 1 - authentication: the service-account allowlist enforced by
// JwtValidator against the jwt_validation policy (the array-aware matcher).
// ==========================================================================
describe("Gate 1: JwtValidator google_service_accounts allowlist", () => {
  const SA_A = "gpu-cs-sa@p3dx-depa-sandbox.iam.gserviceaccount.com";
  const SA_B = "other-sa@proj.iam.gserviceaccount.com";

  test("passes when the workload SA is in the allowlist", () => {
    setValidationPolicy({
      iss: GCP_ISS,
      swname: "CONFIDENTIAL_SPACE",
      google_service_accounts: [SA_A],
    });
    const result = new JwtValidator().validate(
      jwtRequest(gcpToken({ google_service_accounts: [SA_A] })),
    );
    expect(result.success).toBe(true);
  });

  test("fails when the workload SA is not in the allowlist", () => {
    setValidationPolicy({
      iss: GCP_ISS,
      swname: "CONFIDENTIAL_SPACE",
      google_service_accounts: [SA_A],
    });
    const result = new JwtValidator().validate(
      jwtRequest(gcpToken({ google_service_accounts: [SA_B] })),
    );
    expect(result.success).toBe(false);
    expect(result.statusCode).toBe(401);
  });

  test("passes when ANY of multiple workload SAs is allowlisted", () => {
    setValidationPolicy({
      iss: GCP_ISS,
      swname: "CONFIDENTIAL_SPACE",
      google_service_accounts: [SA_A],
    });
    const result = new JwtValidator().validate(
      jwtRequest(gcpToken({ google_service_accounts: [SA_B, SA_A] })),
    );
    expect(result.success).toBe(true);
  });

  test("supports an allowlist holding many service accounts", () => {
    setValidationPolicy({
      iss: GCP_ISS,
      swname: "CONFIDENTIAL_SPACE",
      google_service_accounts: [SA_A, SA_B, "third-sa@x.iam.gserviceaccount.com"],
    });
    const result = new JwtValidator().validate(
      jwtRequest(gcpToken({ google_service_accounts: [SA_B] })),
    );
    expect(result.success).toBe(true);
  });

  test("empty allowlist denies all (secure default before registration)", () => {
    setValidationPolicy({
      iss: GCP_ISS,
      swname: "CONFIDENTIAL_SPACE",
      google_service_accounts: [],
    });
    const result = new JwtValidator().validate(
      jwtRequest(gcpToken({ google_service_accounts: [SA_A] })),
    );
    expect(result.success).toBe(false);
    expect(result.statusCode).toBe(401);
  });

  test("fails when the token carries no service account but policy requires one", () => {
    setValidationPolicy({
      iss: GCP_ISS,
      swname: "CONFIDENTIAL_SPACE",
      google_service_accounts: [SA_A],
    });
    const result = new JwtValidator().validate(jwtRequest(gcpToken()));
    expect(result.success).toBe(false);
    expect(result.statusCode).toBe(401);
  });

  test("still enforces scalar claims (swname mismatch fails)", () => {
    setValidationPolicy({
      iss: GCP_ISS,
      swname: "CONFIDENTIAL_SPACE",
      google_service_accounts: [SA_A],
    });
    const result = new JwtValidator().validate(
      jwtRequest(gcpToken({ swname: "SOMETHING_ELSE", google_service_accounts: [SA_A] })),
    );
    expect(result.success).toBe(false);
    expect(result.statusCode).toBe(401);
  });
});

// ==========================================================================
// Gate 2 - authorization: the image_digest allowlist enforced by
// validateGcpAttestation against the gcp_key_release policy. Image pinning is
// incremental: an empty policy is a pass-through (any image), enforced once
// digests are registered.
// ==========================================================================
describe("Gate 2: validateGcpAttestation image_digest allowlist", () => {
  test("fails when JWT claims are missing", () => {
    const result = validateGcpAttestation(undefined);
    expect(result.success).toBe(false);
    expect(result.statusCode).toBe(400);
    expect(result.error?.errorMessage).toContain(
      "missing GCP Confidential Space JWT claims",
    );
  });

  test("passes when the GCP key release policy is empty (image pinning off)", () => {
    // beforeEach cleared the map; nothing registered.
    const result = validateGcpAttestation(gcpToken());
    expect(result.success).toBe(true);
  });

  test("passes when policy claims exist but are empty", () => {
    setGcpClaims({});
    const result = validateGcpAttestation(gcpToken());
    expect(result.success).toBe(true);
  });

  test("passes when image_digest matches the allowlist", () => {
    setGcpClaims({ image_digest: ["sha256:aaaa"] });
    const result = validateGcpAttestation(
      gcpToken({ submods: { container: { image_digest: "sha256:aaaa" } } }),
    );
    expect(result.success).toBe(true);
  });

  test("fails when image_digest is not in the allowlist", () => {
    setGcpClaims({ image_digest: ["sha256:aaaa"] });
    const result = validateGcpAttestation(
      gcpToken({ submods: { container: { image_digest: "sha256:bbbb" } } }),
    );
    expect(result.success).toBe(false);
    expect(result.statusCode).toBe(400);
  });

  test("does NOT authorize on the service account (that is Gate 1's job)", () => {
    // A registered image_digest that the token lacks must fail even if the SA
    // would otherwise be trusted - Gate 2 is about the code, not the identity.
    setGcpClaims({ image_digest: ["sha256:only-this-image"] });
    const result = validateGcpAttestation(
      gcpToken({
        google_service_accounts: ["trusted-sa@proj.iam.gserviceaccount.com"],
        submods: { container: { image_digest: "sha256:different" } },
      }),
    );
    expect(result.success).toBe(false);
    expect(result.statusCode).toBe(400);
  });
});

// ==========================================================================
describe("validateAttestation routing", () => {
  test("routes to the GCP path when attestationType is 'gcp'", () => {
    // Empty GCP policy => Gate 2 pass-through; success proves the GCP path ran
    // (the azure path would attempt SNP binary verification and fail).
    const result = validateAttestation(undefined, "gcp", gcpToken());
    expect(result.success).toBe(true);
  });

  test("defaults to the azure path when attestationType is omitted", () => {
    // The azure path fails with "Internal error" (not "GCP attestation error").
    const result = validateAttestation(DUMMY_ATTESTATION, "azure");
    expect(result.success).toBe(false);
    expect(result.error?.errorMessage).not.toContain("GCP");
  });
});

// ==========================================================================
// container_measurement canonicalisation - GOLDEN values. These lock the exact
// bytes that get hashed so the KMS (Gate 2) and the offline registration CLI can
// never silently diverge. If you intentionally change the format, bump
// CONTAINER_MEASUREMENT_VERSION and update these expected values.
// ==========================================================================
describe("container measurement: canonical string + golden hash", () => {
  const SAMPLE = {
    image_digest: "sha256:aaaa",
    image_id: "sha256:bbbb",
    restart_policy: "Never",
    args: ["sh", "/server/bin/init_server_basic"],
  };

  test("canonical string is the exact fixed-format v1 layout", () => {
    expect(canonicalContainerString(SAMPLE)).toBe(
      [
        "depa-gcp-container-measurement/v1",
        "image_digest=sha256:aaaa",
        "image_id=sha256:bbbb",
        "restart_policy=Never",
        'args=["sh","/server/bin/init_server_basic"]',
      ].join("\n"),
    );
    expect(canonicalContainerString(SAMPLE).startsWith(
      CONTAINER_MEASUREMENT_VERSION,
    )).toBe(true);
  });

  test("SHA-256 of the canonical string matches the golden hash", () => {
    expect(measurementOf(SAMPLE)).toBe(
      "e6a1ee6787055ddd7aba43c23d6a9daffd540e0031d27900930ce116f60b2cdd",
    );
  });

  test("field order in the object does not change the measurement", () => {
    const reordered = {
      args: ["sh", "/server/bin/init_server_basic"],
      restart_policy: "Never",
      image_id: "sha256:bbbb",
      image_digest: "sha256:aaaa",
    };
    expect(measurementOf(reordered)).toBe(measurementOf(SAMPLE));
  });

  test("a change to any hashed field changes the measurement", () => {
    expect(measurementOf({ ...SAMPLE, args: ["sh", "-x"] })).not.toBe(
      measurementOf(SAMPLE),
    );
    expect(measurementOf({ ...SAMPLE, image_digest: "sha256:zzzz" })).not.toBe(
      measurementOf(SAMPLE),
    );
  });
});

// ==========================================================================
// Gate 2 - authorization via container_measurement (the hostdata analog) and
// the launcher/hardware posture claims (dbgstat / secboot). The KMS recomputes
// the measurement from the token and matches it against the registered
// allowlist, exactly as it would for Azure x-ms-sevsnpvm-hostdata.
// ==========================================================================
describe("Gate 2: validateGcpAttestation container_measurement + posture", () => {
  const CONTAINER = {
    image_digest:
      "sha256:7a26b814c5dad71ae0e4ab08855039394d4429e0a947757c92c8953cc5bacc2d",
    image_id:
      "sha256:72c50742eb507648d40372108a020bac0503333084a7921d83bb8d91c7e4c100",
    restart_policy: "Never",
    args: ["sh", "/server/bin/init_server_basic"],
  };

  test("releases when the recomputed measurement is in the allowlist", () => {
    setGcpClaims({ container_measurement: [measurementOf(CONTAINER)] });
    const result = validateGcpAttestation(gcpTokenWithContainer(CONTAINER));
    expect(result.success).toBe(true);
  });

  test("rejects when the measurement is not in the allowlist", () => {
    setGcpClaims({ container_measurement: [measurementOf(CONTAINER)] });
    // A different image digest -> different measurement -> no match.
    const tampered = { ...CONTAINER, image_digest: "sha256:deadbeef" };
    const result = validateGcpAttestation(gcpTokenWithContainer(tampered));
    expect(result.success).toBe(false);
    expect(result.statusCode).toBe(400);
  });

  test("supports an allowlist of several images (multi-service)", () => {
    const other = { ...CONTAINER, image_digest: "sha256:other", args: ["/kv"] };
    setGcpClaims({
      container_measurement: [measurementOf(CONTAINER), measurementOf(other)],
    });
    expect(
      validateGcpAttestation(gcpTokenWithContainer(other)).success,
    ).toBe(true);
  });

  test("enforces dbgstat posture (debug-enabled token rejected)", () => {
    setGcpClaims({
      container_measurement: [measurementOf(CONTAINER)],
      dbgstat: ["disabled-since-boot"],
    });
    const debugTok = gcpTokenWithContainer(CONTAINER, { dbgstat: "enabled" });
    const result = validateGcpAttestation(debugTok);
    expect(result.success).toBe(false);
    expect(result.statusCode).toBe(400);
  });

  test("passes dbgstat posture when the token is hardened", () => {
    setGcpClaims({
      container_measurement: [measurementOf(CONTAINER)],
      dbgstat: ["disabled-since-boot"],
    });
    const hardened = gcpTokenWithContainer(CONTAINER, {
      dbgstat: "disabled-since-boot",
    });
    expect(validateGcpAttestation(hardened).success).toBe(true);
  });

  test("enforces secboot posture (secboot=false rejected)", () => {
    setGcpClaims({
      container_measurement: [measurementOf(CONTAINER)],
      secboot: ["true"],
    });
    const noSecboot = gcpTokenWithContainer(CONTAINER, { secboot: false });
    const result = validateGcpAttestation(noSecboot);
    expect(result.success).toBe(false);
    expect(result.statusCode).toBe(400);
  });

  test("passes secboot posture when secboot=true", () => {
    setGcpClaims({
      container_measurement: [measurementOf(CONTAINER)],
      secboot: ["true"],
    });
    const secure = gcpTokenWithContainer(CONTAINER, { secboot: true });
    expect(validateGcpAttestation(secure).success).toBe(true);
  });
});
