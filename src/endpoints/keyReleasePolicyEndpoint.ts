// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import * as ccfapp from "@microsoft/ccf-app";
import { ServiceResult } from "../utils/ServiceResult";
import { enableEndpoint } from "../utils/Tooling";
import { keyReleasePolicyMap, gcpKeyReleasePolicyMap } from "../repositories/Maps";
import { ServiceRequest } from "../utils/ServiceRequest";
import { KeyReleasePolicy } from "../policies/KeyReleasePolicy";
import { IKeyReleasePolicy } from "../policies/IKeyReleasePolicy";
import { AttestationProvider } from "../attestation/ISnpAttestation";
import { LogContext } from "../utils/Logger";

// Enable the endpoint
enableEndpoint();

/**
 * Retrieves the key release policy.
 *
 * Cloud is selected the same way as /key and /unwrapKey, via the
 * `attestationType` selector (default "azure"). Since this is a GET, the
 * selector is a query parameter: `?attestationType=gcp` returns the GCP policy
 * (`public:policies.gcp_key_release`), otherwise the Azure policy is returned.
 * @returns A ServiceResult containing the key release policy properties.
 */
export const keyReleasePolicy = (
  request: ccfapp.Request<void>,
): ServiceResult<string | IKeyReleasePolicy> => {
  const logContext = new LogContext().appendScope("keyReleasePolicyEndpoint");
  const serviceRequest = new ServiceRequest<void>(logContext, request);

  // check if caller has a valid identity
  const [_, isValidIdentity] = serviceRequest.isAuthenticated();
  if (isValidIdentity.failure) return isValidIdentity;

  const attestationProvider: AttestationProvider =
    (serviceRequest.query?.["attestationType"] as AttestationProvider) || "azure";
  const policyMap =
    attestationProvider === "gcp" ? gcpKeyReleasePolicyMap : keyReleasePolicyMap;

  try {
    const result = KeyReleasePolicy.getKeyReleasePolicyFromMap(
      policyMap,
      logContext,
    );
    return ServiceResult.Succeeded<IKeyReleasePolicy>(result, logContext);
  } catch (error: any) {
    return ServiceResult.Failed<string>({ errorMessage: error.message }, 500, logContext);
  }
};
