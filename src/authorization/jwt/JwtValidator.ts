// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import * as ccfapp from "@microsoft/ccf-app";
import { ServiceResult } from "../../utils/ServiceResult";
import { IValidatorService } from "../IValidationService";
import { Logger, LogContext } from "../../utils/Logger";
import { JwtValidationPolicyMap } from "./JwtValidationPolicyMap";

export class JwtValidator implements IValidatorService {
  private logContext: LogContext;

  constructor(logContext?: LogContext) {
    this.logContext = (logContext?.clone() || new LogContext()).appendScope("JwtValidator");
  }

  validate(request: ccfapp.Request<any>): ServiceResult<string> {
    const jwtCaller = request.caller as unknown as ccfapp.JwtAuthnIdentity;
    Logger.debug(
      `Authorization: JWT jwtCaller (JwtValidator)-> ${jwtCaller.jwt.keyIssuer}`,
      this.logContext
    );
    const issuer = jwtCaller?.jwt?.payload?.iss;
    if (!issuer) {
      return ServiceResult.Failed(
        {
          errorMessage: "The JWT has no valid iss",
          errorType: "AuthenticationError",
        },
        400,
        this.logContext
      );
    }


    const policy = JwtValidationPolicyMap.read(issuer, this.logContext);
    if (policy === undefined) {
      const errorMessage = `issuer ${issuer} is not defined in the policy`;
      Logger.error(errorMessage, this.logContext);
      return ServiceResult.Failed(
        {
          errorMessage,
          errorType: "AuthenticationError",
        },
        500,
        this.logContext
      );
    }
    Logger.debug(
      `Validate JWT policy for issuer ${issuer}: ${JSON.stringify(policy)}`, this.logContext
    );

    const keys = Object.keys(policy);

    for (let inx = 0; inx < keys.length; inx++) {
      const key = keys[inx];
      const jwtProp = jwtCaller?.jwt?.payload[key];
      let compliant = false;

      // Normalise both sides to arrays and pass if ANY token value matches ANY
      // policy value. This makes the policy value an allowlist and, crucially,
      // supports array-valued token claims such as `google_service_accounts`
      // (the GCP Confidential Space service-account allowlist enforced here at
      // Gate 1, analogous to the Azure managed-identity `sub`/`oid`). Scalar
      // claims (iss, sub, oid, swname) keep the original strict-equality
      // behaviour since a one-element array compares identically.
      const policyValues = Array.isArray(policy[key]) ? policy[key] : [policy[key]];
      const jwtValues = Array.isArray(jwtProp) ? jwtProp : [jwtProp];
      compliant = jwtValues.some((jv) => policyValues.some((pv) => pv === jv));

      Logger.debug(
        `isValidJwtToken: ${key}, expected: ${policy[key]}, found: ${jwtProp}, ${compliant}`, this.logContext
      );

      if (!compliant) {
        const errorMessage = `The JWT has no valid ${key}, expected: ${policy[key]}, found: ${jwtProp}`;
        Logger.error(errorMessage, this.logContext);
        return ServiceResult.Failed(
          { errorMessage, errorType: "AuthenticationError" },
          401,
          this.logContext
        );
      }
    }

    const identityId = jwtCaller?.jwt?.payload?.oid;
    Logger.debug(
      `Authorization: JWT validation result (JwtValidator) for provider ${jwtCaller.jwt.keyIssuer}-> success`,
      this.logContext
    );
    return ServiceResult.Succeeded(identityId, this.logContext);
  }
}
