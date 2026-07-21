// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { Action, checkType } from "./default_ccf.js";
import { ccf } from "@microsoft/ccf-app/global";
import { gcpKeyReleaseMapName } from "../repositories/Maps.js";

export let action = [
    "set_gcp_key_release_policy",
    new Action(
      function (args) {
        checkType(args.type, "string");
        checkType(args.claims, "object");
      },
      function (args) {
        // GCP Confidential Space OIDC token claims (flattened by
        // GcpAttestationValidation.extractGcpClaims). These replace the Azure
        // x-ms-sevsnpvm-* claims: GCP does not expose a raw SNP report, so the
        // key-release policy is expressed over the Confidential Space JWT.
        const CLAIMS = {
          iss: "string", // https://confidentialcomputing.googleapis.com
          // GCP IAM service account(s) the Confidential Space workload runs as.
          // This is the trusted-workload allowlist populated at registration
          // time (analogous to Azure "x-ms-sevsnpvm-hostdata").
          google_service_accounts: "string",
          // TODO: image_digest ("sha256:...") to be added here later to pin a
          // fixed set of trusted container images; for now any image is allowed.
        };
        // Function to add key release policy claims
        const add = (type, claims) => {
          let items = {};
          console.log(
            `[INFO] [scope=set_gcp_key_release_policy->add] Add claims to GCP key release policy for ${type}: ${JSON.stringify(claims)}`,
          );
          let keyBuf = ccf.strToBuf(type);
          if (ccf.kv[gcpKeyReleaseMapName].has(keyBuf)) {
            const itemsBuf = ccf.kv[gcpKeyReleaseMapName].get(keyBuf);
            items = ccf.bufToStr(itemsBuf);
            console.log(
              `[INFO] [scope=set_gcp_key_release_policy->add] KRP add ${type}=>key: ${type} already exist: ${items} in the GCP key release policy`,
            );
            try {
              items = JSON.parse(items);
            } catch (e) {
              console.log(
                `[ERROR] [scope=set_gcp_key_release_policy->add] KRP add ${type}=>Error parsing ${items} from GCP key release policy during add`,
                e,
              );
              throw new Error(
                `[ERROR] [scope=set_gcp_key_release_policy->add] Error parsing ${items} from GCP key release policy during add`,
                e,
              );
            }
          } else {
            console.log(
              `[INFO] [scope=set_gcp_key_release_policy->add] KRP add ${type}=>key: ${type} is new in the GCP key release policy`,
            );
          }

          Object.keys(claims).forEach((key) => {
            if (CLAIMS[key] === undefined) {
              throw new Error(
                `[ERROR] [scope=set_gcp_key_release_policy->add] KRP add ${type}=>The claim ${key} is not an allowed claim`,
              );
            }
            let item = claims[key];
            if (!Array.isArray(item)) {
              item = [item];
            }

            if (items[key] !== undefined) {
              item.forEach((i) => {
                if (!items[key].includes(i)) {
                  console.log(`[INFO] [scope=set_gcp_key_release_policy->add] KRP add ${type}=>Adding ${i} to ${key}`);
                  items[key].push(i);
                } else {
                  console.log(`[INFO] [scope=set_gcp_key_release_policy->add] KRP add ${type}=>Skipping duplicate ${i} in ${key}`);
                }
              });
            } else {
              items[key] = [...new Set(item)];
            }
          });

          let jsonItems = JSON.stringify(items);
          let jsonItemsBuf = ccf.strToBuf(jsonItems);
          ccf.kv[gcpKeyReleaseMapName].set(keyBuf, jsonItemsBuf);
        };

        const addOperator = (type, claims) => {
          let items = {};
          console.log(
            `[INFO] [scope=set_gcp_key_release_policy->addOperator] Add claims to GCP key release policy for ${type}: ${JSON.stringify(claims)}`,
          );
          let keyBuf = ccf.strToBuf(type);
          if (ccf.kv[gcpKeyReleaseMapName].has(keyBuf)) {
            const itemsBuf = ccf.kv[gcpKeyReleaseMapName].get(keyBuf);
            items = ccf.bufToStr(itemsBuf);
            try {
              items = JSON.parse(items);
            } catch (e) {
              throw new Error(
                `[ERROR] [scope=set_gcp_key_release_policy->addOperator] Error parsing ${items} from GCP key release policy during addOperator`,
                e,
              );
            }
          }

          Object.keys(claims).forEach((key) => {
            if (CLAIMS[key] === undefined) {
              throw new Error(
                `[ERROR] [scope=set_gcp_key_release_policy->addOperator] KRP add ${type}=>The claim ${key} is not an allowed claim`,
              );
            }
            let item = claims[key];
            if (Array.isArray(item)) {
              throw new Error(`[ERROR] [scope=set_gcp_key_release_policy->addOperator] The operator claim ${key} cannot be an array`);
            }
            items[key] = item;
          });

          let jsonItems = JSON.stringify(items);
          let jsonItemsBuf = ccf.strToBuf(jsonItems);
          ccf.kv[gcpKeyReleaseMapName].set(keyBuf, jsonItemsBuf);
        };

        const remove = (type, claims) => {
          let items = {};
          console.log(
            `[INFO] [scope=set_gcp_key_release_policy->remove] Remove claims from GCP key release policy for ${type}: ${JSON.stringify(claims)}`,
          );
          let keyBuf = ccf.strToBuf(type);
          if (ccf.kv[gcpKeyReleaseMapName].has(keyBuf)) {
            const itemsBuf = ccf.kv[gcpKeyReleaseMapName].get(keyBuf);
            items = ccf.bufToStr(itemsBuf);
            try {
              items = JSON.parse(items);
            } catch (e) {
              throw new Error(
                `[ERROR] [scope=set_gcp_key_release_policy->remove] Error parsing ${items} from GCP key release policy during remove`,
                e,
              );
            }
          } else {
            throw new Error(
              `[ERROR] [scope=set_gcp_key_release_policy->remove] The key ${type} does not exist in the GCP key release policy`,
            );
          }

          Object.keys(claims).forEach((key) => {
            if (CLAIMS[key] === undefined) {
              throw new Error(
                `[ERROR] [scope=set_gcp_key_release_policy->remove] KRP remove ${type}=>The claim ${key} is not an allowed claim`,
              );
            }
            let item = claims[key];
            if (!Array.isArray(item)) {
              item = [item];
            }

            if (items[key] !== undefined) {
              item.forEach((i) => {
                items[key] = items[key].filter((value) => value !== i);
                if (items[key].length === 0) {
                  delete items[key];
                }
              });
            } else {
              throw new Error(
                `[ERROR] [scope=set_gcp_key_release_policy->remove] The claim ${key} does not exist in the GCP key release policy`,
              );
            }
          });

          let jsonItems = JSON.stringify(items);
          let jsonItemsBuf = ccf.strToBuf(jsonItems);
          ccf.kv[gcpKeyReleaseMapName].set(keyBuf, jsonItemsBuf);
        };

        const removeOperator = (type, claims) => {
          let items = {};
          console.log(
            `[INFO] [scope=set_gcp_key_release_policy->removeOperator] Remove claims from GCP key release policy for ${type}: ${JSON.stringify(claims)}`,
          );
          let keyBuf = ccf.strToBuf(type);
          if (ccf.kv[gcpKeyReleaseMapName].has(keyBuf)) {
            const itemsBuf = ccf.kv[gcpKeyReleaseMapName].get(keyBuf);
            items = ccf.bufToStr(itemsBuf);
            try {
              items = JSON.parse(items);
            } catch (e) {
              throw new Error(
                `[ERROR] [scope=set_gcp_key_release_policy->removeOperator] Error parsing ${items} from GCP key release policy during removeOperator`,
                e,
              );
            }
          } else {
            throw new Error(
              `[ERROR] [scope=set_gcp_key_release_policy->removeOperator] The key ${type} does not exist in the GCP key release policy`,
            );
          }

          Object.keys(claims).forEach((key) => {
            if (CLAIMS[key] === undefined) {
              throw new Error(
                `[ERROR] [scope=set_gcp_key_release_policy->removeOperator] KRP remove ${type}=>The claim ${key} is not an allowed claim`,
              );
            }
            let item = claims[key];
            if (Array.isArray(item)) {
              throw new Error(`[ERROR] [scope=set_gcp_key_release_policy->removeOperator] The operator claim ${key} cannot be an array`);
            }

            if (items[key] !== undefined) {
              delete items[key];
            } else {
              throw new Error(
                `[ERROR] [scope=set_gcp_key_release_policy->removeOperator] The claim ${key} does not exist in the GCP key release policy`,
              );
            }
          });

          let jsonItems = JSON.stringify(items);
          let jsonItemsBuf = ccf.strToBuf(jsonItems);
          ccf.kv[gcpKeyReleaseMapName].set(keyBuf, jsonItemsBuf);
        };

        const type = args.type;
        switch (type) {
          case "add":
            add("claims", args.claims);
            if (args.gte !== undefined) {
              addOperator("gte", args.gte);
            }
            if (args.gt !== undefined) {
              addOperator("gt", args.gt);
            }
            break;
          case "remove":
            remove("claims", args.claims);
            if (args.gte !== undefined) {
              removeOperator("gte", args.gte);
            }
            if (args.gt !== undefined) {
              removeOperator("gt", args.gt);
            }
            break;
          default:
            throw new Error(
              `[ERROR] [scope=set_gcp_key_release_policy] GCP Key Release Policy with type ${type} is not supported`,
            );
        }
      },
    ),
];
