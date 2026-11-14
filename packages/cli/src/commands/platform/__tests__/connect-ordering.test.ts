// The drift guard probes AWS; feature-drift.test.ts covers it.
vi.mock("../../../utils/email/feature-drift.js", () => ({
  assertNoFeatureDrift: vi.fn().mockResolvedValue(undefined),
}));

/**
 * Unit tests for the step ordering and reporting inside `authenticatedConnect`
 * (`wraps platform connect`).
 *
 * Plan 335: registering a connection issues a NEW externalId, and the
 * console-access role's trust policy must carry it before anything slow or
 * failure-prone runs — otherwise a Pulumi failure in the EventBridge deploy
 * throws past the role update and leaves the role trusting a stale
 * externalId, silently. These tests prove:
 *  - the role update runs, and completes, even when the EventBridge deploy
 *    fails (case 1 — the actual regression);
 *  - it runs BEFORE the EventBridge deploy on a fully successful run
 *    (case 2 — guards a future reordering);
 *  - a degraded EventBridge deploy stays exit 0, a failed role update does
 *    not (cases 3-4);
 *  - a trust-policy write that silently didn't take is caught by reading it
 *    back, url-decoding it, and comparing the externalId (cases 5-6);
 *  - a read-back failure (e.g. missing iam:GetRole) is logged, not treated
 *    as a write failure (case 7);
 *  - JSON output and the adopted-account path report the three outcome
 *    fields correctly (cases 8-9).
 *
 * Boundaries mocked: the AWS IAM SDK, the Pulumi automation SDK + the email
 * stack deploy it wraps, the control-plane API (fetch), clack prompts,
 * telemetry, AWS credential validation, region resolution, and connection
 * metadata I/O. The real `connect`/`authenticatedConnect`/`updatePlatformRole`
 * control flow runs against those mocks.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { setJsonMode } from "../../../utils/shared/json-output.js";

const { iamSendMock } = vi.hoisted(() => ({ iamSendMock: vi.fn() }));

vi.mock("@aws-sdk/client-iam", () => {
  class Command {
    input: any;
    constructor(input: any) {
      this.input = input;
    }
  }
  class GetRoleCommand extends Command {}
  class CreateRoleCommand extends Command {}
  class PutRolePolicyCommand extends Command {}
  class UpdateAssumeRolePolicyCommand extends Command {}
  class IAMClient {
    send = iamSendMock;
  }
  return {
    IAMClient,
    GetRoleCommand,
    CreateRoleCommand,
    PutRolePolicyCommand,
    UpdateAssumeRolePolicyCommand,
  };
});

vi.mock("@pulumi/pulumi", () => ({
  automation: {
    LocalWorkspace: {
      createOrSelectStack: vi.fn(),
    },
    installPulumiCli: vi.fn(),
  },
}));
vi.mock("@clack/prompts");
vi.mock("../../../infrastructure/email-stack.js");
vi.mock("../../../telemetry/events.js");
vi.mock("../../../utils/shared/aws.js");
vi.mock("../../../utils/shared/config.js");
vi.mock("../../../utils/shared/fs.js");
vi.mock("../../../utils/shared/metadata.js");
vi.mock("../../../utils/shared/pulumi.js");
vi.mock("../../../utils/shared/region-resolver.js");

import {
  CreateRoleCommand,
  GetRoleCommand,
  UpdateAssumeRolePolicyCommand,
} from "@aws-sdk/client-iam";
import * as clack from "@clack/prompts";
import * as pulumi from "@pulumi/pulumi";
import { deployEmailStack } from "../../../infrastructure/email-stack.js";
import * as aws from "../../../utils/shared/aws.js";
import * as config from "../../../utils/shared/config.js";
import * as fsUtils from "../../../utils/shared/fs.js";
import * as metadata from "../../../utils/shared/metadata.js";
import * as pulumiUtils from "../../../utils/shared/pulumi.js";
import * as regionResolver from "../../../utils/shared/region-resolver.js";
import { connect } from "../connect.js";

const ACCOUNT_ID = "123456789012";
const REGION = "us-east-1";
const API_BASE = "http://api.test";
const APP_BASE = "http://app.test";
const NEW_EXTERNAL_ID = "new-external-id-from-registration";

class ExitError extends Error {
  constructor(public code?: number) {
    super(`process.exit(${code})`);
  }
}

function trustDoc(externalId: string) {
  return {
    Version: "2012-10-17",
    Statement: [
      {
        Effect: "Allow",
        Principal: { AWS: "arn:aws:iam::905130073023:root" },
        Action: "sts:AssumeRole",
        Condition: { StringEquals: { "sts:ExternalId": externalId } },
      },
    ],
  };
}

function extractExternalId(policyDocumentJson: string): string | undefined {
  const parsed = JSON.parse(policyDocumentJson) as {
    Statement?: Array<{
      Condition?: { StringEquals?: Record<string, string> };
    }>;
  };
  return parsed.Statement?.[0]?.Condition?.StringEquals?.["sts:ExternalId"];
}

function awsError(name: string, message: string): Error {
  const error = new Error(message);
  error.name = name;
  return error;
}

function baseMetadata(overrides: Record<string, unknown> = {}) {
  return {
    version: "1.0.0",
    accountId: ACCOUNT_ID,
    region: REGION,
    provider: "aws",
    timestamp: "2026-07-13T00:00:00.000Z",
    services: {
      email: {
        preset: "production",
        pulumiStackName: `wraps-${ACCOUNT_ID}-${REGION}`,
        config: {
          sendingEnabled: true,
          domain: "example.com",
          eventTracking: {
            enabled: true,
            eventBridge: true,
            events: [
              "SEND",
              "DELIVERY",
              "OPEN",
              "CLICK",
              "BOUNCE",
              "COMPLAINT",
            ],
            dynamoDBHistory: false,
            archiveRetention: "90days",
          },
        },
      },
    },
    ...overrides,
  };
}

describe("wraps platform connect — role/EventBridge ordering", () => {
  let exitSpy: ReturnType<typeof vi.spyOn>;
  let consoleLogSpy: ReturnType<typeof vi.spyOn>;
  let sequence: string[];

  // Simulated IAM role state.
  let storedExternalId: string | undefined;
  let mismatchOnWrite: boolean;
  let existenceProbeShouldFail: boolean;
  let verifyGetShouldFail: boolean;
  let getRoleCallCount: number;

  // Simulated Pulumi/EventBridge deploy state.
  let deployShouldFail: boolean;

  beforeEach(() => {
    vi.clearAllMocks();
    setJsonMode(false);
    sequence = [];
    storedExternalId = "stale-external-id-from-before";
    mismatchOnWrite = false;
    existenceProbeShouldFail = false;
    verifyGetShouldFail = false;
    getRoleCallCount = 0;
    deployShouldFail = false;

    exitSpy = vi.spyOn(process, "exit").mockImplementation(((code?: number) => {
      throw new ExitError(code);
    }) as never);
    consoleLogSpy = vi.spyOn(console, "log").mockImplementation(() => {});

    // ---- clack prompts ----
    vi.mocked(clack.intro).mockImplementation(() => {});
    vi.mocked(clack.outro).mockImplementation(() => {});
    vi.mocked(clack.isCancel).mockReturnValue(false);
    vi.mocked(clack.confirm).mockResolvedValue(true);
    vi.mocked(clack.select).mockResolvedValue("org-1");
    vi.mocked(clack.spinner).mockReturnValue({
      start: vi.fn(),
      stop: vi.fn(),
      message: vi.fn(),
    } as never);
    vi.mocked(clack.log).info = vi.fn();
    vi.mocked(clack.log).success = vi.fn();
    vi.mocked(clack.log).error = vi.fn();
    vi.mocked(clack.log).warn = vi.fn();
    vi.mocked(clack.log).step = vi.fn();

    // ---- AWS credentials / region ----
    vi.mocked(aws.validateAWSCredentials).mockResolvedValue({
      accountId: ACCOUNT_ID,
      userId: "AIDATEST",
      arn: `arn:aws:iam::${ACCOUNT_ID}:user/test`,
    } as never);
    vi.mocked(regionResolver.resolveRegionForCommand).mockResolvedValue(REGION);

    // ---- config / auth ----
    vi.mocked(config.resolveTokenAsync).mockResolvedValue("test-token");
    vi.mocked(config.getApiBaseUrl).mockReturnValue(API_BASE);
    vi.mocked(config.getAppBaseUrl).mockReturnValue(APP_BASE);
    vi.mocked(config.readAuthConfig).mockResolvedValue({
      auth: {
        token: "test-token",
        tokenType: "session" as const,
        organizations: [{ id: "org-1", name: "Org", slug: "org" }],
      },
    } as never);

    // ---- fs / pulumi utils ----
    vi.mocked(fsUtils.ensurePulumiWorkDir).mockResolvedValue(
      undefined as never
    );
    vi.mocked(fsUtils.getPulumiWorkDir).mockReturnValue("/tmp/.wraps/pulumi");
    vi.mocked(pulumiUtils.ensurePulumiInstalled).mockResolvedValue(false);

    // ---- metadata ----
    vi.mocked(metadata.loadConnectionMetadata).mockResolvedValue(
      baseMetadata() as never
    );
    vi.mocked(metadata.saveConnectionMetadata).mockResolvedValue(
      undefined as never
    );
    vi.mocked(metadata.createAdoptedConnectionMetadata).mockReturnValue({
      version: "1.0.0",
      accountId: ACCOUNT_ID,
      region: REGION,
      provider: "other",
      timestamp: "2026-07-13T00:00:00.000Z",
      services: {},
    } as never);
    vi.mocked(metadata.buildEmailStackConfig).mockImplementation(
      (_meta: any, region: any) => ({ __stack: true, region }) as never
    );

    // ---- control-plane API ----
    const fetchMock = vi.fn(async (url: string, init: RequestInit = {}) => {
      const path = new URL(url).pathname;
      const method = (init.method || "GET").toUpperCase();
      if (path === "/v1/connections" && method === "POST") {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            success: true,
            connectionId: "conn-1",
            externalId: NEW_EXTERNAL_ID,
            roleArn: `arn:aws:iam::${ACCOUNT_ID}:role/wraps-console-access-role`,
            webhookSecret: "webhook-secret-xyz",
            webhookEndpoint: "https://api.wraps.dev/v1/webhooks/ses",
          }),
        };
      }
      throw new Error(`Unmocked fetch: ${method} ${path}`);
    });
    vi.stubGlobal("fetch", fetchMock);

    // ---- IAM ----
    iamSendMock.mockImplementation(async (command: any) => {
      if (command instanceof GetRoleCommand) {
        getRoleCallCount += 1;
        if (getRoleCallCount === 1 && existenceProbeShouldFail) {
          throw awsError(
            "AccessDeniedException",
            "not authorized: iam:GetRole"
          );
        }
        if (getRoleCallCount > 1 && verifyGetShouldFail) {
          throw awsError(
            "AccessDeniedException",
            "not authorized: iam:GetRole"
          );
        }
        if (!storedExternalId) {
          return { Role: {} };
        }
        return {
          Role: {
            AssumeRolePolicyDocument: encodeURIComponent(
              JSON.stringify(trustDoc(storedExternalId))
            ),
          },
        };
      }
      if (command instanceof CreateRoleCommand) {
        if (!mismatchOnWrite) {
          storedExternalId = extractExternalId(
            command.input.AssumeRolePolicyDocument
          );
        }
        return {};
      }
      if (command instanceof UpdateAssumeRolePolicyCommand) {
        sequence.push("trust-policy-write");
        if (!mismatchOnWrite) {
          storedExternalId = extractExternalId(command.input.PolicyDocument);
        }
        return {};
      }
      // PutRolePolicyCommand (permissions write)
      return {};
    });

    // ---- Pulumi / EventBridge deploy ----
    vi.mocked(deployEmailStack).mockResolvedValue({
      roleArn: "arn:aws:iam::123456789012:role/wraps-email-role",
      configSetName: "wraps-email-config",
      tableName: "wraps-email-history",
      region: REGION,
    } as never);

    vi.mocked(
      pulumi.automation.LocalWorkspace.createOrSelectStack
    ).mockImplementation(async (args: any) => {
      await args.program();
      return {
        setConfig: vi.fn().mockResolvedValue(undefined),
        refresh: vi.fn().mockResolvedValue(undefined),
        exportStack: vi
          .fn()
          .mockResolvedValue({ deployment: { resources: [] } }),
        up: vi.fn(async () => {
          if (deployShouldFail) {
            throw new Error("Pulumi lock error: stale lock (stack busy)");
          }
          sequence.push("eventbridge-deploy");
          return { outputs: {} };
        }),
      } as never;
    });
  });

  afterEach(() => {
    setJsonMode(false);
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  function jsonEnvelopes(): any[] {
    return consoleLogSpy.mock.calls
      .map((c) => {
        try {
          return JSON.parse(c[0] as string);
        } catch {
          return null;
        }
      })
      .filter(Boolean);
  }

  function warnText(): string {
    return vi.mocked(clack.log.warn).mock.calls.flat().map(String).join("\n");
  }

  // ---------------------------------------------------------------------
  // Case 1: the regression guard.
  // ---------------------------------------------------------------------
  it("EventBridge deploy rejects → the role update still ran and the process does not throw", async () => {
    deployShouldFail = true;

    await connect({ yes: true });

    expect(exitSpy).not.toHaveBeenCalled();
    const wroteTrustPolicy = iamSendMock.mock.calls.some(
      ([cmd]) => cmd instanceof UpdateAssumeRolePolicyCommand
    );
    expect(wroteTrustPolicy).toBe(true);
    expect(warnText()).toContain("event streaming");
  });

  // ---------------------------------------------------------------------
  // Case 2: ordering — the role update happens before the deploy begins.
  // ---------------------------------------------------------------------
  it("fully successful run → the trust-policy write happens BEFORE the EventBridge deploy begins", async () => {
    await connect({ yes: true });

    expect(exitSpy).not.toHaveBeenCalled();
    const writeIdx = sequence.indexOf("trust-policy-write");
    const deployIdx = sequence.indexOf("eventbridge-deploy");
    expect(writeIdx).toBeGreaterThanOrEqual(0);
    expect(deployIdx).toBeGreaterThanOrEqual(0);
    expect(writeIdx).toBeLessThan(deployIdx);
  });

  // ---------------------------------------------------------------------
  // Case 3: EventBridge failure stays exit 0, names the retry command.
  // ---------------------------------------------------------------------
  it("EventBridge deploy rejects → exit code 0, and the warning names `wraps email config`", async () => {
    deployShouldFail = true;

    await connect({ yes: true });

    expect(exitSpy).not.toHaveBeenCalled();
    const text = warnText();
    expect(text).toContain("wraps email config");
    expect(text).toContain("connection is registered");
  });

  // ---------------------------------------------------------------------
  // Case 4: role update failure is fatal, names the retry command.
  // ---------------------------------------------------------------------
  it("updatePlatformRole rejects → non-zero exit, and the warning names `wraps platform update-role`", async () => {
    existenceProbeShouldFail = true;

    await expect(connect({ yes: true })).rejects.toBeInstanceOf(ExitError);

    expect(exitSpy).toHaveBeenCalledWith(1);
    expect(warnText()).toContain("wraps platform update-role");
  });

  // ---------------------------------------------------------------------
  // Case 5: verification catches a silent no-op.
  // ---------------------------------------------------------------------
  it("trust policy write resolves but the read-back mismatches → treated as failure, non-zero exit", async () => {
    vi.useFakeTimers();
    mismatchOnWrite = true;

    const resultPromise = connect({ yes: true });
    const assertion = expect(resultPromise).rejects.toBeInstanceOf(ExitError);
    await vi.advanceTimersByTimeAsync(2000);
    await assertion;

    expect(exitSpy).toHaveBeenCalledWith(1);
    expect(warnText()).toContain("wraps platform update-role");
    // The write itself did not throw — only the read-back did.
    const wroteTrustPolicy = iamSendMock.mock.calls.some(
      ([cmd]) => cmd instanceof UpdateAssumeRolePolicyCommand
    );
    expect(wroteTrustPolicy).toBe(true);
  });

  // ---------------------------------------------------------------------
  // Case 6: read-back is URL-decoded correctly on a real match.
  // ---------------------------------------------------------------------
  it("read-back decodes the URL-encoded AssumeRolePolicyDocument and confirms success", async () => {
    setJsonMode(true);
    await connect({ yes: true, json: true });

    const env = jsonEnvelopes().find((e) => e.command === "platform.connect");
    expect(env.success).toBe(true);
    expect(env.data.roleUpdated).toBe(true);
    expect(warnText()).not.toContain("Could not create/update IAM role");
  });

  // ---------------------------------------------------------------------
  // Case 7: a read failure during verification is not a write failure.
  // ---------------------------------------------------------------------
  it("GetRole read-back rejects (access denied) → not treated as a write failure, exit 0", async () => {
    verifyGetShouldFail = true;

    await connect({ yes: true });

    expect(exitSpy).not.toHaveBeenCalled();
    expect(warnText()).not.toContain("Could not create/update IAM role");
    const infoText = vi
      .mocked(clack.log.info)
      .mock.calls.flat()
      .map(String)
      .join("\n");
    expect(infoText.toLowerCase()).toContain("could not verify");
  });

  // ---------------------------------------------------------------------
  // Case 8: JSON output carries the three outcome fields.
  // ---------------------------------------------------------------------
  it("JSON mode carries connectionRegistered/roleUpdated/eventStreamingOk on a fully successful run", async () => {
    setJsonMode(true);

    await connect({ yes: true, json: true });

    const env = jsonEnvelopes().find((e) => e.command === "platform.connect");
    expect(env.success).toBe(true);
    expect(env.data.connectionRegistered).toBe(true);
    expect(env.data.roleUpdated).toBe(true);
    expect(env.data.eventStreamingOk).toBe(true);
  });

  it("JSON mode reports eventStreamingOk:false when the deploy fails, but stays exit 0", async () => {
    setJsonMode(true);
    deployShouldFail = true;

    await connect({ yes: true, json: true });

    expect(exitSpy).not.toHaveBeenCalled();
    const env = jsonEnvelopes().find((e) => e.command === "platform.connect");
    expect(env.success).toBe(true);
    expect(env.data.roleUpdated).toBe(true);
    expect(env.data.eventStreamingOk).toBe(false);
  });

  // ---------------------------------------------------------------------
  // Case 9: adopted accounts never deploy EventBridge; not-applicable, not
  // false.
  // ---------------------------------------------------------------------
  it("adopted account → deployEventBridge is never called, and eventStreamingOk is null (not false)", async () => {
    setJsonMode(true);
    vi.mocked(metadata.loadConnectionMetadata).mockResolvedValue(null as never);

    await connect({ yes: true, json: true });

    expect(
      pulumi.automation.LocalWorkspace.createOrSelectStack
    ).not.toHaveBeenCalled();
    const env = jsonEnvelopes().find((e) => e.command === "platform.connect");
    expect(env.success).toBe(true);
    expect(env.data.adopted).toBe(true);
    expect(env.data.eventStreamingOk).toBeNull();
    expect(env.data.roleUpdated).toBe(true);
  });
});
