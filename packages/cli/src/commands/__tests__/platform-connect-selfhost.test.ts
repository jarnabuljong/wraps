import {
  CreateRoleCommand,
  GetRoleCommand,
  IAMClient,
  PutRolePolicyCommand,
  UpdateAssumeRolePolicyCommand,
} from "@aws-sdk/client-iam";
import { mockClient } from "aws-sdk-client-mock";
import { beforeEach, describe, expect, it, vi } from "vitest";

// The drift guard probes AWS; feature-drift.test.ts covers it.
vi.mock("../../utils/email/feature-drift.js", () => ({
  assertNoFeatureDrift: vi.fn().mockResolvedValue(undefined),
}));

// Do NOT vi.mock("@aws-sdk/client-iam") — mockClient patches the prototype directly.
vi.mock("@pulumi/pulumi", () => ({
  automation: { LocalWorkspace: { createOrSelectStack: vi.fn() } },
}));
vi.mock("@clack/prompts");
vi.mock("../../utils/shared/aws.js");
vi.mock("../../utils/shared/fs.js");
vi.mock("../../utils/shared/metadata.js");
vi.mock("../../utils/shared/pulumi.js");
vi.mock("../../utils/shared/config.js");
vi.mock("../../utils/shared/json-output.js");
vi.mock("../../utils/shared/region-resolver.js");
vi.mock("../../utils/shared/prompts.js");
// Reconcile makes a live Lambda call; mock it to a no-op so connect's unit
// test stays hermetic — leaving selfhostService.apiUrl exactly as the loaded
// metadata sets it (empty stays empty → abort; a set URL stays set). Keep
// normalizeApiUrl real so trailing-slash handling is exercised, not stubbed.
vi.mock("../../utils/selfhost/api-url.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../utils/selfhost/api-url.js")>()),
  reconcileSelfhostApiUrl: vi.fn(),
}));
vi.mock("../../infrastructure/email-stack.js");
vi.mock("../../telemetry/events.js");

import * as prompts from "@clack/prompts";
import * as pulumi from "@pulumi/pulumi";
import * as aws from "../../utils/shared/aws.js";
import * as config from "../../utils/shared/config.js";
import * as fsUtils from "../../utils/shared/fs.js";
import * as jsonOutput from "../../utils/shared/json-output.js";
import * as metadata from "../../utils/shared/metadata.js";
import * as pulumiUtils from "../../utils/shared/pulumi.js";
import * as regionResolver from "../../utils/shared/region-resolver.js";
import { connect } from "../platform/connect.js";

const iamMock = mockClient(IAMClient);

// SMS-only + selfhost: no email means Pulumi EventBridge is skipped,
// isolating the IAM trust policy assertion.
const SELFHOST_SMS_METADATA = {
  version: "1.0.0",
  accountId: "123456789012",
  region: "us-east-1",
  provider: "other" as const,
  timestamp: "2026-05-26T00:00:00.000Z",
  services: {
    sms: { config: { sendingEnabled: true }, preset: "production" },
    selfhost: {
      deployedAt: "2026-05-26T00:00:00.000Z",
      pulumiStackName: "wraps-selfhost-123456789012-us-east-1",
      apiUrl: "https://abc123.lambda-url.us-east-1.on.aws",
      config: {
        databaseUrl: "postgres://user:pass@db.example.com:5432/wraps",
        betterAuthSecret: "deadbeefcafe1234",
        unsubscribeSecret: "feedfacecafe1234",
        licenseKey: "v1.scale.2027-01-01.abc",
        appUrl: "https://app.example.com",
      },
    },
  },
};

const NON_SELFHOST_SMS_METADATA = {
  version: "1.0.0",
  accountId: "123456789012",
  region: "us-east-1",
  provider: "other" as const,
  timestamp: "2026-05-26T00:00:00.000Z",
  services: {
    sms: { config: { sendingEnabled: true }, preset: "production" },
  },
};

// Self-hosted + email: the fixture that exercises deployEventBridge's Pulumi
// path. `webhookSecret: "platform-secret-abc"` stands in for an existing
// app.wraps.dev connection so tests can assert it survives a selfhost
// connect (and vice versa).
const SELFHOST_EMAIL_METADATA = {
  ...SELFHOST_SMS_METADATA,
  services: {
    ...SELFHOST_SMS_METADATA.services,
    email: {
      preset: "production" as const,
      config: {
        tracking: { enabled: true, opens: true, clicks: true },
        sendingEnabled: true,
        eventTracking: { enabled: true, eventBridge: true },
      },
      deployedAt: "2026-05-26T00:00:00.000Z",
      webhookSecret: "platform-secret-abc",
    },
  },
};

describe("platform connect - selfhost trust policy", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    iamMock.reset();

    const mockSpinner = { start: vi.fn(), stop: vi.fn(), message: vi.fn() };
    vi.mocked(prompts.spinner).mockReturnValue(mockSpinner as never);
    vi.mocked(prompts.intro).mockImplementation(() => {});
    vi.mocked(prompts.outro).mockImplementation(() => {});
    vi.mocked(prompts.isCancel).mockReturnValue(false);
    vi.mocked(prompts.log).info = vi.fn();
    vi.mocked(prompts.log).success = vi.fn();
    vi.mocked(prompts.log).error = vi.fn();
    vi.mocked(prompts.log).warn = vi.fn();
    vi.mocked(prompts.log).step = vi.fn();

    vi.mocked(aws.validateAWSCredentials).mockResolvedValue({
      accountId: "123456789012",
      userId: "AIDACKCEVSQ6C2EXAMPLE",
      arn: "arn:aws:iam::123456789012:user/test",
    });

    vi.mocked(regionResolver.resolveRegionForCommand).mockResolvedValue(
      "us-east-1"
    );
    vi.mocked(pulumiUtils.ensurePulumiInstalled).mockResolvedValue(false);
    vi.mocked(fsUtils.ensurePulumiWorkDir).mockResolvedValue(undefined);
    vi.mocked(fsUtils.getPulumiWorkDir).mockReturnValue("/mock/.wraps/pulumi");

    // SaaS connects build their request URL from this; production always
    // returns a real string, so give the auto-mock a sane default.
    vi.mocked(config.getApiBaseUrl).mockReturnValue("https://api.wraps.dev");
    vi.mocked(config.resolveTokenAsync).mockResolvedValue("test-token-123");
    vi.mocked(config.readAuthConfig).mockResolvedValue({
      auth: {
        token: "test-token-123",
        tokenType: "session" as const,
        organizations: [{ id: "org-1", name: "Test Org", slug: "test-org" }],
      },
    });

    // Self-hosted connect resolves a per-instance session, not the SaaS slot.
    vi.mocked(config.resolveSelfhostToken).mockResolvedValue("sh-token-123");
    vi.mocked(config.readSelfhostAuth).mockResolvedValue({
      token: "sh-token-123",
      tokenType: "session" as const,
      organizations: [{ id: "sh-org-1", name: "Self Org", slug: "self-org" }],
    });

    vi.mocked(metadata.loadConnectionMetadata).mockResolvedValue(
      SELFHOST_SMS_METADATA as any
    );
    vi.mocked(metadata.saveConnectionMetadata).mockResolvedValue(undefined);

    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: () =>
          Promise.resolve({
            success: true,
            connectionId: "conn-abc-123",
            externalId: "ext-xyz-456",
            webhookSecret: "webhook-secret-789",
          }),
      })
    );

    // Role does not exist → CreateRole path
    iamMock.on(GetRoleCommand).rejects(
      Object.assign(new Error("NoSuchEntity"), {
        name: "NoSuchEntityException",
      })
    );
    iamMock.on(CreateRoleCommand).resolves({});
    iamMock.on(PutRolePolicyCommand).resolves({});
    iamMock.on(UpdateAssumeRolePolicyCommand).resolves({});
  });

  it("uses the customer account as trusted principal when --selfhosted is passed", async () => {
    await connect({ yes: true, selfhosted: true });

    const createCalls = iamMock.commandCalls(CreateRoleCommand);
    expect(createCalls).toHaveLength(1);
    const trustPolicy = JSON.parse(
      createCalls[0].args[0].input.AssumeRolePolicyDocument!
    );
    expect(trustPolicy.Statement[0].Principal.AWS).toBe(
      "arn:aws:iam::123456789012:root"
    );
  });

  it("creates the self-hosted role name when --selfhosted is passed", async () => {
    await connect({ yes: true, selfhosted: true });

    const createCalls = iamMock.commandCalls(CreateRoleCommand);
    expect(createCalls).toHaveLength(1);
    expect(createCalls[0].args[0].input.RoleName).toBe(
      "wraps-selfhost-console-access-role"
    );
  });

  it("creates the platform role name for a SaaS connect from a machine with selfhost metadata", async () => {
    // Companion to the trust-policy regression above: a stray SaaS connect must
    // touch neither the principal nor the name of the self-hosted role.
    await connect({ yes: true });

    const createCalls = iamMock.commandCalls(CreateRoleCommand);
    expect(createCalls).toHaveLength(1);
    expect(createCalls[0].args[0].input.RoleName).toBe(
      "wraps-console-access-role"
    );
  });

  it("keeps the Wraps platform principal for a SaaS connect from a machine with selfhost metadata", async () => {
    // Regression: the principal used to be chosen from metadata presence, so a
    // plain SaaS connect on a self-hoster's machine silently revoked
    // app.wraps.dev's AssumeRole access.
    await connect({ yes: true });

    const createCalls = iamMock.commandCalls(CreateRoleCommand);
    expect(createCalls).toHaveLength(1);
    const trustPolicy = JSON.parse(
      createCalls[0].args[0].input.AssumeRolePolicyDocument!
    );
    expect(trustPolicy.Statement[0].Principal.AWS).toBe(
      "arn:aws:iam::905130073023:root"
    );
  });

  it("uses Wraps platform account as trusted principal when no selfhost metadata", async () => {
    vi.mocked(metadata.loadConnectionMetadata).mockResolvedValue(
      NON_SELFHOST_SMS_METADATA as any
    );

    await connect({ yes: true });

    const createCalls = iamMock.commandCalls(CreateRoleCommand);
    expect(createCalls).toHaveLength(1);
    const trustPolicy = JSON.parse(
      createCalls[0].args[0].input.AssumeRolePolicyDocument!
    );
    expect(trustPolicy.Statement[0].Principal.AWS).toBe(
      "arn:aws:iam::905130073023:root"
    );
  });

  it("registers the connection against the self-hosted API URL when selfhosted", async () => {
    await connect({ yes: true, selfhosted: true });

    const fetchMock = vi.mocked(fetch);
    expect(fetchMock).toHaveBeenCalled();
    const [url] = fetchMock.mock.calls[0];
    expect(url).toBe(
      "https://abc123.lambda-url.us-east-1.on.aws/v1/connections"
    );
  });

  it("strips the trailing slash from a Lambda Function URL before appending the path", async () => {
    // Regression: real Lambda Function URLs always end in `/`, so a naive
    // `${apiUrl}/v1/connections` yields `//v1/connections` which Elysia 404s.
    vi.mocked(metadata.loadConnectionMetadata).mockResolvedValue({
      ...SELFHOST_SMS_METADATA,
      services: {
        ...SELFHOST_SMS_METADATA.services,
        selfhost: {
          ...SELFHOST_SMS_METADATA.services.selfhost,
          apiUrl: "https://abc123.lambda-url.us-east-1.on.aws/",
        },
      },
    } as any);

    await connect({ yes: true, selfhosted: true });

    const fetchMock = vi.mocked(fetch);
    const [url] = fetchMock.mock.calls[0];
    expect(url).toBe(
      "https://abc123.lambda-url.us-east-1.on.aws/v1/connections"
    );
  });

  it("uses the self-hosted session token and org, not the SaaS slot", async () => {
    // Regression: a logged-in SaaS session must not leak into a selfhost
    // connect. The org/token come from the per-instance self-hosted session.
    await connect({ yes: true, selfhosted: true });

    const fetchMock = vi.mocked(fetch);
    const [, init] = fetchMock.mock.calls[0];
    const headers = (init as RequestInit).headers as Record<string, string>;
    expect(headers.Authorization).toBe("Bearer sh-token-123");
    expect(headers["X-Organization-Id"]).toBe("sh-org-1");
  });

  it("aborts without registering when the self-hosted apiUrl is empty", async () => {
    // An interrupted `selfhost deploy` leaves the service present but with an
    // empty apiUrl — connecting must fail fast, not POST to a malformed URL.
    vi.mocked(metadata.loadConnectionMetadata).mockResolvedValue({
      ...SELFHOST_SMS_METADATA,
      services: {
        ...SELFHOST_SMS_METADATA.services,
        selfhost: { ...SELFHOST_SMS_METADATA.services.selfhost, apiUrl: "" },
      },
    } as any);

    const exitError = new Error("process.exit");
    const exitSpy = vi.spyOn(process, "exit").mockImplementation((() => {
      throw exitError;
    }) as never);

    await expect(connect({ yes: true, selfhosted: true })).rejects.toBe(
      exitError
    );

    expect(exitSpy).toHaveBeenCalledWith(1);
    expect(vi.mocked(fetch)).not.toHaveBeenCalled();

    exitSpy.mockRestore();
  });

  it("registers against the Wraps Platform API when not selfhosted", async () => {
    vi.mocked(config.getApiBaseUrl).mockReturnValue("https://api.wraps.dev");

    await connect({ yes: true });

    const fetchMock = vi.mocked(fetch);
    expect(fetchMock).toHaveBeenCalled();
    const [url] = fetchMock.mock.calls[0];
    expect(url).toBe("https://api.wraps.dev/v1/connections");
  });

  it("aborts a selfhost connect when no auth token is present", async () => {
    // Self-hosted has no manual copy/paste fallback — it must require login
    // against the instance itself, independent of any SaaS session.
    vi.mocked(config.resolveSelfhostToken).mockResolvedValue(null);

    const exitError = new Error("process.exit");
    const exitSpy = vi.spyOn(process, "exit").mockImplementation((() => {
      throw exitError;
    }) as never);

    await expect(connect({ yes: true, selfhosted: true })).rejects.toBe(
      exitError
    );

    expect(exitSpy).toHaveBeenCalledWith(1);
    expect(vi.mocked(fetch)).not.toHaveBeenCalled();

    exitSpy.mockRestore();
  });

  it("emits a structured NOT_AUTHENTICATED error in JSON mode", async () => {
    // `--json` consumers must get a parseable error, not human prose.
    vi.mocked(config.resolveSelfhostToken).mockResolvedValue(null);
    vi.mocked(jsonOutput.isJsonMode).mockReturnValue(true);

    const exitError = new Error("process.exit");
    const exitSpy = vi.spyOn(process, "exit").mockImplementation((() => {
      throw exitError;
    }) as never);

    await expect(
      connect({ yes: true, selfhosted: true, json: true })
    ).rejects.toBe(exitError);

    expect(vi.mocked(jsonOutput.jsonError)).toHaveBeenCalledWith(
      "platform.connect",
      expect.objectContaining({ code: "NOT_AUTHENTICATED" })
    );
    expect(vi.mocked(fetch)).not.toHaveBeenCalled();

    exitSpy.mockRestore();
  });

  it("uses customer account when updating trust policy on an existing role with --selfhosted", async () => {
    // Role exists → UpdateAssumeRolePolicy path
    iamMock.on(GetRoleCommand).resolves({
      Role: { RoleName: "wraps-console-access-role" } as any,
    });

    await connect({ yes: true, selfhosted: true });

    const updateCalls = iamMock.commandCalls(UpdateAssumeRolePolicyCommand);
    expect(updateCalls).toHaveLength(1);
    const trustPolicy = JSON.parse(
      updateCalls[0].args[0].input.PolicyDocument!
    );
    expect(trustPolicy.Statement[0].Principal.AWS).toBe(
      "arn:aws:iam::123456789012:root"
    );
  });

  describe("selfhost webhook target", () => {
    // Set by the mocked buildEmailStackConfig on every deployEventBridge call —
    // this is what proves whether the platform/selfhost webhook keys were
    // passed as explicit overrides or left for metadata reconstruction.
    let capturedOverrides: any;

    beforeEach(() => {
      capturedOverrides = undefined;

      // Every fixture in the outer describe is SMS-only specifically to skip
      // this Pulumi path, so each case here must re-supply an email + selfhost
      // fixture and clone it — authenticatedConnect mutates the loaded object
      // directly (webhookUrl/webhookSecret/selfhostWebhook), and a
      // module-level fixture handed out by reference would leak mutations
      // across tests.
      vi.mocked(metadata.loadConnectionMetadata).mockResolvedValue(
        structuredClone(SELFHOST_EMAIL_METADATA) as any
      );

      vi.mocked(metadata.buildEmailStackConfig).mockImplementation(
        (_meta, _region, overrides) => {
          capturedOverrides = overrides;
          return {} as any;
        }
      );

      const mockStack = {
        setConfig: vi.fn().mockResolvedValue(undefined),
        refresh: vi.fn().mockResolvedValue(undefined),
        exportStack: vi
          .fn()
          .mockResolvedValue({ deployment: { resources: [] } }),
        up: vi.fn().mockResolvedValue({}),
      } as any;
      vi.mocked(
        pulumi.automation.LocalWorkspace.createOrSelectStack
      ).mockResolvedValue(mockStack);
    });

    it("writes the self-hosted secret to selfhostWebhook instead of clobbering the platform's", async () => {
      await connect({ yes: true, selfhosted: true });

      const saved = vi.mocked(metadata.saveConnectionMetadata).mock
        .calls[0][0] as any;
      expect(saved.services.email.selfhostWebhook).toEqual({
        url: "https://abc123.lambda-url.us-east-1.on.aws",
        secret: "webhook-secret-789",
      });
    });

    it("preserves the platform webhook and passes no webhook override key (coexistence regression)", async () => {
      await connect({ yes: true, selfhosted: true });

      const saved = vi.mocked(metadata.saveConnectionMetadata).mock
        .calls[0][0] as any;
      expect(saved.services.email.webhookSecret).toBe("platform-secret-abc");
      expect("webhook" in capturedOverrides).toBe(false);
      expect(capturedOverrides.selfhostWebhook.webhookUrl).toBe(
        "https://abc123.lambda-url.us-east-1.on.aws"
      );
    });

    it("keeps a plain SaaS connect writing webhookSecret exactly as before", async () => {
      await connect({ yes: true });

      const saved = vi.mocked(metadata.saveConnectionMetadata).mock
        .calls[0][0] as any;
      expect(saved.services.email.webhookSecret).toBe("webhook-secret-789");
      expect(saved.services.email.selfhostWebhook).toBeUndefined();
      expect(capturedOverrides.webhook).toBeTruthy();
    });

    it("migrates a legacy reroute onto selfhostWebhook instead of duplicating it", async () => {
      vi.mocked(metadata.loadConnectionMetadata).mockResolvedValue(
        structuredClone({
          ...SELFHOST_EMAIL_METADATA,
          services: {
            ...SELFHOST_EMAIL_METADATA.services,
            email: {
              ...SELFHOST_EMAIL_METADATA.services.email,
              webhookUrl: "https://abc123.lambda-url.us-east-1.on.aws",
              webhookSecret: "old-rerouted-secret",
            },
          },
        }) as any
      );

      await connect({ yes: true, selfhosted: true });

      const saved = vi.mocked(metadata.saveConnectionMetadata).mock
        .calls[0][0] as any;
      expect(saved.services.email.webhookUrl).toBeUndefined();
      expect(saved.services.email.webhookSecret).toBeUndefined();
      expect(saved.services.email.selfhostWebhook.secret).toBe(
        "webhook-secret-789"
      );
      expect(prompts.log.warn).toHaveBeenCalled();
    });

    it("preserves an existing self-hosted target through a later SaaS connect", async () => {
      vi.mocked(metadata.loadConnectionMetadata).mockResolvedValue(
        structuredClone({
          ...SELFHOST_EMAIL_METADATA,
          services: {
            ...SELFHOST_EMAIL_METADATA.services,
            email: {
              ...SELFHOST_EMAIL_METADATA.services.email,
              webhookSecret: "platform-secret-abc",
              selfhostWebhook: {
                url: "https://abc123.lambda-url.us-east-1.on.aws",
                secret: "sh-secret-old",
              },
            },
          },
        }) as any
      );

      await connect({ yes: true });

      const saved = vi.mocked(metadata.saveConnectionMetadata).mock
        .calls[0][0] as any;
      expect(saved.services.email.selfhostWebhook).toEqual({
        url: "https://abc123.lambda-url.us-east-1.on.aws",
        secret: "sh-secret-old",
      });
      expect("selfhostWebhook" in capturedOverrides).toBe(false);
    });
  });

  describe("control-plane identity", () => {
    // The externalId issued by whichever plane you connect to is the
    // sts:ExternalId condition on THAT plane's console access role. Both planes
    // used to write `metadata.platform`, so the last connect silently broke the
    // other plane's AssumeRole. These cases pin the two-slot split.
    //
    // SMS-only fixtures on purpose: no email means deployEventBridge's Pulumi
    // path is skipped, isolating the metadata assertion.
    //
    // Cloning alone is not enough here. authenticatedConnect assigns onto the
    // object loadConnectionMetadata returns, and the cases in the enclosing
    // describe hand out the module-level SELFHOST_SMS_METADATA by reference —
    // so it already carries identity slots written by those earlier connects,
    // and a clone would inherit them. Start every case from an explicitly
    // empty identity state instead of inheriting whichever slot ran last.
    const cleanFixture = () => {
      const base = structuredClone(SELFHOST_SMS_METADATA) as any;
      base.platform = undefined;
      base.selfhostPlatform = undefined;
      return base;
    };

    beforeEach(() => {
      vi.mocked(metadata.loadConnectionMetadata).mockResolvedValue(
        cleanFixture()
      );
    });

    // saveConnectionMetadata is called twice with the SAME object reference, so
    // calls[0][0] reads final state once connect() has resolved.
    const savedMetadata = () =>
      vi.mocked(metadata.saveConnectionMetadata).mock.calls[0][0] as any;

    it("writes the self-hosted identity to its own slot, not the platform's", async () => {
      await connect({ yes: true, selfhosted: true });

      const saved = savedMetadata();
      expect(saved.selfhostPlatform).toEqual({
        externalId: "ext-xyz-456",
        connectionId: "conn-abc-123",
      });
      expect(saved.platform).toBeUndefined();
    });

    it("preserves an existing Wraps platform identity through a selfhost connect", async () => {
      // The core regression: a --selfhosted connect used to overwrite the
      // platform's externalId, so `wraps platform update-role` would then write
      // the self-hosted external ID into the platform's trust policy.
      vi.mocked(metadata.loadConnectionMetadata).mockResolvedValue({
        ...cleanFixture(),
        platform: {
          externalId: "plat-ext-1",
          connectionId: "plat-conn-1",
        },
      });

      await connect({ yes: true, selfhosted: true });

      const saved = savedMetadata();
      expect(saved.platform).toEqual({
        externalId: "plat-ext-1",
        connectionId: "plat-conn-1",
      });
      expect(saved.selfhostPlatform).toEqual({
        externalId: "ext-xyz-456",
        connectionId: "conn-abc-123",
      });
    });

    it("keeps a plain SaaS connect writing the platform slot exactly as before", async () => {
      await connect({ yes: true });

      const saved = savedMetadata();
      expect(saved.platform).toEqual({
        externalId: "ext-xyz-456",
        connectionId: "conn-abc-123",
      });
      expect(saved.selfhostPlatform).toBeUndefined();
    });

    it("preserves an existing self-hosted identity through a later SaaS connect", async () => {
      // Mirror of the regression above: a routine SaaS reconnect must not
      // delete the self-hosted plane's externalId.
      vi.mocked(metadata.loadConnectionMetadata).mockResolvedValue({
        ...cleanFixture(),
        selfhostPlatform: {
          externalId: "sh-ext-1",
          connectionId: "sh-conn-1",
        },
      });

      await connect({ yes: true });

      const saved = savedMetadata();
      expect(saved.selfhostPlatform).toEqual({
        externalId: "sh-ext-1",
        connectionId: "sh-conn-1",
      });
      expect(saved.platform).toEqual({
        externalId: "ext-xyz-456",
        connectionId: "conn-abc-123",
      });
    });
  });
});
