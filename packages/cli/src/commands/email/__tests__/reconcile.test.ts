import { beforeEach, describe, expect, it, vi } from "vitest";
import type { WrapsEmailConfig } from "../../../types/email.js";
import {
  detectFeatureDrift,
  inferDriftedSections,
} from "../../../utils/email/feature-drift.js";
import { setJsonMode } from "../../../utils/shared/json-output.js";
import {
  loadConnectionMetadata,
  saveConnectionMetadataToState,
} from "../../../utils/shared/metadata.js";
import { reconcile } from "../reconcile.js";

vi.mock("@clack/prompts", () => ({
  intro: vi.fn(),
  outro: vi.fn(),
  cancel: vi.fn(),
  note: vi.fn(),
  log: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), success: vi.fn() },
  confirm: vi.fn().mockResolvedValue(true),
  isCancel: vi.fn().mockReturnValue(false),
  spinner: vi.fn(() => ({ start: vi.fn(), stop: vi.fn(), message: vi.fn() })),
}));

vi.mock("../../../utils/shared/aws.js", () => ({
  validateAWSCredentials: vi.fn().mockResolvedValue({
    accountId: "123456789012",
    userId: "AIDATEST",
    arn: "arn:aws:iam::123456789012:user/test",
  }),
}));

vi.mock("../../../utils/shared/region-resolver.js", () => ({
  resolveRegionForCommand: vi.fn().mockResolvedValue("eu-central-1"),
}));

vi.mock("../../../utils/shared/metadata.js", () => ({
  loadConnectionMetadata: vi.fn(),
  saveConnectionMetadataToState: vi.fn(),
}));

vi.mock("../../../utils/email/feature-drift.js", () => ({
  detectFeatureDrift: vi.fn(),
  inferDriftedSections: vi.fn(),
}));

const SETTINGS = {
  domain: "example.com",
  eventTracking: { enabled: true },
} as WrapsEmailConfig;

const DRIFT = [
  {
    feature: "inbound" as const,
    settings: "inbound, inboundDomains",
    resources: ["wraps-inbound-123456789012-eu-central-1"],
  },
];

const REBUILT = {
  ...SETTINGS,
  inbound: {
    enabled: true,
    subdomain: "inbound",
    receivingDomain: "inbound.example.com",
    bucketName: "wraps-inbound-123456789012-eu-central-1",
  },
  inboundDomains: [
    {
      subdomain: "inbound",
      receivingDomain: "inbound.example.com",
      parentDomain: "example.com",
      addedAt: "2026-11-14T00:00:00.000Z",
    },
  ],
} as WrapsEmailConfig;

function storedMetadata() {
  return {
    version: "1.0.0",
    accountId: "123456789012",
    region: "eu-central-1",
    provider: "other",
    timestamp: "2026-11-13T00:00:00.000Z",
    services: {
      email: { config: structuredClone(SETTINGS), preset: "production" },
    },
  };
}

describe("email reconcile", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    setJsonMode(false);
    vi.mocked(loadConnectionMetadata).mockResolvedValue(
      storedMetadata() as never
    );
    vi.mocked(detectFeatureDrift).mockResolvedValue(DRIFT);
    vi.mocked(inferDriftedSections).mockResolvedValue({
      config: REBUILT,
      notes: [],
    });
    vi.mocked(saveConnectionMetadataToState).mockResolvedValue({
      bucket: "wraps-state-123456789012-eu-central-1",
      versionId: "v2",
    });
  });

  it("--preview shows the rebuilt sections and writes nothing", async () => {
    await reconcile({ preview: true });

    expect(inferDriftedSections).toHaveBeenCalled();
    expect(saveConnectionMetadataToState).not.toHaveBeenCalled();
  });

  it("saves the rebuilt sections as a new settings version and keeps the rest", async () => {
    await reconcile({ yes: true });

    expect(saveConnectionMetadataToState).toHaveBeenCalledTimes(1);
    const saved = vi.mocked(saveConnectionMetadataToState).mock.calls[0][0];
    expect(saved.services.email?.config).toEqual(REBUILT);
    expect(saved.services.email?.preset).toBe("production");
    expect(saved.timestamp).not.toBe("2026-11-13T00:00:00.000Z");
  });

  it("writes nothing when the settings already match AWS", async () => {
    vi.mocked(detectFeatureDrift).mockResolvedValue([]);

    await reconcile({ yes: true });

    expect(inferDriftedSections).not.toHaveBeenCalled();
    expect(saveConnectionMetadataToState).not.toHaveBeenCalled();
  });

  it("writes nothing when a section can't be rebuilt", async () => {
    vi.mocked(inferDriftedSections).mockRejectedValue(
      Object.assign(new Error("webhook"), { code: "FEATURE_NOT_INFERABLE" })
    );

    await expect(reconcile({ yes: true })).rejects.toMatchObject({
      code: "FEATURE_NOT_INFERABLE",
    });
    expect(saveConnectionMetadataToState).not.toHaveBeenCalled();
  });

  it("requires --yes outside an interactive terminal (vitest has no TTY)", async () => {
    await expect(reconcile({})).rejects.toMatchObject({
      code: "NON_INTERACTIVE_INPUT",
    });
    expect(saveConnectionMetadataToState).not.toHaveBeenCalled();
  });

  it("refuses without stored email settings", async () => {
    vi.mocked(loadConnectionMetadata).mockResolvedValue(null);

    await expect(reconcile({ yes: true })).rejects.toMatchObject({
      code: "EMAIL_NOT_CONFIGURED",
    });
  });
});
