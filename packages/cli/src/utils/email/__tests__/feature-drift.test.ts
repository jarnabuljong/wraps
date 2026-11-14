import { DescribeTableCommand, DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
  DescribeApiDestinationCommand,
  EventBridgeClient,
} from "@aws-sdk/client-eventbridge";
import {
  GetFunctionConfigurationCommand,
  LambdaClient,
} from "@aws-sdk/client-lambda";
import {
  GetBucketLifecycleConfigurationCommand,
  HeadBucketCommand,
  S3Client,
} from "@aws-sdk/client-s3";
import { DescribeReceiptRuleCommand, SESClient } from "@aws-sdk/client-ses";
import {
  GetConfigurationSetEventDestinationsCommand,
  SESv2Client,
} from "@aws-sdk/client-sesv2";
import { GetQueueUrlCommand, SQSClient } from "@aws-sdk/client-sqs";
import { mockClient } from "aws-sdk-client-mock";
import { beforeEach, describe, expect, it } from "vitest";
import type { WrapsEmailConfig } from "../../../types/email.js";
import { WrapsError } from "../../shared/errors.js";
import type { ConnectionMetadata } from "../../shared/metadata.js";
import {
  assertNoFeatureDrift,
  detectFeatureDrift,
  inferDriftedSections,
  retentionFromDays,
  toInboundDomain,
} from "../feature-drift.js";

const s3 = mockClient(S3Client);
const sqs = mockClient(SQSClient);
const lambda = mockClient(LambdaClient);
const dynamodb = mockClient(DynamoDBClient);
const ses = mockClient(SESClient);
const sesv2 = mockClient(SESv2Client);
const eventbridge = mockClient(EventBridgeClient);

const ACCOUNT = "123456789012";
const REGION = "eu-central-1";
const SCOPE = { accountId: ACCOUNT, region: REGION };
const BUCKET = `wraps-inbound-${ACCOUNT}-${REGION}`;
const NOW = "2026-11-14T00:00:00.000Z";

function awsError(name: string, httpStatusCode = 400): Error {
  const error = new Error(name) as Error & {
    $metadata: { httpStatusCode: number };
  };
  error.name = name;
  error.$metadata = { httpStatusCode };
  return error;
}

/** Nothing deployed: every probe reports "not found". */
function nothingDeployed(): void {
  s3.on(HeadBucketCommand).rejects(awsError("NotFound", 404));
  sqs.on(GetQueueUrlCommand).rejects(awsError("QueueDoesNotExist"));
  lambda
    .on(GetFunctionConfigurationCommand)
    .rejects(awsError("ResourceNotFoundException", 404));
  dynamodb
    .on(DescribeTableCommand)
    .rejects(awsError("ResourceNotFoundException"));
}

/** What the account looked like on 13 Nov: inbound and history deployed. */
function inboundAndHistoryDeployed(): void {
  nothingDeployed();
  s3.on(HeadBucketCommand, { Bucket: BUCKET }).resolves({});
  sqs.on(GetQueueUrlCommand, { QueueName: "wraps-inbound-events" }).resolves({
    QueueUrl: "https://sqs/wraps-inbound-events",
  });
  sqs.on(GetQueueUrlCommand, { QueueName: "wraps-email-events" }).resolves({
    QueueUrl: "https://sqs/wraps-email-events",
  });
  lambda
    .on(GetFunctionConfigurationCommand, {
      FunctionName: "wraps-inbound-email-processor",
    })
    .resolves({});
  lambda
    .on(GetFunctionConfigurationCommand, {
      FunctionName: "wraps-email-event-processor",
    })
    .resolves({ Environment: { Variables: { RETENTION_DAYS: "90" } } });
  dynamodb
    .on(DescribeTableCommand, { TableName: "wraps-email-history" })
    .resolves({});
}

/** The settings file as it was on 13 Nov: sending and events, no inbound. */
const SETTINGS_WITHOUT_INBOUND: WrapsEmailConfig = {
  domain: "example.com",
  eventTracking: { enabled: true, dynamoDBHistory: true },
} as WrapsEmailConfig;

function metadataWith(config: WrapsEmailConfig): ConnectionMetadata {
  return {
    version: "1.0.0",
    accountId: ACCOUNT,
    region: REGION,
    provider: "other",
    timestamp: NOW,
    services: { email: { config } },
  } as unknown as ConnectionMetadata;
}

beforeEach(() => {
  for (const client of [s3, sqs, lambda, dynamodb, ses, sesv2, eventbridge]) {
    client.reset();
  }
});

describe("detectFeatureDrift", () => {
  it("finds the inbound resources a settings file without inbound would delete", async () => {
    inboundAndHistoryDeployed();

    const drifts = await detectFeatureDrift(SETTINGS_WITHOUT_INBOUND, SCOPE);

    expect(drifts).toEqual([
      {
        feature: "inbound",
        settings: "inbound, inboundDomains",
        resources: [
          BUCKET,
          "wraps-inbound-events",
          "wraps-inbound-email-processor",
        ],
      },
    ]);
  });

  it("reports nothing when the settings declare every deployed feature", async () => {
    inboundAndHistoryDeployed();
    const config = {
      ...SETTINGS_WITHOUT_INBOUND,
      inbound: { enabled: true, subdomain: "inbound" },
    } as WrapsEmailConfig;

    expect(await detectFeatureDrift(config, SCOPE)).toEqual([]);
    expect(s3.commandCalls(HeadBucketCommand)).toHaveLength(0);
  });

  it("reports nothing when undeclared features are not deployed", async () => {
    nothingDeployed();

    expect(
      await detectFeatureDrift(
        { domain: "example.com" } as WrapsEmailConfig,
        SCOPE
      )
    ).toEqual([]);
  });

  it("finds event history whose setting was lost", async () => {
    inboundAndHistoryDeployed();
    const config = {
      domain: "example.com",
      eventTracking: { enabled: true },
      inbound: { enabled: true, subdomain: "inbound" },
    } as WrapsEmailConfig;

    expect(await detectFeatureDrift(config, SCOPE)).toEqual([
      {
        feature: "eventHistory",
        settings: "eventTracking.dynamoDBHistory",
        resources: ["wraps-email-history", "wraps-email-event-processor"],
      },
    ]);
  });

  it("fails closed when a probe is denied rather than reading it as absent", async () => {
    nothingDeployed();
    s3.on(HeadBucketCommand).rejects(awsError("Forbidden", 403));

    await expect(
      detectFeatureDrift(SETTINGS_WITHOUT_INBOUND, SCOPE)
    ).rejects.toMatchObject({ code: "FEATURE_DRIFT_CHECK_FAILED" });
  });

  it("fails closed on a Lambda permission error", async () => {
    nothingDeployed();
    lambda
      .on(GetFunctionConfigurationCommand)
      .rejects(awsError("AccessDeniedException", 403));

    await expect(
      detectFeatureDrift(SETTINGS_WITHOUT_INBOUND, SCOPE)
    ).rejects.toMatchObject({ code: "FEATURE_DRIFT_CHECK_FAILED" });
  });
});

describe("assertNoFeatureDrift", () => {
  it("refuses to plan and names the resources and the way out", async () => {
    inboundAndHistoryDeployed();

    const error = await assertNoFeatureDrift(
      metadataWith(SETTINGS_WITHOUT_INBOUND),
      REGION
    ).catch((e: unknown) => e);

    expect(error).toBeInstanceOf(WrapsError);
    expect(error).toMatchObject({ code: "FEATURE_DRIFT" });
    const { message, suggestion } = error as WrapsError;
    expect(message).toContain("inbound");
    expect(message).toContain(BUCKET);
    expect(message).toContain("would delete");
    expect(suggestion).toContain("wraps email reconcile --preview");
  });

  it("lets a command run when nothing drifted", async () => {
    nothingDeployed();

    await expect(
      assertNoFeatureDrift(metadataWith(SETTINGS_WITHOUT_INBOUND), REGION)
    ).resolves.toBeUndefined();
  });

  it("does nothing without an email service", async () => {
    const metadata = {
      ...metadataWith(SETTINGS_WITHOUT_INBOUND),
      services: {},
    };

    await expect(
      assertNoFeatureDrift(metadata as ConnectionMetadata, REGION)
    ).resolves.toBeUndefined();
    expect(s3.commandCalls(HeadBucketCommand)).toHaveLength(0);
  });
});

describe("inferDriftedSections", () => {
  const inboundDrift = [
    {
      feature: "inbound" as const,
      settings: "inbound, inboundDomains",
      resources: [BUCKET],
    },
  ];

  function receivingFor(recipients: string[]): void {
    ses.on(DescribeReceiptRuleCommand).resolves({
      Rule: { Name: "wraps-inbound-catch-all", Recipients: recipients },
    });
    eventbridge
      .on(DescribeApiDestinationCommand)
      .rejects(awsError("ResourceNotFoundException"));
  }

  it("rebuilds the inbound section the 10 Nov setup never saved", async () => {
    receivingFor(["inbound.example.com"]);
    s3.on(GetBucketLifecycleConfigurationCommand).rejects(
      awsError("NoSuchLifecycleConfiguration", 404)
    );

    const { config, notes } = await inferDriftedSections(
      metadataWith(SETTINGS_WITHOUT_INBOUND),
      inboundDrift,
      REGION,
      NOW
    );

    expect(config.inbound).toEqual({
      enabled: true,
      subdomain: "inbound",
      receivingDomain: "inbound.example.com",
      bucketName: BUCKET,
    });
    expect(config.inboundDomains).toEqual([
      {
        subdomain: "inbound",
        receivingDomain: "inbound.example.com",
        parentDomain: "example.com",
        addedAt: NOW,
      },
    ]);
    expect(config.eventTracking).toEqual(
      SETTINGS_WITHOUT_INBOUND.eventTracking
    );
    expect(notes.join("\n")).toContain("inbound.retention");
  });

  it("reads inbound retention from the bucket's Wraps lifecycle rule", async () => {
    receivingFor(["inbound.example.com", "support.other.com"]);
    s3.on(GetBucketLifecycleConfigurationCommand).resolves({
      Rules: [
        {
          ID: "wraps-inbound-retention",
          Status: "Enabled",
          Expiration: { Days: 30 },
        },
      ],
    });
    const settings = {
      ...SETTINGS_WITHOUT_INBOUND,
      additionalDomains: [{ domain: "other.com" }],
    } as WrapsEmailConfig;

    const { config } = await inferDriftedSections(
      metadataWith(settings),
      inboundDrift,
      REGION,
      NOW
    );

    expect(config.inbound?.retention).toBe("30days");
    expect(config.inboundDomains?.map((d) => d.parentDomain)).toEqual([
      "example.com",
      "other.com",
    ]);
  });

  it("refuses when an inbound webhook exists, because its secret can't be read back", async () => {
    receivingFor(["inbound.example.com"]);
    eventbridge.on(DescribeApiDestinationCommand).resolves({
      Name: "wraps-inbound-webhook-destination",
    });

    await expect(
      inferDriftedSections(
        metadataWith(SETTINGS_WITHOUT_INBOUND),
        inboundDrift,
        REGION,
        NOW
      )
    ).rejects.toMatchObject({ code: "FEATURE_NOT_INFERABLE" });
  });

  it("refuses when a receiving domain is not under a tracked domain", async () => {
    receivingFor(["inbound.unknown.org"]);

    await expect(
      inferDriftedSections(
        metadataWith(SETTINGS_WITHOUT_INBOUND),
        inboundDrift,
        REGION,
        NOW
      )
    ).rejects.toMatchObject({ code: "FEATURE_NOT_INFERABLE" });
  });

  it("refuses when the receipt rule is gone", async () => {
    ses
      .on(DescribeReceiptRuleCommand)
      .rejects(awsError("RuleSetDoesNotExistException"));
    eventbridge
      .on(DescribeApiDestinationCommand)
      .rejects(awsError("ResourceNotFoundException"));

    await expect(
      inferDriftedSections(
        metadataWith(SETTINGS_WITHOUT_INBOUND),
        inboundDrift,
        REGION,
        NOW
      )
    ).rejects.toMatchObject({ code: "FEATURE_NOT_INFERABLE" });
  });

  it("rebuilds event tracking and history from the config set and processor", async () => {
    sesv2.on(GetConfigurationSetEventDestinationsCommand).resolves({
      EventDestinations: [
        {
          Name: "wraps-email-eventbridge",
          MatchingEventTypes: ["SEND", "DELIVERY", "BOUNCE", "COMPLAINT"],
        },
      ],
    });
    lambda
      .on(GetFunctionConfigurationCommand)
      .resolves({ Environment: { Variables: { RETENTION_DAYS: "180" } } });

    const { config } = await inferDriftedSections(
      metadataWith({ domain: "example.com" } as WrapsEmailConfig),
      [
        {
          feature: "eventTracking",
          settings: "",
          resources: ["wraps-email-events"],
        },
        {
          feature: "eventHistory",
          settings: "",
          resources: ["wraps-email-history"],
        },
      ],
      REGION,
      NOW
    );

    expect(config.eventTracking).toEqual({
      enabled: true,
      events: ["SEND", "DELIVERY", "BOUNCE", "COMPLAINT"],
      dynamoDBHistory: true,
      archiveRetention: "6months",
    });
  });
});

describe("retentionFromDays", () => {
  it("prefers the shortest name for a day count", () => {
    expect(retentionFromDays(90)).toBe("90days");
    expect(retentionFromDays(365)).toBe("1year");
    expect(retentionFromDays(12)).toBeUndefined();
  });
});

describe("toInboundDomain", () => {
  it("receives on the root domain with an empty subdomain", () => {
    expect(toInboundDomain("example.com", ["example.com"], NOW)).toEqual({
      subdomain: "",
      receivingDomain: "example.com",
      parentDomain: "example.com",
      addedAt: NOW,
    });
  });

  it("picks the longest tracked parent", () => {
    expect(
      toInboundDomain(
        "a.mail.example.com",
        ["example.com", "mail.example.com"],
        NOW
      )?.parentDomain
    ).toBe("mail.example.com");
  });

  it("does not match a domain that merely ends with the same letters", () => {
    expect(
      toInboundDomain("notexample.com", ["example.com"], NOW)
    ).toBeUndefined();
  });
});
