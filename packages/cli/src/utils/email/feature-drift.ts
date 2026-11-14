import { retentionToDays } from "@wraps/core";
import type {
  InboundDomain,
  SESEventType,
  WrapsEmailConfig,
} from "../../types/email.js";
import type { ArchiveRetention } from "../../types/shared.js";
import { errors } from "../shared/errors.js";
import type { ConnectionMetadata } from "../shared/metadata.js";
import { domainToConfigSetName } from "./config-set-slug.js";
import { getReceiptRuleRecipients } from "./receipt-rules.js";

/**
 * Features whose deployed resources the email stack deletes when the settings
 * file stops declaring them.
 *
 * The stack is an inline Pulumi program generated from the settings file
 * (`services.email.config`). Pulumi's own state tracks what is deployed, and
 * `refresh` keeps that in step with AWS, but the program only declares what the
 * settings file enables. A section that went missing (written from another
 * machine, never synced, restored from an old copy) therefore reads as "the
 * user turned this off", and the next preview plans to delete every resource
 * of that feature. This module looks at AWS for each feature the settings file
 * does not enable and refuses to plan when any of its resources exist.
 */
type DriftFeature = "inbound" | "eventTracking" | "eventHistory";

export type FeatureDrift = {
  feature: DriftFeature;
  /** Settings keys the file is missing, for the message. */
  settings: string;
  /** Deployed resource names that belong to the feature. */
  resources: string[];
};

type Scope = { accountId: string; region: string };

type ResourceProbe = {
  name: (scope: Scope) => string;
  exists: (name: string, region: string) => Promise<boolean>;
};

type FeatureSpec = {
  feature: DriftFeature;
  settings: string;
  isDeclared: (config: WrapsEmailConfig) => boolean;
  probes: ResourceProbe[];
};

function errorName(error: unknown): string | undefined {
  if (!(error instanceof Error)) {
    return;
  }
  const withCode = error as Error & { Code?: string };
  return withCode.Code ?? error.name;
}

function httpStatus(error: unknown): number | undefined {
  return (error as { $metadata?: { httpStatusCode?: number } } | undefined)
    ?.$metadata?.httpStatusCode;
}

async function probe(
  name: string,
  absentErrors: string[],
  call: () => Promise<unknown>
): Promise<boolean> {
  try {
    await call();
    return true;
  } catch (error) {
    const code = errorName(error);
    if (code && absentErrors.includes(code)) {
      return false;
    }
    throw errors.featureDriftCheckFailed(name, code ?? String(error));
  }
}

async function bucketPresent(name: string, region: string): Promise<boolean> {
  const { S3Client, HeadBucketCommand } = await import("@aws-sdk/client-s3");
  const client = new S3Client({ region });
  try {
    await client.send(new HeadBucketCommand({ Bucket: name }));
    return true;
  } catch (error) {
    const code = errorName(error);
    if (
      code === "NotFound" ||
      code === "NoSuchBucket" ||
      httpStatus(error) === 404
    ) {
      return false;
    }
    throw errors.featureDriftCheckFailed(name, code ?? String(error));
  }
}

async function queuePresent(name: string, region: string): Promise<boolean> {
  const { SQSClient, GetQueueUrlCommand } = await import("@aws-sdk/client-sqs");
  const client = new SQSClient({ region });
  return await probe(
    name,
    ["QueueDoesNotExist", "AWS.SimpleQueueService.NonExistentQueue"],
    () => client.send(new GetQueueUrlCommand({ QueueName: name }))
  );
}

async function functionPresent(name: string, region: string): Promise<boolean> {
  const { LambdaClient, GetFunctionConfigurationCommand } = await import(
    "@aws-sdk/client-lambda"
  );
  const client = new LambdaClient({ region });
  return await probe(name, ["ResourceNotFoundException"], () =>
    client.send(new GetFunctionConfigurationCommand({ FunctionName: name }))
  );
}

async function tablePresent(name: string, region: string): Promise<boolean> {
  const { DynamoDBClient, DescribeTableCommand } = await import(
    "@aws-sdk/client-dynamodb"
  );
  const client = new DynamoDBClient({ region });
  return await probe(name, ["ResourceNotFoundException"], () =>
    client.send(new DescribeTableCommand({ TableName: name }))
  );
}

const INBOUND_FUNCTION = "wraps-inbound-email-processor";
const EVENT_PROCESSOR_FUNCTION = "wraps-email-event-processor";
const INBOUND_WEBHOOK_DESTINATION = "wraps-inbound-webhook-destination";
const EVENT_DESTINATION = "wraps-email-eventbridge";
const INBOUND_RETENTION_RULE = "wraps-inbound-retention";

function inboundBucketName(scope: Scope): string {
  return `wraps-inbound-${scope.accountId}-${scope.region}`;
}

/** Names match the resource files under `infrastructure/resources/`. */
const FEATURES: FeatureSpec[] = [
  {
    feature: "inbound",
    settings: "inbound, inboundDomains",
    isDeclared: (config) => config.inbound?.enabled === true,
    probes: [
      { name: inboundBucketName, exists: bucketPresent },
      { name: () => "wraps-inbound-events", exists: queuePresent },
      { name: () => INBOUND_FUNCTION, exists: functionPresent },
    ],
  },
  {
    feature: "eventTracking",
    settings: "eventTracking.enabled",
    isDeclared: (config) => config.eventTracking?.enabled === true,
    probes: [{ name: () => "wraps-email-events", exists: queuePresent }],
  },
  {
    feature: "eventHistory",
    settings: "eventTracking.dynamoDBHistory",
    isDeclared: (config) => config.eventTracking?.dynamoDBHistory === true,
    probes: [
      { name: () => "wraps-email-history", exists: tablePresent },
      { name: () => EVENT_PROCESSOR_FUNCTION, exists: functionPresent },
    ],
  },
];

/**
 * List features that have resources deployed in AWS but are not enabled in the
 * settings file. Probes only the undeclared features. Any probe error other
 * than "not found" throws, so a missing permission can never read as "nothing
 * deployed".
 */
export async function detectFeatureDrift(
  config: WrapsEmailConfig,
  scope: Scope
): Promise<FeatureDrift[]> {
  const drifts: FeatureDrift[] = [];
  for (const spec of FEATURES) {
    if (spec.isDeclared(config)) {
      continue;
    }
    const resources: string[] = [];
    for (const resourceProbe of spec.probes) {
      const name = resourceProbe.name(scope);
      if (await resourceProbe.exists(name, scope.region)) {
        resources.push(name);
      }
    }
    if (resources.length > 0) {
      drifts.push({
        feature: spec.feature,
        settings: spec.settings,
        resources,
      });
    }
  }
  return drifts;
}

/**
 * Refuse to plan from a settings file that would delete deployed resources.
 * Call it with the metadata as loaded, before the command applies its own
 * changes, so a deliberate disable (inbound destroy, upgrade disabling
 * history) still works: that feature is declared in the stored file.
 */
export async function assertNoFeatureDrift(
  metadata: ConnectionMetadata,
  region: string
): Promise<void> {
  const config = metadata.services.email?.config;
  if (!config) {
    return;
  }
  const drifts = await detectFeatureDrift(config, {
    accountId: metadata.accountId,
    region,
  });
  if (drifts.length > 0) {
    throw errors.featureDrift(drifts, metadata.accountId, region);
  }
}

/** Every `ArchiveRetention` once, shortest first, so 90 days reads as "90days". */
const RETENTIONS_BY_PREFERENCE = Object.keys({
  "7days": true,
  "30days": true,
  "90days": true,
  "3months": true,
  "6months": true,
  "9months": true,
  "1year": true,
  "18months": true,
  "2years": true,
  "30months": true,
  "3years": true,
  "4years": true,
  "5years": true,
  "6years": true,
  "7years": true,
  "8years": true,
  "9years": true,
  "10years": true,
  indefinite: true,
  permanent: true,
} satisfies Record<ArchiveRetention, true>) as ArchiveRetention[];

export function retentionFromDays(days: number): ArchiveRetention | undefined {
  return RETENTIONS_BY_PREFERENCE.find(
    (retention) => retentionToDays(retention) === days
  );
}

type InferredSections = {
  config: WrapsEmailConfig;
  /** Fields set to a default because AWS does not record them. */
  notes: string[];
};

async function readInboundRetention(
  scope: Scope
): Promise<ArchiveRetention | undefined> {
  const { S3Client, GetBucketLifecycleConfigurationCommand } = await import(
    "@aws-sdk/client-s3"
  );
  const client = new S3Client({ region: scope.region });
  const bucket = inboundBucketName(scope);
  try {
    const response = await client.send(
      new GetBucketLifecycleConfigurationCommand({ Bucket: bucket })
    );
    const days = response.Rules?.find(
      (rule) => rule.ID === INBOUND_RETENTION_RULE
    )?.Expiration?.Days;
    return days === undefined ? undefined : retentionFromDays(days);
  } catch (error) {
    if (errorName(error) === "NoSuchLifecycleConfiguration") {
      return;
    }
    throw errors.featureDriftCheckFailed(
      bucket,
      errorName(error) ?? String(error)
    );
  }
}

async function inboundWebhookDeployed(region: string): Promise<boolean> {
  const { EventBridgeClient, DescribeApiDestinationCommand } = await import(
    "@aws-sdk/client-eventbridge"
  );
  const client = new EventBridgeClient({ region });
  return await probe(
    INBOUND_WEBHOOK_DESTINATION,
    ["ResourceNotFoundException"],
    () =>
      client.send(
        new DescribeApiDestinationCommand({ Name: INBOUND_WEBHOOK_DESTINATION })
      )
  );
}

/** Split a receiving domain into the tracked parent it belongs to and the label in front. */
export function toInboundDomain(
  receivingDomain: string,
  parentDomains: string[],
  addedAt: string
): InboundDomain | undefined {
  const parent = parentDomains
    .filter((d) => receivingDomain === d || receivingDomain.endsWith(`.${d}`))
    .sort((a, b) => b.length - a.length)[0];
  if (!parent) {
    return;
  }
  return {
    subdomain:
      receivingDomain === parent
        ? ""
        : receivingDomain.slice(0, -(parent.length + 1)),
    receivingDomain,
    parentDomain: parent,
    addedAt,
  };
}

async function inferInbound(
  config: WrapsEmailConfig,
  scope: Scope,
  now: string
): Promise<Pick<WrapsEmailConfig, "inbound" | "inboundDomains">> {
  if (await inboundWebhookDeployed(scope.region)) {
    throw errors.featureNotInferable(
      "inbound",
      `${INBOUND_WEBHOOK_DESTINATION} exists, and its secret lives only in EventBridge. Restore the inbound section from an earlier version of the settings file, or run wraps email inbound init again.`
    );
  }
  const recipients = await getReceiptRuleRecipients(scope.region);
  if (!recipients || recipients.length === 0) {
    throw errors.featureNotInferable(
      "inbound",
      "the SES receipt rule wraps-inbound-catch-all has no recipients, so the receiving domains are unknown."
    );
  }
  const parents = [
    config.domain,
    ...(config.additionalDomains ?? []).map((d) => d.domain),
  ].filter((d): d is string => Boolean(d));
  const inboundDomains: InboundDomain[] = [];
  for (const recipient of recipients) {
    const domain = toInboundDomain(recipient, parents, now);
    if (!domain) {
      throw errors.featureNotInferable(
        "inbound",
        `the receipt rule receives for ${recipient}, which is not under a domain in the settings file.`
      );
    }
    inboundDomains.push(domain);
  }
  const retention = await readInboundRetention(scope);
  const [first] = inboundDomains;
  return {
    inbound: {
      enabled: true,
      subdomain: first.subdomain,
      receivingDomain: first.receivingDomain,
      bucketName: inboundBucketName(scope),
      ...(retention && { retention }),
    },
    inboundDomains,
  };
}

async function readEventTypes(
  config: WrapsEmailConfig,
  region: string
): Promise<SESEventType[] | undefined> {
  if (!config.domain) {
    return;
  }
  const { SESv2Client, GetConfigurationSetEventDestinationsCommand } =
    await import("@aws-sdk/client-sesv2");
  const client = new SESv2Client({ region });
  const configSet = domainToConfigSetName(config.domain);
  try {
    const response = await client.send(
      new GetConfigurationSetEventDestinationsCommand({
        ConfigurationSetName: configSet,
      })
    );
    const types = response.EventDestinations?.find(
      (destination) => destination.Name === EVENT_DESTINATION
    )?.MatchingEventTypes;
    return types && types.length > 0 ? (types as SESEventType[]) : undefined;
  } catch (error) {
    if (errorName(error) === "NotFoundException") {
      return;
    }
    throw errors.featureDriftCheckFailed(
      configSet,
      errorName(error) ?? String(error)
    );
  }
}

async function readHistoryRetention(
  region: string
): Promise<ArchiveRetention | undefined> {
  const { LambdaClient, GetFunctionConfigurationCommand } = await import(
    "@aws-sdk/client-lambda"
  );
  const client = new LambdaClient({ region });
  try {
    const response = await client.send(
      new GetFunctionConfigurationCommand({
        FunctionName: EVENT_PROCESSOR_FUNCTION,
      })
    );
    const days = Number(response.Environment?.Variables?.RETENTION_DAYS);
    return Number.isFinite(days) && days > 0
      ? retentionFromDays(days)
      : undefined;
  } catch (error) {
    if (errorName(error) === "ResourceNotFoundException") {
      return;
    }
    throw errors.featureDriftCheckFailed(
      EVENT_PROCESSOR_FUNCTION,
      errorName(error) ?? String(error)
    );
  }
}

/**
 * Rebuild the settings sections for drifted features from what AWS records.
 * Throws `FEATURE_NOT_INFERABLE` rather than guess a value whose loss would
 * change a deployed resource (a webhook secret, an unknown receiving domain).
 */
export async function inferDriftedSections(
  metadata: ConnectionMetadata,
  drifts: FeatureDrift[],
  region: string,
  now = new Date().toISOString()
): Promise<InferredSections> {
  const current = metadata.services.email?.config;
  if (!current) {
    throw new Error("Email service config not found in metadata");
  }
  const scope = { accountId: metadata.accountId, region };
  const drifted = new Set(drifts.map((d) => d.feature));
  const notes: string[] = [];
  let config: WrapsEmailConfig = { ...current };

  if (drifted.has("inbound")) {
    config = { ...config, ...(await inferInbound(config, scope, now)) };
    if (!config.inbound?.retention) {
      notes.push(
        "inbound.retention: the bucket has no Wraps lifecycle rule, so none is set."
      );
    }
    notes.push(
      `inboundDomains[].addedAt: AWS does not record it; set to ${now}.`
    );
  }

  if (drifted.has("eventTracking")) {
    const events = await readEventTypes(config, region);
    config = {
      ...config,
      eventTracking: {
        ...config.eventTracking,
        enabled: true,
        ...(events && { events }),
      },
    };
    if (!events) {
      notes.push(
        "eventTracking.events: no Wraps event destination found; the default (all types) applies."
      );
    }
  }

  if (drifted.has("eventHistory")) {
    const archiveRetention = await readHistoryRetention(region);
    config = {
      ...config,
      eventTracking: {
        ...config.eventTracking,
        enabled: config.eventTracking?.enabled ?? false,
        dynamoDBHistory: true,
        ...(archiveRetention && { archiveRetention }),
      },
    };
    if (!archiveRetention) {
      notes.push(
        "eventTracking.archiveRetention: not readable from the event processor; the default (90days) applies."
      );
    }
  }

  return { config, notes };
}
