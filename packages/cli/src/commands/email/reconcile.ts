import * as clack from "@clack/prompts";
import pc from "picocolors";
import { trackCommand } from "../../telemetry/events.js";
import type {
  EmailReconcileOptions,
  WrapsEmailConfig,
} from "../../types/index.js";
import {
  detectFeatureDrift,
  type FeatureDrift,
  inferDriftedSections,
} from "../../utils/email/feature-drift.js";
import { validateAWSCredentials } from "../../utils/shared/aws.js";
import { errors, WrapsError } from "../../utils/shared/errors.js";
import { isJsonMode, jsonSuccess } from "../../utils/shared/json-output.js";
import {
  loadConnectionMetadata,
  saveConnectionMetadataToState,
} from "../../utils/shared/metadata.js";
import { DeploymentProgress } from "../../utils/shared/output.js";
import { isInteractive } from "../../utils/shared/prompts.js";
import { resolveRegionForCommand } from "../../utils/shared/region-resolver.js";

const SECTION_KEYS: Record<
  FeatureDrift["feature"],
  Array<keyof WrapsEmailConfig>
> = {
  inbound: ["inbound", "inboundDomains"],
  eventTracking: ["eventTracking"],
  eventHistory: ["eventTracking"],
};

function sectionsFor(
  drifts: FeatureDrift[],
  config: WrapsEmailConfig
): Partial<WrapsEmailConfig> {
  const keys = new Set(drifts.flatMap((d) => SECTION_KEYS[d.feature]));
  return Object.fromEntries(
    [...keys].map((key) => [key, config[key]])
  ) as Partial<WrapsEmailConfig>;
}

/**
 * Rebuild settings sections for features that are deployed in AWS but
 * missing from the settings file, and save them as a new version of the
 * settings file. The email stack plans from that file, so a missing section
 * would otherwise plan to delete the feature's resources.
 */
export async function reconcile(options: EmailReconcileOptions): Promise<void> {
  const startTime = Date.now();
  if (!isJsonMode()) {
    clack.intro(
      pc.bold(
        options.preview
          ? "Reconcile Wraps settings with AWS (preview)"
          : "Reconcile Wraps settings with AWS"
      )
    );
  }

  const progress = new DeploymentProgress();

  const identity = await progress.execute(
    "Validating AWS credentials",
    async () => validateAWSCredentials()
  );

  const region = await resolveRegionForCommand({
    accountId: identity.accountId,
    optionRegion: options.region,
    service: "email",
    label: "email deployment",
  });

  const metadata = await loadConnectionMetadata(identity.accountId, region);
  const emailService = metadata?.services.email;
  if (!(metadata && emailService)) {
    throw new WrapsError(
      `No Wraps email settings found for account ${identity.accountId} in ${region}`,
      "EMAIL_NOT_CONFIGURED",
      "Reconcile repairs an existing settings file. Use wraps email connect to adopt existing infrastructure.",
      "https://wraps.dev/docs/cli-reference"
    );
  }

  const drifts = await progress.execute(
    "Checking deployed resources against settings",
    async () =>
      await detectFeatureDrift(emailService.config, {
        accountId: identity.accountId,
        region,
      })
  );

  if (drifts.length === 0) {
    trackCommand("email:reconcile", {
      success: true,
      drift_count: 0,
      preview: options.preview === true,
      duration_ms: Date.now() - startTime,
    });
    if (isJsonMode()) {
      jsonSuccess("email.reconcile", { region, drift: [], saved: false });
      return;
    }
    progress.succeed("Settings already declare every deployed feature");
    clack.outro("Nothing to reconcile.");
    return;
  }

  const inferred = await progress.execute(
    "Reading deployed configuration",
    async () => await inferDriftedSections(metadata, drifts, region)
  );
  const sections = sectionsFor(drifts, inferred.config);

  if (!isJsonMode()) {
    console.log();
    for (const drift of drifts) {
      console.log(
        `  ${pc.yellow("!")} ${pc.bold(drift.feature)} is deployed but missing from settings (${drift.settings})`
      );
      console.log(`    ${pc.dim(drift.resources.join(", "))}`);
    }
    console.log();
    clack.note(JSON.stringify(sections, null, 2), "Sections to write");
    for (const note of inferred.notes) {
      clack.log.info(pc.dim(note));
    }
  }

  if (options.preview) {
    trackCommand("email:reconcile", {
      success: true,
      drift_count: drifts.length,
      preview: true,
      duration_ms: Date.now() - startTime,
    });
    if (isJsonMode()) {
      jsonSuccess("email.reconcile", {
        region,
        drift: drifts,
        sections,
        notes: inferred.notes,
        saved: false,
        preview: true,
      });
      return;
    }
    clack.outro(
      `Preview only. Run ${pc.cyan("wraps email reconcile")} without --preview to save.`
    );
    return;
  }

  if (!options.yes) {
    if (!isInteractive()) {
      throw errors.nonInteractiveInput("Confirmation", "--yes");
    }
    const confirmed = await clack.confirm({
      message: `Write these sections to the Wraps settings for ${identity.accountId} in ${region}?`,
    });
    if (clack.isCancel(confirmed) || !confirmed) {
      clack.cancel("Nothing was written.");
      process.exit(0);
    }
  }

  metadata.services.email = { ...emailService, config: inferred.config };
  metadata.timestamp = new Date().toISOString();
  const saved = await progress.execute(
    "Saving settings",
    async () => await saveConnectionMetadataToState(metadata)
  );

  trackCommand("email:reconcile", {
    success: true,
    drift_count: drifts.length,
    preview: false,
    duration_ms: Date.now() - startTime,
  });

  if (isJsonMode()) {
    jsonSuccess("email.reconcile", {
      region,
      drift: drifts,
      sections,
      notes: inferred.notes,
      saved: true,
      stateBucket: saved?.bucket ?? null,
      versionId: saved?.versionId ?? null,
    });
    return;
  }

  if (saved) {
    progress.succeed(
      `Saved to s3://${saved.bucket}${saved.versionId ? ` (version ${saved.versionId})` : ""}`
    );
  } else {
    progress.info(
      "No state bucket for this account and region; saved locally only"
    );
  }
  clack.outro(
    `Check the plan before you deploy: ${pc.cyan("wraps email upgrade --preview")}`
  );
}
