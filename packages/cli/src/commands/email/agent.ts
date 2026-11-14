import { promises as dns } from "node:dns";
import * as clack from "@clack/prompts";
import * as pulumi from "@pulumi/pulumi";
import pc from "picocolors";
import { deployEmailStack } from "../../infrastructure/email-stack.js";
import type {
  EmailAgentCreateOptions,
  EmailAgentKillOptions,
  EmailAgentListOptions,
  EmailAgentPolicyOptions,
} from "../../types/index.js";
import { assertNoFeatureDrift } from "../../utils/email/feature-drift.js";
import {
  createAgentApiClient,
  parseAgentApiError as parseError,
} from "../../utils/shared/agent-api.js";
import {
  getAWSRegion,
  isSESSandbox,
  validateAWSCredentials,
} from "../../utils/shared/aws.js";
import {
  ensurePulumiWorkDir,
  getPulumiWorkDir,
} from "../../utils/shared/fs.js";
import {
  isJsonMode,
  jsonError,
  jsonSuccess,
} from "../../utils/shared/json-output.js";
import {
  buildEmailStackConfig,
  getAllTrackedDomains,
  loadConnectionMetadata,
  saveConnectionMetadata,
} from "../../utils/shared/metadata.js";
import { DeploymentProgress } from "../../utils/shared/output.js";
import {
  ensurePulumiInstalled,
  withLockRetry,
} from "../../utils/shared/pulumi.js";
import {
  DEFAULT_PULUMI_TIMEOUT_MS,
  withTimeout,
} from "../../utils/shared/timeout.js";

// Default policy applied to a freshly created agent. Conservative caps + an
// empty allowlist mean every send starts flagged for approval until an operator
// widens the leash (edit via the API / dashboard).
const DEFAULT_AGENT_POLICY = {
  maxPerHour: 20,
  maxPerDay: 100,
  allowedRecipients: [] as string[],
  allowedRecipientDomains: [] as string[],
};

// Agent names become part of the IAM user name (`wraps-agent-{name}`) and the
// email local part, so keep them to a safe lowercase slug. Capped at 52 chars:
// the `wraps-agent-` prefix (12) + 52 = the 64-char IAM username limit (COR-8).
const AGENT_NAME_PATTERN = /^[a-z0-9][a-z0-9-]{0,51}$/;

// `resolveMx` can hang on a slow or unreachable resolver; a create that has
// already succeeded must never stall on this probe.
const MX_LOOKUP_TIMEOUT_MS = 3000;

/**
 * Whether the agent's own domain can receive mail. `buildEmailDNSRecords`
 * only creates an MX for the MAIL FROM subdomain (bounce handling), so a
 * send-only domain has no apex MX and every human reply bounces.
 *
 * Returns `null` — "could not determine" — for anything other than a
 * definite ENOTFOUND/ENODATA "no MX" answer (a timeout, ESERVFAIL, a
 * network error, …), so a flaky resolver never produces a false-alarm
 * warning printed right next to freshly minted credentials.
 */
async function domainAcceptsMail(domain: string): Promise<boolean | null> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timedOut = Symbol("mx-lookup-timeout");
  const timeout = new Promise<typeof timedOut>((resolve) => {
    timer = setTimeout(() => resolve(timedOut), MX_LOOKUP_TIMEOUT_MS);
  });

  try {
    const result = await Promise.race([dns.resolveMx(domain), timeout]);
    if (result === timedOut) {
      return null;
    }
    return result.length > 0;
  } catch (error) {
    const code = (error as NodeJS.ErrnoException | undefined)?.code;
    if (code === "ENODATA" || code === "ENOTFOUND") {
      return false;
    }
    return null;
  } finally {
    if (timer) {
      clearTimeout(timer);
    }
  }
}

type AgentRecord = {
  id: string;
  name: string;
  emailAddress: string;
  domain: string;
  status: string;
  policy: typeof DEFAULT_AGENT_POLICY;
  credentialUserArn: string | null;
  enforcerFunctionArn: string | null;
  awsAccountId: string | null;
  createdAt: string;
  updatedAt: string;
};

/**
 * Create a leashed agent: a scoped send credential that can only invoke the
 * enforcer Lambda. Registers the agent with the Wraps Platform, deploys the
 * per-agent IAM user + enforcer infra, syncs deploy outputs back, then prints
 * the access key + MCP env snippet once.
 *
 * @throws {WrapsError} If AWS credentials or Pulumi are unavailable
 */
export async function agentCreate(
  options: EmailAgentCreateOptions
): Promise<void> {
  if (!isJsonMode()) {
    clack.intro(pc.bold("Create Agent Mailbox"));
  }

  const progress = new DeploymentProgress();

  // 1. Prerequisites: Pulumi + AWS credentials
  await progress.execute("Checking prerequisites", async () =>
    ensurePulumiInstalled()
  );
  const identity = await progress.execute(
    "Validating AWS credentials",
    async () => validateAWSCredentials()
  );

  // 2. Region + metadata (requires outbound email deployed)
  const region = options.region || (await getAWSRegion());
  const metadata = await loadConnectionMetadata(identity.accountId, region);

  if (!metadata?.services?.email?.config) {
    progress.stop();
    if (isJsonMode()) {
      jsonError("email.agent.create", {
        code: "EMAIL_NOT_CONFIGURED",
        message: "Email infrastructure is not deployed in this region.",
        suggestion: "Run: wraps email init",
      });
      return;
    }
    clack.log.error("Email infrastructure is not deployed in this region.");
    console.log(`\nDeploy first: ${pc.cyan("wraps email init")}\n`);
    process.exit(1);
  }

  await assertNoFeatureDrift(metadata, region);

  const emailService = metadata.services.email;
  const emailConfig = emailService.config;

  // 3. Require an authenticated Wraps Platform session (the approval queue and
  //    policy sync live server-side).
  const api = await createAgentApiClient(options.token);
  if (!api.ok) {
    progress.stop();
    if (isJsonMode()) {
      jsonError("email.agent.create", {
        code: "NOT_AUTHENTICATED",
        message: "No API token found.",
        suggestion: "Run: wraps auth login",
      });
      return;
    }
    clack.log.error("Not signed in to the Wraps Platform.");
    console.log(`\nSign in first: ${pc.cyan("wraps auth login")}\n`);
    process.exit(1);
  }

  // 4. Platform connection is a hard prerequisite: the approval-execute flow
  //    assumes the customer's `wraps-console-access-role`, which only exists
  //    after `wraps platform connect`. Verify the AWS account is connected.
  const connected = await progress.execute(
    "Verifying platform connection",
    async () => {
      const resp = await api.get("/v1/connections");
      if (!resp.ok) {
        throw new Error(await parseError(resp));
      }
      const data = (await resp.json()) as {
        connections: Array<{ accountId: string; webhookConnected?: boolean }>;
      };
      return data.connections.some((c) => c.accountId === identity.accountId);
    }
  );

  if (!connected) {
    progress.stop();
    if (isJsonMode()) {
      jsonError("email.agent.create", {
        code: "PLATFORM_NOT_CONNECTED",
        message: "This AWS account is not connected to the Wraps Platform.",
        suggestion: "Run: wraps platform connect",
      });
      return;
    }
    clack.log.error("This AWS account is not connected to the Wraps Platform.");
    console.log(
      `\nAgent approvals require a platform connection. Connect first:\n  ${pc.cyan("wraps platform connect")}\n`
    );
    process.exit(1);
  }

  // 5. Warn if SES is still in the sandbox (agents can only reach verified
  //    addresses until production access is granted).
  const sandbox = await isSESSandbox(region);
  if (sandbox && !isJsonMode()) {
    clack.log.warn(
      `SES is in the ${pc.yellow("sandbox")} in ${region}. Agents can only send to verified addresses until you request production access.`
    );
  }

  // 5b. Reuse the account webhook secret registered by `platform connect`
  //     (SEC-1). The enforcer→API callback authenticates against
  //     `awsAccount.webhookSecret`, so minting a fresh per-agent secret would
  //     401 every flagged send. Never generate a new one — if the account
  //     secret is missing locally, hard-stop with guidance.
  const webhookSecret = emailService.webhookSecret;
  if (!webhookSecret) {
    progress.stop();
    if (isJsonMode()) {
      jsonError("email.agent.create", {
        code: "WEBHOOK_SECRET_MISSING",
        message:
          "No account webhook secret found. The agent approval callback cannot authenticate without it.",
        suggestion: "Run: wraps platform connect",
      });
      return;
    }
    clack.log.error("No account webhook secret found for this account/region.");
    console.log(
      `\nAgent approvals reuse the webhook secret registered by platform connect.\nConnect (or reconnect) first so it is stored locally:\n  ${pc.cyan("wraps platform connect")}\n`
    );
    process.exit(1);
  }

  // 6. Prompt for the agent name
  let name = options.name;
  if (!name) {
    if (isJsonMode() || options.yes) {
      progress.stop();
      jsonError("email.agent.create", {
        code: "NAME_REQUIRED",
        message: "Agent name is required in non-interactive mode.",
        suggestion: "Pass the agent name: wraps email agent create <name>",
      });
      return;
    }
    const answer = await clack.text({
      message: "Agent name (lowercase, used in the email address):",
      placeholder: "sdr",
      validate: (value) =>
        AGENT_NAME_PATTERN.test(value)
          ? undefined
          : "Use lowercase letters, numbers, and hyphens, max 52 chars (e.g. sdr, support-bot).",
    });
    if (clack.isCancel(answer)) {
      clack.cancel("Operation cancelled.");
      process.exit(0);
    }
    name = answer;
  }

  if (!AGENT_NAME_PATTERN.test(name)) {
    progress.stop();
    if (isJsonMode()) {
      jsonError("email.agent.create", {
        code: "INVALID_NAME",
        message:
          "Agent name must be lowercase letters, numbers, and hyphens, max 52 chars.",
      });
      return;
    }
    clack.log.error(
      "Agent name must be lowercase letters, numbers, and hyphens, max 52 chars."
    );
    process.exit(1);
  }

  // 7. Pick the sending domain from verified domains in metadata.
  const trackedDomains = getAllTrackedDomains(metadata);
  const rootDomain = emailConfig.domain || trackedDomains[0]?.domain || "";

  let domain = options.domain;
  if (!domain) {
    if (isJsonMode() || options.yes) {
      domain = rootDomain;
    } else {
      const DEDICATED = "__dedicated__";
      const selected = await clack.select({
        message: "Which verified domain should this agent send from?",
        options: [
          ...trackedDomains.map((d) => ({
            value: d.domain,
            label: d.domain,
            hint: d.isPrimary ? "primary" : d.purpose,
          })),
          {
            value: DEDICATED,
            label: "Use a dedicated agents. subdomain",
            hint: "recommended — isolates agent reputation",
          },
        ],
      });
      if (clack.isCancel(selected)) {
        clack.cancel("Operation cancelled.");
        process.exit(0);
      }

      if (selected === DEDICATED) {
        clack.note(
          [
            "A dedicated subdomain keeps agent sends from affecting your main",
            "domain's reputation. Set one up first, then re-run agent create:",
            "",
            `  ${pc.cyan(`wraps email domains add agents.${rootDomain}`)}`,
            "",
            "Once verified, choose it from the domain list here.",
          ].join("\n"),
          "Dedicated agent subdomain"
        );
        process.exit(0);
      }
      domain = selected as string;
    }
  }

  let emailAddress = `${name}@${domain}`;

  // 8. Register the agent with the Wraps Platform (creates the Neon row).
  //    Registration precedes deploy, so a prior failed deploy can leave an
  //    orphaned row (credentialUserArn: null). On a 409 we look the row up: if
  //    it never deployed we resume against it; a fully deployed duplicate is a
  //    real conflict.
  const registration = await progress.execute(
    "Registering agent",
    async (): Promise<
      { kind: "created" | "resume"; agent: AgentRecord } | { kind: "conflict" }
    > => {
      const resp = await api.post("/v1/agents", {
        name,
        emailAddress,
        domain,
        policy: DEFAULT_AGENT_POLICY,
      });
      if (resp.ok) {
        return { kind: "created", agent: (await resp.json()) as AgentRecord };
      }
      if (resp.status !== 409) {
        throw new Error(await parseError(resp));
      }
      // 409 — find the pre-existing same-name agent to decide resume vs conflict.
      const listResp = await api.get("/v1/agents");
      const existing = listResp.ok
        ? ((await listResp.json()) as { agents: AgentRecord[] }).agents.find(
            (a) => a.name === name
          )
        : undefined;
      if (existing && !existing.credentialUserArn) {
        return { kind: "resume", agent: existing };
      }
      return { kind: "conflict" };
    }
  );

  if (registration.kind === "conflict") {
    progress.stop();
    const message = `An agent named "${name}" already exists and is already deployed.`;
    const suggestion =
      "Agent names are permanent — killing an agent does not free its name. Choose a different name.";
    if (isJsonMode()) {
      jsonError("email.agent.create", {
        code: "AGENT_ALREADY_EXISTS",
        message,
        suggestion,
      });
      return;
    }
    clack.log.error(message);
    console.log(`\n${suggestion}\n`);
    process.exit(1);
  }

  const created = registration.agent;

  // A resumed (previously undeployed) agent continues the flow unchanged — same
  // config id, alias, and policy-sync — it just skips the POST above. The
  // durable Neon row is the source of truth for the address: the enforcer pins
  // the sending identity to the stored `emailAddress` (SEC-3), so if the
  // operator picked a different domain on this run we honor the original and
  // reconcile the local copies, rather than deploying a mailbox whose printed
  // address the enforcer would then block.
  if (registration.kind === "resume") {
    const addressChanged = created.emailAddress !== emailAddress;
    domain = created.domain;
    emailAddress = created.emailAddress;
    if (!isJsonMode()) {
      clack.note(
        addressChanged
          ? `Found an existing undeployed agent "${name}" — resuming deploy with its original address ${pc.cyan(created.emailAddress)} (a new domain choice is ignored; the sending identity is fixed at creation).`
          : `Found an existing undeployed agent "${name}" — resuming deploy.`,
        "Resuming"
      );
    }
  }

  // 9. Merge into the agents config (dedupe by name). The Neon agent id pins
  //    the per-agent enforcer alias (`agent-<id>`) the deploy creates (SEC-2).
  const existingAgents = emailConfig.agents;
  const mergedAgents = [
    ...(existingAgents?.agents ?? []).filter((a) => a.name !== name),
    { id: created.id, name, emailAddress, domain },
  ];
  const updatedEmailConfig = {
    ...emailConfig,
    agents: {
      enabled: true,
      webhookSecret,
      agents: mergedAgents,
    },
  };

  // 11. Confirm deployment (unless non-interactive).
  if (!(options.yes || isJsonMode())) {
    clack.log.info(`Agent address: ${pc.cyan(emailAddress)}`);
    const confirmed = await clack.confirm({
      message: "Deploy the agent enforcer + scoped credential?",
      initialValue: true,
    });
    if (clack.isCancel(confirmed) || !confirmed) {
      clack.cancel("Operation cancelled.");
      process.exit(0);
    }
  }

  // 12. Deploy the stack and capture outputs (enforcer ARN + agent creds).
  const stackConfig = buildEmailStackConfig(metadata, region, {
    emailConfig: updatedEmailConfig,
  });
  const stackName =
    emailService.pulumiStackName || `wraps-${identity.accountId}-${region}`;

  const outputs = await progress.execute(
    "Deploying agent enforcement infrastructure",
    async () => {
      await ensurePulumiWorkDir({ accountId: identity.accountId, region });
      const stack = await pulumi.automation.LocalWorkspace.createOrSelectStack(
        {
          stackName,
          projectName: "wraps-email",
          program: async () => {
            const result = await deployEmailStack(stackConfig);
            return result as Record<string, unknown>;
          },
        },
        { workDir: getPulumiWorkDir() }
      );

      await stack.setConfig("aws:region", { value: region });

      const upResult = await withLockRetry(
        () =>
          withTimeout(
            stack.up({ onOutput: () => {} }),
            DEFAULT_PULUMI_TIMEOUT_MS,
            "Pulumi deployment"
          ),
        { accountId: identity.accountId, region, autoConfirm: options.yes }
      );

      const o = upResult.outputs;
      return {
        agentEnforcerArn: o.agentEnforcerArn?.value as string | undefined,
        agentPolicyTableName: o.agentPolicyTableName?.value as
          | string
          | undefined,
        agentCredentials: o.agentCredentials?.value as
          | Record<
              string,
              { accessKeyId: string; secretAccessKey: string; userArn: string }
            >
          | undefined,
        agentAliasArns: o.agentAliasArns?.value as
          | Record<string, string>
          | undefined,
      };
    }
  );

  const creds = outputs.agentCredentials?.[name];
  if (!creds) {
    progress.stop();
    if (isJsonMode()) {
      jsonError("email.agent.create", {
        code: "NO_CREDENTIALS",
        message: "Deployment finished but no agent credentials were returned.",
      });
      return;
    }
    clack.log.error(
      "Deployment finished but no agent credentials were returned."
    );
    process.exit(1);
  }

  // The per-agent alias ARN is what the credential can invoke, so it's the
  // WRAPS_AGENT_ENFORCER_ARN the MCP client uses (SEC-2). Without it the agent
  // has no reachable endpoint — treat a missing alias like missing credentials.
  const aliasArn = outputs.agentAliasArns?.[name];
  if (!aliasArn) {
    progress.stop();
    if (isJsonMode()) {
      jsonError("email.agent.create", {
        code: "NO_ALIAS",
        message:
          "Deployment finished but no agent enforcer alias was returned.",
      });
      return;
    }
    clack.log.error(
      "Deployment finished but no agent enforcer alias was returned."
    );
    process.exit(1);
  }

  // The unqualified function ARN is the execute-path endpoint the approval flow
  // invokes (the alias ARN is agent-only). Without it, `policy-sync` would store
  // a null enforcerFunctionArn and every approved send would later fail
  // "not deployed" — so treat it as fatal now rather than persisting a
  // half-synced agent.
  const enforcerFunctionArn = outputs.agentEnforcerArn;
  if (!enforcerFunctionArn) {
    progress.stop();
    if (isJsonMode()) {
      jsonError("email.agent.create", {
        code: "NO_ENFORCER_ARN",
        message:
          "Deployment finished but no agent enforcer function ARN was returned.",
      });
      return;
    }
    clack.log.error(
      "Deployment finished but no agent enforcer function ARN was returned."
    );
    process.exit(1);
  }

  // Persist the alias ARN onto the agent's config entry so it survives in
  // metadata for recovery/inspection.
  const savedAgentEntry = updatedEmailConfig.agents.agents.find(
    (a) => a.name === name
  );
  if (savedAgentEntry) {
    savedAgentEntry.aliasArn = aliasArn;
  }

  // 13. SAVE ORDER (CLAUDE.md): persist stack outputs to metadata AND sync the
  //     deploy outputs to the API BEFORE printing the credential. If the
  //     process dies after printing, the agent would be unrecoverable.
  await progress.execute("Saving configuration", async () => {
    metadata.services.email = {
      ...emailService,
      config: updatedEmailConfig,
      deployedAt: new Date().toISOString(),
    };
    metadata.timestamp = new Date().toISOString();
    await saveConnectionMetadata(metadata);
  });

  const sync = await progress.execute("Syncing agent policy", async () => {
    const resp = await api.post(`/v1/agents/${created.id}/policy-sync`, {
      credentialUserArn: creds.userArn,
      enforcerFunctionArn,
      awsAccountId: identity.accountId,
    });
    if (!resp.ok) {
      throw new Error(await parseError(resp));
    }
    // A 200 can still carry syncStatus:"failed" — the agent row exists but the
    // enforcer never got its CONFIG item, so the agent cannot send. Surface it
    // below rather than throwing: the credential must still reach the operator.
    return (await resp.json()) as {
      syncStatus?: "synced" | "skipped" | "failed";
      warning?: string;
    };
  });

  const syncFailed = sync.syncStatus === "failed";

  // Whether a human reply to this agent's address can be received. Never let
  // this jeopardise the create's output — creation already succeeded, so any
  // failure here (beyond what domainAcceptsMail already swallows into `null`)
  // is itself swallowed rather than surfaced. domainAcceptsMail already
  // classifies every expected DNS failure into null; this outer catch is
  // belt-and-suspenders against an unexpected throw.
  let mailAccepted: boolean | null = null;
  try {
    mailAccepted = await domainAcceptsMail(domain);
    // baseline:allow-next-line no-swallowed-errors — creation already succeeded; nothing here should ever reach the operator
  } catch {
    mailAccepted = null;
  }

  // 14. Output — credential shown ONCE.
  if (isJsonMode()) {
    jsonSuccess("email.agent.create", {
      id: created.id,
      name,
      emailAddress,
      domain,
      region,
      // Unqualified function ARN (execute path) + per-agent alias ARN (what the
      // agent's credential invokes → WRAPS_AGENT_ENFORCER_ARN).
      enforcerArn: enforcerFunctionArn,
      enforcerAliasArn: aliasArn,
      policyTableName: outputs.agentPolicyTableName ?? null,
      accessKeyId: creds.accessKeyId,
      secretAccessKey: creds.secretAccessKey,
      userArn: creds.userArn,
      // The command DID create the agent and mint a real credential even when
      // the sync failed — jsonSuccess (not jsonError) is deliberate here so
      // the credential doesn't have to be smuggled through an error payload a
      // scripted caller isn't looking at. syncStatus is the field to branch on.
      syncStatus: sync.syncStatus ?? "unknown",
      warning: sync.warning ?? null,
      // true/false when the apex MX lookup resolved definitively, null when it
      // could not be determined (timeout, network issue, …) — null must never
      // be read as "no MX".
      domainAcceptsMail: mailAccepted,
    });
    return;
  }

  progress.stop();

  console.log();
  if (syncFailed) {
    clack.log.warn(pc.bold(`Agent "${name}" was created but CANNOT send yet.`));
  } else {
    clack.log.success(pc.bold(`Agent "${name}" is ready.`));
  }
  console.log();
  console.log(`  ${pc.dim("Address:")}     ${pc.cyan(emailAddress)}`);
  console.log(`  ${pc.dim("Agent ID:")}    ${pc.cyan(created.id)}`);
  console.log(`  ${pc.dim("Enforcer:")}    ${pc.cyan(aliasArn)}`);
  console.log();

  // mailAccepted === false is a definite "no MX" — only then is a human
  // reply guaranteed to bounce. null ("could not determine": timeout,
  // network issue, …) must stay silent, or a flaky resolver trains people to
  // ignore output printed right next to real credentials.
  if (mailAccepted === false) {
    clack.log.warn(
      `Replies to ${pc.cyan(emailAddress)} will bounce — ${pc.cyan(domain)} has no MX record.`
    );
    console.log(
      `  Set ${pc.cyan("replyTo")} on every send to a mailbox that can receive, or run ${pc.cyan("wraps email inbound")} to make ${domain} receive mail.`
    );
    console.log();
  }

  const mcpEnv = [
    `WRAPS_AGENT_ID=${created.id}`,
    `WRAPS_AGENT_ENFORCER_ARN=${aliasArn}`,
    `AWS_ACCESS_KEY_ID=${creds.accessKeyId}`,
    `AWS_SECRET_ACCESS_KEY=${creds.secretAccessKey}`,
    `AWS_REGION=${region}`,
  ].join("\n");

  clack.note(mcpEnv, "MCP env — save now, the secret is shown only once");

  console.log();

  if (syncFailed) {
    console.log(pc.bold("This agent cannot send until the sync succeeds:"));
    if (sync.warning) {
      console.log(`  ${pc.yellow(sync.warning)}`);
    }
    console.log(
      `  Still failing after that? Reach us: ${pc.cyan("wraps support")}`
    );
    console.log();
  } else {
    console.log(pc.bold("Next steps:"));
    console.log(
      `  1. Add the env above to your agent's ${pc.cyan("@wraps.dev/mcp")} config`
    );
    console.log(
      `  2. Review pending sends: ${pc.cyan("wraps email agent list")}`
    );
    console.log();
  }
}

/**
 * List agents for the authenticated organization.
 */
export async function agentList(options: EmailAgentListOptions): Promise<void> {
  const api = await createAgentApiClient(options.token);
  if (!api.ok) {
    if (isJsonMode()) {
      jsonError("email.agent.list", {
        code: "NOT_AUTHENTICATED",
        message: "No API token found.",
        suggestion: "Run: wraps auth login",
      });
    } else {
      clack.log.error("No API token found. Run: wraps auth login");
    }
    return;
  }

  const resp = await api.get("/v1/agents");
  if (!resp.ok) {
    const message = await parseError(resp);
    if (isJsonMode()) {
      jsonError("email.agent.list", { code: "API_ERROR", message });
    } else {
      clack.log.error(`Failed to list agents: ${message}`);
    }
    return;
  }

  const { agents } = (await resp.json()) as { agents: AgentRecord[] };

  if (isJsonMode()) {
    jsonSuccess("email.agent.list", { agents });
    return;
  }

  if (agents.length === 0) {
    clack.log.info("No agents yet. Create one: wraps email agent create");
    return;
  }

  const rows = agents.map((a) => {
    const status =
      a.status === "KILLED" ? pc.red("KILLED") : pc.green("ACTIVE");
    const caps = `${a.policy.maxPerHour}/hr · ${a.policy.maxPerDay}/day`;
    return `${status}  ${pc.cyan(a.emailAddress.padEnd(32))}  ${pc.dim(caps)}`;
  });

  clack.note(rows.join("\n"), `Agents — ${agents.length}`);
}

/**
 * Kill an agent: flips it to KILLED and syncs the kill flag to the enforcer so
 * it refuses future sends immediately.
 */
export async function agentKill(options: EmailAgentKillOptions): Promise<void> {
  const api = await createAgentApiClient(options.token);
  if (!api.ok) {
    if (isJsonMode()) {
      jsonError("email.agent.kill", {
        code: "NOT_AUTHENTICATED",
        message: "No API token found.",
        suggestion: "Run: wraps auth login",
      });
    } else {
      clack.log.error("No API token found. Run: wraps auth login");
    }
    return;
  }

  // Resolve the target agent (by name or id).
  const listResp = await api.get("/v1/agents");
  if (!listResp.ok) {
    const message = await parseError(listResp);
    if (isJsonMode()) {
      jsonError("email.agent.kill", { code: "API_ERROR", message });
    } else {
      clack.log.error(`Failed to list agents: ${message}`);
    }
    return;
  }
  const { agents } = (await listResp.json()) as { agents: AgentRecord[] };
  const active = agents.filter((a) => a.status !== "KILLED");

  let target = options.name
    ? agents.find((a) => a.name === options.name || a.id === options.name)
    : undefined;

  if (!target) {
    if (options.name) {
      if (isJsonMode()) {
        jsonError("email.agent.kill", {
          code: "NOT_FOUND",
          message: `No agent named "${options.name}".`,
        });
      } else {
        clack.log.error(`No agent named "${options.name}".`);
      }
      return;
    }
    if (isJsonMode() || options.yes) {
      jsonError("email.agent.kill", {
        code: "NAME_REQUIRED",
        message: "Agent name is required in non-interactive mode.",
      });
      return;
    }
    if (active.length === 0) {
      clack.log.info("No active agents to kill.");
      return;
    }
    const selected = await clack.select({
      message: "Which agent do you want to kill?",
      options: active.map((a) => ({ value: a.id, label: a.emailAddress })),
    });
    if (clack.isCancel(selected)) {
      clack.cancel("Operation cancelled.");
      process.exit(0);
    }
    target = agents.find((a) => a.id === selected);
  }

  if (!target) {
    return;
  }

  if (!(options.yes || isJsonMode())) {
    const confirmed = await clack.confirm({
      message: `Kill ${pc.cyan(target.emailAddress)}? It can no longer send email.`,
      initialValue: false,
    });
    if (clack.isCancel(confirmed) || !confirmed) {
      clack.cancel("Operation cancelled.");
      process.exit(0);
    }
  }

  const resp = await api.post(`/v1/agents/${target.id}/kill`);
  if (!resp.ok) {
    const message = await parseError(resp);
    if (isJsonMode()) {
      jsonError("email.agent.kill", { code: "API_ERROR", message });
    } else {
      clack.log.error(`Failed to kill agent: ${message}`);
    }
    return;
  }

  if (isJsonMode()) {
    jsonSuccess("email.agent.kill", {
      id: target.id,
      name: target.name,
      status: "KILLED",
    });
    return;
  }

  clack.log.success(`Killed ${pc.cyan(target.emailAddress)}.`);
}

// mri yields a string for a single flag occurrence, an array for a repeated
// one, and undefined when it is absent at all — normalize all three to a
// list so the merge logic below never has to branch on shape.
function toList(value: unknown): string[] {
  if (value === undefined) {
    return [];
  }
  return Array.isArray(value) ? value.map(String) : [String(value)];
}

function dedupePreserveOrder(base: string[], additions: string[]): string[] {
  const seen = new Set(base);
  const result = [...base];
  for (const item of additions) {
    if (!seen.has(item)) {
      seen.add(item);
      result.push(item);
    }
  }
  return result;
}

function sameStringArray(a: string[], b: string[]): boolean {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

/**
 * Change an agent's send caps or allowlist after creation. Merges the given
 * flags over the agent's CURRENT policy — an unspecified field is preserved,
 * never reset — then PATCHes the merged result.
 */
export async function agentPolicy(
  options: EmailAgentPolicyOptions
): Promise<void> {
  const api = await createAgentApiClient(options.token);
  if (!api.ok) {
    if (isJsonMode()) {
      jsonError("email.agent.policy", {
        code: "NOT_AUTHENTICATED",
        message: "No API token found.",
        suggestion: "Run: wraps auth login",
      });
    } else {
      clack.log.error("No API token found. Run: wraps auth login");
    }
    return;
  }

  // Resolve the target agent (by name or id) — same shape as agentKill.
  const listResp = await api.get("/v1/agents");
  if (!listResp.ok) {
    const message = await parseError(listResp);
    if (isJsonMode()) {
      jsonError("email.agent.policy", { code: "API_ERROR", message });
    } else {
      clack.log.error(`Failed to list agents: ${message}`);
    }
    return;
  }
  const { agents } = (await listResp.json()) as { agents: AgentRecord[] };

  const target = options.name
    ? agents.find((a) => a.name === options.name || a.id === options.name)
    : undefined;

  if (!target) {
    const message = options.name
      ? `No agent named "${options.name}".`
      : "Agent name is required.";
    if (isJsonMode()) {
      jsonError("email.agent.policy", { code: "NOT_FOUND", message });
    } else {
      clack.log.error(message);
    }
    return;
  }

  if (target.status === "KILLED") {
    const message = `Agent "${target.name}" is killed — its policy can no longer be changed.`;
    if (isJsonMode()) {
      jsonError("email.agent.policy", { code: "AGENT_KILLED", message });
    } else {
      clack.log.error(message);
    }
    return;
  }

  const clearAllowlist = options.clearAllowlist === true;
  const allowRecipientAdditions = toList(options.allowRecipient);
  const allowDomainAdditions = toList(options.allowDomain);

  if (
    clearAllowlist &&
    (allowRecipientAdditions.length > 0 || allowDomainAdditions.length > 0)
  ) {
    const message =
      "--clear-allowlist cannot be combined with --allow-recipient or --allow-domain.";
    if (isJsonMode()) {
      jsonError("email.agent.policy", { code: "VALIDATION", message });
    } else {
      clack.log.error(message);
    }
    return;
  }

  const current = target.policy;
  const maxPerHour =
    options.maxPerHour === undefined
      ? current.maxPerHour
      : Number(options.maxPerHour);
  const maxPerDay =
    options.maxPerDay === undefined
      ? current.maxPerDay
      : Number(options.maxPerDay);

  if (!(Number.isInteger(maxPerHour) && maxPerHour >= 0)) {
    const message = "--max-per-hour must be a whole number >= 0.";
    if (isJsonMode()) {
      jsonError("email.agent.policy", { code: "VALIDATION", message });
    } else {
      clack.log.error(message);
    }
    return;
  }
  if (!(Number.isInteger(maxPerDay) && maxPerDay >= 0)) {
    const message = "--max-per-day must be a whole number >= 0.";
    if (isJsonMode()) {
      jsonError("email.agent.policy", { code: "VALIDATION", message });
    } else {
      clack.log.error(message);
    }
    return;
  }

  const allowedRecipients = clearAllowlist
    ? []
    : dedupePreserveOrder(current.allowedRecipients, allowRecipientAdditions);
  const allowedRecipientDomains = clearAllowlist
    ? []
    : dedupePreserveOrder(
        current.allowedRecipientDomains,
        allowDomainAdditions
      );

  const nextPolicy = {
    maxPerHour,
    maxPerDay,
    allowedRecipients,
    allowedRecipientDomains,
  };

  const noChange =
    nextPolicy.maxPerHour === current.maxPerHour &&
    nextPolicy.maxPerDay === current.maxPerDay &&
    sameStringArray(nextPolicy.allowedRecipients, current.allowedRecipients) &&
    sameStringArray(
      nextPolicy.allowedRecipientDomains,
      current.allowedRecipientDomains
    );

  if (noChange) {
    if (isJsonMode()) {
      jsonSuccess("email.agent.policy", {
        agent: target,
        syncStatus: "skipped",
        noChange: true,
      });
    } else {
      clack.log.info("No changes.");
    }
    return;
  }

  const resp = await api.patch(`/v1/agents/${target.id}/policy`, nextPolicy);
  if (!resp.ok) {
    const message = await parseError(resp);
    if (isJsonMode()) {
      jsonError("email.agent.policy", { code: "API_ERROR", message });
    } else {
      clack.log.error(`Failed to update policy: ${message}`);
    }
    return;
  }

  const body = (await resp.json()) as {
    agent: AgentRecord;
    syncStatus: "synced" | "skipped" | "failed";
    warning?: string;
  };
  const syncFailed = body.syncStatus === "failed";

  if (isJsonMode()) {
    jsonSuccess("email.agent.policy", {
      agent: body.agent,
      syncStatus: body.syncStatus,
      warning: body.warning ?? null,
    });
    if (syncFailed) {
      process.exit(1);
    }
    return;
  }

  const before = `${current.maxPerHour}/hr · ${current.maxPerDay}/day`;
  const after = `${body.agent.policy.maxPerHour}/hr · ${body.agent.policy.maxPerDay}/day`;
  clack.log.success(`${before} → ${after}`);
  console.log(
    `  Allowlist: ${body.agent.policy.allowedRecipients.length} recipient(s), ${body.agent.policy.allowedRecipientDomains.length} domain(s)`
  );

  if (syncFailed) {
    if (body.warning) {
      clack.log.warn(body.warning);
    }
    process.exit(1);
  }
}
