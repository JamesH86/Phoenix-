import { createHash } from "node:crypto";
import {
  chmod,
  lstat,
  readFile,
  rename,
  writeFile,
} from "node:fs/promises";
import { pathToFileURL } from "node:url";

const EVENT_TYPES = Object.freeze(["payment.created", "payment.updated"]);
const DEFAULT_API_VERSION = "2026-07-15";
const SANDBOX_BASE_URL = "https://connect.squareupsandbox.com/v2";

function safeWebhookUrl(value) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error("notification URL must be a valid URL");
  }
  if (
    parsed.protocol !== "https:" ||
    parsed.username ||
    parsed.password ||
    parsed.search ||
    parsed.hash ||
    parsed.pathname !== "/api/square-webhook"
  ) {
    throw new Error("notification URL must be the exact public HTTPS /api/square-webhook URL");
  }
  const host = parsed.hostname.toLowerCase();
  if (
    host === "localhost" ||
    host === "127.0.0.1" ||
    host === "::1" ||
    host.endsWith(".local")
  ) {
    throw new Error("notification URL must use a public host");
  }
  return parsed.toString();
}

async function loadCredentials(credentialsFile) {
  const fileStat = await lstat(credentialsFile);
  if (!fileStat.isFile() || fileStat.isSymbolicLink()) {
    throw new Error("credential path must be a regular file");
  }
  if ((fileStat.mode & 0o077) !== 0) {
    throw new Error("credential file must not be accessible by group or other users");
  }
  let credentials;
  try {
    credentials = JSON.parse(await readFile(credentialsFile, "utf8"));
  } catch {
    throw new Error("credential file must contain valid JSON");
  }
  if (credentials.environment !== "sandbox") {
    throw new Error("this helper only accepts Square Sandbox credentials");
  }
  for (const key of ["access_token", "application_id", "location_id"]) {
    if (typeof credentials[key] !== "string" || !credentials[key]) {
      throw new Error(`credential file is missing ${key}`);
    }
  }
  const apiVersion = credentials.api_version || DEFAULT_API_VERSION;
  if (!/^\d{4}-\d{2}-\d{2}$/u.test(apiVersion)) {
    throw new Error("credential file has an invalid api_version");
  }
  return { credentials, apiVersion };
}

async function squareRequest(fetchImpl, credentials, apiVersion, method, path, body) {
  let response;
  try {
    response = await fetchImpl(`${SANDBOX_BASE_URL}${path}`, {
      method,
      headers: {
        Authorization: `Bearer ${credentials.access_token}`,
        "Content-Type": "application/json",
        "Square-Version": apiVersion,
      },
      body: body === undefined ? undefined : JSON.stringify(body),
      redirect: "error",
      signal: typeof AbortSignal.timeout === "function" ? AbortSignal.timeout(8_000) : undefined,
    });
  } catch {
    throw new Error("Square webhook API could not be reached");
  }
  let payload = {};
  try {
    payload = JSON.parse(await response.text());
  } catch {
    throw new Error("Square webhook API returned an invalid response");
  }
  if (!response.ok) {
    const code = Array.isArray(payload.errors) && payload.errors[0]?.code
      ? String(payload.errors[0].code)
      : "UPSTREAM_ERROR";
    throw new Error(`Square webhook API rejected the request (${code})`);
  }
  return payload;
}

async function findMatchingSubscription(fetchImpl, credentials, apiVersion, notificationUrl) {
  let cursor = "";
  for (let page = 0; page < 10; page += 1) {
    const suffix = cursor ? `?include_disabled=true&limit=100&cursor=${encodeURIComponent(cursor)}` : "?include_disabled=true&limit=100";
    const payload = await squareRequest(
      fetchImpl,
      credentials,
      apiVersion,
      "GET",
      `/webhooks/subscriptions${suffix}`,
    );
    const match = (Array.isArray(payload.subscriptions) ? payload.subscriptions : []).find(
      (subscription) =>
        subscription?.notification_url === notificationUrl &&
        subscription?.enabled === true &&
        EVENT_TYPES.every((eventType) => subscription.event_types?.includes(eventType)),
    );
    if (match) return match;
    cursor = typeof payload.cursor === "string" ? payload.cursor : "";
    if (!cursor) return null;
  }
  throw new Error("Square webhook subscription list exceeded the safety page limit");
}

async function storeSubscription(credentialsFile, credentials, notificationUrl, subscription) {
  if (
    typeof subscription?.id !== "string" ||
    !subscription.id ||
    typeof subscription?.signature_key !== "string" ||
    !subscription.signature_key
  ) {
    throw new Error("Square did not return a complete webhook subscription");
  }
  const updated = {
    ...credentials,
    notification_url: notificationUrl,
    webhook_notification_url: notificationUrl,
    webhook_signature_key: subscription.signature_key,
    webhook_subscription_id: subscription.id,
    webhook_event_types: [...EVENT_TYPES],
  };
  const temporaryFile = `${credentialsFile}.${process.pid}.tmp`;
  try {
    await writeFile(temporaryFile, `${JSON.stringify(updated, null, 2)}\n`, {
      encoding: "utf8",
      mode: 0o600,
      flag: "wx",
    });
    await chmod(temporaryFile, 0o600);
    await rename(temporaryFile, credentialsFile);
    await chmod(credentialsFile, 0o600);
  } catch (error) {
    throw new Error("webhook was created but its private configuration could not be stored", {
      cause: error,
    });
  }
}

function idempotencyKey(applicationId, notificationUrl) {
  return createHash("sha256")
    .update(applicationId, "utf8")
    .update("\0", "utf8")
    .update(notificationUrl, "utf8")
    .update("\0payment.created\0payment.updated", "utf8")
    .digest("hex")
    .slice(0, 45);
}

export async function configureSandboxWebhook({
  credentialsFile,
  notificationUrl,
  confirmedUrl = "",
  apply = false,
  fetchImpl = globalThis.fetch,
}) {
  if (typeof credentialsFile !== "string" || !credentialsFile) {
    throw new Error("--credentials-file is required");
  }
  const exactUrl = safeWebhookUrl(notificationUrl);
  const { credentials, apiVersion } = await loadCredentials(credentialsFile);
  if (!apply) {
    return { applied: false, notificationUrl: exactUrl, eventTypes: [...EVENT_TYPES] };
  }
  if (confirmedUrl !== exactUrl) {
    throw new Error("--confirm-url must exactly repeat the stable notification URL");
  }
  if (typeof fetchImpl !== "function") throw new Error("fetch is unavailable");

  let subscription = await findMatchingSubscription(
    fetchImpl,
    credentials,
    apiVersion,
    exactUrl,
  );
  let created = false;
  if (subscription) {
    const retrieved = await squareRequest(
      fetchImpl,
      credentials,
      apiVersion,
      "GET",
      `/webhooks/subscriptions/${encodeURIComponent(subscription.id)}`,
    );
    subscription = retrieved.subscription;
  } else {
    const createdResponse = await squareRequest(
      fetchImpl,
      credentials,
      apiVersion,
      "POST",
      "/webhooks/subscriptions",
      {
        idempotency_key: idempotencyKey(credentials.application_id, exactUrl),
        subscription: {
          name: "Phoenix Guardian payments",
          event_types: [...EVENT_TYPES],
          notification_url: exactUrl,
          api_version: apiVersion,
        },
      },
    );
    subscription = createdResponse.subscription;
    created = true;
  }

  await storeSubscription(credentialsFile, credentials, exactUrl, subscription);
  return { applied: true, created, notificationUrl: exactUrl, eventTypes: [...EVENT_TYPES] };
}

function parseArgs(argv) {
  const args = { apply: false, credentialsFile: "", notificationUrl: "", confirmedUrl: "" };
  for (let index = 0; index < argv.length; index += 1) {
    const current = argv[index];
    if (current === "--apply") args.apply = true;
    else if (current === "--credentials-file") args.credentialsFile = argv[++index] || "";
    else if (current === "--notification-url") args.notificationUrl = argv[++index] || "";
    else if (current === "--confirm-url") args.confirmedUrl = argv[++index] || "";
    else throw new Error(`unknown argument: ${current}`);
  }
  return args;
}

async function main() {
  const result = await configureSandboxWebhook(parseArgs(process.argv.slice(2)));
  if (!result.applied) {
    process.stdout.write(
      `Validated locally. No Square change made. Re-run with --apply and --confirm-url ${result.notificationUrl}\n`,
    );
    return;
  }
  process.stdout.write(
    `${result.created ? "Created" : "Reused"} the Square Sandbox webhook and stored its private settings without printing them.\n`,
  );
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`Webhook setup stopped: ${error.message}\n`);
    process.exitCode = 1;
  });
}
