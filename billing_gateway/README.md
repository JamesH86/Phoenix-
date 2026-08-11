# Phoenix Square Billing Gateway

This directory is a standalone Vercel Node service for Phoenix Guardian tier sales. Square hosts the checkout UI; the gateway keeps Square credentials and license-signing material server-side.

The design is stateless and stores no card, bank, buyer, order, or payment records. A signed purchase receipt carries the minimum order reference back to Phoenix. Every status check and license claim retrieves the Square order and then its payment and verifies the order, location, amount, currency, application, payment status, and refund state against fixed server-side tier definitions.

## Paid tiers

| Tier | Charge | Access period |
| --- | ---: | ---: |
| Solo Researcher | $50 USD | 30 days |
| Cybersecurity Personnel | $150 USD | 30 days |
| Enterprise | $1,000 USD | 30 days |
| Government | $1,500 USD | 30 days |

The free demo does not use this payment gateway.

## Security properties

- Square access tokens, webhook keys, receipt secrets, and Ed25519 private keys are read only from server-side environment variables.
- Checkout uses one fixed-price line item, disables tipping, and includes a unique idempotency key and signed purchase reference.
- Purchase receipts are HMAC-SHA256 authenticated, bound to the Square environment, application, location, tier, amount, and currency, and expire after 45 days.
- A claim succeeds only after `RetrieveOrder` followed by `GetPayment` confirms one exact `COMPLETED`, unrefunded payment from the configured Square application.
- Licenses use Ed25519 signatures and expire exactly 30 days after Square's immutable payment creation timestamp for the completed hosted-checkout payment. Repeating a claim returns the same deterministic license.
- The webhook validates `x-square-hmacsha256-signature` against the exact registered notification URL plus the untouched raw request body with a constant-time comparison.
- Valid webhook deliveries have no fulfillment side effect and always receive an idempotent `200`. Status and claim remain authoritative, so duplicate or out-of-order webhook deliveries cannot mint access.
- All responses are `no-store`; API errors never include Square bodies, credentials, order IDs, or payment IDs.

## API

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/api/health` | `GET` | Process liveness; does not reveal configuration |
| `/api/status` | `GET` | Safe readiness, public license key, and fixed tier catalog |
| `/api/checkout` | `POST` | Create a Square-hosted payment link |
| `/api/purchase-status` | `POST` | Re-verify a signed purchase receipt against Square |
| `/api/claim` | `POST` | Issue the Ed25519 30-day license after verification |
| `/api/square-webhook` | `POST` | Validate and safely acknowledge Square events |

Example checkout request:

```json
{
  "tier": "base",
  "purchase_id": "client-generated-uuid",
  "return_url": "https://your-app.example/plans"
}
```

The client should generate a UUID once and reuse it if the checkout request is retried. Keep the returned `purchase_receipt` in protected local/session storage and send it as `purchase_receipt` to the status and claim endpoints. Never put the receipt or license token in a URL.

## Local setup

Requires Node.js 20 or newer.

1. Generate owner-only signing values:

   ```bash
   npm run generate:keys
   ```

   This writes `.env.generated` with mode `0600`; it does not print the secrets. Copy those values into `.env.local` or directly into Vercel's encrypted environment-variable settings.

2. Copy `.env.example` to `.env.local` and fill in the matching Square Sandbox application values. Do not commit `.env.local`.

3. Run checks:

   ```bash
   npm test
   npm run check
   ```

4. Run locally with Vercel CLI if installed:

   ```bash
   vercel dev
   ```

## Deploy and connect the live webhook

1. Create a dedicated Vercel project with this `billing_gateway` directory as its project root.
2. Add every variable from `.env.example` as a server-side Vercel environment variable. Do not use a browser-exposed prefix.
3. Deploy, select a stable custom billing domain, and verify `/api/health`.
4. Set `SQUARE_WEBHOOK_NOTIFICATION_URL` to the exact public URL, for example `https://billing.example.com/api/square-webhook`, and redeploy.
5. In the same Square application's **Webhooks** section and the matching Sandbox or Production environment, create a subscription for `payment.created` and `payment.updated` using that exact URL.
6. Copy the subscription's signature key into `SQUARE_WEBHOOK_SIGNATURE_KEY`, redeploy, then use Square's webhook test action.
7. Confirm `/api/status` reports `ready: true` and `components.live_webhook: true` before wiring Phoenix's Buy buttons to `/api/checkout`.

Square signs the exact notification URL, so changing the domain, path, slash, or query string requires updating both Square and Vercel together.

After the stable public HTTPS domain is known, the Sandbox subscription can be prepared and created without exposing any credential in terminal output. First run the local-only validation (it makes no Square request):

```bash
npm run configure:sandbox-webhook -- \
  --credentials-file /absolute/private/path/square_sandbox_credentials.json \
  --notification-url https://your-stable-domain.example/api/square-webhook
```

Only after confirming that exact deployed URL, create or safely reuse the subscription with one guarded command:

```bash
npm run configure:sandbox-webhook -- \
  --credentials-file /absolute/private/path/square_sandbox_credentials.json \
  --notification-url https://your-stable-domain.example/api/square-webhook \
  --apply \
  --confirm-url https://your-stable-domain.example/api/square-webhook
```

The helper subscribes to `payment.created` and `payment.updated`, retrieves Square's signature key, and atomically saves the URL, subscription ID, event types, and signature key back into the owner-only JSON file. It prints none of those private values. The stored signature key still needs to be added to the deployed gateway as `SQUARE_WEBHOOK_SIGNATURE_KEY`, followed by a redeploy and Square webhook test.

## Production cutover

Keep `SQUARE_ENVIRONMENT=sandbox` until a complete Sandbox checkout, webhook, status, and claim test passes. Production mode is intentionally fail-closed: the service remains unavailable unless production Square credentials, an HTTPS webhook URL and signature key, the HMAC receipt secret, and a valid Ed25519 private key are all present.

Use a separate Production environment-variable scope, rotate any credential that was exposed, complete Square seller identity and bank verification in Square itself, and run one controlled real-money purchase/refund test before general launch. The gateway does not bypass Square onboarding and does not handle bank credentials.

Rate limits and abuse controls belong at the Vercel Firewall layer. Restrict `PHOENIX_ALLOWED_ORIGINS` to exact Phoenix origins; CORS is not authentication, so purchase verification never trusts browser state.
