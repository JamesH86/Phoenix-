# Square billing for 30-day Phoenix access

Phoenix uses Square-hosted checkout for one-time purchases of paid tier control keys. Each verified purchase issues one key with a fixed 30-day term. Automatic renewal and recurring Square subscriptions are not implemented; a customer must purchase another 30-day term after the key expires.

The Demo tier remains free and does not use Square. Paid offers are fixed by the Phoenix server:

| Tier | Charge | Access term |
| --- | ---: | --- |
| Solo Researcher | $50 USD | 30 days |
| Base Cybersecurity Personnel | $150 USD | 30 days |
| Enterprise | $1,000 USD | 30 days |
| Government | $1,500 USD | 30 days |

The browser never supplies the amount, currency, Square location, or resulting tier. Phoenix selects those values from its server-side offer catalog.

## Payment and key-delivery boundary

1. Phoenix creates a unique pending purchase and a Square-hosted payment link.
2. The buyer enters payment details only on Square's checkout page.
3. Square sends a signed server-to-server payment event to Phoenix's public webhook.
4. Phoenix verifies the signature and requires a completed payment whose order, location, amount, and currency exactly match the pending purchase.
5. The checkout redirect or browser callback can only resume status checks. It cannot mark a payment complete or issue a key.
6. A one-time claim secret authorizes key delivery. Phoenix stores only its SHA-256 digest in the purchase ledger.
7. Phoenix returns the plaintext control key once, stores only the key digest, and rejects a second claim.

Square handles card and wallet data. Phoenix must never collect or store card numbers, security codes, bank account numbers, debit-card numbers, or online-banking credentials. Configure payout bank accounts and debit-card transfer options only in the Square Dashboard.

## Private configuration

Keep Square configuration outside the Git repository. On macOS or Linux, use an owner-only directory and file, for example:

```text
~/PhoenixGuardian/square.json
```

The directory must be mode `0700` and the JSON file mode `0600`. Phoenix rejects a symbolic-link configuration file and, on POSIX systems, rejects a file readable or writable by group or other users. On Windows, keep the file under the account owner's private profile and restrict it with an owner-only ACL.

Set the path without placing secrets on the command line:

```bash
export PHOENIX_SQUARE_CONFIG_FILE="$HOME/PhoenixGuardian/square.json"
chmod 700 "$HOME/PhoenixGuardian"
chmod 600 "$PHOENIX_SQUARE_CONFIG_FILE"
```

The file has these exact fields. The values below are placeholders, not working credentials:

```json
{
  "environment": "sandbox",
  "access_token": "REPLACE_WITH_SQUARE_ACCESS_TOKEN",
  "application_id": "REPLACE_WITH_SQUARE_APPLICATION_ID",
  "location_id": "REPLACE_WITH_SQUARE_LOCATION_ID",
  "webhook_signature_key": "REPLACE_WITH_WEBHOOK_SIGNATURE_KEY",
  "notification_url": "https://billing.example.com/api/billing/square/webhook"
}
```

Environment variables can be used instead, and override the corresponding JSON values:

| Variable | Required value |
| --- | --- |
| `PHOENIX_SQUARE_CONFIG_FILE` | Absolute path to the private JSON file |
| `PHOENIX_SQUARE_ENVIRONMENT` | Exactly `sandbox` or `production` |
| `PHOENIX_SQUARE_ACCESS_TOKEN` | Matching Sandbox or Production access token |
| `PHOENIX_SQUARE_APPLICATION_ID` | Matching Square application ID |
| `PHOENIX_SQUARE_LOCATION_ID` | Square location that receives the purchase |
| `PHOENIX_SQUARE_WEBHOOK_SIGNATURE_KEY` | Signature key for the configured webhook subscription |
| `PHOENIX_SQUARE_NOTIFICATION_URL` | Exact public HTTPS webhook URL |

The signature key and notification URL must be configured together. Do not commit a filled configuration file, paste credentials into support messages, place them in frontend JavaScript, or expose them in API status responses. Rotate any value that might have been disclosed.

Keep the private purchase ledger outside the repository as well. Its directory should be `0700` and its SQLite file `0600`. The ledger contains purchase IDs, fixed offer details, Square order/payment references, state, timestamps, and hashes; it must not contain payment-card or bank-account data.

## Square Sandbox

Use Sandbox first. Sandbox uses test credentials and Square's Sandbox API, does not transfer real money, and must be visibly labeled as test mode in Phoenix.

- Use a separate Phoenix configuration directory and purchase database for Sandbox.
- Use only Square Sandbox payment details.
- Do not deliver Sandbox-issued keys as paid Production licenses.
- Test successful, pending, failed, duplicate, mismatched-amount, wrong-location, invalid-signature, and replayed events.
- Confirm that a checkout redirect without a verified webhook cannot issue a key.

Do not mix Sandbox application IDs, tokens, locations, webhook keys, or databases with Production.

## Webhook configuration

Register this exact endpoint in the Square Developer Console:

```text
POST https://YOUR_PUBLIC_BILLING_HOST/api/billing/square/webhook
```

Subscribe to:

- `payment.created`
- `payment.updated`

Phoenix accepts a signed event for idempotent processing, but makes a purchase claimable only when the included payment status is `COMPLETED` and every stored purchase field matches.

For every request, Phoenix must:

- read the unmodified raw request bytes;
- read the `x-square-hmacsha256-signature` header;
- calculate Square's HMAC-SHA-256 signature using the webhook signature key, the exact configured notification URL, and the raw body;
- compare signatures in constant time;
- deduplicate by Square event ID and reject an event ID replayed with different content;
- never log the signature key, access token, claim secret, or product key.

The notification URL used during verification must match the URL registered with Square exactly, including scheme, host, path, and any trailing slash. A reverse proxy must preserve the raw request body.

## Production requirements

Production checkout is not ready merely because the Phoenix button renders. Before switching `environment` to `production`, the owner must complete all of the following:

- Complete Square's required seller identity and business verification. Phoenix cannot bypass Square verification requirements.
- Link and verify the destination bank account in the Square Dashboard. A linked debit card can support eligible transfer options, but it does not replace Square's seller verification requirements.
- Create Production application credentials and a Production location in the Square Developer Console.
- Deploy the billing webhook at a stable, seller-controlled public HTTPS URL with a valid TLS certificate.
- Register that exact URL and the two payment events in the Production Square application.
- Store Production credentials in a deployment secret manager or an owner-only `0600` file outside the repository.
- Complete an end-to-end low-value Production verification and confirm receipt in Square before enabling buyer-facing checkout.
- Publish clear purchase-term, refund, privacy, acceptable-use, and support information and obtain appropriate tax/legal guidance for the jurisdictions served.

`127.0.0.1`, `localhost`, a private Tailscale address, and a customer's installed PWA are not public webhook destinations. Keep Phoenix's defensive control API private; expose only the narrowly scoped billing/webhook service required for checkout and license delivery.

## Operational behavior

- A paid key expires 30 days after issuance under the current Phoenix subscription store.
- A completed payment creates at most one claimable purchase, and a purchase can be claimed only once.
- Non-completed payment events never issue keys.
- Duplicate valid events are acknowledged idempotently and do not issue duplicate keys.
- Manual key entry remains available for activating a legitimately purchased key on another device.
- Refund and dispute automation is not yet implemented. Until it is, the owner must review those events in Square and revoke affected keys with `python3 tools/phoenix_subscription.py revoke KEY_ID` when appropriate.
- Automatic renewal is not implemented. Do not describe the current checkout as an auto-renewing subscription.

Square fees, payout timing, account eligibility, transfer availability, and verification decisions are controlled by Square, not Phoenix.

## Official Square references

- [Create a Square-hosted payment link](https://developer.squareup.com/docs/checkout-api)
- [Payments API webhook events](https://developer.squareup.com/docs/payments-api/webhooks)
- [Verify a Square webhook signature](https://developer.squareup.com/docs/webhooks/step3validate)
- [Square seller identity and business verification](https://squareup.com/help/us/en/article/8663-verify-your-identity-and-square-business-information)
- [Link Square transfer methods](https://squareup.com/help/us/en/article/3896-link-and-edit-your-bank-account)
