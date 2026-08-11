import {
  createHash,
  generateKeyPairSync,
  randomBytes,
} from "node:crypto";
import { writeFileSync } from "node:fs";
import { resolve } from "node:path";

const outputPath = resolve(process.cwd(), ".env.generated");
const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const privateDer = privateKey.export({ format: "der", type: "pkcs8" });
const publicDer = publicKey.export({ format: "der", type: "spki" });
const keyId = createHash("sha256").update(publicDer).digest("base64url").slice(0, 12);

const contents = [
  "# Generated locally. Never commit this file.",
  `PHOENIX_PURCHASE_RECEIPT_SECRET_B64=${randomBytes(32).toString("base64")}`,
  `PHOENIX_LICENSE_ED25519_PRIVATE_KEY_B64=${privateDer.toString("base64")}`,
  `PHOENIX_LICENSE_KEY_ID=${keyId}`,
  `# Phoenix clients verify licenses with this public SPKI key:`,
  `# PHOENIX_LICENSE_ED25519_PUBLIC_KEY_SPKI_B64=${publicDer.toString("base64")}`,
  "",
].join("\n");

writeFileSync(outputPath, contents, { encoding: "utf8", flag: "wx", mode: 0o600 });
process.stdout.write(`Created ${outputPath} with owner-only permissions.\n`);
