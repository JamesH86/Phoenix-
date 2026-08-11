import { access, readFile } from "node:fs/promises";
import { resolve } from "node:path";

const root = resolve(process.cwd(), "public");
const required = [
  "index.html",
  "styles.css",
  "app.js",
  "assets/phoenix-guardian-logo.png",
  "assets/phoenix-icon-192.png",
];

await Promise.all(required.map((file) => access(resolve(root, file))));
const html = await readFile(resolve(root, "index.html"), "utf8");
if (!html.includes('src="/app.js"') || !html.includes('href="/styles.css"')) {
  throw new Error("Storefront asset links are incomplete");
}
process.stdout.write("Phoenix storefront assets verified.\n");
