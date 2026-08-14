#!/usr/bin/env node

import { generateKeyPairSync, randomBytes } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const outputArgument = process.argv[2];
if (!outputArgument) {
  console.error(
    "usage: node scripts/generate-identity-issuer-key.mjs OUTPUT_DIRECTORY",
  );
  process.exit(2);
}

const outputDirectory = resolve(outputArgument);
const keyId =
  process.env.OPENAB_IDENTITY_KEY_ID ??
  `openab-poc-${new Date().toISOString().slice(0, 10)}-${randomBytes(4).toString("hex")}`;

try {
  mkdirSync(outputDirectory, { mode: 0o700 });
} catch (error) {
  console.error(
    `refusing to use existing or unavailable output directory ${outputDirectory}: ${error.message}`,
  );
  process.exit(1);
}

const { privateKey, publicKey } = generateKeyPairSync("rsa", {
  modulusLength: 3072,
  publicExponent: 0x10001,
});
const privatePem = privateKey.export({ type: "pkcs8", format: "pem" });
const publicJwk = publicKey.export({ format: "jwk" });
const jwks = {
  keys: [
    {
      ...publicJwk,
      use: "sig",
      alg: "RS256",
      kid: keyId,
    },
  ],
};

writeFileSync(`${outputDirectory}/private.pem`, privatePem, {
  mode: 0o600,
  flag: "wx",
});
writeFileSync(`${outputDirectory}/jwks.json`, `${JSON.stringify(jwks, null, 2)}\n`, {
  mode: 0o644,
  flag: "wx",
});

console.log(`created private key: ${outputDirectory}/private.pem`);
console.log(`created public JWKS: ${outputDirectory}/jwks.json`);
console.log(`key id: ${keyId}`);
