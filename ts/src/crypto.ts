import {
  createCipheriv,
  createDecipheriv,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  scryptSync,
  sign as cryptoSign,
  verify as cryptoVerify,
} from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { blake3 } from "@noble/hashes/blake3.js";

// ASN.1 DER prefixes for raw 32-byte Ed25519 keys
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

export function blake3Hex(input: Uint8Array | string): string {
  const bytes = typeof input === "string" ? Buffer.from(input, "utf8") : input;
  return Buffer.from(blake3(bytes)).toString("hex");
}

export function isValidHex(value: string, expectedBytes?: number): boolean {
  if (!/^[0-9a-fA-F]+$/.test(value) || value.length % 2 !== 0) {
    return false;
  }
  if (expectedBytes !== undefined && value.length !== expectedBytes * 2) {
    return false;
  }
  return true;
}

export interface GeneratedKeypair {
  publicKeyHex: string;
  privateSeedHex: string;
}

export function generateEd25519Keypair(): GeneratedKeypair {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const spki = publicKey.export({ format: "der", type: "spki" });
  const pkcs8 = privateKey.export({ format: "der", type: "pkcs8" });

  const rawPub = spki.subarray(ED25519_SPKI_PREFIX.length);
  const rawSeed = pkcs8.subarray(ED25519_PKCS8_PREFIX.length);

  if (rawPub.length !== 32 || rawSeed.length !== 32) {
    throw new Error("unexpected Ed25519 key length");
  }

  return {
    publicKeyHex: rawPub.toString("hex"),
    privateSeedHex: rawSeed.toString("hex"),
  };
}

export function publicKeyFromSeedHex(privateSeedHex: string): string {
  if (!isValidHex(privateSeedHex, 32)) {
    throw new Error("ed25519 seed must be 32 bytes hex");
  }
  const pkcs8 = Buffer.concat([ED25519_PKCS8_PREFIX, Buffer.from(privateSeedHex, "hex")]);
  const privKey = createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
  const pubKey = createPublicKey(privKey);
  const spki = pubKey.export({ format: "der", type: "spki" });
  return spki.subarray(ED25519_SPKI_PREFIX.length).toString("hex");
}

export function signEd25519(privateSeedHex: string, payload: Uint8Array): string {
  if (!isValidHex(privateSeedHex, 32)) {
    throw new Error("ed25519 signing seed must be 32 bytes hex");
  }
  const pkcs8 = Buffer.concat([ED25519_PKCS8_PREFIX, Buffer.from(privateSeedHex, "hex")]);
  const privKey = createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
  const sig = cryptoSign(null, Buffer.from(payload), privKey);
  return sig.toString("hex");
}

export function verifyEd25519(
  publicKeyHex: string,
  payload: Uint8Array,
  signatureHex: string,
): boolean {
  if (!isValidHex(publicKeyHex, 32) || !isValidHex(signatureHex, 64)) {
    return false;
  }
  try {
    const spki = Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(publicKeyHex, "hex")]);
    const pubKey = createPublicKey({ key: spki, format: "der", type: "spki" });
    return cryptoVerify(null, Buffer.from(payload), pubKey, Buffer.from(signatureHex, "hex"));
  } catch {
    return false;
  }
}

export function deriveWalletId(publicKeyHex: string): string {
  if (!isValidHex(publicKeyHex, 32)) {
    throw new Error("invalid Ed25519 public key hex");
  }
  const digest = blake3Hex(Buffer.concat([Buffer.from("v-kernelx/wallet-id-v1:"), Buffer.from(publicKeyHex, "hex")]));
  return `wlt_${digest.slice(0, 24)}`;
}

interface EncryptedKeyFile {
  version: number;
  walletId: string;
  publicKeyHex: string;
  kdf: "scrypt";
  cipher: "aes-256-gcm";
  saltHex: string;
  ivHex: string;
  tagHex: string;
  ciphertextHex: string;
  createdAtMs: number;
}

export class EncryptedKeystore {
  private readonly dir: string;
  private readonly passphrase: string;

  constructor(keystoreDir: string, passphrase: string) {
    if (!passphrase || passphrase.length < 8) {
      throw new Error("keystore passphrase must be at least 8 characters");
    }
    this.dir = keystoreDir;
    this.passphrase = passphrase;
    fs.mkdirSync(this.dir, { recursive: true, mode: 0o700 });
  }

  private keyPath(walletId: string): string {
    const safe = walletId.replace(/[^a-zA-Z0-9_-]/g, "_");
    return path.join(this.dir, `${safe}.key.json`);
  }

  storeKey(walletId: string, keypair: GeneratedKeypair): void {
    const salt = randomBytes(16);
    const iv = randomBytes(12);
    const derived = scryptSync(this.passphrase, salt, 32);
    const cipher = createCipheriv("aes-256-gcm", derived, iv);
    const ciphertext = Buffer.concat([
      cipher.update(Buffer.from(keypair.privateSeedHex, "hex")),
      cipher.final(),
    ]);
    const tag = cipher.getAuthTag();

    const record: EncryptedKeyFile = {
      version: 1,
      walletId,
      publicKeyHex: keypair.publicKeyHex,
      kdf: "scrypt",
      cipher: "aes-256-gcm",
      saltHex: salt.toString("hex"),
      ivHex: iv.toString("hex"),
      tagHex: tag.toString("hex"),
      ciphertextHex: ciphertext.toString("hex"),
      createdAtMs: Date.now(),
    };

    const filePath = this.keyPath(walletId);
    const tmpPath = `${filePath}.tmp`;
    fs.writeFileSync(tmpPath, JSON.stringify(record, null, 2), { mode: 0o600 });
    fs.renameSync(tmpPath, filePath);
  }

  hasKey(walletId: string): boolean {
    return fs.existsSync(this.keyPath(walletId));
  }

  signWithWallet(walletId: string, payload: Uint8Array): string {
    const filePath = this.keyPath(walletId);
    if (!fs.existsSync(filePath)) {
      throw new Error(`private key not found in keystore for wallet ${walletId}`);
    }
    const record = JSON.parse(fs.readFileSync(filePath, "utf8")) as EncryptedKeyFile;
    const derived = scryptSync(this.passphrase, Buffer.from(record.saltHex, "hex"), 32);
    const decipher = createDecipheriv(
      "aes-256-gcm",
      derived,
      Buffer.from(record.ivHex, "hex"),
    );
    decipher.setAuthTag(Buffer.from(record.tagHex, "hex"));
    const seed = Buffer.concat([
      decipher.update(Buffer.from(record.ciphertextHex, "hex")),
      decipher.final(),
    ]);
    try {
      return signEd25519(seed.toString("hex"), payload);
    } finally {
      seed.fill(0);
      derived.fill(0);
    }
  }
}

export function resolveOrCreateLocalSecret(filePath: string, envVarName: string): string {
  const fromEnv = process.env[envVarName];
  if (fromEnv && fromEnv.trim().length >= 8) {
    return fromEnv.trim();
  }
  fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
  if (fs.existsSync(filePath)) {
    return fs.readFileSync(filePath, "utf8").trim();
  }
  const secret = randomBytes(32).toString("hex");
  const tmpPath = `${filePath}.tmp`;
  fs.writeFileSync(tmpPath, secret, { mode: 0o600 });
  fs.renameSync(tmpPath, filePath);
  return secret;
}
