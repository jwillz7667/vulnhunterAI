import { randomBytes, createHash, createCipheriv, createDecipheriv } from "crypto";

export function generateId(): string {
  return randomBytes(16).toString("hex");
}

export function generateUUID(): string {
  const bytes = randomBytes(16);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20, 32),
  ].join("-");
}

export function hashString(input: string, algorithm = "sha256"): string {
  return createHash(algorithm).update(input).digest("hex");
}

export function encryptSecret(plaintext: string, key: string): string {
  const keyHash = createHash("sha256").update(key).digest();
  const iv = randomBytes(16);
  const cipher = createCipheriv("aes-256-cbc", keyHash, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  return iv.toString("hex") + ":" + encrypted.toString("hex");
}

export function decryptSecret(ciphertext: string, key: string): string {
  const keyHash = createHash("sha256").update(key).digest();
  const [ivHex, encHex] = ciphertext.split(":");
  const iv = Buffer.from(ivHex, "hex");
  const encrypted = Buffer.from(encHex, "hex");
  const decipher = createDecipheriv("aes-256-cbc", keyHash, iv);
  return decipher.update(encrypted) + decipher.final("utf8");
}
