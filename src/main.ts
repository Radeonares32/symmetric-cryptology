import { generateKeyPairSync, publicEncrypt, privateDecrypt } from "crypto";
import { readFileSync, writeFileSync } from "fs";
import { scheduleJob } from "node-schedule";

export class EncryptionManager {
  private privateKeyPath: string;
  private publicKeyPath: string;
  private privateKey: string | null;
  private publicKey: string | null;

  constructor(privateKeyPath: string, publicKeyPath: string) {
    this.privateKeyPath = privateKeyPath;
    this.publicKeyPath = publicKeyPath;
    this.privateKey = null;
    this.publicKey = null;
  }

  private generateKeys(): { privateKey: string; publicKey: string } {
    const { privateKey, publicKey } = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      publicKeyEncoding: {
        type: "pkcs1",
        format: "pem",
      },
      privateKeyEncoding: {
        type: "pkcs1",
        format: "pem",
      },
    });
    return { privateKey, publicKey };
  }

  public checkAndGenerateKeys(): void {
    try {
      this.privateKey = readFileSync(this.privateKeyPath, "utf-8");
      this.publicKey = readFileSync(this.publicKeyPath, "utf-8");
    } catch (error:any) {
      if (error.code === "ENOENT") {
        console.log("Keys not found, new ones are being generated");
      }
      const { privateKey, publicKey } = this.generateKeys();
      writeFileSync(this.privateKeyPath, privateKey);
      writeFileSync(this.publicKeyPath, publicKey);
      this.privateKey = privateKey;
      this.publicKey = publicKey;
    }
  }

  public getPrivateKey(): string {
    if (!this.privateKey) {
      throw new Error("Private key not available");
    }
    return this.privateKey;
  }

  public getPublicKey(): string {
    if (!this.publicKey) {
      throw new Error("Public key not available");
    }
    return this.publicKey;
  }

  public encrypt(data: any): string {
    return publicEncrypt(
      this.getPublicKey(),
      Buffer.from(JSON.stringify(data))
    ).toString("base64");
  }

  public decrypt(encryptedData: string): string {
    return privateDecrypt(
      this.getPrivateKey(),
      Buffer.from(encryptedData, "base64")
    ).toString();
  }

  public scheduleKeyRegeneration(interval: string): void {
    const job = scheduleJob(interval, () => {
      console.log("Keys not found, new ones are being generated");
      const {
        privateKey: newPrivateKey,
        publicKey: newPublicKey,
      } = this.generateKeys();
      writeFileSync(this.privateKeyPath, newPrivateKey, { flag: "w" });
      writeFileSync(this.publicKeyPath, newPublicKey, { flag: "w" });
      this.privateKey = newPrivateKey;
      this.publicKey = newPublicKey;
    });
  }
}

/* const encryptionManager = new EncryptionManager(
  "./private-key.pem",
  "./public-key.pem"
);
encryptionManager.checkAndGenerateKeys();
encryptionManager.scheduleKeyRegeneration("* * * * * *");
 */