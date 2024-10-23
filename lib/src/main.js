"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.EncryptionManager = void 0;
const crypto_1 = require("crypto");
const fs_1 = require("fs");
const node_schedule_1 = require("node-schedule");
class EncryptionManager {
    constructor(privateKeyPath, publicKeyPath) {
        Object.defineProperty(this, "privateKeyPath", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        Object.defineProperty(this, "publicKeyPath", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        Object.defineProperty(this, "privateKey", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        Object.defineProperty(this, "publicKey", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        this.privateKeyPath = privateKeyPath;
        this.publicKeyPath = publicKeyPath;
        this.privateKey = null;
        this.publicKey = null;
    }
    generateKeys() {
        const { privateKey, publicKey } = (0, crypto_1.generateKeyPairSync)("rsa", {
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
    checkAndGenerateKeys() {
        try {
            this.privateKey = (0, fs_1.readFileSync)(this.privateKeyPath, "utf-8");
            this.publicKey = (0, fs_1.readFileSync)(this.publicKeyPath, "utf-8");
        }
        catch (error) {
            if (error.code === "ENOENT") {
                console.log("Keys not found, new ones are being generated.");
            }
            const { privateKey, publicKey } = this.generateKeys();
            (0, fs_1.writeFileSync)(this.privateKeyPath, privateKey);
            (0, fs_1.writeFileSync)(this.publicKeyPath, publicKey);
            this.privateKey = privateKey;
            this.publicKey = publicKey;
        }
    }
    getPrivateKey() {
        if (!this.privateKey) {
            throw new Error("Private key not available");
        }
        return this.privateKey;
    }
    getPublicKey() {
        if (!this.publicKey) {
            throw new Error("Public key not available");
        }
        return this.publicKey;
    }
    encrypt(data) {
        return (0, crypto_1.publicEncrypt)(this.getPublicKey(), Buffer.from(JSON.stringify(data))).toString("base64");
    }
    decrypt(encryptedData) {
        return (0, crypto_1.privateDecrypt)(this.getPrivateKey(), Buffer.from(encryptedData, "base64")).toString();
    }
    scheduleKeyRegeneration(interval) {
        const job = (0, node_schedule_1.scheduleJob)(interval, () => {
            console.log("Keys not found, new ones are being generated.");
            const { privateKey: newPrivateKey, publicKey: newPublicKey, } = this.generateKeys();
            (0, fs_1.writeFileSync)(this.privateKeyPath, newPrivateKey, { flag: "w" });
            (0, fs_1.writeFileSync)(this.publicKeyPath, newPublicKey, { flag: "w" });
            this.privateKey = newPrivateKey;
            this.publicKey = newPublicKey;
        });
    }
}
exports.EncryptionManager = EncryptionManager;
/* const encryptionManager = new EncryptionManager(
  "./private-key.pem",
  "./public-key.pem"
);
encryptionManager.checkAndGenerateKeys();
encryptionManager.scheduleKeyRegeneration("* * * * * *");
 */ 
