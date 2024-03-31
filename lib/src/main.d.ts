export declare class EncryptionManager {
    private privateKeyPath;
    private publicKeyPath;
    private privateKey;
    private publicKey;
    constructor(privateKeyPath: string, publicKeyPath: string);
    private generateKeys;
    checkAndGenerateKeys(): void;
    getPrivateKey(): string;
    getPublicKey(): string;
    encrypt(data: any): string;
    decrypt(encryptedData: string): string;
    scheduleKeyRegeneration(interval: string): void;
}
