import crypto from "crypto";
import fs from "fs";
import chalk from "chalk";

// 🔹 Secure storage path
export const CONFIG_FILE = "config.enc";

// 🔹 Encrypt configuration before saving
export function encryptConfig(data: any, password: string): void {
    const json = JSON.stringify(data);
    const salt = crypto.randomBytes(16);
    const key = crypto.scryptSync(password, salt, 32);
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
    let encrypted = cipher.update(json, "utf8", "hex");
    encrypted += cipher.final("hex");
    const authTag = cipher.getAuthTag().toString("hex");

    const payload = JSON.stringify({
        salt: salt.toString("hex"),
        iv: iv.toString("hex"),
        authTag,
        encrypted
    });

    fs.writeFileSync(CONFIG_FILE, payload, "utf-8");
    console.log(chalk.green("✅ Encrypted config saved!"));
}

// 🔹 Decrypt configuration before using
export function decryptConfig(password: string): { privateKey: string; rpcUrl: string } | null {
    if (!fs.existsSync(CONFIG_FILE)) {
        return null;
    }

    const data = JSON.parse(fs.readFileSync(CONFIG_FILE, "utf-8"));
    const key = crypto.scryptSync(password, Buffer.from(data.salt, "hex"), 32);
    const decipher = crypto.createDecipheriv(
        "aes-256-gcm",
        key,
        Buffer.from(data.iv, "hex")
    );
    decipher.setAuthTag(Buffer.from(data.authTag, "hex"));

    let decrypted = decipher.update(data.encrypted, "hex", "utf8");
    decrypted += decipher.final("utf8");
    return JSON.parse(decrypted);
} 