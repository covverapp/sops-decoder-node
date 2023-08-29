"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.decryptScalar = exports.decrypt = exports.decodeFile = exports.SopsError = void 0;
const crypto = require("crypto");
const os = require("os");
const aws = require("aws-sdk");
const fs = require("fs");
const UNENCRYPTED_SUFFIX = "_unencrypted";
class SopsError extends Error {
}
exports.SopsError = SopsError;
const checkEncryptedSuffix = (modifier) => (key) => !key.endsWith(modifier);
const checkUnencryptedSuffix = (modifier) => (key) => key.endsWith(modifier);
const checkUnencryptedRegex = (modifier) => (key) => new RegExp(modifier).test(key);
const checkEncryptedRegex = (modifier) => (key) => !new RegExp(modifier).test(key);
/**
 * Read the given file from the FileSytem and return the decoded data
 *
 * @param path
 */
function decodeFile(path) {
    return __awaiter(this, void 0, void 0, function* () {
        const data = yield new Promise((resolve, reject) => {
            fs.readFile(path, (err, contents) => {
                if (err) {
                    reject(err);
                }
                else {
                    resolve(contents);
                }
            });
        });
        const tree = JSON.parse(data.toString());
        return decrypt(tree);
    });
}
exports.decodeFile = decodeFile;
/**
 * Decode the given EncodedTree structure as an SOPS block of structured data
 *
 * @param tree data previous read
 */
function decrypt(tree) {
    return __awaiter(this, void 0, void 0, function* () {
        const { sops } = tree;
        if (!sops) {
            return tree;
        }
        const key = yield getKey(tree);
        const encryptionModifier = getEncryptionModifier(sops);
        if (key === null) {
            throw new SopsError("missing key");
        }
        const digest = crypto.createHash("sha512");
        const result = walkAndDecrypt(tree, key, "", digest, true, false, encryptionModifier);
        if (sops.mac) {
            const hash = decryptScalar(sops.mac, key, sops.lastmodified, null, false);
            if (hash.toUpperCase() !== digest.digest("hex").toUpperCase()) {
                throw new Error("Hash mismatch");
            }
        }
        return result;
    });
}
exports.decrypt = decrypt;
// Convert to a string value
function toBytes(value) {
    if (typeof value === "boolean") {
        return value === true ? 'True' : 'False';
    }
    else if (typeof value !== "string") {
        return value.toString();
    }
    return value;
}
// Given a sops config, return the appropriate encryption modifier
function getEncryptionModifier(sops) {
    if (sops === null || sops === void 0 ? void 0 : sops.encrypted_regex) {
        return checkEncryptedRegex(sops === null || sops === void 0 ? void 0 : sops.encrypted_regex);
    }
    if (sops === null || sops === void 0 ? void 0 : sops.encrypted_suffix) {
        return checkEncryptedSuffix(sops === null || sops === void 0 ? void 0 : sops.encrypted_suffix);
    }
    if (sops === null || sops === void 0 ? void 0 : sops.unencrypted_regex) {
        return checkUnencryptedRegex(sops === null || sops === void 0 ? void 0 : sops.unencrypted_regex);
    }
    return checkUnencryptedSuffix((sops === null || sops === void 0 ? void 0 : sops.unencrypted_suffix) || UNENCRYPTED_SUFFIX);
}
/**
 *  Decrypt a single value, update the digest if provided
 */
function decryptScalar(value, key, aad, digest, unencrypted) {
    if (unencrypted || typeof value !== "string") {
        if (digest) {
            digest.update(toBytes(value));
        }
        return value;
    }
    const valre = value.match(/^ENC\[AES256_GCM,data:(.+),iv:(.+),tag:(.+),type:(.+)\]/);
    if (!valre) {
        return value;
    }
    const encValue = Buffer.from(valre[1], "base64");
    const iv = Buffer.from(valre[2], "base64");
    const tag = Buffer.from(valre[3], "base64");
    const valtype = valre[4];
    const decryptor = crypto.createDecipheriv("aes-256-gcm", key, iv);
    decryptor.setAuthTag(tag);
    decryptor.setAAD(Buffer.from(aad));
    const cleartext = decryptor.update(encValue, undefined, "utf8") + decryptor.final("utf8");
    if (digest) {
        digest.update(cleartext);
    }
    switch (valtype) {
        case "bytes":
            return cleartext;
        case "str":
            return cleartext;
        case "int":
            return parseInt(cleartext, 10);
        case "float":
            return parseFloat(cleartext);
        case "bool":
            return cleartext.toLowerCase() === "true";
        default:
            throw new SopsError(`Unknown type ${valtype}`);
    }
}
exports.decryptScalar = decryptScalar;
function walkAndDecrypt(tree, key, aad = "", digest, isRoot = true, unencrypted = false, encryptionModifier) {
    const doValue = (value, caad, unencrypted_branch) => {
        if (Array.isArray(value)) {
            return value.map((vv) => doValue(vv, caad, unencrypted_branch));
        }
        if (typeof value === "object") {
            return walkAndDecrypt(value, key, caad, digest, false, false, encryptionModifier);
        }
        return decryptScalar(value, key, caad, digest, unencrypted_branch);
    };
    const result = {};
    Object.entries(tree).forEach(([k, value]) => {
        if (k === "sops" && isRoot) {
            // The top level 'sops' node is ignored since it's the internal configuration
            return;
        }
        result[k] = doValue(value, `${aad}${k}:`, unencrypted || encryptionModifier(k));
    });
    return result;
}
/**
 * Get the key from the 'sops.kms' node of the tree
 *
 * @param tree
 */
function getKey(tree) {
    return __awaiter(this, void 0, void 0, function* () {
        if (!tree.sops || !tree.sops.kms) {
            return null;
        }
        const kmsTree = tree.sops.kms;
        if (!Array.isArray(kmsTree)) {
            return null;
        }
        // eslint-disable-next-line no-restricted-syntax
        for (const entry of kmsTree) {
            if (!entry.enc || !entry.arn) {
                // Invalid format for a KMS node
                // eslint-disable-next-line no-continue
                continue;
            }
            try {
                // eslint-disable-next-line no-await-in-loop
                const kms = yield getAwsSessionForEntry(entry);
                // eslint-disable-next-line no-await-in-loop
                const response = yield kms
                    .decrypt({
                    CiphertextBlob: Buffer.from(entry.enc, "base64"),
                    EncryptionContext: entry.context || {},
                })
                    .promise();
                if (!response.Plaintext || !(response.Plaintext instanceof Buffer)) {
                    throw new SopsError("Invalid response");
                }
                return response.Plaintext;
            }
            catch (err) {
                // log it
            }
        }
        return null;
    });
}
/**
 * Return a boto3 session using a role if one exists in the entry
 * @param entry
 */
function getAwsSessionForEntry(entry) {
    return __awaiter(this, void 0, void 0, function* () {
        // extract the region from the ARN
        // arn:aws:kms:{REGION}:...
        const res = entry.arn.match(/^arn:aws:kms:(.+):([0-9]+):key\/(.+)$/);
        if (!res || res.length < 4) {
            throw new SopsError(`Invalid ARN ${entry.arn} insufficent components`);
        }
        if (!res) {
            throw new SopsError(`Invalid ARN ${entry.arn} in entry`);
        }
        const region = res[1];
        if (!entry.role) {
            // if there are no role to assume, return the client directly
            try {
                // const client = new aws.KMS({ region, credentials: null });
                const client = new aws.KMS({ region, credentials: null });
                return client;
            }
            catch (err) {
                throw new SopsError(`Unable to get boto3 client in ${region}`);
            }
        }
        // otherwise, create a client using temporary tokens that assume the role
        try {
            const client = new aws.STS();
            const role = yield client
                .assumeRole({
                RoleArn: entry.role,
                RoleSessionName: `sops@${os.hostname()}`,
            })
                .promise();
            try {
                const credentials = role.Credentials;
                if (!credentials) {
                    throw new Error("missing credentails");
                }
                const keyid = credentials.AccessKeyId;
                const secretkey = credentials.SecretAccessKey;
                const token = credentials.SessionToken;
                return new aws.KMS({
                    region,
                    accessKeyId: keyid,
                    secretAccessKey: secretkey,
                    sessionToken: token,
                });
            }
            catch (err) {
                throw new SopsError("failed to initialize KMS client");
            }
        }
        catch (err) {
            throw new SopsError(`Unable to switch roles ${err}`);
        }
    });
}
