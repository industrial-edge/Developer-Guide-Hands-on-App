// tslint:disabled:no-var-requires
/**
 * @module node_opcua_crypto
 */
import * as constants from "constants";
import * as crypto from "crypto";
import { createFastUninitializedBuffer } from "./buffer_utils";
import { Certificate, CertificatePEM, DER, PEM, PrivateKey, PrivateKeyPEM, PublicKey, PublicKeyPEM, Signature } from "./common";
import { combine_der } from "./crypto_explore_certificate";
import * as assert from "assert";
import { hexy } from "hexy";

const jsrsasign = require("jsrsasign");

const PEM_REGEX = /^(-----BEGIN (.*)-----\r?\n([/+=a-zA-Z0-9\r\n]*)\r?\n-----END \2-----\r?\n?)/gm;

const PEM_TYPE_REGEX = /^(-----BEGIN (.*)-----)/m;
// Copyright 2012 The Obvious Corporation.
// identifyPemType

/*=
 * Extract and identify the PEM file type represented in the given
 * buffer. Returns the extracted type string or undefined if the
 * buffer doesn't seem to be any sort of PEM format file.
 */
export function identifyPemType(rawKey: Buffer | string): undefined | string {
    if (rawKey instanceof Buffer) {
        rawKey = rawKey.toString("utf8");
    }
    const match = PEM_TYPE_REGEX.exec(rawKey);
    return !match ? undefined : match[2];
}

export function convertPEMtoDER(raw_key: PEM): DER {
    let match: any;
    let pemType;
    let base64str;

    const parts: DER[] = [];

    PEM_REGEX.lastIndex = 0;
    // tslint:disable-next-line:no-conditional-assignment
    while ((match = PEM_REGEX.exec(raw_key)) !== null) {
        pemType = match[2];
        // pemType shall be "RSA PRIVATE KEY" , "PUBLIC KEY", "CERTIFICATE", "X509 CRL"
        base64str = match[3];
        base64str = base64str.replace(/\r?\n/g, "");
        parts.push(Buffer.from(base64str, "base64"));
    }
    return combine_der(parts);
}

/**
 * @method toPem
 * @param raw_key
 * @param pem
 * @return
 */
export function toPem(raw_key: Buffer | string, pem: string): string {
    assert(raw_key, "expecting a key");
    assert(typeof pem === "string");
    let pemType = identifyPemType(raw_key);
    if (pemType) {
        return raw_key instanceof Buffer ?  raw_key.toString("utf8") : raw_key;
    } else {
        pemType = pem;
        assert(["CERTIFICATE REQUEST", "CERTIFICATE", "RSA PRIVATE KEY", "PUBLIC KEY", "X509 CRL"].indexOf(pemType) >= 0);
        let b = (raw_key as Buffer).toString("base64");
        let str = "-----BEGIN " + pemType + "-----\n";
        while (b.length) {
            str += b.substr(0, 64) + "\n";
            b = b.substr(64);
        }
        str += "-----END " + pemType + "-----";
        str += "\n";
        return str;
    }
}

// istanbul ignore next
export function hexDump(buffer: Buffer, width?: number): string {
    if (!buffer) {
        return "<>";
    }
    width = width || 32;
    if (buffer.length > 1024) {
        return hexy(buffer.slice(0, 1024), { width, format: "twos" }) + "\n .... ( " + buffer.length + ")";
    } else {
        return hexy(buffer, { width, format: "twos" });
    }
}

interface MakeMessageChunkSignatureOptions {
    signatureLength: number;
    algorithm: string;
    privateKey: CertificatePEM;
}

/**
 * @method makeMessageChunkSignature
 * @param chunk
 * @param options
 * @param options.signatureLength
 * @param options.algorithm   for example "RSA-SHA256"
 * @param options.privateKey
 * @return - the signature
 */
export function makeMessageChunkSignature(chunk: Buffer, options: MakeMessageChunkSignatureOptions): Buffer {
    assert(Object.prototype.hasOwnProperty.call(options,"algorithm"));
    assert(chunk instanceof Buffer);
    assert(["RSA PRIVATE KEY", "PRIVATE KEY"].indexOf(identifyPemType(options.privateKey) as string) >= 0);
    // signature length = 128 bytes
    const signer = crypto.createSign(options.algorithm);
    signer.update(chunk);
    const signature = signer.sign(options.privateKey);
    assert(!options.signatureLength || signature.length === options.signatureLength);
    return signature;
}

export interface VerifyMessageChunkSignatureOptions {
    signatureLength?: number;
    algorithm: string;
    publicKey: PublicKeyPEM;
}

/**
 * @method verifyMessageChunkSignature
 *
 *     const signer = {
 *           signatureLength : 128,
 *           algorithm : "RSA-SHA256",
 *           publicKey: "qsdqsdqsd"
 *     };
 * @param blockToVerify
 * @param signature
 * @param options
 * @param options.signatureLength
 * @param options.algorithm    for example "RSA-SHA256"
 * @param options.publicKey
 * @return true if the signature is valid
 */
export function verifyMessageChunkSignature(
    blockToVerify: Buffer,
    signature: Signature,
    options: VerifyMessageChunkSignatureOptions
): boolean {
    assert(blockToVerify instanceof Buffer);
    assert(signature instanceof Buffer);
    assert(typeof options.publicKey === "string");
    assert(identifyPemType(options.publicKey));

    const verify = crypto.createVerify(options.algorithm);
    verify.update(blockToVerify);
    return verify.verify(options.publicKey, signature);
}

export function makeSHA1Thumbprint(buffer: Buffer): Signature {
    return crypto.createHash("sha1").update(buffer).digest();
}

// Basically when you =encrypt something using an RSA key (whether public or private), the encrypted value must
// be smaller than the key (due to the maths used to do the actual encryption). So if you have a 1024-bit key,
// in theory you could encrypt any 1023-bit value (or a 1024-bit value smaller than the key) with that key.
// However, the PKCS#1 standard, which OpenSSL uses, specifies a padding scheme (so you can encrypt smaller
// quantities without losing security), and that padding scheme takes a minimum of 11 bytes (it will be longer
// if the value you're encrypting is smaller). So the highest number of bits you can encrypt with a 1024-bit
// key is 936 bits because of this (unless you disable the padding by adding the OPENSSL_NO_PADDING flag,
// in which case you can go up to 1023-1024 bits). With a 2048-bit key it's 1960 bits instead.

export const RSA_PKCS1_OAEP_PADDING: number = constants.RSA_PKCS1_OAEP_PADDING;
export const RSA_PKCS1_PADDING: number = constants.RSA_PKCS1_PADDING;

export enum PaddingAlgorithm {
    RSA_PKCS1_OAEP_PADDING = 4,
    RSA_PKCS1_PADDING = 1,
}

assert(PaddingAlgorithm.RSA_PKCS1_OAEP_PADDING === constants.RSA_PKCS1_OAEP_PADDING);
assert(PaddingAlgorithm.RSA_PKCS1_PADDING === constants.RSA_PKCS1_PADDING);

// publicEncrypt and  privateDecrypt only work with
// small buffer that depends of the key size.
export function publicEncrypt_native(buffer: Buffer, publicKey: PublicKeyPEM, algorithm?: PaddingAlgorithm): Buffer {
    if (algorithm === undefined) {
        algorithm = PaddingAlgorithm.RSA_PKCS1_PADDING;
    }
    assert(algorithm === RSA_PKCS1_PADDING || algorithm === RSA_PKCS1_OAEP_PADDING);
    assert(buffer instanceof Buffer, "Expecting a buffer");
    return crypto.publicEncrypt(
        {
            key: publicKey,
            padding: algorithm,
        },
        buffer
    );
}

export function privateDecrypt_native(buffer: Buffer, privateKey: PrivateKeyPEM, algorithm?: PaddingAlgorithm): Buffer {
    if (algorithm === undefined) {
        algorithm = PaddingAlgorithm.RSA_PKCS1_PADDING;
    }

    assert(algorithm === RSA_PKCS1_PADDING || algorithm === RSA_PKCS1_OAEP_PADDING);
    assert(buffer instanceof Buffer, "Expecting a buffer");
    try {
        return crypto.privateDecrypt(
            {
                key: privateKey,
                padding: algorithm,
            },
            buffer
        );
    } catch (err) {
        return Buffer.alloc(1);
    }
}

export const publicEncrypt = publicEncrypt_native;
export const privateDecrypt = privateDecrypt_native;

export function publicEncrypt_long(
    buffer: Buffer,
    publicKey: PublicKeyPEM,
    blockSize: number,
    padding: number,
    algorithm?: PaddingAlgorithm
): Buffer {
    if (algorithm === undefined) {
        algorithm = PaddingAlgorithm.RSA_PKCS1_PADDING;
    }
    assert(algorithm === RSA_PKCS1_PADDING || algorithm === RSA_PKCS1_OAEP_PADDING);

    const chunk_size = blockSize - padding;
    const nbBlocks = Math.ceil(buffer.length / chunk_size);

    const outputBuffer = createFastUninitializedBuffer(nbBlocks * blockSize);
    for (let i = 0; i < nbBlocks; i++) {
        const currentBlock = buffer.slice(chunk_size * i, chunk_size * (i + 1));
        const encrypted_chunk = publicEncrypt(currentBlock, publicKey, algorithm);
        assert(encrypted_chunk.length === blockSize);
        encrypted_chunk.copy(outputBuffer, i * blockSize);
    }
    return outputBuffer;
}

export function privateDecrypt_long(buffer: Buffer, privateKey: PrivateKeyPEM, blockSize: number, algorithm?: number): Buffer {
    algorithm = algorithm || RSA_PKCS1_PADDING;
    assert(algorithm === RSA_PKCS1_PADDING || algorithm === RSA_PKCS1_OAEP_PADDING);

    const nbBlocks = Math.ceil(buffer.length / blockSize);

    const outputBuffer = createFastUninitializedBuffer(nbBlocks * blockSize);

    let total_length = 0;
    for (let i = 0; i < nbBlocks; i++) {
        const currentBlock = buffer.slice(blockSize * i, Math.min(blockSize * (i + 1), buffer.length));
        const decrypted_buf = privateDecrypt(currentBlock, privateKey, algorithm);
        decrypted_buf.copy(outputBuffer, total_length);
        total_length += decrypted_buf.length;
    }
    return outputBuffer.slice(0, total_length);
}

export function coerceCertificatePem(certificate: Certificate | CertificatePEM): CertificatePEM {
    if (certificate instanceof Buffer) {
        certificate = toPem(certificate, "CERTIFICATE");
    }
    assert(typeof certificate === "string");
    return certificate;
}

export function coercePublicKeyPem(publicKey: PublicKey | PublicKeyPEM): PublicKeyPEM {
    if (publicKey instanceof Buffer) {
        publicKey = toPem(publicKey, "PUBLIC KEY");
    }
    assert(typeof publicKey === "string");
    return publicKey;
}

/***
 * @method rsa_length
 * A very expensive way to determine the rsa key length ( i.e 2048bits or 1024bits)
 * @param key  a PEM public key or a PEM rsa private key
 * @return { the key length in bytes.
 */
export function rsa_length(key: PublicKeyPEM | PublicKey): number {
    key = coercePublicKeyPem(key);
    assert(typeof key === "string");
    const a = jsrsasign.KEYUTIL.getKey(key);
    return a.n.toString(16).length / 2;
}

export function extractPublicKeyFromCertificateSync(certificate: Certificate | CertificatePEM): PublicKeyPEM {
    certificate = coerceCertificatePem(certificate);
    const key = jsrsasign.KEYUTIL.getKey(certificate);
    const publicKeyAsPem = jsrsasign.KEYUTIL.getPEM(key);
    assert(typeof publicKeyAsPem === "string");
    return publicKeyAsPem;
}

// https://github.com/kjur/jsrsasign/blob/master/x509-1.1.js
// tool to analyse asn1 base64 blocks : http://lapo.it/asn1js
/**
 * extract the publickey from a certificate
 * @async
 */
export function extractPublicKeyFromCertificate(
    certificate: CertificatePEM | Certificate,
    callback: (err: Error | null, publicKeyPEM?: PublicKeyPEM) => void
): void {
    let err1: any = null;
    let keyPem: PublicKeyPEM;
    try {
        keyPem = extractPublicKeyFromCertificateSync(certificate);
    } catch (err) {
        err1 = err;
    }
    setImmediate(() => {
        callback(err1, keyPem);
    });
}
