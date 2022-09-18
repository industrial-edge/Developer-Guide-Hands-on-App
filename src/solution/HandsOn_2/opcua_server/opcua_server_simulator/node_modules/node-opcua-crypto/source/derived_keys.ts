/**
 * @module node_opcua_crypto
 */
import * as crypto from "crypto";

import { createFastUninitializedBuffer } from "./buffer_utils";
import { Nonce } from "./common";
import { verifyMessageChunkSignature, VerifyMessageChunkSignatureOptions } from "./crypto_utils";
import { exploreCertificateInfo } from "./explore_certificate";
import * as assert from "assert";

function HMAC_HASH(sha1or256: "SHA1" | "SHA256", secret: Buffer, message: Buffer) {
    return crypto.createHmac(sha1or256, secret).update(message).digest();
}

function plus(buf1: Buffer, buf2: Buffer): Buffer {
    return Buffer.concat([buf1, buf2]);
}

// OPC-UA Spec 1.02 part 6 - 6.7.5  Deriving Keys page 42
// Once the  SecureChannel  is established the  Messages  are signed and encrypted with keys derived
// from the  Nonces  exchanged in t he  OpenSecureChannel  call. These keys are derived by passing the
// Nonces  to a pseudo - random function which produces a sequence of bytes from a set of inputs.   A
// pseudo- random function  is represented by the following function declaration:
// Byte[] PRF(
//     Byte[] secret,
//     Byte[] seed,
//     Int32 length,
//     Int32 offset
// )
// Where length   is the number of bytes to return and  offset  is a number of bytes from the beginning of
// the sequence.
// The lengths of the keys that need to be generated depend on the  SecurityPolicy  used for the
//    channel. The following information is specified by the  SecurityPolicy:
//    a)  SigningKeyLength  (from the  DerivedSignatureKeyLength);
//    b)  EncryptingKeyLength  (implied by the  SymmetricEncryptionAlgorithm);
//    c)  EncryptingBlockSize  (implied by the  SymmetricEncryptionAlgorithm).
//  The parameters  passed to the pseudo random function are specified in  Table 36.
//  Table 36  - Cryptography Key Generation Parameters
//
// Key                         Secret       Seed         Length               Offset
// ClientSigningKey            ServerNonce  ClientNonce  SigningKeyLength     0
// ClientEncryptingKey         ServerNonce  ClientNonce  EncryptingKeyLength  SigningKeyLength
// ClientInitializationVector  ServerNonce  ClientNonce  EncryptingBlockSize  SigningKeyLength+ EncryptingKeyLength
// ServerSigningKey            ClientNonce  ServerNonce  SigningKeyLength     0
// ServerEncryptingKey         ClientNonce  ServerNonce  EncryptingKeyLength  SigningKeyLength
// ServerInitializationVector  ClientNonce  ServerNonce  EncryptingBlockSize  SigningKeyLength+ EncryptingKeyLength
//
// The  Client  keys are used to secure  Messages  sent by the  Client. The  Server  keys are used to
// secure Messages  sent by the  Server.
// The SSL/TLS  specification  defines a pseudo random function called P_HASH which is used for this purpose.
//
// The P_HASH  algorithm is defined as follows:
//
//    P_HASH(secret, seed) = HMAC_HASH(secret, A(1) + seed) +
//                            HMAC_HASH(secret, A(2) + seed) +
//                            HMAC_HASH(secret, A(3) + seed) + ...
// Where A(n) is defined as:
//       A(0) = seed
//       A(n) = HMAC_HASH(secret, A(n-1))
//            + indicates that the results are appended to previous results.
// Where HASH is a hash function such as SHA1 or SHA256. The hash function to use depends on the SecurityPolicyUri.
//
//
// see also http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512/ws-secureconversation-1.3-os.html
//          http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf
export function makePseudoRandomBuffer(secret: Nonce, seed: Nonce, minLength: number, sha1or256: "SHA1" | "SHA256"): Buffer {
    assert(seed instanceof Buffer);
    assert(sha1or256 === "SHA1" || sha1or256 === "SHA256");

    const a = [];
    a[0] = seed;
    let index = 1;
    let p_hash = createFastUninitializedBuffer(0);
    while (p_hash.length <= minLength) {
        /* eslint  new-cap:0 */
        a[index] = HMAC_HASH(sha1or256, secret, a[index - 1]);
        p_hash = plus(p_hash, HMAC_HASH(sha1or256, secret, plus(a[index], seed)));
        index += 1;
    }
    return p_hash.slice(0, minLength);
}

export interface ComputeDerivedKeysOptions {
    signatureLength: number;
    signingKeyLength: number;
    encryptingKeyLength: number;

    encryptingBlockSize: number;
    algorithm: string;
    sha1or256?: "SHA1" | "SHA256";
}

export interface DerivedKeys extends ComputeDerivedKeysOptions {
    signatureLength: number;
    signingKeyLength: number;
    encryptingKeyLength: number;

    encryptingBlockSize: number;
    algorithm: string;
    sha1or256: "SHA1" | "SHA256";

    signingKey: Buffer;
    encryptingKey: Buffer;
    initializationVector: Buffer;
}

export function computeDerivedKeys(secret: Nonce, seed: Nonce, options: ComputeDerivedKeysOptions): DerivedKeys {
    assert(Number.isFinite(options.signatureLength));
    assert(Number.isFinite(options.encryptingKeyLength));
    assert(Number.isFinite(options.encryptingBlockSize));
    assert(typeof options.algorithm === "string");
    options.sha1or256 = options.sha1or256 || "SHA1";
    assert(typeof options.sha1or256 === "string");

    const offset1 = options.signingKeyLength;
    const offset2 = offset1 + options.encryptingKeyLength;
    const minLength = offset2 + options.encryptingBlockSize;

    const buf = makePseudoRandomBuffer(secret, seed, minLength, options.sha1or256);

    // +---------------+---------------------+-----------------------+
    // + signingKey    + encryptingKey       + initializationVector  +
    // +---------------+---------------------+-----------------------+
    return {
        signatureLength: options.signatureLength,
        signingKeyLength: options.signingKeyLength,
        encryptingKeyLength: options.encryptingKeyLength,

        encryptingBlockSize: options.encryptingBlockSize,
        algorithm: options.algorithm,
        sha1or256: options.sha1or256,

        signingKey: buf.slice(0, offset1),
        encryptingKey: buf.slice(offset1, offset2),
        initializationVector: buf.slice(offset2, minLength),
    };
}

/**
 * @method reduceLength
 * @param buffer
 * @param byteToRemove
 * @return buffer
 */
export function reduceLength(buffer: Buffer, byteToRemove: number): Buffer {
    return buffer.slice(0, buffer.length - byteToRemove);
}

/**
 * @method removePadding
 * @param buffer
 * @return buffer with padding removed
 */
export function removePadding(buffer: Buffer): Buffer {
    const nbPaddingBytes = buffer.readUInt8(buffer.length - 1) + 1;
    return reduceLength(buffer, nbPaddingBytes);
}

export type VerifyChunkSignatureOptions = VerifyMessageChunkSignatureOptions;

/**
 * @method verifyChunkSignature
 *
 *     const signer = {
 *           signatureLength : 128,
 *           algorithm : "RSA-SHA256",
 *           public_key: "qsdqsdqsd"
 *     };
 *
 * @param chunk  The message chunk to verify.
 * @param options
 * @param options.signatureLength
 * @param options.algorithm  the algorithm.
 * @param options.publicKey
 * @return {*}
 */
export function verifyChunkSignature(chunk: Buffer, options: VerifyChunkSignatureOptions): boolean {
    assert(chunk instanceof Buffer);
    let signatureLength = options.signatureLength || 0;
    if (signatureLength === 0) {
        // let's get the signatureLength by checking the size
        // of the certificate's public key
        const cert = exploreCertificateInfo(options.publicKey);
        signatureLength = cert.publicKeyLength || 0; // 1024 bits = 128Bytes or 2048=256Bytes
    }
    const block_to_verify = chunk.slice(0, chunk.length - signatureLength);
    const signature = chunk.slice(chunk.length - signatureLength);
    return verifyMessageChunkSignature(block_to_verify, signature, options);
}

// /**
//  * extract the public key from a certificate - using the pem module
//  *
//  * @method extractPublicKeyFromCertificate_WithPem
//  * @async
//  * @param certificate
//  * @param callback {Function}
//  * @param callback.err
//  * @param callback.publicKey as pem
//  */
// exports.extractPublicKeyFromCertificate_WithPem = function (certificate, callback) {
//
//     const err1 = new Error();
//     const cert_pem = crypto_utils.toPem(certificate, "CERTIFICATE");
//     require("pem").getPublicKey(cert_pem, function (err, data) {
//         if (err) {
//             console.log(err1.stack);
//             console.log(" CANNOT EXTRAT PUBLIC KEY from Certificate".red, certificate);
//             return callback(err);
//         }
//         callback(err, data.publicKey);
//     });
// };
//

export function computePaddingFooter(buffer: Buffer, derivedKeys: DerivedKeys): Buffer {
    assert(Object.prototype.hasOwnProperty.call(derivedKeys, "encryptingBlockSize"));
    const paddingSize = derivedKeys.encryptingBlockSize - ((buffer.length + 1) % derivedKeys.encryptingBlockSize);
    const padding = createFastUninitializedBuffer(paddingSize + 1);
    padding.fill(paddingSize);
    return padding;
}

function derivedKeys_algorithm(derivedKeys: DerivedKeys) {
    assert(Object.prototype.hasOwnProperty.call(derivedKeys, "algorithm"));
    const algorithm = derivedKeys.algorithm || "aes-128-cbc";
    assert(algorithm === "aes-128-cbc" || algorithm === "aes-256-cbc");
    return algorithm;
}

export function encryptBufferWithDerivedKeys(buffer: Buffer, derivedKeys: DerivedKeys): Buffer {
    const algorithm = derivedKeys_algorithm(derivedKeys);
    const key = derivedKeys.encryptingKey;
    const initVector = derivedKeys.initializationVector;
    const cypher = crypto.createCipheriv(algorithm, key, initVector);

    cypher.setAutoPadding(false);
    const encrypted_chunks = [];
    encrypted_chunks.push(cypher.update(buffer));
    encrypted_chunks.push(cypher.final());
    return Buffer.concat(encrypted_chunks);
}

export function decryptBufferWithDerivedKeys(buffer: Buffer, derivedKeys: DerivedKeys): Buffer {
    const algorithm = derivedKeys_algorithm(derivedKeys);
    const key = derivedKeys.encryptingKey;
    const initVector = derivedKeys.initializationVector;
    const cypher = crypto.createDecipheriv(algorithm, key, initVector);

    cypher.setAutoPadding(false);

    const decrypted_chunks = [];
    decrypted_chunks.push(cypher.update(buffer));
    decrypted_chunks.push(cypher.final());

    return Buffer.concat(decrypted_chunks);
}

/**
 * @method makeMessageChunkSignatureWithDerivedKeys
 * @param message
 * @param derivedKeys
 * @return
 */
export function makeMessageChunkSignatureWithDerivedKeys(message: Buffer, derivedKeys: DerivedKeys): Buffer {
    assert(message instanceof Buffer);
    assert(derivedKeys.signingKey instanceof Buffer);
    assert(typeof derivedKeys.sha1or256 === "string");
    assert(derivedKeys.sha1or256 === "SHA1" || derivedKeys.sha1or256 === "SHA256");
    const signature = crypto.createHmac(derivedKeys.sha1or256, derivedKeys.signingKey).update(message).digest();
    assert(signature.length === derivedKeys.signatureLength);
    return signature;
}

/**
 * @method verifyChunkSignatureWithDerivedKeys
 * @param chunk
 * @param derivedKeys
 * @return
 */
export function verifyChunkSignatureWithDerivedKeys(chunk: Buffer, derivedKeys: DerivedKeys): boolean {
    const message = chunk.slice(0, chunk.length - derivedKeys.signatureLength);
    const signature = chunk.slice(chunk.length - derivedKeys.signatureLength);
    const verif = makeMessageChunkSignatureWithDerivedKeys(message, derivedKeys);
    return verif.toString("hex") === signature.toString("hex");
}
