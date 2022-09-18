import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";
import { Certificate, CertificatePEM, DER, PEM, PrivateKey, PrivateKeyPEM, PublicKey, PublicKeyPEM } from "../source/common";
import { convertPEMtoDER, identifyPemType } from "../source/crypto_utils";
const sshpk = require("sshpk");

/**
 * @method readKeyPem
 * @param filename
 */
export function readKeyPem(filename: string): string {
    const raw_key = fs.readFileSync(filename, "utf8");
    const pemType = identifyPemType(raw_key);
    assert(typeof pemType === "string"); // must have a valid pem type
    return raw_key;
}

function _readPemFile(filename: string): PEM {
    assert(typeof filename === "string");
    return fs.readFileSync(filename, "ascii");
}

function _readPemOrDerFileAsDER(filename: string): DER {
    if (filename.match(/.*\.der/)) {
        return fs.readFileSync(filename) as Buffer;
    }
    const raw_key: string = _readPemFile(filename);
    return convertPEMtoDER(raw_key);
}

/**
 * read a DER or PEM certificate from file
 */
export function readCertificate(filename: string): Certificate {
    return _readPemOrDerFileAsDER(filename) as Certificate;
}

/**
 * read a DER or PEM certificate from file
 */
export function readPublicKey(filename: string): PublicKey {
    return _readPemOrDerFileAsDER(filename) as PublicKey;
}

/**
 * read a DER or PEM certificate from file
 */
export function readPrivateKey(filename: string): PrivateKey {
    return _readPemOrDerFileAsDER(filename) as PrivateKey;
}

export function readCertificatePEM(filename: string): CertificatePEM {
    return _readPemFile(filename);
}

export function readPublicKeyPEM(filename: string): PublicKeyPEM {
    return _readPemFile(filename);
}

export function readPrivateKeyPEM(filename: string): PrivateKeyPEM {
    return _readPemFile(filename);
}
let __certificate_store = path.join(__dirname, "../../certificates/");

export function setCertificateStore(store: string): string {
    const old_store = __certificate_store;
    __certificate_store = store;
    return old_store;
}

export function read_sshkey_as_pem(filename: string): PublicKeyPEM {
    if (filename.substr(0, 1) !== ".") {
        filename = __certificate_store + filename;
    }
    const key: string = fs.readFileSync(filename, "ascii");
    const sshKey = sshpk.parseKey(key, "ssh");

    return sshKey.toString("pkcs8") as PEM;
}

/**
 *
 * @param filename
 */
export function readPrivateRsaKey(filename: string): PrivateKeyPEM {
    if (filename.substr(0, 1) !== "." && !fs.existsSync(filename)) {
        filename = __certificate_store + filename;
    }
    return fs.readFileSync(filename, "ascii") as string;
}

export function readPublicRsaKey(filename: string): PublicKeyPEM {
    return readPrivateRsaKey(filename);
}
