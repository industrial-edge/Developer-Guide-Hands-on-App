/**
 * @module node_opcua_crypto
 */

import { Certificate, CertificatePEM } from "./common";
import { exploreCertificate, SubjectPublicKey } from "./crypto_explore_certificate";
import { DirectoryName } from "./asn1";
import { convertPEMtoDER } from "./crypto_utils";
import * as assert from "assert";

export type PublicKeyLength = 64 | 96 | 128 | 256 | 384 | 512;

/**
 * A structure exposing useful information about a certificate
 */
export interface CertificateInfo {
    /** the public key length in bits */
    publicKeyLength: PublicKeyLength;
    /** the date at which the certificate starts to be valid */
    notBefore: Date;
    /** the date after which the certificate is not valid any more */
    notAfter: Date;
    /** info about certificate owner */
    subject: DirectoryName;
    /** public key */
    publicKey: SubjectPublicKey;
}

export function coerceCertificate(certificate: Certificate | CertificatePEM): Certificate {
    if (typeof certificate === "string") {
        certificate = convertPEMtoDER(certificate);
    }
    assert(certificate instanceof Buffer);
    return certificate;
}

/**
 * @method exploreCertificateInfo
 * returns useful information about the certificate such as public key length, start date and end of validity date,
 * and CN
 * @param certificate the certificate to explore
 */
export function exploreCertificateInfo(certificate: Certificate | CertificatePEM): CertificateInfo {
    certificate = coerceCertificate(certificate);

    const certInfo = exploreCertificate(certificate);
    const data: CertificateInfo = {
        publicKeyLength: certInfo.tbsCertificate.subjectPublicKeyInfo.keyLength,
        notBefore: certInfo.tbsCertificate.validity.notBefore,
        notAfter: certInfo.tbsCertificate.validity.notAfter,
        publicKey: certInfo.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey,
        subject: certInfo.tbsCertificate.subject,
    };
    // istanbul ignore next
    if (
        !(
            data.publicKeyLength === 512 ||
            data.publicKeyLength === 384 ||
            data.publicKeyLength === 256 ||
            data.publicKeyLength === 128
        )
    ) {
        throw new Error("Invalid public key length (expecting 128,256,384 or 512)" + data.publicKeyLength);
    }
    return data;
}
