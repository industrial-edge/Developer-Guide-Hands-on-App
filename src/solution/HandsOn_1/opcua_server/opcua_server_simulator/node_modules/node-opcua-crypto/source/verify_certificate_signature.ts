// tslint:disable: no-console

// Now that we got a hash of the original certificate,
// we need to verify if we can obtain the same hash by using the same hashing function
// (in this case SHA-384). In order to do that, we need to extract just the body of
// the signed certificate. Which, in our case, is everything but the signature.
// The start of the body is always the first digit of the second line of the following command:
import * as crypto from "crypto";

import { Certificate, PrivateKey } from "./common";
import { split_der, exploreCertificate } from "./crypto_explore_certificate";
import { toPem } from "./crypto_utils";
import { _readAlgorithmIdentifier, _readSignatureValueBin, TagType, readTag, _readStruct, _getBlock } from "./asn1";

export function verifyCertificateOrClrSignature(certificateOrCrl: Buffer, parentCertificate: Certificate): boolean {
    const block_info = readTag(certificateOrCrl, 0);
    const blocks = _readStruct(certificateOrCrl, block_info);
    const bufferToBeSigned = certificateOrCrl.slice(block_info.position, blocks[1].position - 2);

    //xx console.log("bufferToBeSigned  = ", bufferToBeSigned.length, bufferToBeSigned.toString("hex").substr(0, 50), bufferToBeSigned.toString("hex").substr(-10));
    const signatureAlgorithm = _readAlgorithmIdentifier(certificateOrCrl, blocks[1]);
    const signatureValue = _readSignatureValueBin(certificateOrCrl, blocks[2]);

    const p = split_der(parentCertificate)[0];
    //xx    const publicKey = extractPublicKeyFromCertificateSync(p);
    const certPem = toPem(p, "CERTIFICATE");
    const verify = crypto.createVerify(signatureAlgorithm.identifier);
    verify.update(bufferToBeSigned);
    verify.end();
    return verify.verify(certPem, signatureValue);
}

export function verifyCertificateSignature(certificate: Certificate, parentCertificate: Certificate): boolean {
    return verifyCertificateOrClrSignature(certificate, parentCertificate);
}
export function verifyCertificateRevocationListSignature(
    certificateRevocationList: Certificate,
    parentCertificate: Certificate
): boolean {
    return verifyCertificateOrClrSignature(certificateRevocationList, parentCertificate);
}

export type _VerifyStatus = "BadCertificateIssuerUseNotAllowed" | "BadCertificateInvalid" | "Good";
export async function verifyCertificateChain(certificateChain: Certificate[]): Promise<{ status: _VerifyStatus; reason: string }> {
    // verify that all the certificate
    // second certificate must be used for CertificateSign

    for (let index = 1; index < certificateChain.length; index++) {
        const cert = certificateChain[index - 1];
        const certParent = certificateChain[index];

        // parent child must have keyCertSign
        const certParentInfo = exploreCertificate(certParent);
        const keyUsage = certParentInfo.tbsCertificate.extensions!.keyUsage!;

        // istanbul ignore next
        if (!keyUsage.keyCertSign) {
            return {
                status: "BadCertificateIssuerUseNotAllowed",
                reason: "One of the certificate in the chain has not keyUsage set for Certificate Signing",
            };
        }

        const parentSignChild = verifyCertificateSignature(cert, certParent);
        if (!parentSignChild) {
            return {
                status: "BadCertificateInvalid",
                reason: "One of the certificate in the chain is not signing the previous certificate",
            };
        }
        const certInfo = exploreCertificate(cert);

        // istanbul ignore next
        if (!certInfo.tbsCertificate.extensions) {
            return {
                status: "BadCertificateInvalid",
                reason: "Cannot find X409 Extension 3 in certificate",
            };
        }

        // istanbul ignore next
        if (!certParentInfo.tbsCertificate.extensions || !certInfo.tbsCertificate.extensions.authorityKeyIdentifier) {
            return {
                status: "BadCertificateInvalid",
                reason: "Cannot find X409 Extension 3 in certificate (parent)",
            };
        }

        // istanbul ignore next
        if (
            certParentInfo.tbsCertificate.extensions.subjectKeyIdentifier !==
            certInfo.tbsCertificate.extensions.authorityKeyIdentifier.keyIdentifier
        ) {
            return {
                status: "BadCertificateInvalid",
                reason:
                    "subjectKeyIdentifier authorityKeyIdentifier in child certificate do not match subjectKeyIdentifier of parent certificate",
            };
        }
    }
    return {
        status: "Good",
        reason: `certificate chain is valid(length = ${certificateChain.length})`,
    };
}
