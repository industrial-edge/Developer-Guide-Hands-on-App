import * as assert from "assert";
import { BlockInfo, readTag, _findBlockAtIndex, _getBlock, _readObjectIdentifier, _readStruct, _readVersionValue } from "./asn1";

import { BasicConstraints, X509KeyUsage, _readExtension } from "./crypto_explore_certificate";

export interface ExtensionRequest {
    basicConstraints: BasicConstraints;
    keyUsage: X509KeyUsage;
    subjectAltName: any;
}
export interface CertificateSigningRequestInfo {
    extensionRequest: ExtensionRequest;
}

function _readExtensionRequest(buffer: Buffer): ExtensionRequest {
    const block = readTag(buffer, 0);

    const inner_blocks = _readStruct(buffer, block);
    const extensions = inner_blocks.map((block1) => _readExtension(buffer, block1));

    const result: any = {};
    for (const e of extensions) {
        result[e.identifier.name] = e.value;
    }
    const { basicConstraints, keyUsage, subjectAltName } = result;
    return { basicConstraints, keyUsage, subjectAltName };
}

export function readCertificationRequestInfo(buffer: Buffer, block: BlockInfo): CertificateSigningRequestInfo {
    const blocks = _readStruct(buffer, block);
    if (blocks.length === 4) {
        const extensionRequestBlock = _findBlockAtIndex(blocks, 0);
        if (!extensionRequestBlock) {
            throw new Error("cannot find extensionRequest block");
        }
        const blocks1 = _readStruct(buffer, extensionRequestBlock);
        const blocks2 = _readStruct(buffer, blocks1[0]);
        const identifier = _readObjectIdentifier(buffer, blocks2[0]);
        if (identifier.name !== "extensionRequest") {
            throw new Error(" Cannot find extension Request in ASN1 block");
        }
        const buf = _getBlock(buffer, blocks2[1]);

        const extensionRequest = _readExtensionRequest(buf);

        return { extensionRequest };
    }
    throw new Error("Invalid CSR or ");
}

// see https://tools.ietf.org/html/rfc2986 : Certification Request Syntax Specification Version 1.7

export function exploreCertificateSigningRequest(crl: Buffer): CertificateSigningRequestInfo {
    const blockInfo = readTag(crl, 0);
    const blocks = _readStruct(crl, blockInfo);
    const csrInfo = readCertificationRequestInfo(crl, blocks[0]);
    return csrInfo;
}
