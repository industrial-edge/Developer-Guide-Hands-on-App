import * as fs from "fs";
import { promisify } from "util";
import { convertPEMtoDER } from "../source/crypto_utils";
import { CertificateRevocationList } from "../source/common";
import { assert } from "console";

export type CertificateSigningRequest = Buffer;

export async function readCertificateSigningRequest(filename: string): Promise<CertificateSigningRequest> {
    const csr = await promisify(fs.readFile)(filename);
    if (csr[0] === 0x30 && csr[1] === 0x82) {
        // der format
        return csr as CertificateRevocationList;
    }
    const raw_crl = csr.toString();
    return convertPEMtoDER(raw_crl);
}
