import * as fs from "fs";
import { promisify } from "util";
import { convertPEMtoDER } from "../source/crypto_utils";
import { CertificateRevocationList } from "../source/common";

export async function readCertificateRevocationList(filename: string): Promise<CertificateRevocationList> {
    const crl = await promisify(fs.readFile)(filename);
    if (crl[0] === 0x30 && crl[1] === 0x82) {
        // der format
        return crl as CertificateRevocationList;
    }
    const raw_crl = crl.toString();
    return convertPEMtoDER(raw_crl);
}
