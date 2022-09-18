import { exploreCertificate } from ".";
import { Certificate } from "./common";
import { PrivateKey } from "./common";
import { explorePrivateKey } from "./explore_private_key";

export function  publicKeyAndPrivateKeyMatches(certificate: Certificate,privateKey: PrivateKey): boolean {

    const i = exploreCertificate(certificate);
    const j = explorePrivateKey(privateKey);

    const modulus1 = i.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey.modulus;
    const modulus2 = j.modulus;
    
    if (modulus1.length != modulus2.length) {
        return false;
    }
    return modulus1.toString("hex") === modulus2.toString("hex");
}