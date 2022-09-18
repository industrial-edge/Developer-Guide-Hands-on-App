import * as assert from "assert";
import { BlockInfo, readTag, TagType, _readIntegerAsByteString, _readStruct } from "./asn1";
import { PrivateKey } from "./common";

// tslint:disable:no-empty-interface
export interface PrivateKeyInternals {
    /***/
    version: Buffer;
    modulus: Buffer;
    publicExponent: Buffer;
    privateExponent: Buffer;
    prime1: Buffer;
    prime2: Buffer;
    exponent1: Buffer;
    exponent2: Buffer;

}

function f(buffer: Buffer, b: BlockInfo) {
    return buffer.slice(b.position+1, b.position + b.length)
}
const doDebug= !!process.env.DEBUG;
/**
 * 
 * @param privateKey RSAPrivateKey ::= SEQUENCE {
 *  version           Version,
 *  modulus           INTEGER,  -- n
 *  publicExponent    INTEGER,  -- e
 *  privateExponent   INTEGER,  -- d
 *  prime1            INTEGER,  -- p
 *  prime2            INTEGER,  -- q
 *  exponent1         INTEGER,  -- d mod (p-1)
 *  exponent2         INTEGER,  -- d mod (q-1)
 *  coefficient       INTEGER,  -- (inverse of q) mod p
 *  otherPrimeInfos   OtherPrimeInfos OPTIONAL
}
 */
export function explorePrivateKey(privateKey: PrivateKey): PrivateKeyInternals {
    assert(privateKey instanceof Buffer);
    const block_info = readTag(privateKey, 0);
    const blocks = _readStruct(privateKey, block_info);

    if (blocks.length === 9) {
        // alice_rsa
        const version = f(privateKey,blocks[0]);// _readIntegerAsByteString(privateKey, blocks1[0]);
        const modulus=  f(privateKey, blocks[1]);
        const publicExponent=  f(privateKey, blocks[2]);
        const privateExponent=  f(privateKey, blocks[3]);
        const prime1=  f(privateKey, blocks[4]);
        const prime2=  f(privateKey, blocks[5]);
        const exponent1=  f(privateKey, blocks[6]);
        const exponent2=  f(privateKey, blocks[7]);
    
        return {
            version,
            modulus,
            publicExponent,
            privateExponent,
            prime1,
            prime2,
            exponent1,
            exponent2
        };
    
    }
    /* istanbul ignore next */
    if (doDebug) {
        // tslint:disable:no-console
        console.log("--------------------")
        console.log(block_info);

        // tslint:disable:no-console
        console.log(
            blocks.map((b) => ({
                tag: TagType[b.tag] + " 0x" + b.tag.toString(16),
                l: b.length,
                p: b.position,
                buff: privateKey.slice(b.position, b.position + b.length).toString("hex"),
            }))
        );
    }

    const b = blocks[2];
    const bb = privateKey.slice(b.position, b.position + b.length);
    const block_info1 = readTag(bb, 0);
    const blocks1 = _readStruct(bb, block_info1);

    /* istanbul ignore next */
    if (doDebug) {
        // tslint:disable:no-console
        console.log(
            blocks1.map((b) => ({
                tag: TagType[b.tag] + " 0x" + b.tag.toString(16),
                l: b.length,
                p: b.position,
                buff: bb.slice(b.position, b.position + b.length).toString("hex"),
            }))
        );
    }

    const version =f(bb, blocks1[0]);
    const modulus=  f(bb, blocks1[1]);
    const publicExponent=  f(bb, blocks1[2]);
    const privateExponent=  f(bb, blocks1[3]);
    const prime1=  f(bb, blocks1[4]);
    const prime2=  f(bb, blocks1[5]);
    const exponent1=  f(bb, blocks1[6]);
    const exponent2=  f(bb, blocks1[7]);


    return {
        version,
        modulus,
        publicExponent,
        privateExponent,
        prime1,
        prime2,
        exponent1,
        exponent2
    };
}
