// tslint:disable: no-console
import * as fs from "fs";
import { exploreCertificate, readCertificate } from ".";

async function testCertificate(filename: string): Promise<void> {
    const cert1 = await readCertificate(filename);
    try {
        const info = exploreCertificate(cert1);
        //        console.log(info);
    } catch (err) {
        console.log(filename, "err = ", err.message);
    }
}
async function testCertificate1(filename: string): Promise<void> {
    const cert1 = fs.readFileSync(filename);
    try {
        const info = exploreCertificate(cert1);
        //        console.log(info);
    } catch (err) {
        console.log(filename, "err = ", err.message);
        console.log(err);
        throw err;
    }
}

(async () => {
    try {
        testCertificate1("./read.cer");
        testCertificate1("./unsol.cer");
        testCertificate1("./write.cer");
    } catch (err) {
        console.log("???? ERR !!!! ", err.message);
    }
})();
