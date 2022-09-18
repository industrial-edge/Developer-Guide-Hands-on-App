// ---------------------------------------------------------------------------------------------------------------------
// node-opcua
// ---------------------------------------------------------------------------------------------------------------------
// Copyright (c) 2014-2021 - Etienne Rossignon - etienne.rossignon (at) gadz.org
// ---------------------------------------------------------------------------------------------------------------------
//
// This  project is licensed under the terms of the MIT license.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
// documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so,  subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
// Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
// WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
// ---------------------------------------------------------------------------------------------------------------------
// tslint:disable:no-shadowed-variable
import * as assert from "assert";
import * as async from "async";
import * as chalk from "chalk";
import * as fs from "fs";
import * as path from "path";

import { ErrorCallback, Filename, KeySize } from "./common";

import {
    adjustApplicationUri,
    adjustDate,
    certificateFileExist,
    configurationFileTemplate,
    createRandomFileIfNotExist,
    debugLog,
    displaySubtitle,
    displayTitle,
    ensure_openssl_installed,
    ExecuteOptions,
    execute_openssl,
    execute_openssl_no_failure,
    generateStaticConfig,
    make_path,
    mkdir,
    Params,
    processAltNames,
    ProcessAltNamesParam,
    quote,
    setEnv,
    useRandFile,
    x509Date,
} from "./toolbox";
import { Subject, SubjectOptions } from "../misc/subject";
import { CertificateSigningRequestInfo, exploreCertificateSigningRequest, readCertificateSigningRequest } from "node-opcua-crypto";

export const defaultSubject = "/C=FR/ST=IDF/L=Paris/O=Local NODE-OPCUA Certificate Authority/CN=NodeOPCUA-CA";

const config = {
    certificateDir: "INVALID",
    forceCA: false,
    pkiDir: "INVALID",
};

const n = make_path;
const q = quote;

// convert 'c07b9179'  to    "192.123.145.121"
function octetStringToIpAddress(a: string) {
    return (
        parseInt(a.substr(0, 2), 16).toString() +
        "." +
        parseInt(a.substr(2, 2), 16).toString() +
        "." +
        parseInt(a.substr(4, 2), 16).toString() +
        "." +
        parseInt(a.substr(6, 2), 16).toString()
    );
}

function construct_CertificateAuthority(certificateAuthority: CertificateAuthority, callback: ErrorCallback) {
    // create the CA directory store
    // create the CA directory store
    //
    // PKI/CA
    //     |
    //     +-+> private
    //     |
    //     +-+> public
    //     |
    //     +-+> certs
    //     |
    //     +-+> crl
    //     |
    //     +-+> conf
    //     |
    //     +-f: serial
    //     +-f: crlNumber
    //     +-f: index.txt
    //

    const subject = certificateAuthority.subject;

    const caRootDir = certificateAuthority.rootDir;

    function make_folders() {
        mkdir(caRootDir);
        mkdir(path.join(caRootDir, "private"));
        mkdir(path.join(caRootDir, "public"));
        // xx execute("chmod 700 private");
        mkdir(path.join(caRootDir, "certs"));
        mkdir(path.join(caRootDir, "crl"));
        mkdir(path.join(caRootDir, "conf"));
    }
    make_folders();

    function construct_default_files() {
        const serial = path.join(caRootDir, "serial");
        if (!fs.existsSync(serial)) {
            fs.writeFileSync(serial, "1000");
        }

        const crlNumber = path.join(caRootDir, "crlnumber");
        if (!fs.existsSync(crlNumber)) {
            fs.writeFileSync(crlNumber, "1000");
        }

        const indexFile = path.join(caRootDir, "index.txt");
        if (!fs.existsSync(indexFile)) {
            fs.writeFileSync(indexFile, "");
        }
    }
    construct_default_files();

    if (fs.existsSync(path.join(caRootDir, "private/cakey.pem")) && !config.forceCA) {
        // certificate already exists => do not overwrite
        debugLog("CA private key already exists ... skipping");
        return callback();
    }

    // tslint:disable:no-empty
    displayTitle("Create Certificate Authority (CA)", (err?: Error | null) => { /** */ });

    const indexFileAttr = path.join(caRootDir, "index.txt.attr");
    if (!fs.existsSync(indexFileAttr)) {
        fs.writeFileSync(indexFileAttr, "unique_subject = no");
    }

    const caConfigFile = certificateAuthority.configFile;
    // eslint-disable-next-line no-constant-condition
    if (1 || !fs.existsSync(caConfigFile)) {
        let data = configurationFileTemplate; // inlineText(configurationFile);
        data = data.replace(/%%ROOT_FOLDER%%/, make_path(caRootDir));

        fs.writeFileSync(caConfigFile, data);
    }

    // http://www.akadia.com/services/ssh_test_certificate.html
    const subjectOpt = " -subj \"" + subject.toString() + "\" ";
    const options = { cwd: caRootDir };
    processAltNames({} as Params);

    const configFile = generateStaticConfig("conf/caconfig.cnf", options);
    const configOption = " -config " + q(n(configFile));

    const keySize = certificateAuthority.keySize;

    const randomFile = "random.rnd";

    const tasks = [
        (callback: ErrorCallback) => displayTitle("Creating random file random.rnd", callback),

        (callback: ErrorCallback) => createRandomFileIfNotExist(randomFile, options, callback),

        (callback: ErrorCallback) => displayTitle("Generate the CA private Key - " + keySize, callback),

        // The first step is to create your RSA Private Key.
        // This key is a 1025,2048,3072 or 2038 bit RSA key which is encrypted using
        // Triple-DES and stored in a PEM format so that it is readable as ASCII text.
        (callback: ErrorCallback) =>
            execute_openssl(
                "genrsa " + " -out  private/cakey.pem" + (useRandFile() ? " -rand " + randomFile : "") + " " + keySize,
                options,
                callback
            ),

        (callback: ErrorCallback) => displayTitle("Generate a certificate request for the CA key", callback),

        // Once the private key is generated a Certificate Signing Request can be generated.
        // The CSR is then used in one of two ways. Ideally, the CSR will be sent to a Certificate Authority, such as
        // Thawte or Verisign who will verify the identity of the requestor and issue a signed certificate.
        // The second option is to self-sign the CSR, which will be demonstrated in the next section
        (callback: ErrorCallback) =>
            execute_openssl(
                "req -new" +
                " -sha256 " +
                " -text " +
                " -extensions v3_ca" +
                configOption +
                " -key private/cakey.pem " +
                " -out private/cakey.csr " +
                subjectOpt,
                options,
                callback
            ),

        // xx // Step 3: Remove Passphrase from Key
        // xx execute("cp private/cakey.pem private/cakey.pem.org");
        // xx execute(openssl_path + " rsa -in private/cakey.pem.org -out private/cakey.pem -passin pass:"+paraphrase);

        (callback: ErrorCallback) => displayTitle("Generate CA Certificate (self-signed)", callback),

        (callback: ErrorCallback) =>
            execute_openssl(
                " x509 -sha256 -req -days 3650 " +
                " -text " +
                " -extensions v3_ca" +
                " -extfile " +
                q(n(configFile)) +
                " -in private/cakey.csr " +
                " -signkey private/cakey.pem " +
                " -out public/cacert.pem",
                options,
                callback
            ),

        (callback: ErrorCallback) => displaySubtitle("generate initial CRL (Certificate Revocation List)", callback),

        (callback: ErrorCallback) => regenerateCrl(certificateAuthority.revocationList, configOption, options, callback),

        (callback: ErrorCallback) => displayTitle("Create Certificate Authority (CA) ---> DONE", callback),
    ];

    async.series(tasks, callback);
}
function regenerateCrl(revocationList: string, configOption: any, options: any, callback: ErrorCallback) {
    const tasks = [
        (callback: ErrorCallback) => displaySubtitle("regenerate CRL (Certificate Revocation List)", callback),

        (callback: ErrorCallback) =>
            // produce a CRL in PEM format
            execute_openssl("ca -gencrl " + configOption + " -out crl/revocation_list.crl", options, callback),

        (callback: ErrorCallback) =>
            execute_openssl(
                "crl " + " -in  crl/revocation_list.crl -out  crl/revocation_list.der " + " -outform der",
                options,
                callback
            ),

        (callback: ErrorCallback) => displaySubtitle("Display (Certificate Revocation List)", callback),

        (callback: ErrorCallback) =>
            execute_openssl("crl " + " -in " + q(n(revocationList)) + " -text " + " -noout", options, callback),
    ];
    async.series(tasks, callback);
}

export interface CertificateAuthorityOptions {
    keySize: KeySize;
    location: string;
    subject?: string | SubjectOptions;
}

export class CertificateAuthority {
    public readonly keySize: KeySize;
    public readonly location: string;
    public readonly subject: Subject;

    constructor(options: CertificateAuthorityOptions) {
        assert(Object.prototype.hasOwnProperty.call(options,"location"));
        assert(Object.prototype.hasOwnProperty.call(options,"keySize"));
        this.location = options.location;
        this.keySize = options.keySize || 2048;
        this.subject = new Subject(options.subject || defaultSubject);
    }

    public get rootDir() {
        return this.location;
    }

    public get configFile() {
        return path.normalize(path.join(this.rootDir, "./conf/caconfig.cnf"));
    }

    public get caCertificate() {
        // the Certificate Authority Certificate
        return make_path(this.rootDir, "./public/cacert.pem");
    }

    /**
     * the file name where  the current Certificate Revocation List is stored (in DER format)
     */
    public get revocationListDER() {
        return make_path(this.rootDir, "./crl/revocation_list.der");
    }

    /**
     * the file name where  the current Certificate Revocation List is stored (in PEM format)
     */
    public get revocationList() {
        return make_path(this.rootDir, "./crl/revocation_list.crl");
    }

    public get caCertificateWithCrl() {
        return make_path(this.rootDir, "./public/cacertificate_with_crl.pem");
    }

    public async initialize(): Promise<void>;
    public initialize(callback: ErrorCallback): void;
    public initialize(callback?: ErrorCallback): any {
        assert(typeof callback === "function");
        construct_CertificateAuthority(this, callback!);
    }

    public async constructCACertificateWithCRL(): Promise<void>;
    public constructCACertificateWithCRL(callback: ErrorCallback): void;
    public constructCACertificateWithCRL(callback?: ErrorCallback): any {
        assert(typeof callback === "function");
        const cacertWithCRL = this.caCertificateWithCrl;

        // note : in order to check if the certificate is revoked,
        // you need to specify -crl_check and have both the CA cert and the (applicable) CRL in your trust store.
        // There are two ways to do that:
        // 1. concatenate cacert.pem and crl.pem into one file and use that for -CAfile.
        // 2. use some linked
        // ( from http://security.stackexchange.com/a/58305/59982)

        if (fs.existsSync(this.revocationList)) {
            fs.writeFileSync(
                cacertWithCRL,
                fs.readFileSync(this.caCertificate, "utf8") + fs.readFileSync(this.revocationList, "utf8")
            );
        } else {
            // there is no revocation list yet
            fs.writeFileSync(cacertWithCRL, fs.readFileSync(this.caCertificate));
        }
        callback!();
    }

    public async constructCertificateChain(certificate: Filename): Promise<void>;
    public constructCertificateChain(certificate: Filename, callback: ErrorCallback): void;
    public constructCertificateChain(certificate: Filename, callback?: ErrorCallback): any {
        assert(typeof callback === "function");
        assert(fs.existsSync(certificate));
        assert(fs.existsSync(this.caCertificate));

        debugLog(chalk.yellow("        certificate file :"), chalk.cyan(certificate));
        // append
        fs.writeFileSync(
            certificate,
            fs.readFileSync(certificate, "utf8") + fs.readFileSync(this.caCertificate, "utf8")
            //   + fs.readFileSync(this.revocationList)
        );
        callback!();
    }

    public async createSelfSignedCertificate(certificateFile: Filename, privateKey: Filename, params: Params): Promise<void>;
    public createSelfSignedCertificate(
        certificateFile: Filename,
        privateKey: Filename,
        params: Params,
        callback: ErrorCallback
    ): void;
    public createSelfSignedCertificate(
        certificateFile: Filename,
        privateKey: Filename,
        params: Params,
        callback?: ErrorCallback
    ): any {
        assert(typeof privateKey === "string");
        assert(fs.existsSync(privateKey));
        assert(typeof callback === "function");

        if (!certificateFileExist(certificateFile)) {
            return callback!();
        }

        adjustDate(params);
        adjustApplicationUri(params);
        processAltNames(params);

        const csrFile = certificateFile + "_csr";
        assert(csrFile);
        const configFile = generateStaticConfig(this.configFile);

        const options = {
            cwd: this.rootDir,
            openssl_conf: make_path(configFile),
        };

        const configOption = "";

        const subject = params.subject ? new Subject(params.subject!).toString() : "";
        const subjectOptions = subject && subject.length > 1 ? " -subj " + subject + " " : "";
        const tasks = [];
        tasks.push((callback: ErrorCallback) => displaySubtitle("- the certificate signing request", callback));
        tasks.push((callback: ErrorCallback) =>
            execute_openssl(
                "req " +
                " -new -sha256 -text " +
                configOption +
                subjectOptions +
                " -batch -key " +
                q(n(privateKey)) +
                " -out " +
                q(n(csrFile)),
                options,
                callback
            )
        );

        tasks.push((callback: ErrorCallback) => displaySubtitle("- creating the self-signed certificate", callback));
        tasks.push((callback: ErrorCallback) =>
            execute_openssl(
                "ca " +
                " -selfsign " +
                " -keyfile " +
                q(n(privateKey)) +
                " -startdate " +
                x509Date(params.startDate!) +
                " -enddate " +
                x509Date(params.endDate!) +
                " -batch -out " +
                q(n(certificateFile)) +
                " -in " +
                q(n(csrFile)),
                options,
                callback
            )
        );

        tasks.push((callback: ErrorCallback) => displaySubtitle("- dump the certificate for a check", callback));
        tasks.push((callback: ErrorCallback) =>
            execute_openssl("x509 -in " + q(n(certificateFile)) + "  -dates -fingerprint -purpose -noout", {}, callback)
        );

        tasks.push((callback: ErrorCallback) => displaySubtitle("- verify self-signed certificate", callback));
        tasks.push((callback: ErrorCallback) =>
            execute_openssl_no_failure(
                "verify -verbose -CAfile " + q(n(certificateFile)) + " " + q(n(certificateFile)),
                options,
                callback
            )
        );

        tasks.push((callback: ErrorCallback) => fs.unlink(csrFile, callback));

        async.series(tasks, (err?: Error | null) => {
            callback!(err);
        });
    }

    /**
     * revoke a certificate and update the CRL
     *
     * @method revokeCertificate
     * @param certificate -  the certificate to revoke
     * @param params
     * @param [params.reason = "keyCompromise" {String}]
     * @param callback
     * @async
     */
    public revokeCertificate(certificate: Filename, params: Params, callback: ErrorCallback): void;
    public async revokeCertificate(certificate: Filename, params: Params): Promise<void>;
    public revokeCertificate(certificate: Filename, params: Params, callback?: ErrorCallback): any {
        assert(typeof callback === "function");

        const crlReasons = [
            "unspecified",
            "keyCompromise",
            "CACompromise",
            "affiliationChanged",
            "superseded",
            "cessationOfOperation",
            "certificateHold",
            "removeFromCRL",
        ];

        const configFile = generateStaticConfig("conf/caconfig.cnf", { cwd: this.rootDir });

        const options = {
            cwd: this.rootDir,
            openssl_conf: make_path(configFile),
        };

        setEnv("ALTNAME", "");
        const randomFile = path.join(this.rootDir, "random.rnd");
        setEnv("RANDFILE", randomFile);

        // // tslint:disable-next-line:no-string-literal
        // if (!fs.existsSync((process.env as any)["OPENSSL_CONF"])) {
        //     throw new Error("Cannot find OPENSSL_CONF");
        // }

        const configOption = " -config " + q(n(configFile));

        const reason = params.reason || "keyCompromise";
        assert(crlReasons.indexOf(reason) >= 0);

        const tasks = [
            (callback: ErrorCallback) => displayTitle("Revoking certificate  " + certificate, callback),

            (callback: ErrorCallback) => displaySubtitle("Make sure random file exists" + randomFile, callback),
            (callback: ErrorCallback) => createRandomFileIfNotExist(randomFile, {}, callback),

            (callback: ErrorCallback) => displaySubtitle("Revoke certificate", callback),

            (callback: ErrorCallback) => {
                execute_openssl_no_failure(
                    "ca -verbose " + configOption + " -revoke " + q(certificate) + " -crl_reason " + reason,
                    options,
                    callback
                );
            },
            // regenerate CRL (Certificate Revocation List)
            (callback: ErrorCallback) => regenerateCrl(this.revocationList, configOption, options, callback),

            (callback: ErrorCallback) => displaySubtitle("Verify that certificate is revoked  ", callback),

            (callback: (err?: Error) => void) => {
                execute_openssl_no_failure(
                    "verify -verbose" +
                    // configOption +
                    " -CRLfile " +
                    q(n(this.revocationList)) +
                    " -CAfile " +
                    q(n(this.caCertificate)) +
                    " -crl_check " +
                    q(n(certificate)),
                    options,
                    (err: Error | null, output?: string) => {
                        callback();
                    }
                );
            },
            // produce CRL in DER format
            (callback: ErrorCallback) => displaySubtitle("Produce CRL in DER form ", callback),
            (callback: ErrorCallback) =>
                execute_openssl(
                    "crl " + " -in " + q(n(this.revocationList)) + " -out " + "crl/revocation_list.der " + " -outform der",
                    options,
                    callback
                ),
            // produce CRL in PEM format with text
            (callback: ErrorCallback) => displaySubtitle("Produce CRL in PEM form ", callback),
            (callback: ErrorCallback) =>
                execute_openssl(
                    "crl " +
                    " -in " +
                    q(n(this.revocationList)) +
                    " -out " +
                    "crl/revocation_list.pem " +
                    " -outform pem" +
                    " -text ",
                    options,
                    callback
                ),
        ];

        async.series(tasks, callback!);
    }

    /**
     *
     * @param certificate            - the certificate filename to generate
     * @param certificateSigningRequestFilename   - the certificate signing request
     * @param params                 - parameters
     * @param params.applicationUri  - the applicationUri
     * @param params.startDate       - startDate of the certificate
     * @param params.validity        - number of day of validity of the certificate
     * @param callback
     */
    public async signCertificateRequest(
        certificate: Filename,
        certificateSigningRequestFilename: Filename,
        params: Params
    ): Promise<Filename>;
    public signCertificateRequest(
        certificate: Filename,
        certificateSigningRequestFilename: Filename,
        params: Params,
        callback: (err: Error | null, certificate?: Filename) => void
    ): void;
    public signCertificateRequest(
        certificate: Filename,
        certificateSigningRequestFilename: Filename,
        params: Params,
        callback?: (err: Error | null, certificate?: Filename) => void
    ): any {
        // istanbul ignore next
        if (!callback) {
            throw new Error("Internal Error");
        }

        ensure_openssl_installed((err) => {
            try {
                assert(fs.existsSync(certificateSigningRequestFilename));
                assert(typeof callback === "function");
                if (!certificateFileExist(certificate)) {
                    return callback(null);
                }
                adjustDate(params);
                adjustApplicationUri(params);
                processAltNames(params);

                const options: ExecuteOptions = { cwd: this.rootDir };
                let configFile: string;
                const tasks = [];

                let csrInfo: CertificateSigningRequestInfo;
                // note :
                // subjectAltName is not copied across
                //  see https://github.com/openssl/openssl/issues/10458
                tasks.push((callback: ErrorCallback) => {
                    readCertificateSigningRequest(certificateSigningRequestFilename)
                        .then((csr: Buffer) => {
                            csrInfo = exploreCertificateSigningRequest(csr);
                            callback();
                        })
                        .catch((err) => callback(err));
                });
                tasks.push((callback: ErrorCallback) => {
                    const applicationUri = csrInfo.extensionRequest.subjectAltName.uniformResourceIdentifier[0];
                    if (typeof applicationUri !== "string") {
                        return callback(new Error("Cannot find applicationUri in CSR"));
                    }

                    const dns = csrInfo.extensionRequest.subjectAltName.dNSName || [];
                    let ip = csrInfo.extensionRequest.subjectAltName.iPAddress || [];
                    ip = ip.map(octetStringToIpAddress);

                    const params: ProcessAltNamesParam = {
                        applicationUri,
                        dns,
                        ip,
                    };

                    processAltNames(params);

                    configFile = generateStaticConfig("conf/caconfig.cnf", options);
                    callback();
                });

                tasks.push((callback: ErrorCallback) =>
                    displaySubtitle("- then we ask the authority to sign the certificate signing request", callback)
                );
                tasks.push((callback: ErrorCallback) => {
                    const configOption = " -config " + configFile;
                    execute_openssl(
                        "ca " +
                        configOption +
                        " -startdate " +
                        x509Date(params.startDate!) +
                        " -enddate " +
                        x509Date(params.endDate!) +
                        " -batch -out " +
                        q(n(certificate)) +
                        " -in " +
                        q(n(certificateSigningRequestFilename)),
                        options,
                        callback
                    );
                });

                tasks.push((callback: ErrorCallback) => displaySubtitle("- dump the certificate for a check", callback));
                tasks.push((callback: ErrorCallback) =>
                    execute_openssl("x509 -in " + q(n(certificate)) + "  -dates -fingerprint -purpose -noout", options, callback)
                );

                tasks.push((callback: ErrorCallback) => displaySubtitle("- construct CA certificate with CRL", callback));
                tasks.push((callback: ErrorCallback) => {
                    this.constructCACertificateWithCRL(callback);
                });

                // construct certificate chain
                //   concatenate certificate with CA Certificate and revocation list
                tasks.push((callback: ErrorCallback) => displaySubtitle("- construct certificate chain", callback));
                tasks.push((callback: ErrorCallback) => {
                    this.constructCertificateChain(certificate, callback);
                });

                // todo
                tasks.push((callback: ErrorCallback) => displaySubtitle("- verify certificate against the root CA", callback));
                tasks.push((callback: ErrorCallback) => {
                    this.verifyCertificate(certificate, callback);
                });

                async.series(tasks as any, (err?: Error) => {
                    // istanbul ignore next
                    if (err) {
                        return callback(err);
                    }
                    callback(null, certificate);
                });
            } catch (err) {
                callback!(err as Error);
            }
        });

    }

    public async verifyCertificate(certificate: Filename): Promise<void>;
    public verifyCertificate(certificate: Filename, callback: ErrorCallback): void;
    public verifyCertificate(certificate: Filename, callback?: ErrorCallback): any {
        // openssl verify crashes on windows! we cannot use it reliably
        // istanbul ignore next
        const isImplemented = false;

        // istanbul ignore next
        if (isImplemented) {
            const options = { cwd: this.rootDir };
            const configFile = generateStaticConfig("conf/caconfig.cnf", options);

            setEnv("OPENSSL_CONF", make_path(configFile));
            const configOption = " -config " + configFile;

            execute_openssl_no_failure(
                "verify -verbose " + " -CAfile " + q(n(this.caCertificateWithCrl)) + " " + q(n(certificate)),
                options,
                (err: Error | null) => {
                    callback!(err ? err : undefined);
                }
            );
        } else {
            return callback!();
        }
    }
}

// tslint:disable:no-var-requires
// eslint-disable-next-line @typescript-eslint/no-var-requires
const thenify = require("thenify");
const opts = { multiArgs: false };
CertificateAuthority.prototype.initialize = thenify.withCallback(CertificateAuthority.prototype.initialize, opts);
CertificateAuthority.prototype.constructCACertificateWithCRL = thenify.withCallback(
    CertificateAuthority.prototype.constructCACertificateWithCRL,
    opts
);
CertificateAuthority.prototype.constructCertificateChain = thenify.withCallback(
    CertificateAuthority.prototype.constructCertificateChain,
    opts
);
CertificateAuthority.prototype.createSelfSignedCertificate = thenify.withCallback(
    CertificateAuthority.prototype.createSelfSignedCertificate,
    opts
);
CertificateAuthority.prototype.revokeCertificate = thenify.withCallback(CertificateAuthority.prototype.revokeCertificate, opts);
CertificateAuthority.prototype.verifyCertificate = thenify.withCallback(CertificateAuthority.prototype.verifyCertificate, opts);
CertificateAuthority.prototype.signCertificateRequest = thenify.withCallback(
    CertificateAuthority.prototype.signCertificateRequest,
    opts
);
