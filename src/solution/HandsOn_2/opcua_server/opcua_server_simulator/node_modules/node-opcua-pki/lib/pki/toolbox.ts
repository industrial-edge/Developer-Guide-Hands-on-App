// ---------------------------------------------------------------------------------------------------------------------
// node-opcua-pki
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
// tslint:disable:no-console
// tslint:disable:no-shadowed-variable

import * as assert from "assert";

import * as async from "async";
import * as byline from "byline";
import * as chalk from "chalk";
import * as child_process from "child_process";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import { get_openssl_exec_path } from "../misc/install_prerequisite";
import { Subject, SubjectOptions } from "../misc/subject";
import { ErrorCallback, Filename } from "./common";
import _ca_config_template from "./templates/ca_config_template.cnf";
import _simple_config_template from "./templates/simple_config_template.cnf";

const exportedEnvVars: any = {};

export function quote(str: string): string {
    return "\"" + str + "\"";
}

// tslint:disable-next-line:variable-name
export const g_config = {
    opensslVersion: "unset",
    silent: process.env.VERBOSE ? !process.env.VERBOSE : true,
    force: false,
};

const doDebug = process.env.NODEOPCUAPKIDEBUG || false;
const displayError = true;
const displayDebug = !!process.env.NODEOPCUAPKIDEBUG || false;
// tslint:disable-next-line:no-empty
export function debugLog(...args: [any?, ...any[]]) {
    // istanbul ignore next
    if (displayDebug) {
        console.log.apply(null, args);
    }
}

let opensslPath: string | undefined; // not initialized

export function find_openssl(callback: (err: Error | null, opensslPath?: string) => void) {
    get_openssl_exec_path((err: Error | null, _opensslPath?: string) => {
        opensslPath = _opensslPath;
        callback(err, opensslPath);
    });
}

export function mkdir(folder: string): void {
    if (!fs.existsSync(folder)) {
        // istanbul ignore next
        if (!g_config.silent) {
            console.log(chalk.white(" .. constructing "), folder);
        }
        fs.mkdirSync(folder);
    }
}

export function setEnv(varName: string, value: string): void {
    // istanbul ignore next
    if (!g_config.silent) {
        console.log("          set " + varName + "=" + value);
    }
    exportedEnvVars[varName] = value;

    if (["OPENSSL_CONF"].indexOf(varName) >= 0) {
        process.env[varName] = value;
    }
    if (["RANDFILE"].indexOf(varName) >= 0) {
        process.env[varName] = value;
    }
}

export function hasEnv(varName: string): boolean {
    return Object.prototype.hasOwnProperty.call(exportedEnvVars, varName);
}

export interface ExecuteOptions {
    cwd?: string;
    hideErrorMessage?: boolean;
}

export function execute(cmd: string, options: ExecuteOptions, callback: (err: Error | null, output: string) => void) {
    assert(typeof callback === "function");

    /// assert(g_config.CARootDir && fs.existsSync(option.CARootDir));
    options.cwd = options.cwd || process.cwd();

    // istanbul ignore next
    if (!g_config.silent) {
        console.log(chalk.cyan("                  CWD         "), options.cwd);
    }

    const outputs: string[] = [];

    const child = child_process.exec(
        cmd,
        {
            cwd: options.cwd,
            windowsHide: true,
        },
        (err: child_process.ExecException | null) => {
            // istanbul ignore next
            if (err) {
                if (!options.hideErrorMessage) {
                    const fence = "###########################################";
                    console.error(chalk.bgWhiteBright.redBright(`${fence} OPENSSL ERROR ${fence}`));
                    console.error(chalk.bgWhiteBright.redBright("CWD = " + options.cwd));
                    console.error(chalk.bgWhiteBright.redBright(err.message));
                    console.error(chalk.bgWhiteBright.redBright(`${fence} OPENSSL ERROR ${fence}`));
                }
                // console.log("        ERR = ".bgWhite.red, err);
            }
            callback(err, outputs.join(""));
        }
    );

    const stream2 = byline(child.stdout!);
    stream2.on("data", (line: string) => {
        outputs.push(line + "\n");
    });

    // istanbul ignore next
    if (!g_config.silent) {
        const stream1 = byline(child.stderr!);
        stream1.on("data", (line: string) => {
            line = line.toString();
            if (displayError) {
                process.stdout.write(chalk.white("        stderr ") + chalk.red(line) + "\n");
            }
        });
        stream2.on("data", (line: string) => {
            line = line.toString();
            if (doDebug) {
                process.stdout.write(chalk.white("        stdout ") + chalk.whiteBright(line) + "\n");
            }
        });
    }
}

export function useRandFile() {
    // istanbul ignore next
    if (g_config.opensslVersion && g_config.opensslVersion.toLowerCase().indexOf("libressl") > -1) {
        return false;
    }
    return true;
}

function openssl_require2DigitYearInDate() {
    // istanbul ignore next
    if (!g_config.opensslVersion) {
        throw new Error(
            "openssl_require2DigitYearInDate : openssl version is not known:" + "  please call ensure_openssl_installed(callback)"
        );
    }
    return g_config.opensslVersion.match(/OpenSSL 0\.9/);
}

g_config.opensslVersion = "";

export function ensure_openssl_installed(callback: (err?: Error) => void) {
    assert(typeof callback === "function");
    if (!opensslPath) {
        return find_openssl((err: Error | null) => {
            // istanbul ignore next
            if (err) {
                return callback(err);
            }

            execute_openssl("version", { cwd: "." }, (err: Error | null, outputs?: string) => {
                // istanbul ignore next
                if (err) {
                    return callback(err);
                }
                g_config.opensslVersion = outputs!.trim();
                if (doDebug) {
                    console.log("OpenSSL version : ", g_config.opensslVersion);
                }
                callback(err ? err : undefined);
            });
        });
    } else {
        return callback();
    }
}

function getTempFolder(): string {
    return os.tmpdir();
}

export interface ExecuteOpenSSLOptions extends ExecuteOptions {
    openssl_conf?: string;
}

export function execute_openssl(
    cmd: string,
    options: ExecuteOpenSSLOptions,
    callback: (err: Error | null, output?: string) => void
): void {
    // tslint:disable-next-line:variable-name
    const empty_config_file = n(getTempFolder(), "empty_config.cnf");
    if (!fs.existsSync(empty_config_file)) {
        fs.writeFileSync(empty_config_file, "# empty config file");
    }

    assert(typeof callback === "function");

    options = options || {};
    options.openssl_conf = options.openssl_conf || empty_config_file; // "!! OPEN SLL CONF NOT DEFINED BAD FILE !!";
    assert(options.openssl_conf);
    setEnv("OPENSSL_CONF", options.openssl_conf!);

    // istanbul ignore next
    if (!g_config.silent) {
        console.log(chalk.cyan("                  OPENSSL_CONF"), process.env.OPENSSL_CONF);
        console.log(chalk.cyan("                  RANDFILE    "), process.env.RANDFILE);
        console.log(chalk.cyan("                  CMD         openssl "), chalk.cyanBright(cmd));
    }

    ensure_openssl_installed((err?: Error) => {
        // istanbul ignore next
        if (err) {
            return callback(err);
        }
        execute(quote(opensslPath!) + " " + cmd, options, callback);
    });
}
export function executeOpensslAsync(cmd: string, options: ExecuteOpenSSLOptions): Promise<string> {
    return new Promise((resolve, reject) => {
        execute_openssl(cmd, options, (err, output) => {
            // istanbul ignore next
            if (err) {
                reject(err);
            } else {
                resolve(output || "");
            }
        });
    });
}

export function execute_openssl_no_failure(
    cmd: string,
    options: ExecuteOpenSSLOptions,
    callback: (err: Error | null, output?: string) => void
) {
    options = options || {};
    options.hideErrorMessage = true;
    execute_openssl(cmd, options, (err: Error | null, output?: string) => {
        // istanbul ignore next
        if (err) {
            debugLog(" (ignored error =  ERROR : )", err!.message);
        }
        callback(null, output);
    });
}

// istanbul ignore next
export function displayChapter(str: string, callback: (err?: Error) => void) {
    const l = "                                                                                               ";
    console.log(chalk.bgWhite(l) + " ");
    str = ("        " + str + l).substring(0, l.length);
    console.log(chalk.bgWhite.cyan(str));
    console.log(chalk.bgWhite(l) + " ");
    if (callback) {
        callback();
    }
}

export function displayTitle(str: string, callback: (err?: Error) => void) {
    // istanbul ignore next
    if (!g_config.silent) {
        console.log("");
        console.log(chalk.yellowBright(str));
        console.log(chalk.yellow(new Array(str.length + 1).join("=")), "\n");
    }
    if (callback) {
        callback();
    }
}

export function displaySubtitle(str: string, callback: (err?: Error) => void) {
    // istanbul ignore next
    if (!g_config.silent) {
        console.log("");
        console.log("    " + chalk.yellowBright(str));
        console.log("    " + chalk.white(new Array(str.length + 1).join("-")), "\n");
    }
    if (callback) {
        callback();
    }
}

export function getEnvironmentVarNames(): any[] {
    return Object.keys(exportedEnvVars).map((varName: string) => {
        return { key: varName, pattern: "\\$ENV\\:\\:" + varName };
    });
}

export function generateStaticConfig(configPath: string, options?: ExecuteOptions) {
    const prePath = (options && options.cwd) || "";
    const staticConfigPath = configPath + ".tmp";
    let staticConfig = fs.readFileSync(path.join(prePath, configPath), { encoding: "utf8" });
    for (const envVar of getEnvironmentVarNames()) {
        staticConfig = staticConfig.replace(new RegExp(envVar.pattern, "gi"), exportedEnvVars[envVar.key]);
    }
    fs.writeFileSync(path.join(prePath, staticConfigPath), staticConfig);

    return staticConfigPath;
}

const q = quote;

export function make_path(folderName: string, filename?: string): string {
    let s;
    if (filename) {
        s = path.join(path.normalize(folderName), filename);
    } else {
        assert(folderName);
        s = folderName;
    }
    s = s.replace(/\\/g, "/");
    return s;
}

const n = make_path;

/**
 *   calculate the public key from private key
 *   openssl rsa -pubout -in private_key.pem
 *
 * @method getPublicKeyFromPrivateKey
 * @param privateKeyFilename
 * @param publicKeyFilename
 * @param callback
 */
export function getPublicKeyFromPrivateKey(
    privateKeyFilename: string,
    publicKeyFilename: string,
    callback: (err: Error | null) => void
) {
    assert(fs.existsSync(privateKeyFilename));
    execute_openssl("rsa -pubout -in " + q(n(privateKeyFilename)) + " -out " + q(n(publicKeyFilename)), {}, callback);
}

/**
 * extract public key from a certificate
 *   openssl x509 -pubkey -in certificate.pem -nottext
 *
 * @method getPublicKeyFromCertificate
 * @param certificateFilename
 * @param publicKeyFilename
 * @param callback
 */
export function getPublicKeyFromCertificate(
    certificateFilename: string,
    publicKeyFilename: string,
    callback: (err: Error | null) => void
) {
    assert(fs.existsSync(certificateFilename));
    execute_openssl("x509 -pubkey -in " + q(n(certificateFilename)) + " > " + q(n(publicKeyFilename)), {}, callback);
}

type KeyLength = 1024 | 2048 | 3072 | 4096;

/**
 * create a RSA PRIVATE KEY
 *
 * @method createPrivateKey
 *
 * @param privateKeyFilename
 * @param keyLength
 * @param callback {Function}
 */
export function createPrivateKey(privateKeyFilename: string, keyLength: KeyLength, callback: ErrorCallback) {
    // istanbul ignore next
    if (useRandFile()) {
        assert(hasEnv("RANDFILE"));
    }

    assert([1024, 2048, 3072, 4096].indexOf(keyLength) >= 0);
    const randomFile = exportedEnvVars.RANDFILE ? q(n(exportedEnvVars.RANDFILE)) : "random.rnd";
    const tasks = [
        (callback: ErrorCallback) => createRandomFileIfNotExist(randomFile, {}, callback),

        (callback: ErrorCallback) => {
            execute_openssl(
                "genrsa " + " -out " + q(n(privateKeyFilename)) + (useRandFile() ? " -rand " + randomFile : "") + " " + keyLength,
                {},
                (err: Error | null) => {
                    callback(err ? err : undefined);
                }
            );
        },
    ];

    async.series(tasks, callback);
}

export function createRandomFile(randomFile: string, options: ExecuteOptions, callback: (err?: Error) => void) {
    // istanbul ignore next
    if (!useRandFile()) {
        return callback();
    }
    execute_openssl("rand " + " -out " + randomFile + " -hex 256", options, (err: Error | null) => {
        callback(err ? err : undefined);
    });
}

export function createRandomFileIfNotExist(randomFile: string, options: ExecuteOptions, callback: ErrorCallback): void {
    const randomFilePath = options.cwd ? path.join(options.cwd, randomFile) : randomFile;
    fs.exists(randomFilePath, (exists: boolean) => {
        if (exists) {
            if (doDebug) {
                console.log(
                    chalk.yellow("         randomFile"),
                    chalk.cyan(randomFile),
                    chalk.yellow(" already exists => skipping")
                );
            }
            return callback();
        } else {
            createRandomFile(randomFile, options, callback);
        }
    });
}

// tslint:disable-next:no-empty-interface
export interface CreateCertificateSigningRequestOptions extends ProcessAltNamesParam {
    subject?: SubjectOptions | string;
}

export interface CreateCertificateSigningRequestWithConfigOptions extends CreateCertificateSigningRequestOptions {
    rootDir: Filename;
    configFile: Filename;
    privateKey: Filename;
}

/**
 * create a certificate signing request
 *
 * @param certificateSigningRequestFilename
 * @param params
 * @param callback
 */
export function createCertificateSigningRequest(
    certificateSigningRequestFilename: string,
    params: CreateCertificateSigningRequestWithConfigOptions,
    callback: (err?: Error) => void
): void {
    assert(params);
    assert(params.rootDir);
    assert(params.configFile);
    assert(params.privateKey);
    assert(typeof params.privateKey === "string");
    assert(fs.existsSync(params.configFile!), "config file must exist " + params.configFile);
    assert(fs.existsSync(params.privateKey!), "Private key must exist" + params.privateKey);
    assert(fs.existsSync(params.rootDir!), "RootDir key must exist");
    assert(typeof certificateSigningRequestFilename === "string");

    // note : this openssl command requires a config file
    processAltNames(params);
    const configFile = generateStaticConfig(params.configFile!);
    const options = { cwd: params.rootDir, openssl_conf: configFile };

    const configOption = " -config " + q(n(configFile));

    const subject = params.subject ? new Subject(params.subject).toString() : undefined;
    // process.env.OPENSSL_CONF  ="";
    const subjectOptions = subject ? " -subj \"" + subject + "\"" : "";
    async.series(
        [
            (callback: (err?: Error) => void) => {
                displaySubtitle("- Creating a Certificate Signing Request", callback);
            },
            (callback: (err?: Error) => void) => {
                execute_openssl(
                    "req -new" +
                        "  -sha256 " +
                        " -batch " +
                        " -text " +
                        configOption +
                        " -key " +
                        q(n(params.privateKey!)) +
                        subjectOptions +
                        " -out " +
                        q(n(certificateSigningRequestFilename)),
                    options,
                    (err: Error | null) => {
                        callback(err ? err : undefined);
                    }
                );
            },
        ],
        (err) => callback(err!)
    );
}

export function x509Date(date: Date): string {
    const Y = date.getUTCFullYear();
    const M = date.getUTCMonth() + 1;
    const D = date.getUTCDate();
    const h = date.getUTCHours();
    const m = date.getUTCMinutes();
    const s = date.getUTCSeconds();

    function w(s: string | number, l: number): string {
        return ("00000" + s).substr(-l, l);
    }

    if (openssl_require2DigitYearInDate()) {
        // for example: on MacOS , where openssl 0.98 is installed by default
        return w(Y, 2) + w(M, 2) + w(D, 2) + w(h, 2) + w(m, 2) + w(s, 2) + "Z";
    } else {
        // for instance when openssl version is greater than 1.0.0
        return w(Y, 4) + w(M, 2) + w(D, 2) + w(h, 2) + w(m, 2) + w(s, 2) + "Z";
    }
}

export interface ProcessAltNamesParam {
    dns?: string[];
    ip?: string[];
    applicationUri?: string;
}

export interface StartDateEndDateParam {
    startDate?: Date;
    endDate?: Date;
    validity?: number;
}

export interface CreateSelfSignCertificateParam extends ProcessAltNamesParam, StartDateEndDateParam {
    subject?: SubjectOptions | string;
}

// purpose of self-signed certificate
export enum CertificatePurpose {
    NotSpecified = 0,
    ForCertificateAuthority = 1,
    ForApplication = 2,
    ForUserAuthentication = 3, // X509
}

export interface CreateSelfSignCertificateWithConfigParam extends CreateSelfSignCertificateParam {
    rootDir: Filename;
    configFile: Filename;
    privateKey: Filename;
    purpose: CertificatePurpose;
}

export interface Params extends ProcessAltNamesParam, StartDateEndDateParam {
    subject?: SubjectOptions | string;

    privateKey?: string;
    configFile?: string;
    rootDir?: string;

    outputFile?: string;
    reason?: string;
}

export function adjustDate(params: StartDateEndDateParam) {
    assert(params instanceof Object);
    params.startDate = params.startDate || new Date();
    assert(params.startDate instanceof Date);

    params.validity = params.validity || 365; // one year

    params.endDate = new Date(params.startDate.getTime());
    params.endDate.setDate(params.startDate.getDate() + params.validity);

    // xx params.endDate = x509Date(endDate);
    // xx params.startDate = x509Date(startDate);

    assert(params.endDate instanceof Date);
    assert(params.startDate instanceof Date);

    // istanbul ignore next
    if (!g_config.silent) {
        console.log(" start Date ", params.startDate.toUTCString(), x509Date(params.startDate));
        console.log(" end   Date ", params.endDate.toUTCString(), x509Date(params.endDate));
    }
}

export function adjustApplicationUri(params: Params) {
    const applicationUri = params.applicationUri;
    if (applicationUri!.length > 200) {
        throw new Error("Openssl doesn't support urn with length greater than 200" + applicationUri);
    }
}

export function certificateFileExist(certificateFile: string): boolean {
    assert(typeof certificateFile === "string");

    // istanbul ignore next
    if (fs.existsSync(certificateFile) && !g_config.force) {
        console.log(
            chalk.yellow("        certificate ") + chalk.cyan(certificateFile) + chalk.yellow(" already exists => do not overwrite")
        );
        return false;
    }
    return true;
}

/**
 *
 * @param params
 * @param params.applicationUri
 * @param params.dns
 * @param params.ip
 * @private
 */
export function processAltNames(params: ProcessAltNamesParam) {
    params.dns = params.dns || [];
    params.ip = params.ip || [];

    // construct subjectAtlName
    let subjectAltName: string[] = [];
    subjectAltName.push("URI:" + params.applicationUri);
    subjectAltName = ([] as string[]).concat(
        subjectAltName,
        params.dns.map((d: string) => "DNS:" + d)
    );
    subjectAltName = ([] as string[]).concat(
        subjectAltName,
        params.ip.map((d: string) => "IP:" + d)
    );
    const subjectAltNameString = subjectAltName.join(", ");
    setEnv("ALTNAME", subjectAltNameString);
}

/**
 *
 * @param certificate
 * @param params
 * @param params.configFile
 * @param params.rootDir
 * @param params.privateKey
 * @param params.applicationUri
 * @param params.dns
 * @param params.ip
 * @param params.validity certificate duration in days
 * @param params.purpose
 * @param [params.subject= "/C=FR/ST=IDF/L=Paris/O=Local NODE-OPCUA Certificate Authority/CN=ZZNodeOPCUA"]
 * @param callback
 */
export function createSelfSignCertificate(
    certificate: string,
    params: CreateSelfSignCertificateWithConfigParam,
    callback: (err?: Error | null) => void
) {
    ensure_openssl_installed((err) => {
        if (err) {
            return callback(err);
        }
        try {
            params.purpose = params.purpose || CertificatePurpose.ForApplication;
            assert(params.purpose, "Please provide a Certificate Purpose");
            /**
             * note: due to a limitation of openssl ,
             *       it is not possible to control the startDate of the certificate validity
             *       to achieve this the certificateAuthority tool shall be used.
             */
            assert(fs.existsSync(params.configFile));
            assert(fs.existsSync(params.rootDir));
            assert(fs.existsSync(params.privateKey));
            if (!params.subject) {
                return callback(new Error("Missing subject"));
            }
            assert(typeof params.applicationUri === "string");
            assert(params.dns instanceof Array);

            // xx no key size in self-signed assert(params.keySize == 2048 || params.keySize == 4096);

            processAltNames(params);

            adjustDate(params);
            assert(Object.prototype.hasOwnProperty.call(params, "validity"));

            let subject = new Subject(params.subject);
            subject = subject.toString();

            const certificateRequestFilename = certificate + ".csr";

            const configFile = generateStaticConfig(params.configFile!);
            const configOption = " -config " + q(n(configFile));

            let extension: string;
            switch (params.purpose) {
            case CertificatePurpose.ForApplication:
                extension = "v3_selfsigned";
                break;
            case CertificatePurpose.ForCertificateAuthority:
                extension = "v3_ca";
                break;
            case CertificatePurpose.ForUserAuthentication:
            default:
                extension = "v3_selfsigned";
            }

            const tasks = [
                (callback: ErrorCallback) => {
                    displayTitle("Generate a certificate request", callback);
                },

                // Once the private key is generated a Certificate Signing Request can be generated.
                // The CSR is then used in one of two ways. Ideally, the CSR will be sent to a Certificate Authority, such as
                // Thawte or Verisign who will verify the identity of the requestor and issue a signed certificate.
                // The second option is to self-sign the CSR, which will be demonstrated in the next section
                (callback: ErrorCallback) => {
                    execute_openssl(
                        "req -new" +
                            " -sha256 " +
                            " -text " +
                            " -extensions " +
                            extension +
                            " " +
                            configOption +
                            " -key " +
                            q(n(params.privateKey!)) +
                            " -out " +
                            q(n(certificateRequestFilename)) +
                            " -subj \"" +
                            subject +
                            "\"",
                        {},
                        callback
                    );
                },

                // Xx // Step 3: Remove Passphrase from Key
                // Xx execute("cp private/cakey.pem private/cakey.pem.org");
                // Xx execute(openssl_path + " rsa -in private/cakey.pem.org
                // Xx -out private/cakey.pem -passin pass:"+paraphrase);

                (callback: ErrorCallback) => {
                    displayTitle("Generate Certificate (self-signed)", callback);
                },
                (callback: ErrorCallback) => {
                    execute_openssl(
                        " x509 -req " +
                            " -days " +
                            params.validity +
                            " -extensions " +
                            extension +
                            " " +
                            " -extfile " +
                            q(n(configFile)) +
                            " -in " +
                            q(n(certificateRequestFilename)) +
                            " -signkey " +
                            q(n(params.privateKey!)) +
                            " -text " +
                            " -out " +
                            q(certificate) +
                            " -text ",
                        {},
                        callback
                    );
                },

                // remove unnecessary certificate request file
                (callback: ErrorCallback) => {
                    fs.unlink(certificateRequestFilename, callback);
                },
            ];
            async.series(tasks, callback);
        } catch (err) {
            callback(err as Error);
        }
    });
}

// tslint:disable-next-line:variable-name
export const configurationFileTemplate: string = _ca_config_template;
/**
 *
 * a minimalist config file for openssl that allows
 * self-signed certificate to be generated.
 *
 */
// tslint:disable-next-line:variable-name
export const configurationFileSimpleTemplate: string = _simple_config_template;

/**
 * @param certificate - the certificate file in PEM format, file must exist
 * @param callback
 */
export function dumpCertificate(certificate: Filename, callback: (err: Error | null, output?: string) => void): void {
    assert(fs.existsSync(certificate));
    assert(typeof callback === "function");

    execute_openssl("x509 " + " -in " + q(n(certificate)) + " -text " + " -noout", {}, callback);
}

export function toDer(certificatePem: string, callback: (err: Error | null, output?: string) => void) {
    assert(fs.existsSync(certificatePem));
    const certificateDer = certificatePem.replace(".pem", ".der");
    execute_openssl("x509  " + " -outform der " + " -in " + certificatePem + " -out " + certificateDer, {}, callback);
}

export function fingerprint(certificatePem: string, callback: (err: Error | null, output?: string) => void) {
    // openssl x509 -in my_certificate.pem -hash -dates -noout -fingerprint
    assert(fs.existsSync(certificatePem));
    execute_openssl("x509  " + " -fingerprint " + " -noout " + " -in " + certificatePem, {}, callback);
}
