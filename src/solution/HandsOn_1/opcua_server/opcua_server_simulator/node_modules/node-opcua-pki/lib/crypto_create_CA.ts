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
// Error.stackTraceLimit = Infinity;
// tslint:disable:variable-name
// tslint:disable:no-console
// tslint:disable:object-literal-sort-keys
// tslint:disable:no-shadowed-variable

import * as assert from "assert";
import * as async from "async";
import * as chalk from "chalk";
import * as rimraf from "rimraf";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";

import { callbackify } from "util";

import { makeApplicationUrn } from "./misc/applicationurn";
import { extractFullyQualifiedDomainName, getFullyQualifiedDomainName } from "./misc/hostname";
import { Subject, SubjectOptions } from "./misc/subject";
import { CertificateAuthority, defaultSubject } from "./pki/certificate_authority";
import { CertificateManager, CreateSelfSignCertificateParam1 } from "./pki/certificate_manager";
import { ErrorCallback, Filename, KeySize } from "./pki/common";
import {
    createCertificateSigningRequest,
    CreateCertificateSigningRequestWithConfigOptions,
    createPrivateKey,
    displayChapter,
    displaySubtitle,
    displayTitle,
    dumpCertificate,
    ensure_openssl_installed,
    fingerprint,
    g_config,
    getPublicKeyFromPrivateKey,
    make_path,
    mkdir,
    setEnv,
    toDer,
    debugLog,
} from "./pki/toolbox";

// see https://github.com/yargs/yargs/issues/781
import * as commands from "yargs";
// eslint-disable-next-line @typescript-eslint/no-var-requires
const { hideBin } = require("yargs/helpers")
// eslint-disable-next-line @typescript-eslint/no-var-requires
const argv = require("yargs/yargs")(hideBin(process.argv))


const epilog = "Copyright (c) sterfive - node-opcua - 2017-2021";

// ------------------------------------------------- some useful dates
function get_offset_date(date: Date, nbDays: number): Date {
    const d = new Date(date.getTime());
    d.setDate(d.getDate() + nbDays);
    return d;
}

const today = new Date();
const yesterday = get_offset_date(today, -1);
const two_years_ago = get_offset_date(today, -2 * 365);
const next_year = get_offset_date(today, 365);

interface LocalConfig {
    CAFolder?: string;
    PKIFolder?: string;

    keySize?: KeySize;

    subject?: SubjectOptions | string;

    certificateDir?: Filename;

    privateKey?: Filename;

    applicationUri?: string;

    outputFile?: string;

    altNames?: string[];
    dns?: string[];
    ip?: string[];

    startDate?: Date;
    validity?: number;
}

let gLocalConfig: LocalConfig = {};

let g_certificateAuthority: CertificateAuthority; // the Certificate Authority

/***
 *
 *
 * prerequisites :
 *   g_config.CAFolder : the folder of the CA
 */
function construct_CertificateAuthority(subject: string, callback: ErrorCallback) {
    // verify that g_config file has been loaded
    assert(typeof gLocalConfig.CAFolder === "string", "expecting a CAFolder in config");
    assert(typeof gLocalConfig.keySize === "number", "expecting a keySize in config");

    if (!g_certificateAuthority) {
        g_certificateAuthority = new CertificateAuthority({
            keySize: gLocalConfig.keySize!,
            location: gLocalConfig.CAFolder!,
            subject,
        });
        g_certificateAuthority.initialize(callback);
    } else {
        // istanbul ignore next
        return callback();
    }
}

let certificateManager: CertificateManager; // the Certificate Manager
/***
 *
 *
 * prerequisites :
 *   g_config.PKIFolder : the folder of the PKI
 */
function construct_CertificateManager(callback: ErrorCallback) {
    assert(typeof gLocalConfig.PKIFolder === "string", "expecting a PKIFolder in config");

    if (!certificateManager) {
        certificateManager = new CertificateManager({
            keySize: gLocalConfig.keySize!,
            location: gLocalConfig.PKIFolder!,
        });
        return certificateManager.initialize(callback);
    } else {
        // istanbul ignore next
        return callback();
    }
}

function displayConfig(config: { [key: string]: any }) {
    function w(str: string, l: number): string {
        return (str + "                            ").substr(0, l);
    }

    console.log(chalk.yellow(" configuration = "));

    for (const [key, value] of Object.entries(config)) {
        console.log("   " + chalk.yellow(w(key, 30)) + " : " + chalk.cyan(value.toString()));
    }
}

function default_template_content(): string {
    // istanbul ignore next
    if ((process as any).pkg && (process as any).pkg.entrypoint) {
        // we are using PKG compiled package !

        // console.log("___filename", __filename);
        // console.log("__dirname", __dirname);
        // console.log("process.pkg.entrypoint", (process as any).pkg.entrypoint);
        const a = fs.readFileSync(path.join(__dirname, "../../bin/crypto_create_CA_config.example.js"), "utf8");
        console.log(a);
        return a;
    }
    function find_default_config_template() {
        const rootFolder = find_module_root_folder();
        let default_config_template = path.join(rootFolder, "bin", path.basename(__filename, ".js") + "_config.example.js");

        if (!fs.existsSync(default_config_template)) {
            default_config_template = path.join(__dirname, "..", path.basename(__filename, ".js") + "_config.example.js");

            if (!fs.existsSync(default_config_template)) {
                default_config_template = path.join(__dirname, "../bin/" + path.basename(__filename, ".js") + "_config.example.js");
            }
        }
        return default_config_template;
    }
    const default_config_template = find_default_config_template();
    assert(fs.existsSync(default_config_template));
    const default_config_template_content = fs.readFileSync(default_config_template, "utf8");
    return default_config_template_content;
}

/**
 *
 */
function find_module_root_folder() {
    let rootFolder = path.join(__dirname);

    for (let i = 0; i < 4; i++) {
        if (fs.existsSync(path.join(rootFolder, "package.json"))) {
            return rootFolder;
        }
        rootFolder = path.join(rootFolder, "..");
    }

    assert(fs.existsSync(path.join(rootFolder, "package.json")), "root folder must have a package.json file");
    return rootFolder;
}

/* eslint complexity:off, max-statements:off */
function readConfiguration(argv: any, callback: ErrorCallback) {
    assert(typeof callback === "function");

    if (argv.silent) {
        g_config.silent = true;
    }

    callbackify(extractFullyQualifiedDomainName)((err: Error | null, fqdn) => {
        // istanbul ignore next
        if (err) {
            return callback(err);
        }
        const hostname = os.hostname();
        let certificateDir: string;

        function performSubstitution(str: string): string {
            str = str.replace("{CWD}", process.cwd());
            if (certificateDir) {
                str = str.replace("{root}", certificateDir);
            }
            if (gLocalConfig && gLocalConfig.PKIFolder) {
                str = str.replace("{PKIFolder}", gLocalConfig.PKIFolder);
            }
            str = str.replace("{hostname}", hostname);
            str = str.replace("%FQDN%", fqdn);
            return str;
        }

        function prepare(file: Filename): Filename {
            const tmp = path.resolve(performSubstitution(file));
            return make_path(tmp);
        }

        // ------------------------------------------------------------------------------------------------------------
        certificateDir = argv.root;
        assert(typeof certificateDir === "string");

        certificateDir = prepare(certificateDir);
        mkdir(certificateDir);
        assert(fs.existsSync(certificateDir));

        // ------------------------------------------------------------------------------------------------------------
        const default_config = path.join(certificateDir, "config.js");

        if (!fs.existsSync(default_config)) {
            // copy
            debugLog(chalk.yellow(" Creating default g_config file "), chalk.cyan(default_config));
            const default_config_template_content = default_template_content();
            fs.writeFileSync(default_config, default_config_template_content);
        } else {
            debugLog(chalk.yellow(" using  g_config file "), chalk.cyan(default_config));
        }
        if (!fs.existsSync(default_config)) {
            console.log(chalk.redBright(" cannot find config file ", default_config));
        }

        // see http://stackoverflow.com/questions/94445/using-openssl-what-does-unable-to-write-random-state-mean
        // set random file to be random.rnd in the same folder as the g_config file
        const defaultRandomFile = path.join(path.dirname(default_config), "random.rnd");
        setEnv("RANDFILE", defaultRandomFile);

        /* eslint global-require: 0*/
        gLocalConfig = require(default_config);

        gLocalConfig.subject = new Subject(gLocalConfig.subject!);

        // if subject is provided on the command line , it has hight priority
        if (argv.subject) {
            gLocalConfig.subject = new Subject(argv.subject);
        }

        // istanbul ignore next
        if (!gLocalConfig.subject.commonName) {
            throw new Error("subject must have a Common Name");
        }

        gLocalConfig.certificateDir = certificateDir;

        // ------------------------------------------------------------------------------------------------------------
        let CAFolder = argv.CAFolder || path.join(certificateDir, "CA");
        CAFolder = prepare(CAFolder);
        gLocalConfig.CAFolder = CAFolder;

        // ------------------------------------------------------------------------------------------------------------
        gLocalConfig.PKIFolder = path.join(gLocalConfig.certificateDir, "PKI");
        if (argv.PKIFolder) {
            gLocalConfig.PKIFolder = prepare(argv.PKIFolder);
        }
        gLocalConfig.PKIFolder = prepare(gLocalConfig.PKIFolder);

        if (argv.privateKey) {
            gLocalConfig.privateKey = prepare(argv.privateKey);
        }

        if (argv.applicationUri) {
            gLocalConfig.applicationUri = performSubstitution(argv.applicationUri);
        }

        if (argv.output) {
            gLocalConfig.outputFile = argv.output;
        }

        gLocalConfig.altNames = [];
        if (argv.altNames) {
            gLocalConfig.altNames = argv.altNames.split(";");
        }
        gLocalConfig.dns = [getFullyQualifiedDomainName()];
        if (argv.dns) {
            gLocalConfig.dns = argv.dns.split(",").map(performSubstitution);
        }
        gLocalConfig.ip = [];
        if (argv.ip) {
            gLocalConfig.ip = argv.ip.split(",");
        }
        if (argv.keySize) {
            const v = argv.keySize;
            if (v !== 1024 && v !== 2048 && v !== 3072 && v !== 4096) {
                throw new Error("invalid keysize specified " + v + " should be 1024,2048,3072 or 4096");
            }
            gLocalConfig.keySize = argv.keySize;
        }

        if (argv.validity) {
            gLocalConfig.validity = argv.validity;
        }
        // xx displayConfig(g_config);
        // ------------------------------------------------------------------------------------------------------------

        return callback();
    });
}

interface OptionMap {
    [key: string]: commands.Options;
}

function add_standard_option(options: OptionMap, optionName: string) {
    switch (optionName) {
    case "root":
        options.root = {
            alias: "r",
            type: "string",
            default: "{CWD}/certificates",
            describe: "the location of the Certificate folder",
        };
        break;

    case "CAFolder":
        options.CAFolder = {
            alias: "c",
            type: "string",
            default: "{root}/CA",
            describe: "the location of the Certificate Authority folder",
        };
        break;

    case "PKIFolder":
        options.PKIFolder = {
            type: "string",
            default: "{root}/PKI",
            describe: "the location of the Public Key Infrastructure",
        };
        break;

    case "silent":
        options.silent = {
            alias: "s",
            type: "boolean",
            default: false,
            describe: "minimize output",
        };
        break;

    case "privateKey":
        options.privateKey = {
            alias: "p",
            type: "string",
            default: "{PKIFolder}/own/private_key.pem",
            describe: "the private key to use to generate certificate",
        };
        break;

    case "keySize":
        options.keySize = {
            alias: ["k", "keyLength"],
            type: "number",
            default: 2048,
            describe: "the private key size in bits (1024|2048|3072|4096)",
        };
        break;
    default:
        throw Error("Unknown option  " + optionName);
    }
}

function on_completion(err: Error | null | undefined, done: ErrorCallback) {
    assert(typeof done === "function", "expecting function");
    // istanbul ignore next
    if (err) {
        console.log(chalk.redBright("ERROR : ") + err.message);
    }
    done();
}

function createDefaultCertificate(
    base_name: string,
    prefix: string,
    key_length: KeySize,
    applicationUri: string,
    dev: any,
    done: ErrorCallback
) {
    // possible key length in bits
    assert(key_length === 1024 || key_length === 2048 || key_length === 3072 || key_length === 4096);

    assert(typeof done === "function");

    const private_key_file = make_path(base_name, prefix + "key_" + key_length + ".pem");
    const public_key_file = make_path(base_name, prefix + "public_key_" + key_length + ".pub");
    const certificate_file = make_path(base_name, prefix + "cert_" + key_length + ".pem");
    const certificate_file_outofdate = make_path(base_name, prefix + "cert_" + key_length + "_outofdate.pem");
    const certificate_file_not_active_yet = make_path(base_name, prefix + "cert_" + key_length + "_not_active_yet.pem");
    const certificate_revoked = make_path(base_name, prefix + "cert_" + key_length + "_revoked.pem");
    const self_signed_certificate_file = make_path(base_name, prefix + "selfsigned_cert_" + key_length + ".pem");

    const fqdn = getFullyQualifiedDomainName();
    const hostname = os.hostname();
    const dns: string[] = [
        // for conformance reason, localhost shall not be present in the DNS field of COP
        // ***FORBIDEN** "localhost",
        getFullyQualifiedDomainName(),
    ];
    if (hostname !== fqdn) {
        dns.push(hostname);
    }

    const ip: string[] = [];

    function createCertificateIfNotExist(
        certificate: Filename,
        private_key: Filename,
        applicationUri: string,
        startDate: Date,
        validity: number,
        callback: (err?: Error | null, certificate?: string) => void
    ) {
        // istanbul ignore next
        if (fs.existsSync(certificate)) {
            console.log(chalk.yellow("         certificate"), chalk.cyan(certificate), chalk.yellow(" already exists => skipping"));
            return callback();
        } else {
            createCertificate(certificate, private_key, applicationUri, startDate, validity, callback);
        }
    }

    function createCertificate(
        certificate: Filename,
        privateKey: Filename,
        applicationUri: string,
        startDate: Date,
        validity: number,
        callback: (err: Error | null, certificate?: string) => void
    ) {
        const certificateSigningRequestFile = certificate + ".csr";

        const configFile = make_path(base_name, "../certificates/PKI/own/openssl.cnf");

        const dns = [os.hostname()];
        const ip = ["127.0.0.1"];

        const params: CreateCertificateSigningRequestWithConfigOptions = {
            applicationUri,
            privateKey,
            rootDir: ".",
            configFile,
            dns,
            ip,
        };

        // create CSR
        createCertificateSigningRequest(certificateSigningRequestFile, params, (err?: Error) => {
            // istanbul ignore next
            if (err) {
                return callback(err);
            }
            g_certificateAuthority.signCertificateRequest(
                certificate,
                certificateSigningRequestFile,
                {
                    applicationUri,
                    dns,
                    ip,
                    startDate,
                    validity,
                },
                callback
            );
        });
    }

    function createSelfSignedCertificate(
        certificate: Filename,
        private_key: Filename,
        applicationUri: string,
        startDate: Date,
        validity: number,
        callback: ErrorCallback
    ) {
        g_certificateAuthority.createSelfSignedCertificate(
            certificate,
            private_key,
            {
                applicationUri,
                dns,
                ip,
                startDate,
                validity,
            },
            callback
        );
    }

    function revoke_certificate(certificate: Filename, callback: ErrorCallback) {
        g_certificateAuthority.revokeCertificate(certificate, {}, callback);
    }

    function createPrivateKeyIfNotExist(privateKey: Filename, keyLength: KeySize, callback: ErrorCallback) {
        if (fs.existsSync(privateKey)) {
            console.log(chalk.yellow("         privateKey"), chalk.cyan(privateKey), chalk.yellow(" already exists => skipping"));
            return callback();
        } else {
            createPrivateKey(privateKey, keyLength, callback);
        }
    }

    let tasks1 = [
        (callback: ErrorCallback) => displaySubtitle(" create private key :" + private_key_file, callback),

        (callback: ErrorCallback) => createPrivateKeyIfNotExist(private_key_file, key_length, callback),

        (callback: ErrorCallback) => displaySubtitle(" extract public key " + public_key_file + " from private key ", callback),

        (callback: ErrorCallback) => getPublicKeyFromPrivateKey(private_key_file, public_key_file, callback),

        (callback: ErrorCallback) => displaySubtitle(" create Certificate " + certificate_file, callback),

        (callback: ErrorCallback) =>
            createCertificateIfNotExist(certificate_file, private_key_file, applicationUri, yesterday, 365, callback),

        (callback: ErrorCallback) => displaySubtitle(" create self signed Certificate " + self_signed_certificate_file, callback),

        (callback: ErrorCallback) => {
            if (fs.existsSync(self_signed_certificate_file)) {
                // self_signed certificate already exists
                return callback();
            }
            createSelfSignedCertificate(self_signed_certificate_file, private_key_file, applicationUri, yesterday, 365, callback);
        },
    ];

    if (dev) {
        const tasks2 = [
            (callback: ErrorCallback) =>
                createCertificateIfNotExist(
                    certificate_file_outofdate,
                    private_key_file,
                    applicationUri,
                    two_years_ago,
                    365,
                    callback
                ),

            (callback: ErrorCallback) =>
                createCertificateIfNotExist(
                    certificate_file_not_active_yet,
                    private_key_file,
                    applicationUri,
                    next_year,
                    365,
                    callback
                ),

            (callback: ErrorCallback) => {
                if (fs.existsSync(certificate_revoked)) {
                    // self_signed certificate already exists
                    return callback();
                }
                createCertificateIfNotExist(
                    certificate_revoked,
                    private_key_file,
                    applicationUri + "Revoked", // make sure we used a uniq URI here
                    yesterday,
                    365,
                    (err?: Error | null, certificate?: string) => {
                        console.log(" certificate to revoke => ", certificate);
                        revoke_certificate(certificate_revoked, callback);
                    }
                );
            },
        ];
        tasks1 = tasks1.concat(tasks2);
    }

    async.series(tasks1, done);
}

// tslint:disable-next-line:no-empty
let done: ErrorCallback = (err?: Error | null) => {/** */};

function create_default_certificates(dev: boolean, done: ErrorCallback) {
    function __create_default_certificates(
        base_name: string,
        prefix: string,
        key_length: KeySize,
        applicationUri: string,
        done: ErrorCallback
    ) {
        createDefaultCertificate(base_name, prefix, key_length, applicationUri, dev, done);
    }
    assert(gLocalConfig);
    const base_name = gLocalConfig.certificateDir!;
    assert(fs.existsSync(base_name));

    let clientURN: string;
    let serverURN: string;
    let discoveryServerURN: string;
    const task1 = [
        (callback: ErrorCallback) => {
            callbackify(extractFullyQualifiedDomainName)((err: Error | null, fqdn?: string) => {
                // xx console.log("FQDN = ", fqdn, err ? err.message : "");
                callback();
            });
        },
        (callback: ErrorCallback) => {
            const hostname = os.hostname();
            const fqdn = getFullyQualifiedDomainName();
            console.log(chalk.yellow("     hostname = "), chalk.cyan(hostname));
            console.log(chalk.yellow("     fqdn     = "), chalk.cyan(fqdn));
            clientURN = makeApplicationUrn(hostname, "NodeOPCUA-Client");
            serverURN = makeApplicationUrn(hostname, "NodeOPCUA-Server");
            discoveryServerURN = makeApplicationUrn(hostname, "NodeOPCUA-DiscoveryServer");
            setImmediate(callback);
        },

        (callback: ErrorCallback) => displayTitle("Create  Application Certificate for Server & its private key", callback),

        (callback: ErrorCallback) => {
            async.parallelLimit(
                [
                    (callback1: ErrorCallback) => __create_default_certificates(base_name, "client_", 1024, clientURN, callback1),
                    (callback1: ErrorCallback) => __create_default_certificates(base_name, "client_", 2048, clientURN, callback1),
                    (callback1: ErrorCallback) => __create_default_certificates(base_name, "client_", 3072, clientURN, callback1),
                    (callback1: ErrorCallback) => __create_default_certificates(base_name, "client_", 4096, clientURN, callback1),
                ],
                1,
                callback
            );
        },
        (callback: ErrorCallback) => displayTitle("Create  Application Certificate for Client & its private key", callback),
        (callback: ErrorCallback) => {
            async.parallelLimit(
                [
                    (callback: ErrorCallback) => __create_default_certificates(base_name, "server_", 1024, serverURN, callback),
                    (callback: ErrorCallback) => __create_default_certificates(base_name, "server_", 2048, serverURN, callback),
                    (callback: ErrorCallback) => __create_default_certificates(base_name, "server_", 3072, serverURN, callback),
                    (callback: ErrorCallback) => __create_default_certificates(base_name, "server_", 4096, serverURN, callback),
                ],
                1,
                callback
            );
        },
        (callback: ErrorCallback) =>
            displayTitle("Create  Application Certificate for DiscoveryServer & its private key", callback),
        (callback: ErrorCallback) => {
            async.parallelLimit(
                [
                    (callback: ErrorCallback) =>
                        __create_default_certificates(base_name, "discoveryServer_", 1024, discoveryServerURN, callback),
                    (callback: ErrorCallback) =>
                        __create_default_certificates(base_name, "discoveryServer_", 2048, discoveryServerURN, callback),
                    (callback: ErrorCallback) =>
                        __create_default_certificates(base_name, "discoveryServer_", 3072, discoveryServerURN, callback),
                    (callback: ErrorCallback) =>
                        __create_default_certificates(base_name, "discoveryServer_", 4096, discoveryServerURN, callback),
                ],
                1,
                callback
            );
        },
    ];
    async.series(task1, (err?: Error | null) => {
        // istanbul ignore next
        if (err) {
            console.log("ERROR FOUND => ", err.message);
        }
        done(err);
    });
}

function createDefaultCertificates(dev: boolean, callback: ErrorCallback) {
    async.series(
        [
            (callback: ErrorCallback) => construct_CertificateAuthority("", callback),
            (callback: ErrorCallback) => construct_CertificateManager(callback),
            (callback: ErrorCallback) => create_default_certificates(dev, callback),
        ],
        (err?: Error | null) => {
            // istanbul ignore next
            if (err) {
                console.log(chalk.red("ERROR "), err.message);
            }
            return callback(err);
        }
    );
}

assert(typeof done === "function");

argv
    .strict()
    .wrap(132)
    .command(
        "demo",
        "create default certificate for node-opcua demos",
        (yargs: commands.Argv) => {
            const options: { [key: string]: commands.Options } = {};
            options.dev = {
                type: "boolean",
                describe: "create all sort of fancy certificates for dev testing purposes",
            };
            options.clean = {
                type: "boolean",
                describe: "Purge existing directory [use with care!]",
            };

            add_standard_option(options, "silent");
            add_standard_option(options, "root");

            const local_argv = yargs
                .strict()
                .wrap(132)
                .options(options)
                .usage("$0  demo [--dev] [--silent] [--clean]")
                .example("$0  demo --dev", "create a set of demo certificates")
                .help("help").argv;

            return local_argv;
        },
        (local_argv: any) => {
            const tasks = [];

            tasks.push((callback: ErrorCallback) => ensure_openssl_installed(callback));
            tasks.push((callback: ErrorCallback) => displayChapter("Create Demo certificates", callback));
            tasks.push((callback: ErrorCallback) => displayTitle("reading configuration", callback));
            tasks.push((callback: ErrorCallback) => readConfiguration(local_argv, callback));

            if (local_argv.clean) {
                tasks.push((callback: ErrorCallback) => displayTitle("Cleaning old certificates", callback));

                tasks.push((callback: ErrorCallback) => {
                    assert(gLocalConfig);
                    const certificateDir = gLocalConfig.certificateDir;
                    rimraf(certificateDir + "/*.pem*", () => {
                        return callback();
                    });
                });

                tasks.push((callback: ErrorCallback) => {
                    assert(gLocalConfig);
                    const certificateDir = gLocalConfig.certificateDir;
                    rimraf(certificateDir + "/*.pub", () => {
                        return callback();
                    });
                });

                tasks.push((callback: ErrorCallback) => {
                    assert(gLocalConfig);
                    const certificateDir = gLocalConfig.certificateDir!;
                    mkdir(certificateDir);
                    return callback();
                });
            }

            tasks.push((callback: ErrorCallback) => displayTitle("create certificates", callback));

            tasks.push((callback: ErrorCallback) => createDefaultCertificates(local_argv.dev, callback));

            tasks.push((callback: ErrorCallback) => displayChapter("Demo certificates  CREATED", callback));

            async.series(tasks, (err?: Error | null) => on_completion(err, done));
        }
    )

    .command(
        "createCA",
        "create a Certificate Authority",
        /* builder*/ (yargs: commands.Argv) => {
            const options: any = {
                subject: {
                    default: defaultSubject,
                    type: "string",
                    describe: "the CA certificate subject",
                },
            };

            add_standard_option(options, "root");
            add_standard_option(options, "CAFolder");
            add_standard_option(options, "keySize");
            add_standard_option(options, "silent");

            const local_argv = yargs.strict().wrap(132).options(options).help("help").epilog(epilog).argv;
            return local_argv;
        },
        /*handler*/ (local_argv: any) => {
            const tasks = [];
            tasks.push(ensure_openssl_installed);
            tasks.push((callback: ErrorCallback) => readConfiguration(local_argv, callback));
            tasks.push((callback: ErrorCallback) => construct_CertificateAuthority(local_argv.subject, callback));
            async.series(tasks, (err?: Error | null) => on_completion(err, done));
        }
    )

    .command(
        "createPKI",
        "create a Public Key Infrastructure",
        (yargs: commands.Argv) => {
            const options = {};

            add_standard_option(options, "root");
            add_standard_option(options, "PKIFolder");
            add_standard_option(options, "keySize");
            add_standard_option(options, "silent");

            return yargs.strict().wrap(132).options(options).help("help").epilog(epilog).argv;
        },
        (local_argv: any) => {
            const tasks = [];
            tasks.push((callback: ErrorCallback) => readConfiguration(local_argv, callback));
            tasks.push((callback: ErrorCallback) => construct_CertificateManager(callback));
            async.series(tasks, (err?: Error | null) => on_completion(err, done));
        }
    )

    // ----------------------------------------------- certificate
    .command(
        "certificate",
        "create a new certificate",
        (yargs: commands.Argv) => {
            const options: OptionMap = {
                applicationUri: {
                    alias: "a",
                    demand: true,
                    describe: "the application URI",
                    default: "urn:{hostname}:Node-OPCUA-Server",
                    type: "string",
                },
                output: {
                    default: "my_certificate.pem",
                    alias: "o",
                    demand: true,
                    describe: "the name of the generated certificate =>",
                    type: "string",
                },
                selfSigned: {
                    alias: "s",
                    default: false,
                    type: "boolean",
                    describe: "if true, certificate will be self-signed",
                },
                validity: {
                    alias: "v",
                    default: null,
                    type: "number",
                    describe: "the certificate validity in days",
                },
                dns: {
                    default: "{hostname}",
                    type: "string",
                    describe: "the list of valid domain name (comma separated)",
                },
                ip: {
                    default: "",
                    type: "string",
                    describe: "the list of valid IPs (comma separated)",
                },
                subject: {
                    default: "",
                    type: "string",
                    describe: "the certificate subject ( for instance /C=FR/ST=Centre/L=Orleans/O=SomeOrganization/CN=Hello )",
                },
            };
            add_standard_option(options, "silent");
            add_standard_option(options, "root");
            add_standard_option(options, "CAFolder");
            add_standard_option(options, "PKIFolder");
            add_standard_option(options, "privateKey");

            const local_argv = yargs.strict().wrap(132).options(options).help("help").epilog(epilog).argv;
            return local_argv;
        },
        (local_argv: any) => {
            function command_certificate(local_argv: any, done: ErrorCallback) {
                assert(typeof done === "function");
                const selfSigned = local_argv.selfSigned;

                if (!selfSigned) {
                    command_full_certificate(local_argv, done);
                } else {
                    command_selfsigned_certificate(local_argv, done);
                }
            }

            function command_selfsigned_certificate(local_argv: any, done: ErrorCallback) {
                const tasks = [];

                tasks.push((callback: ErrorCallback) => {
                    callbackify(extractFullyQualifiedDomainName)((err: Error | null, fqdn?: string) => {
                        // xx console.log("FQDN = ", fqdn, err ? err.message : "");
                        callback();
                    });
                });

                tasks.push((callback: ErrorCallback) => readConfiguration(local_argv, callback));

                tasks.push((callback: ErrorCallback) => construct_CertificateManager(callback));

                tasks.push((callback: ErrorCallback) =>
                    displaySubtitle(" create self signed Certificate " + gLocalConfig.outputFile, callback)
                );

                tasks.push((callback: ErrorCallback) => {
                    let subject =
                        local_argv.subject && local_argv.subject.length > 1
                            ? new Subject(local_argv.subject)
                            : gLocalConfig.subject!;

                    subject = JSON.parse(JSON.stringify(subject));

                    const params: CreateSelfSignCertificateParam1 = {
                        applicationUri: gLocalConfig.applicationUri || "",
                        dns: gLocalConfig.dns || [],
                        ip: gLocalConfig.ip || [],
                        outputFile: gLocalConfig.outputFile || "self_signed_certificate.pem",
                        startDate: gLocalConfig.startDate || new Date(),
                        subject,
                        validity: gLocalConfig.validity || 365,
                    };

                    certificateManager.createSelfSignedCertificate(params, (err?: Error | null) => {
                        callback(err!);
                    });
                });
                // console.log(" output file =  ",g_config.output);

                async.series(tasks, (err?: Error | null) => on_completion(err, done));
            }

            function command_full_certificate(local_argv: any, done: ErrorCallback) {
                let the_csr_file: Filename;
                let certificate: Filename;
                const tasks = [];

                tasks.push((callback: ErrorCallback) => readConfiguration(local_argv, callback));

                tasks.push((callback: ErrorCallback) => construct_CertificateManager(callback));

                tasks.push((callback: ErrorCallback) => construct_CertificateAuthority("", callback));

                tasks.push((callback: ErrorCallback) => {
                    assert(fs.existsSync(gLocalConfig.CAFolder!), " CA folder must exist");
                    return callback();
                });

                tasks.push((callback: ErrorCallback) => {
                    gLocalConfig.privateKey = undefined; // use PKI private key
                    // create a Certificate Request from the certificate Manager

                    gLocalConfig.subject =
                        local_argv.subject && local_argv.subject.length > 1 ? local_argv.subject : gLocalConfig.subject;

                    certificateManager.createCertificateRequest(gLocalConfig, (err: Error | null, csr_file?: string) => {
                        // istanbul ignore next
                        if (err) {
                            return callback(err);
                        }

                        the_csr_file = csr_file!;
                        console.log(" csr_file = ", csr_file);
                        return callback();
                    });
                });
                tasks.push((callback: ErrorCallback) => {
                    certificate = the_csr_file.replace(".csr", ".pem");

                    if (fs.existsSync(certificate)) {
                        return callback(new Error(" File " + certificate + " already exist"));
                    }

                    g_certificateAuthority.signCertificateRequest(certificate, the_csr_file, gLocalConfig, (err: Error | null) => {
                        return callback(err!);
                    });
                });

                tasks.push((callback: ErrorCallback) => {
                    // console.error("g_config.outputFile=", gLocalConfig.outputFile);

                    assert(typeof gLocalConfig.outputFile === "string");
                    fs.writeFileSync(gLocalConfig.outputFile!, fs.readFileSync(certificate, "ascii"));
                    return callback();
                });

                async.series(tasks, (err?: Error | null) => on_completion(err, done));
            }

            command_certificate(local_argv, done);
        }
    )

    // ----------------------------------------------- revoke
    .command(
        "revoke <certificateFile>",
        "revoke a existing certificate",
        (yargs: commands.Argv) => {
            const options = {};
            add_standard_option(options, "root");
            add_standard_option(options, "CAFolder");

            yargs.strict().wrap(132).help("help").usage("$0 revoke  my_certificate.pem").options(options).epilog(epilog);
            return yargs;
        },
        (local_argv: any) => {
            function revoke_certificate(certificate: Filename, callback: ErrorCallback) {
                g_certificateAuthority.revokeCertificate(certificate, {}, callback);
            }

            // example : node bin\crypto_create_CA.js revoke my_certificate.pem
            const certificate = path.resolve(local_argv.certificateFile);
            console.log(chalk.yellow(" Certificate to revoke : "), chalk.cyan(certificate));

            if (!fs.existsSync(certificate)) {
                return done(new Error("cannot find certificate to revoke " + certificate));
            }
            const tasks = [];

            tasks.push((callback: ErrorCallback) => readConfiguration(local_argv, callback));
            tasks.push((callback: ErrorCallback) => construct_CertificateAuthority("", callback));
            tasks.push((callback: ErrorCallback) => revoke_certificate(certificate, callback));

            async.series(tasks, (err?: Error | null) => {
                if (!err) {
                    console.log("done ... ");
                    console.log("  crl = ", g_certificateAuthority.revocationList);
                    console.log("\nyou should now publish the new Certificate Revocation List");
                } else {
                    console.log("failed ... ", err.message);
                }
                done(err);
            });
        }
    )

    .command(
        "dump <certificateFile>",
        "display a certificate",
        () => { /** */},
        (yargs: any) => {
            dumpCertificate(yargs.certificateFile, (err: Error | null, data?: string) => {
                if (!err) {
                    console.log(data);
                }
                done(err!);
            });
        }
    )

    .command(
        "toder <pemCertificate>",
        "convert a certificate to a DER format with finger print",
        () => {/** */},
        (yargs: commands.Argv) => {
            function convertToDerFromCommandLine(argv: any, done: ErrorCallback) {
                toDer(argv.pemCertificate, (err: Error | null) => done(err!));
            }
            convertToDerFromCommandLine(yargs, done);
        }
    )

    .command(
        "fingerprint <certificateFile>",
        "print the certificate fingerprint",
        () => { /** */},
        (local_argv: any) => {
            const certificate = local_argv.certificateFile;
            fingerprint(certificate, (err: Error | null, data?: string) => {
                if (!err) {
                    const s = data!.split("=")[1].split(":").join("").trim();
                    console.log(s);
                }
                done(err!);
            });
        }
    )
    .command("$0", "help", (yargs: commands.Argv) => {
        console.log("--help for help");
        return yargs;
    })
    .epilog(epilog)
    .help("help")
    .strict().argv;

export function main(argumentsList: string, _done?: ErrorCallback) {
    if (_done) {
        done = _done!;
    }

    commands.parse(argumentsList, (err: Error | null, g_argv: any) => {
        // istanbul ignore next
        if (err) {
            console.log(" err = ", err);
            console.log(" use --help for more info");
            setImmediate(() => {
                commands.showHelp();
                done(err);
            });
        } else {
            if (g_argv.help) {
                setImmediate(() => {
                    commands.showHelp();
                    done();
                });
            } else {
                done();
            }
        }
    });
}
