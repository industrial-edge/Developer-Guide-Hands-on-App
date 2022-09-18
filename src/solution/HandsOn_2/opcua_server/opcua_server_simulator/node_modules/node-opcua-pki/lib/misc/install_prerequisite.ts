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
// tslint:disable:no-console
// tslint:disable:no-shadowed-variable

import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import * as url from "url";
import * as assert from "assert";
import * as byline from "byline";
import * as chalk from "chalk";
import * as child_process from "child_process";
import * as ProgressBar from "progress";
import * as yauzl from "yauzl";
import { Readable } from "stream";

import Table = require("cli-table");

const doDebug = process.env.NODEOPCUAPKIDEBUG || false;

declare interface ProxyOptions {
    host: string;
    port: number;
    localAddress?: string;
    proxyAuth?: string;
    headers?: { [key: string]: any };
    protocol: string; // "https" | "http"
}
declare interface WgetOptions {
    gunzip?: boolean;
    proxy?: ProxyOptions;
}

declare interface WgetInterface {
    download(url: string, outputFilename: string, options: WgetOptions): any;
}

// tslint:disable-next-line:no-var-requires
// eslint-disable-next-line @typescript-eslint/no-var-requires
const wget = require("wget-improved-2") as WgetInterface;

type CallbackFunc<T> = (err: Error | null, result?: T) => void;

interface ExecuteResult {
    exitCode: number;
    output: string;
}

function makeOptions(): WgetOptions {
    const proxy =
        process.env.HTTPS_PROXY || process.env.https_proxy || process.env.HTTP_PROXY || process.env.http_proxy || undefined;
    if (proxy) {
        const a = new url.URL(proxy);
        const auth = a.username ? a.username + ":" + a.password : undefined;

        const options: WgetOptions = {
            proxy: {
                port: a.port ? parseInt(a.port, 10) : 80,
                protocol: a.protocol.replace(":", ""),
                host: a.hostname ?? "",
                proxyAuth: auth,
            },
        };
        console.log(chalk.green("- using proxy "), proxy);
        console.log(options);
        return options;
    }
    return {};
}

function execute(cmd: string, callback: CallbackFunc<ExecuteResult>, cwd?: string) {
    let output = "";

    // xx cwd = cwd ? {cwd: cwd} : {};
    const options = {
        cwd,
        windowsHide: true,
    };

    const child = child_process.exec(
        cmd,
        options,
        (err: child_process.ExecException | null /*, stdout: string, stderr: string*/) => {
            const exitCode = err === null ? 0 : err!.code!;
            callback(err ? err : null, { exitCode, output });
        }
    );

    const stream1 = byline(child.stdout!);
    stream1.on("data", (line: string) => {
        output += line + "\n";
        // istanbul ignore next
        if (doDebug) {
            process.stdout.write("        stdout " + chalk.yellow(line) + "\n");
        }
    });
}

function quote(str: string): string {
    return '"' + str.replace(/\\/g, "/") + "\"";
}

function is_expected_openssl_version(strVersion: string): boolean {
    return !!strVersion.match(/OpenSSL 1.(0|1)./);
}

export function check_system_openssl_version(callback: (err: Error | null, output?: string) => void) {
    execute("which openssl", (err: Error | null, result?: ExecuteResult) => {
        // istanbul ignore next
        if (err) {
            console.log("warning: ", err.message);
            return callback(new Error("Cannot find openssl"));
        }

        const exitCode = result!.exitCode;
        const output = result!.output;

        if (exitCode !== 0) {
            console.log(
                chalk.yellow(" it seems that ") + chalk.cyan("openssl") + chalk.yellow(" is not installed on your computer ")
            );
            console.log(chalk.yellow("Please install it before running this programs"));

            return callback(new Error("Cannot find openssl"));
        }
        const opensslExecPath = output.replace(/\n\r/g, "").trim();

        // tslint:disable-next-line:variable-name
        const q_opensslExecPath = quote(opensslExecPath);

        // istanbul ignore next
        if (doDebug) {
            console.log("              OpenSSL found in : " + chalk.yellow(opensslExecPath));
        }
        // ------------------------ now verify that openssl version is the correct one
        execute(q_opensslExecPath + " version", (err: Error | null, result?: ExecuteResult) => {
            if (err) {
                return callback(err);
            }

            const exitCode = result!.exitCode;
            const output = result!.output;

            const version = output.trim();

            const versionOK = exitCode === 0 && is_expected_openssl_version(version);
            if (!versionOK) {
                let message =
                    chalk.whiteBright("Warning !!!!!!!!!!!! ") +
                    "\nyour version of openssl is " +
                    version +
                    ". It doesn't match the expected version";

                if (process.platform === "darwin") {
                    message +=
                        chalk.cyan("\nplease refer to :") +
                        chalk.yellow(
                            " https://github.com/node-opcua/node-opcua/" + "wiki/installing-node-opcua-or-node-red-on-MacOS"
                        );
                }

                const table = new Table();
                table.push([message]);
                console.error(table.toString());
            }
            return callback(null, output);
        });
    });
}

function install_and_check_win32_openssl_version(callback: (err: Error | null, opensslExecPath?: string) => void): void {
    const downloadFolder = path.join(os.tmpdir(), ".");

    function get_openssl_folder_win32(): string {
        if (process.env.LOCALAPPDATA) {
            const userProgramFolder = path.join(process.env.LOCALAPPDATA, "Programs");
            if (fs.existsSync(userProgramFolder)) {
                return path.join(userProgramFolder, "openssl");
            }
        }
        return path.join(process.cwd(), "openssl");
    }

    function get_openssl_exec_path_win32(): string {
        const opensslFolder = get_openssl_folder_win32();
        return path.join(opensslFolder, "openssl.exe");
    }

    function check_openssl_win32(callback: (err: Error | null, opensslOk?: boolean, opensslPath?: string) => void) {
        const opensslExecPath = get_openssl_exec_path_win32();

        const exists = fs.existsSync(opensslExecPath);
        if (!exists) {
            console.log("checking presence of ", opensslExecPath);
            console.log(chalk.red(" cannot find file ") + opensslExecPath);
            return callback(null, false, "cannot find file " + opensslExecPath);
        } else {
            // tslint:disable-next-line:variable-name
            const q_openssl_exe_path = quote(opensslExecPath);
            const cwd = ".";

            execute(
                q_openssl_exe_path + " version",
                (err: Error | null, result?: ExecuteResult) => {
                    if (err) {
                        return callback(err);
                    }

                    const exitCode = result!.exitCode;
                    const output = result!.output;

                    const version = output.trim();
                    // istanbul ignore next

                    if (doDebug) {
                        console.log(" Version = ", version);
                    }
                    callback(null, exitCode === 0 && is_expected_openssl_version(version), version);
                },
                cwd
            );
        }
    }

    /**
     * detect whether windows OS is a 64 bits or 32 bits
     * http://ss64.com/nt/syntax-64bit.html
     * http://blogs.msdn.com/b/david.wang/archive/2006/03/26/howto-detect-process-bitness.aspx
     * @return {number}
     */
    function win32or64(): 32 | 64 {
        if (process.env.PROCESSOR_ARCHITECTURE === "x86" && process.env.PROCESSOR_ARCHITEW6432) {
            return 64;
        }

        if (process.env.PROCESSOR_ARCHITECTURE === "AMD64") {
            return 64;
        }

        // check if we are running node  x32 on a x64 arch
        if (process.env.CURRENT_CPU === "x64") {
            return 64;
        }
        return 32;
    }

    function download_openssl(callback: (err: Error | null, downloadedFile?: string) => void) {
        // const url = (win32or64() === 64 )
        //         ? "http://indy.fulgan.com/SSL/openssl-1.0.2o-x64_86-win64.zip"
        //         : "http://indy.fulgan.com/SSL/openssl-1.0.2o-i386-win32.zip"
        //     ;
        const url =
            win32or64() === 64
                ? "https://github.com/node-opcua/node-opcua-pki/releases/download/2.14.2/openssl-1.0.2u-x64_86-win64.zip"
                : "https://github.com/node-opcua/node-opcua-pki/releases/download/2.14.2/openssl-1.0.2u-i386-win32.zip";
        // the zip file
        const outputFilename = path.join(downloadFolder, path.basename(url));

        console.log("downloading " + chalk.yellow(url) + " to " + outputFilename);

        if (fs.existsSync(outputFilename)) {
            return callback(null, outputFilename);
        }
        const options = makeOptions();
        const bar = new ProgressBar(chalk.cyan("[:bar]") + chalk.cyan(" :percent ") + chalk.white(":etas"), {
            complete: "=",
            incomplete: " ",
            total: 100,
            width: 100,
        });

        const download = wget.download(url, outputFilename, options);
        download.on("error", (err: Error) => {
            console.log(err);
        });
        download.on("end", (output: string) => {
            // istanbul ignore next
            if (doDebug) {
                console.log(output);
            }
            // console.log("done ...");
            setImmediate(() => {
                callback(null, outputFilename);
            });
        });
        download.on("progress", (progress: any) => {
            bar.update(progress);
        });
    }

    function unzip_openssl(zipFilename: string, callback: (err?: Error) => void) {
        const opensslFolder = get_openssl_folder_win32();

        yauzl.open(zipFilename, { lazyEntries: true }, (err?: Error | null, zipFile?: yauzl.ZipFile) => {
            if (err) {
                return callback(err);
            }
            if (!zipFile) {
                return callback(new Error("Internal error"));
            }

            zipFile.readEntry();

            zipFile.on("end", (err?: Error) => {
                setImmediate(() => {
                    // istanbul ignore next
                    if (doDebug) {
                        console.log("unzip done");
                    }
                    callback(err);
                });
            });

            zipFile.on("entry", (entry: yauzl.Entry) => {
                zipFile.openReadStream(entry, (err?: Error | null, readStream?: Readable) => {
                    if (err) {
                        return callback(err);
                    }

                    const file = path.join(opensslFolder, entry.fileName);

                    // istanbul ignore next
                    if (doDebug) {
                        console.log(" unzipping :", file);
                    }

                    const writeStream = fs.createWriteStream(file, "binary");
                    // ensure parent directory exists
                    readStream!.pipe(writeStream);

                    writeStream.on("close", () => {
                        zipFile.readEntry();
                    });
                });
            });
        });
    }

    const opensslFolder = get_openssl_folder_win32();
    const opensslExecPath = get_openssl_exec_path_win32();

    if (!fs.existsSync(opensslFolder)) {
        // istanbul ignore next
        if (doDebug) {
            console.log("creating openssl_folder", opensslFolder);
        }
        fs.mkdirSync(opensslFolder);
    }

    check_openssl_win32((err: Error | null, opensslOK?: boolean) => {
        if (err) {
            return callback(err);
        }
        if (!opensslOK) {
            console.log(chalk.yellow("openssl seems to be missing and need to be installed"));
            download_openssl((err: Error | null, filename?: string) => {
                if (err) {
                    return callback(err);
                }

                // istanbul ignore next
                if (doDebug) {
                    console.log("deflating ", chalk.yellow(filename!));
                }
                unzip_openssl(filename!, (err?: Error) => {
                    if (err) {
                        return callback(err);
                    }
                    const opensslExists = !!fs.existsSync(opensslExecPath);

                    // istanbul ignore next
                    if (doDebug) {
                        console.log(
                            "verifying ",
                            opensslExists,
                            opensslExists ? chalk.green("OK ") : chalk.red(" Error"),
                            opensslExecPath
                        );
                        console.log("done ", err ? err : "");
                    }

                    check_openssl_win32((err: Error | null) => {
                        callback(err, opensslExecPath);
                    });
                });
            });
        } else {
            // istanbul ignore next
            if (doDebug) {
                console.log(chalk.green("openssl is already installed and have the expected version."));
            }
            return callback(null, opensslExecPath);
        }
    });
}

/**
 *
 * @param callback    {Function}
 * @param callback.err {Error|null}
 * @param callback.pathToOpenSSL {string}
 */
export function install_prerequisite(callback: (err: Error | null, pathToOpenSSL?: string) => void) {
    // istanbul ignore else
    if (process.platform !== "win32") {
        return check_system_openssl_version(callback);
    } else {
        return install_and_check_win32_openssl_version(callback);
    }
}

export function get_openssl_exec_path(callback: (err: Error | null, execPath?: string) => void) {
    assert(typeof callback === "function");

    if (process.platform === "win32") {
        install_prerequisite((err: Error | null, opensslExecPath?: string) => {
            if (err) {
                return callback(err);
            }
            if (!fs.existsSync(opensslExecPath!)) {
                throw new Error("internal error cannot find " + opensslExecPath);
            }
            callback(err, opensslExecPath);
        });
    } else {
        setImmediate(() => {
            callback(null, "openssl");
        });
    }
}
