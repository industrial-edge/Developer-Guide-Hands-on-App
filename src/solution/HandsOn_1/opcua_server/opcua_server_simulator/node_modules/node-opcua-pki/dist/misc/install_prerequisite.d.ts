export declare function check_system_openssl_version(callback: (err: Error | null, output?: string) => void): void;
/**
 *
 * @param callback    {Function}
 * @param callback.err {Error|null}
 * @param callback.pathToOpenSSL {string}
 */
export declare function install_prerequisite(callback: (err: Error | null, pathToOpenSSL?: string) => void): void;
export declare function get_openssl_exec_path(callback: (err: Error | null, execPath?: string) => void): void;
