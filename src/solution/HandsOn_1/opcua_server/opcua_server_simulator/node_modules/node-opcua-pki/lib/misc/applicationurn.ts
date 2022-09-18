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
import * as assert from "assert";
import * as crypto from "crypto";

export function makeApplicationUrn(hostname: string, suffix: string): string {

    // beware : Openssl doesn't support urn with length greater than 64 !!
    //          sometimes hostname length could be too long ...
    // application urn length must not exceed 64 car. to comply with openssl
    // see cryptoCA
    let hostnameHash = hostname;
    if (hostnameHash.length + 7 + suffix.length >= 64) {
        // we need to reduce the applicationUrn side => let's take
        // a portion of the hostname hash.
        hostnameHash = crypto.createHash("md5")
            .update(hostname)
            .digest("hex")
            .substr(0, 16);
    }

    const applicationUrn = "urn:" + hostnameHash + ":" + suffix;
    assert(applicationUrn.length <= 64);
    return applicationUrn;
}
