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

export interface SubjectOptions {
    commonName?: string;
    organization?: string;
    organizationalUnit?: string;
    locality?: string;
    state?: string;
    country?: string;
    domainComponent?: string;
}

const _keys = {
    C: "country",
    CN: "commonName",
    DC: "domainComponent",
    L: "locality",
    O: "organization",
    OU: "organizationalUnit",
    ST: "state",
};

export class Subject implements SubjectOptions {
    public readonly commonName?: string;
    public readonly organization?: string;
    public readonly organizationalUnit?: string;
    public readonly locality?: string;
    public readonly state?: string;
    public readonly country?: string;
    public readonly domainComponent?: string;

    constructor(options: SubjectOptions | string) {
        if (typeof options === "string") {
            options = Subject.parse(options);
        }
        this.commonName = options.commonName;
        this.organization = options.organization;
        this.organizationalUnit = options.organizationalUnit;
        this.locality = options.locality;
        this.state = options.state;
        this.country = options.country;
        this.domainComponent = options.domainComponent;
    }

    public static parse(str: string): SubjectOptions {
        const elements = str.split(/\/(?=[^/]*?=)/);
        const options: Record<string, unknown> = {};

        elements.forEach((element: string) => {
            if (element.length === 0) {
                return;
            }
            const s: string[] = element.split("=");

            if (s.length !== 2) {
                throw new Error("invalid format for " + element);
            }
            const longName = (_keys as any)[s[0]];
            const value = s[1];
            options[longName] = Buffer.from(value, "ascii").toString("utf8");
        });
        return options as SubjectOptions;
    }

    public toString() {
        let tmp = "";
        if (this.country) {
            tmp += "/C=" + this.country;
        }
        if (this.state) {
            tmp += "/ST=" + this.state;
        }
        if (this.locality) {
            tmp += "/L=" + this.locality;
        }
        if (this.organization) {
            tmp += "/O=" + this.organization;
        }
        if (this.organizationalUnit) {
            tmp += "/OU=" + this.organization;
        }
        if (this.commonName) {
            tmp += "/CN=" + this.commonName;
        }
        if (this.domainComponent) {
            tmp += "/DC=" + this.domainComponent;
        }
        return tmp;
    }
}
