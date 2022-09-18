export type KeySize = 1024 | 2048 | 3072 | 4096;
export type Thumbprint = string;
export type Filename = string;
export type CertificateStatus = "unknown" | "trusted" | "rejected";
export type ErrorCallback = (err?: Error | null) => void;
