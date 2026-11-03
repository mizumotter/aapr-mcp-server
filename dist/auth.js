/**
 * Keyless authentication for Play Room (keypair + JWT assertion + DPoP).
 *
 * - The credential's ES256 signing key lives in the OS keychain, never in env
 *   vars or files. Only PLAYROOM_CREDENTIAL_ID (not a secret) is configured.
 * - A fresh DPoP key is generated per process and kept in memory only.
 * - Access tokens last 15 minutes and are bound to the DPoP key, so a leaked
 *   token is useless on its own. They are refreshed shortly before expiry.
 *
 * Nothing in this module may be returned in tool output or error messages.
 */
import { Entry } from "@napi-rs/keyring";
import { SignJWT, exportJWK, generateKeyPair, importJWK, } from "jose";
import { createHash, randomUUID } from "node:crypto";
const KEYCHAIN_SERVICE = "aapr-mcp-server";
const JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const REFRESH_MARGIN_MS = 60_000;
/** Legacy API key (kept during migration). */
export class ApiKeyAuth {
    apiKey;
    constructor(apiKey) {
        this.apiKey = apiKey;
    }
    async headers() {
        return { Authorization: `Bearer ${this.apiKey}` };
    }
    invalidate() { }
    async close() { }
}
function keychainEntry(credentialId) {
    return new Entry(KEYCHAIN_SERVICE, credentialId);
}
export function saveCredential(stored) {
    keychainEntry(stored.credentialId).setPassword(JSON.stringify({ version: 1, ...stored }));
}
function loadCredential(credentialId) {
    const raw = keychainEntry(credentialId).getPassword();
    if (!raw) {
        throw new Error(`No key for credential ${credentialId} in the OS keychain. Run "aapr-mcp-server enroll" first.`);
    }
    const parsed = JSON.parse(raw);
    if (parsed.version !== 1 || parsed.credentialId !== credentialId) {
        throw new Error("Keychain entry has an unexpected format");
    }
    return parsed;
}
/** base64url(sha256(value)) — the DPoP `ath` claim */
function sha256B64u(value) {
    return createHash("sha256").update(value).digest("base64url");
}
/** htu: origin + path, without query or fragment (RFC 9449 §4.2) */
function htuOf(url) {
    const u = new URL(url);
    return u.origin + u.pathname;
}
export class KeylessAuth {
    stored;
    signingKey;
    dpopKey;
    dpopJwk;
    token = null;
    pending = null;
    constructor(stored, signingKey, dpopKey, dpopJwk) {
        this.stored = stored;
        this.signingKey = signingKey;
        this.dpopKey = dpopKey;
        this.dpopJwk = dpopJwk;
    }
    /** `origin` must be the API's canonical origin (e.g. https://www.theplayroom.ai). */
    static async fromKeychain(credentialId, origin) {
        const stored = loadCredential(credentialId);
        if (stored.origin !== origin) {
            throw new Error(`Credential ${credentialId} was enrolled for ${stored.origin}, not ${origin}`);
        }
        const signingKey = await importJWK(stored.privateJwk, "ES256");
        const { privateKey, publicKey } = await generateKeyPair("ES256");
        const { kty, crv, x, y } = await exportJWK(publicKey);
        return new KeylessAuth(stored, signingKey, privateKey, { kty, crv, x, y });
    }
    dpopProof(method, url, accessToken) {
        return new SignJWT({
            htm: method.toUpperCase(),
            htu: htuOf(url),
            jti: randomUUID(),
            ...(accessToken ? { ath: sha256B64u(accessToken) } : {}),
        })
            .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: this.dpopJwk })
            .setIssuedAt()
            .sign(this.dpopKey);
    }
    async fetchToken() {
        const tokenUrl = `${this.stored.origin}/api/v1/agent-auth/token`;
        const assertion = await new SignJWT({ jti: randomUUID() })
            .setProtectedHeader({ alg: "ES256" })
            .setIssuer(this.stored.credentialId)
            .setSubject(this.stored.agentId)
            .setAudience(tokenUrl)
            .setIssuedAt()
            .setExpirationTime("60s")
            .sign(this.signingKey);
        const res = await fetch(tokenUrl, {
            method: "POST",
            headers: {
                "Content-Type": "application/x-www-form-urlencoded",
                DPoP: await this.dpopProof("POST", tokenUrl),
            },
            body: new URLSearchParams({ grant_type: JWT_BEARER, assertion }),
        });
        const body = (await res.json().catch(() => ({})));
        if (!res.ok || !body.access_token) {
            // Only the OAuth error code: never echo request material
            throw new Error(`Token request failed (${res.status} ${body.error ?? "unknown_error"})`);
        }
        this.token = {
            value: body.access_token,
            expiresAt: Date.now() + (body.expires_in ?? 900) * 1000,
        };
        return body.access_token;
    }
    async accessToken() {
        if (this.token && this.token.expiresAt - REFRESH_MARGIN_MS > Date.now()) {
            return this.token.value;
        }
        // Share one in-flight refresh between concurrent tool calls
        this.pending ??= this.fetchToken().finally(() => {
            this.pending = null;
        });
        return this.pending;
    }
    async headers(method, url) {
        const token = await this.accessToken();
        return {
            Authorization: `DPoP ${token}`,
            DPoP: await this.dpopProof(method, url, token),
        };
    }
    invalidate() {
        this.token = null;
    }
    /** Best-effort revocation of the live token when the process exits. */
    async close() {
        if (!this.token)
            return;
        const url = `${this.stored.origin}/api/v1/agent-auth/revoke`;
        try {
            await fetch(url, { method: "POST", headers: await this.headers("POST", url) });
        }
        catch {
            // The token expires within 15 minutes anyway
        }
        this.token = null;
    }
}
/**
 * Register a new key pair using a one-time enrollment code from the dashboard.
 * Stores the private key in the OS keychain and returns the ids to configure.
 */
export async function enroll(origin, code) {
    const { privateKey, publicKey } = await generateKeyPair("ES256", { extractable: true });
    const { kty, crv, x, y } = await exportJWK(publicKey);
    const enrollUrl = `${origin}/api/v1/agent-auth/enroll`;
    const proof = await new SignJWT({
        code_hash: createHash("sha256").update(code).digest("hex"),
        jti: randomUUID(),
    })
        .setProtectedHeader({ alg: "ES256" })
        .setAudience(enrollUrl)
        .setIssuedAt()
        .setExpirationTime("60s")
        .sign(privateKey);
    const res = await fetch(enrollUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enrollment_code: code, public_jwk: { kty, crv, x, y }, proof }),
    });
    const body = (await res.json().catch(() => ({})));
    if (!res.ok || !body.credential_id || !body.agent_id) {
        throw new Error(`Enrollment failed (${res.status} ${body.error ?? ""}): ${body.message ?? ""}`.trim());
    }
    saveCredential({
        credentialId: body.credential_id,
        agentId: body.agent_id,
        origin,
        privateJwk: await exportJWK(privateKey),
    });
    return { credentialId: body.credential_id, agentId: body.agent_id, scopes: body.scopes ?? [] };
}
//# sourceMappingURL=auth.js.map