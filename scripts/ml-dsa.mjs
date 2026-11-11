// ML-DSA-65 (FIPS 204) verification with Node's own crypto.
//
// Node has ML-DSA from 24.7 (on OpenSSL 3.5). Older Node cannot verify it,
// and this module then throws rather than reporting a signature as good or
// bad: a check that cannot run must fail the job, never pass it.
//
// Keys are the raw 1952-byte public key (the KMS nist-pqc export, and what
// the app bundles), wrapped here in the fixed SPKI header. Signatures are pure
// ML-DSA with an empty context, which is what KMS and OpenSSL produce.
import { createPublicKey, verify } from 'node:crypto';

export const ML_DSA_65_PUBLIC_KEY_BYTES = 1952;
export const ML_DSA_65_SIG_BYTES = 3309;

// SubjectPublicKeyInfo header for id-ml-dsa-65 (2.16.840.1.101.3.4.3.18).
const SPKI_PREFIX = Buffer.from('308207b2300b0609608648016503040312038207a100', 'hex');

let support;

/** Throws when this Node cannot verify ML-DSA-65. */
export function assertMlDsa65Available() {
  if (support === undefined) {
    try {
      const k = createPublicKey({
        key: Buffer.concat([SPKI_PREFIX, Buffer.alloc(ML_DSA_65_PUBLIC_KEY_BYTES)]),
        format: 'der',
        type: 'spki',
      });
      support = k.asymmetricKeyType === 'ml-dsa-65';
    } catch {
      support = false;
    }
  }
  if (!support) {
    throw new Error(
      `ML-DSA-65 is not available in Node ${process.version}; ` +
        'verifying it needs Node 24.7 or later (OpenSSL 3.5)',
    );
  }
}

/** The KeyObject for a raw ML-DSA-65 public key. */
export function mlDsa65PublicKey(raw) {
  assertMlDsa65Available();
  if (raw.length !== ML_DSA_65_PUBLIC_KEY_BYTES) {
    throw new Error(`an ML-DSA-65 public key is ${ML_DSA_65_PUBLIC_KEY_BYTES} bytes, not ${raw.length}`);
  }
  return createPublicKey({ key: Buffer.concat([SPKI_PREFIX, raw]), format: 'der', type: 'spki' });
}

/**
 * Whether [signature] is a valid ML-DSA-65 signature over [message] under the
 * raw public key [rawKey] (Buffers). False for a wrong-length or malformed
 * signature; throws only when ML-DSA-65 is unavailable or the key is not 1952
 * bytes.
 */
export function verifyMlDsa65(message, rawKey, signature) {
  const key = mlDsa65PublicKey(rawKey);
  if (signature.length !== ML_DSA_65_SIG_BYTES) return false;
  try {
    return verify(null, message, key, signature);
  } catch {
    return false;
  }
}
