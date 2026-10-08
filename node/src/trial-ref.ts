/**
 * Free-trial conversion references (SPEC 9.7, servers since 2026-10-06). The server signs an opaque reference into the
 * license of every free trial a purchase can still convert (`license.trialRef`). The app adds it to its "Buy now" link;
 * the seller's checkout carries it to the payment provider, and the purchase then turns THIS trial into the paid license
 * (same key) whatever e-mail address the buyer pays with. The SDK never interprets it: the server verifies it.
 */

/** URL parameter (and Paddle custom-data key / FastSpring tag) that carries the reference. */
export const TRIAL_REF_PARAM = 'velsigil_trial';
/** Stripe Payment Links take it in their own parameter. */
const STRIPE_PAYMENT_LINK_HOST = 'buy.stripe.com';
const STRIPE_REFERENCE_PARAM = 'client_reference_id';

const TRIAL_REF_RE = /^[A-Za-z0-9_-]{1,200}$/;

/** A well-formed reference: 1-200 characters of `[A-Za-z0-9_-]` (safe in a URL without encoding). */
export function isTrialRef(value: unknown): value is string {
  return typeof value === 'string' && TRIAL_REF_RE.test(value);
}

/**
 * `url` with the reference appended as `velsigil_trial=<ref>` (before any `#fragment`; the rest of the URL is kept as
 * it is), or as `client_reference_id=<ref>` for a Stripe Payment Link (`https://buy.stripe.com/…`). Returns `url`
 * unchanged when the reference is absent or malformed, or `url` is not an absolute http(s) URL.
 */
export function withTrialRef(url: string, ref: string | null | undefined): string {
  if (!isTrialRef(ref)) return url;
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return url;
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return url;
  const param = parsed.hostname.toLowerCase() === STRIPE_PAYMENT_LINK_HOST ? STRIPE_REFERENCE_PARAM : TRIAL_REF_PARAM;
  const hashAt = url.indexOf('#');
  const base = hashAt >= 0 ? url.slice(0, hashAt) : url;
  const fragment = hashAt >= 0 ? url.slice(hashAt) : '';
  const separator = !base.includes('?') ? '?' : base.endsWith('?') || base.endsWith('&') ? '' : '&';
  return `${base}${separator}${param}=${ref}${fragment}`;
}
