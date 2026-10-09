/** URL parameter (also the Paddle custom-data key and FastSpring tag) for the trial reference. */
export const TRIAL_REF_PARAM = 'velsigil_trial';
const STRIPE_PAYMENT_LINK_HOST = 'buy.stripe.com';
const STRIPE_REFERENCE_PARAM = 'client_reference_id';

const TRIAL_REF_RE = /^[A-Za-z0-9_-]{1,200}$/;

export function isTrialRef(value: unknown): value is string {
  return typeof value === 'string' && TRIAL_REF_RE.test(value);
}

/** Adds the trial reference to a "Buy now" URL so the purchase converts this trial; else returns `url`. */
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
