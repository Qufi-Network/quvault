/*
 * Rate limiting.
 *
 * WHY IT IS IN THE DATABASE. QuVault runs as a serverless function. An in-memory counter there
 * is close to theatre: every instance keeps its own, instances come and go, and a cold start
 * resets the count — so the real allowance is the configured limit multiplied by however many
 * instances the platform happens to spin up. The counter therefore lives in Postgres, where
 * there is one of it, and costs one round trip on the routes that are actually worth limiting.
 *
 * WHAT IS LIMITED, AND WHAT IS NOT. Not every route needs this. A cheap authenticated read is
 * already behind a session and a database lookup; hammering it costs a query and nothing else.
 * What is worth protecting is: routes reachable with no session at all, routes that spend
 * somebody else's quota (Veyns approvals, the chain API), and routes that touch money. So the
 * policy is attached to individual routes rather than applied to everything, and the cost is
 * proportional to the risk.
 *
 * FIXED WINDOWS, not a sliding log. A fixed window lets a caller send up to twice the limit
 * across a window boundary. That is a known and accepted property: the aim is to stop hammering
 * and quota burn, not to enforce a precise rate, and a sliding window costs more storage and
 * more complexity than that aim justifies.
 *
 * HONESTY ABOUT THE TWO KINDS OF KEY:
 *
 *   by 'user'    — sound. A session identifies a person, the server issued it, and it cannot
 *                  be minted by the caller.
 *   by 'address' — BEST EFFORT ONLY. There is no session yet, so the only handle is the
 *                  client address, and behind a proxy that comes from `x-forwarded-for`, a
 *                  header the client can set. It is trustworthy exactly as far as the proxy in
 *                  front is: Vercel overwrites it, so it holds there; run this with no proxy,
 *                  or behind one that appends without sanitising, and the limit is evadable by
 *                  spoofing the header, and a distributed caller evades it regardless.
 *
 * That asymmetry is why nothing that touches money is keyed by address. The address-keyed
 * limits cover sign-in only, where the worst case is nonce-table growth and brute-force noise.
 */

/**
 * The policies. Every limited route names one of these, so the numbers live in one place and a
 * route's allowance is visible where the route is declared.
 *
 * The windows are deliberately generous. A limiter that trips on ordinary use is a bug that
 * looks like an attack, and an operator who has been paged at 3am by their own rate limiter
 * turns it off.
 */
export const RATE = {
  /** Sign-in, before any session exists. Keyed by address, with all the caveats above. */
  login: { name: 'login', limit: 30, seconds: 300, by: 'address' },
  /** Asking Veyns for a palm scan. Their quota, so ours to be careful with. */
  palm: { name: 'palm', limit: 40, seconds: 300, by: 'user' },
  /** Planning a spend: selects UTXOs and fetches a fee rate, so it hits the chain API. */
  spend: { name: 'spend', limit: 40, seconds: 300, by: 'user' },
  /** Releasing an unlock secret, and broadcasting. Already single-use; this bounds the attempts. */
  unlock: { name: 'unlock', limit: 60, seconds: 300, by: 'user' },
  /** Reads that reach an upstream service on our behalf. */
  upstream: { name: 'upstream', limit: 200, seconds: 300, by: 'user' },
  /** Ordinary authenticated writes: cheap, but not unbounded. */
  write: { name: 'write', limit: 200, seconds: 300, by: 'user' },
};

/**
 * The client's address, as well as it can be known.
 *
 * `x-forwarded-for` when there is a proxy in front, the socket otherwise. See the header
 * comment: this is a best-effort signal and the limits that use it are the ones where that is
 * acceptable.
 */
export function clientAddress(req, { trustProxy = true } = {}) {
  if (trustProxy) {
    const forwarded = req.headers?.['x-forwarded-for'];
    const first = String(forwarded ?? '').split(',')[0].trim();
    if (first) return first;
  }
  return req.socket?.remoteAddress ?? 'unknown';
}

/**
 * The row this request counts against.
 *
 * The window start is part of the key, so a new window is a new row rather than an update that
 * has to reason about when to reset. Expired rows are then just rows with a past `expiresAt`,
 * and cleaning them up is a delete rather than a correctness concern.
 */
export function bucketFor({ policy, key, now }) {
  const windowStart = Math.floor(now / policy.seconds) * policy.seconds;
  return {
    bucket: `${policy.name}:${key}:${windowStart}`,
    expiresAt: windowStart + policy.seconds,
    retryAfter: Math.max(1, windowStart + policy.seconds - now),
  };
}

/** Whether this many hits in the window is over the line. */
export const isOverLimit = (hits, policy) => hits > policy.limit;

/** What a refused caller is told. Says when to come back, and nothing about anyone else. */
export const refusalMessage = retryAfter =>
  `Too many requests. Try again in ${retryAfter} second${retryAfter === 1 ? '' : 's'}.`;
