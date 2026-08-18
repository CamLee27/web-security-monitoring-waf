/**
 * CamCareer Web Security Monitoring — Public Portfolio Extract
 *
 * This file is a curated, non-standalone extract based on the security
 * monitoring portions of the integrated production Cloudflare Worker.
 *
 * The production Worker also contains visitor analytics, navigation tracking,
 * report rendering, administrative endpoints, and additional classification
 * logic that are intentionally not reproduced here.
 *
 * Some detection patterns, classification thresholds, and operational details
 * are intentionally omitted from the public portfolio copy.
 *
 * No secrets, real visitor IP addresses, location data, account identifiers,
 * or private report destinations are included.
 */

// Representative suspicious-path categories used by the production system.
// The production implementation contains additional patterns.
const SUSPICIOUS_PATH_RULES = [
  {
    category: "Environment / secret file probe",
    pattern: /(?:^|\/)\.env(?:$|[._-])/i,
  },
  {
    category: "Version-control metadata probe",
    pattern: /(?:^|\/)\.(?:git|svn|hg)(?:\/|$)/i,
  },
  {
    category: "WordPress probe",
    pattern:
      /(?:^|\/)(?:wp-admin(?:\/|$)|wp-login\.php(?:\/|$)|wp-config\.php(?:\/|$)|xmlrpc\.php(?:\/|$))/i,
  },
  {
    category: "PHP probe",
    pattern: /\.php(?:$|\/)/i,
  },
  {
    category: "Credential / key-file probe",
    pattern:
      /(?:^|\/)(?:\.aws\/credentials|\.ssh(?:\/|$)|id_rsa(?:\.pub)?|authorized_keys)(?:$|\/)/i,
  },
];

/**
 * Security-focused portion of the production request flow.
 *
 * The actual Worker performs the origin fetch first, then records a request
 * when it is either a 404 or matches one or more suspicious-path categories.
 */
export async function monitorSecurityRequest(request, response, env, ctx) {
  const observation = getRequestObservation(request, response);

  if (!observation) return;

  ctx.waitUntil(
    recordRequestObservation(request, response, env, observation).catch((error) =>
      console.error("Security-request logging failed:", error)
    )
  );
}

function getRequestObservation(request, response) {
  const path = normalizeObservedPath(new URL(request.url).pathname);
  const suspiciousCategories = getSuspiciousPathCategories(path);
  const is404 = response.status === 404;

  // Normal successful requests that do not match a security pattern are not
  // stored in the security-request table.
  if (!is404 && suspiciousCategories.length === 0) return null;

  return {
    path,
    is404,
    suspiciousCategories,
  };
}

function getSuspiciousPathCategories(pathname) {
  const candidates = new Set([String(pathname || "/")]);

  try {
    candidates.add(decodeURIComponent(String(pathname || "/")));
  } catch {
    // Keep the original path if decoding fails.
  }

  const matches = [];

  for (const rule of SUSPICIOUS_PATH_RULES) {
    const matched = [...candidates].some((candidate) =>
      rule.pattern.test(candidate)
    );

    if (matched && !matches.includes(rule.category)) {
      matches.push(rule.category);
    }
  }

  return matches;
}

function normalizeObservedPath(pathname) {
  return String(pathname || "/").slice(0, 512);
}

/**
 * Store a permanent security/request observation in Cloudflare D1.
 *
 * The production database binding is SECURITY_DB. Values are parameterized
 * rather than interpolated directly into the SQL statement.
 */
async function recordRequestObservation(
  request,
  response,
  env,
  observation
) {
  requireDatabase(env);

  const identity = await getVisitorIdentity(request);

  if (isExcludedIp(identity.ip, env.EXCLUDED_IPS)) return;

  const url = new URL(request.url);
  const client = getRequestClientMetadata(request);

  await env.SECURITY_DB.prepare(`
    INSERT INTO request_observations (
      visitor_hash, ip, visit_date, timestamp, path, method, status,
      is_404, suspicious_path, suspicious_categories, referrer,
      city, region, region_code, postal_code, country, internet_provider,
      user_agent, browser_brands, platform_hint, mobile_hint,
      bot_score, bot_js_passed
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `)
    .bind(
      identity.visitorHash,
      identity.ip,
      identity.date,
      identity.timestamp,
      observation.path,
      request.method,
      response.status,
      observation.is404 ? 1 : 0,
      observation.suspiciousCategories.length > 0 ? 1 : 0,
      JSON.stringify(observation.suspiciousCategories),
      getReferrer(request, url),
      client.city,
      client.region,
      client.regionCode,
      client.postalCode,
      client.country,
      client.internetProvider,
      client.userAgent,
      client.browserBrands,
      client.platformHint,
      client.mobileHint,
      client.botScore,
      toDbBoolean(client.botJsPassed)
    )
    .run();
}

function getRequestClientMetadata(request) {
  const cf = request.cf || {};
  const botManagement = cf.botManagement || {};

  return {
    city: cf.city || "Unknown",
    region: cf.region || "Unknown",
    regionCode: cf.regionCode || "",
    postalCode: cf.postalCode || "",
    country: cf.country || "Unknown",
    internetProvider: cf.asOrganization || "Unknown",
    userAgent: request.headers.get("user-agent") || "Unknown",
    browserBrands: request.headers.get("sec-ch-ua") || "",
    platformHint: cleanClientHint(request.headers.get("sec-ch-ua-platform")),
    mobileHint: cleanClientHint(request.headers.get("sec-ch-ua-mobile")),
    botScore:
      typeof botManagement.score === "number" ? botManagement.score : null,
    botJsPassed:
      typeof botManagement.jsDetection?.passed === "boolean"
        ? botManagement.jsDetection.passed
        : null,
  };
}

/**
 * Public summary of the production classification design.
 *
 * Exact production thresholds are intentionally omitted here. The live Worker
 * combines multiple signals rather than treating any single signal as proof.
 */
export const TRAFFIC_CLASSIFICATIONS = [
  "Likely Human",
  "Uncertain",
  "Likely Bot / Scanner",
];

export const CLASSIFICATION_SIGNAL_GROUPS = [
  "Cloudflare bot-management signals",
  "suspicious-path activity",
  "repeated 404 behavior",
  "request timing / burst behavior",
  "reported browser and user-agent information",
  "network-provider context",
  "normal page activity",
  "intentional navigation behavior",
];

/**
 * Summarize recorded security observations for reporting.
 */
function getRequestSecuritySummary(visit) {
  const observations = visit.requestObservations || [];

  const count404 = observations.filter(
    (observation) => observation.is404 === true || observation.status === 404
  ).length;

  const suspiciousRequests = observations.filter(
    (observation) => observation.suspiciousPath === true
  );

  const pathCounts = new Map();

  for (const observation of suspiciousRequests) {
    const path = observation.path || "Unknown";
    pathCounts.set(path, Number(pathCounts.get(path) || 0) + 1);
  }

  const topSuspiciousPaths = [...pathCounts.entries()]
    .map(([path, count]) => ({ path, count }))
    .sort((a, b) => b.count - a.count || a.path.localeCompare(b.path))
    .slice(0, 5);

  return {
    recordedRequestCount: observations.length,
    count404,
    suspiciousRequestCount: suspiciousRequests.length,
    topSuspiciousPaths,
  };
}

async function getVisitorIdentity(request) {
  const ip = getRequestIp(request);
  const date = getChicagoDate();

  return {
    ip,
    date,
    visitorHash: await sha256(`${date}:${ip}`),
    timestamp: new Date().toISOString(),
  };
}

function getRequestIp(request) {
  const forwardedIp = request.headers
    .get("X-Forwarded-For")
    ?.split(",")[0]
    ?.trim();

  return request.headers.get("CF-Connecting-IP") || forwardedIp || "Unknown";
}

function getReferrer(request, currentUrl) {
  const referrerHeader = request.headers.get("referer");
  if (!referrerHeader) return "Direct or unavailable";

  try {
    const parsed = new URL(referrerHeader);
    const internal =
      normalizeHostname(parsed.hostname) ===
      normalizeHostname(currentUrl.hostname);

    return internal
      ? `${parsed.hostname}${parsed.pathname || "/"}`
      : parsed.hostname;
  } catch {
    return "Unavailable";
  }
}

function isExcludedIp(ip, excludedIpsValue) {
  if (!excludedIpsValue) return false;

  return excludedIpsValue
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean)
    .includes(ip);
}

function requireDatabase(env) {
  if (!env.SECURITY_DB) {
    throw new Error("The SECURITY_DB D1 binding is missing.");
  }
}

function toDbBoolean(value) {
  return value === null || value === undefined ? null : value ? 1 : 0;
}

function cleanClientHint(value) {
  return String(value || "").replace(/^"|"$/g, "");
}

function normalizeHostname(hostname) {
  return String(hostname || "").toLowerCase().replace(/^www\./, "");
}

function getChicagoDate() {
  const parts = new Intl.DateTimeFormat("en-US", {
    timeZone: "America/Chicago",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).formatToParts(new Date());

  const values = Object.fromEntries(
    parts.map((part) => [part.type, part.value])
  );

  return `${values.year}-${values.month}-${values.day}`;
}

async function sha256(value) {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);

  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Production features intentionally not reproduced in this public extract:
 *
 * - Exact bot/scanner classification thresholds and full decision tree
 * - Complete suspicious-path rule library
 * - Visitor analytics and navigation-event implementation
 * - Full Resend email templates and report rendering
 * - Manual administrative report endpoint details
 * - Account-specific Cloudflare configuration
 * - Secrets and private visitor data
 *
 * Cursor-based reporting and WAF behavior are documented separately in the
 * repository documentation.
 */
