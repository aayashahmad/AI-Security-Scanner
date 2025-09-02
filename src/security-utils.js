/**
 * Format an issue for reporting
 * @param {string} id - Issue identifier
 * @param {string} severity - Issue severity (critical, high, medium, low)
 * @param {string} details - Issue details
 * @returns {Object} - Formatted issue
 */
export function formatIssue(id, severity, details) {
  return { id, severity, details };
}

/**
 * Analyze HTTP headers for security issues
 * @param {string} url - The URL being analyzed
 * @param {Object} res - The HTTP response
 * @returns {Array} - List of security issues
 */
export function analyzeHeaders(url, res) {
  const h = Object.fromEntries(
    Object.entries(res.headers || {}).map(([k, v]) => [k.toLowerCase(), v])
  );

  const issues = [];

  // HTTPS check
  const isHttps = url.startsWith("https://");
  if (!isHttps) issues.push(formatIssue("no_https", "critical", "Page not served over HTTPS"));

  // Security headers checks
  if (!h["strict-transport-security"]) {
    issues.push(formatIssue("missing_hsts", "high", "Add Strict-Transport-Security"));
  } else {
    // Check HSTS max-age
    const hsts = h["strict-transport-security"];
    const maxAgeMatch = hsts.match(/max-age=([0-9]+)/);
    if (maxAgeMatch && parseInt(maxAgeMatch[1]) < 31536000) { // Less than 1 year
      issues.push(formatIssue("weak_hsts", "medium", "HSTS max-age should be at least 1 year (31536000 seconds)"));
    }
  }

  if (!h["content-security-policy"]) {
    issues.push(formatIssue("missing_csp", "high", "Add Content-Security-Policy"));
  } else {
    // Check for unsafe CSP directives
    const csp = h["content-security-policy"];
    if (csp.includes("unsafe-inline") || csp.includes("unsafe-eval")) {
      issues.push(formatIssue("unsafe_csp", "medium", "CSP contains unsafe-inline or unsafe-eval directives"));
    }
  }

  if (h["x-content-type-options"]?.toLowerCase() !== "nosniff") {
    issues.push(formatIssue("x_content_type_options", "medium", "Set X-Content-Type-Options: nosniff"));
  }

  if (!h["x-frame-options"] && !h["content-security-policy"]?.includes("frame-ancestors")) {
    issues.push(formatIssue("clickjacking", "medium", "Add X-Frame-Options or frame-ancestors in CSP"));
  }

  if (!h["referrer-policy"]) {
    issues.push(formatIssue("missing_referrer_policy", "low", "Add Referrer-Policy"));
  }

  if (!h["permissions-policy"]) {
    issues.push(formatIssue("missing_permissions_policy", "low", "Add Permissions-Policy"));
  }

  if (!h["cross-origin-resource-policy"]) {
    issues.push(formatIssue("missing_corp", "low", "Add Cross-Origin-Resource-Policy"));
  }

  // Cookie checks
  const setCookie = ([]).concat(h["set-cookie"] || []);
  setCookie.forEach(c => {
    const lower = c.toLowerCase();
    const cookieIssues = [];
    
    if (!lower.includes("secure")) cookieIssues.push("Secure");
    if (!lower.includes("httponly")) cookieIssues.push("HttpOnly");
    if (!/(samesite=lax|samesite=strict|samesite=none)/.test(lower)) cookieIssues.push("SameSite");
    
    // Check if this looks like a session cookie
    const isLikelySessionCookie = /sess|auth|token|id|logged|user/i.test(c);
    
    if (cookieIssues.length) {
      const severity = isLikelySessionCookie ? "high" : "medium";
      issues.push(formatIssue(
        "cookie_flags", 
        severity, 
        `Cookie missing flags: ${cookieIssues.join(", ")}${isLikelySessionCookie ? " (possible session cookie)" : ""}`
      ));
    }
  });

  // Check for mixed content (only for HTTPS pages)
  if (isHttps && res.data && typeof res.data === "string") {
    const mixedContentRegex = /http:\/\/(?!localhost|127\.0\.0\.1)/i;
    if (mixedContentRegex.test(res.data)) {
      issues.push(formatIssue("mixed_content", "high", "Page contains mixed content (HTTP resources on HTTPS page)"));
    }
  }

  return issues;
}

/**
 * Calculate security score based on issues
 * @param {Array} issues - List of security issues
 * @returns {Object} - Score details
 */
export function score(issues) {
  const weights = {
    no_https: 20,
    missing_hsts: 10,
    weak_hsts: 5,
    missing_csp: 20,
    unsafe_csp: 10,
    x_content_type_options: 5,
    clickjacking: 5,
    missing_referrer_policy: 5,
    missing_permissions_policy: 5,
    missing_corp: 5,
    cookie_flags: 20,
    mixed_content: 10
  };
  
  const total = Object.values(weights).reduce((a, b) => a + b, 0);
  const penalty = issues.reduce((sum, i) => sum + (weights[i.id] || 0), 0);
  const pct = Math.max(0, Math.round(((total - penalty) / total) * 100));
  
  return { total, penalty, pct };
}

/**
 * Group issues by type across multiple pages
 * @param {Array} results - Scan results for multiple pages
 * @returns {Object} - Grouped issues
 */
export function groupIssuesByType(results) {
  const issueGroups = {};
  
  results.forEach(result => {
    result.issues.forEach(issue => {
      if (!issueGroups[issue.id]) {
        issueGroups[issue.id] = {
          id: issue.id,
          severity: issue.severity,
          details: issue.details,
          count: 0,
          urls: []
        };
      }
      
      issueGroups[issue.id].count++;
      if (!issueGroups[issue.id].urls.includes(result.url)) {
        issueGroups[issue.id].urls.push(result.url);
      }
    });
  });
  
  // Convert to array and sort by severity and count
  return Object.values(issueGroups).sort((a, b) => {
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    if (severityOrder[a.severity] !== severityOrder[b.severity]) {
      return severityOrder[a.severity] - severityOrder[b.severity];
    }
    return b.count - a.count;
  });
}

/**
 * Calculate overall security score for all scanned pages
 * @param {Array} results - Scan results for multiple pages
 * @returns {number} - Overall security score (0-100)
 */
export function calculateOverallScore(results) {
  if (results.length === 0) return 0;
  
  const totalScore = results.reduce((sum, result) => sum + (result.score?.pct || 0), 0);
  return Math.round(totalScore / results.length);
}