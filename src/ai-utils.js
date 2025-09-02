import dotenv from "dotenv";

dotenv.config();

/**
 * Generate a prompt for the AI to analyze security findings
 * @param {Array} results - Security scan results
 * @returns {string} - Formatted prompt for AI
 */
export function generateAIPrompt(results) {
  // Extract key information for the prompt
  const totalUrls = results.length;
  const issuesByType = {};
  const issuesBySeverity = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0
  };
  
  // Count issues by type and severity
  results.forEach(result => {
    result.issues.forEach(issue => {
      // Count by type
      if (!issuesByType[issue.id]) {
        issuesByType[issue.id] = {
          count: 0,
          severity: issue.severity,
          details: issue.details
        };
      }
      issuesByType[issue.id].count++;
      
      // Count by severity
      issuesBySeverity[issue.severity]++;
    });
  });
  
  // Format issues for the prompt
  const formattedIssues = Object.entries(issuesByType)
    .map(([id, data]) => `- ${id} (${data.severity}): ${data.details} (found on ${data.count} pages)`)
    .join("\n");
  
  // Calculate average security score
  const avgScore = results.reduce((sum, r) => sum + (r.score?.pct || 0), 0) / totalUrls;
  
  // Generate the prompt
  return `
Analyze the following website security scan results and provide:
1. A concise executive summary of the security posture
2. Prioritized recommendations for fixing the most critical issues
3. Specific remediation steps for each type of issue
4. A security risk assessment (low, medium, high)

Scan Overview:
- Domain: ${results[0]?.url ? new URL(results[0].url).hostname : "Unknown"}
- Total URLs scanned: ${totalUrls}
- Average security score: ${Math.round(avgScore)}%
- Issues by severity:
  - Critical: ${issuesBySeverity.critical}
  - High: ${issuesBySeverity.high}
  - Medium: ${issuesBySeverity.medium}
  - Low: ${issuesBySeverity.low}

Detailed Issues:
${formattedIssues}

Provide your analysis in markdown format.
`;
}

/**
 * Process security findings to generate recommendations
 * @param {Array} results - Security scan results
 * @returns {string} - Generated analysis and recommendations
 */
export async function analyzeWithAI(results) {
  // Always use the fallback summary generation
  console.log("Using built-in summary generation.");
  return generateFallbackSummary(results);
  
  // Note: OpenAI integration has been removed to avoid compatibility issues
  // If you want to add AI capabilities in the future, you can implement
  // the OpenAI SDK integration here

}

/**
 * Generate a fallback summary when AI analysis is not available
 * @param {Array} results - Security scan results
 * @returns {string} - Generated summary
 */
function generateFallbackSummary(results) {
  const totalUrls = results.length;
  const issuesBySeverity = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0
  };
  
  // Count issues by severity
  results.forEach(result => {
    result.issues.forEach(issue => {
      issuesBySeverity[issue.severity]++;
    });
  });
  
  // Calculate average security score
  const avgScore = results.reduce((sum, r) => sum + (r.score?.pct || 0), 0) / totalUrls;
  
  // Find common issues
  const issueCount = {};
  results.forEach(result => {
    result.issues.forEach(issue => {
      if (!issueCount[issue.id]) {
        issueCount[issue.id] = {
          count: 0,
          severity: issue.severity,
          details: issue.details
        };
      }
      issueCount[issue.id].count++;
    });
  });
  
  // Sort issues by count (descending)
  const sortedIssues = Object.entries(issueCount)
    .sort((a, b) => b[1].count - a[1].count)
    .map(([id, data]) => ({ id, ...data }));
  
  // Generate recommendations based on common issues
  const recommendations = [];
  
  if (issueCount.no_https) {
    recommendations.push("Implement HTTPS across all pages by obtaining an SSL certificate and configuring your web server to redirect HTTP to HTTPS.");
  }
  
  if (issueCount.missing_csp) {
    recommendations.push("Implement a Content Security Policy (CSP) to prevent XSS attacks by specifying which dynamic resources are allowed to load.");
  }
  
  if (issueCount.missing_hsts) {
    recommendations.push("Enable HTTP Strict Transport Security (HSTS) to ensure that browsers always connect to your site over HTTPS.");
  }
  
  if (issueCount.cookie_flags) {
    recommendations.push("Secure all cookies by adding the Secure, HttpOnly, and SameSite flags to prevent theft and CSRF attacks.");
  }
  
  if (issueCount.clickjacking) {
    recommendations.push("Prevent clickjacking attacks by implementing X-Frame-Options or frame-ancestors in your Content Security Policy.");
  }
  
  // Add generic recommendations if specific ones are not available
  if (recommendations.length < 3) {
    recommendations.push("Regularly update all software components and dependencies to patch security vulnerabilities.");
    recommendations.push("Implement a web application firewall (WAF) to protect against common web attacks.");
    recommendations.push("Conduct regular security assessments and penetration testing to identify and address vulnerabilities.");
  }
  
  // Determine overall risk level
  let riskLevel = "low";
  if (issuesBySeverity.critical > 0 || issuesBySeverity.high > 5) {
    riskLevel = "high";
  } else if (issuesBySeverity.high > 0 || issuesBySeverity.medium > 10) {
    riskLevel = "medium";
  }
  
  // Generate the summary
  return `
## Security Scan Summary

### Executive Summary

The security scan of ${results[0]?.url ? new URL(results[0].url).hostname : "the website"} revealed an overall security score of **${Math.round(avgScore)}%** with a **${riskLevel.toUpperCase()}** risk level. The scan identified ${issuesBySeverity.critical} critical, ${issuesBySeverity.high} high, ${issuesBySeverity.medium} medium, and ${issuesBySeverity.low} low severity issues across ${totalUrls} URLs.

### Key Findings

${sortedIssues.slice(0, 5).map(issue => `- **${issue.id}** (${issue.severity}): ${issue.details} - Found on ${issue.count} pages`).join("\n")}

### Top Recommendations

${recommendations.slice(0, 5).map((rec, i) => `${i + 1}. ${rec}`).join("\n")}

### Remediation Steps

1. **Security Headers**: Implement all missing security headers in your web server configuration or application code.
   - Add Content-Security-Policy to restrict resource loading
   - Enable Strict-Transport-Security with a long max-age
   - Set X-Content-Type-Options to nosniff
   - Configure X-Frame-Options or frame-ancestors in CSP

2. **HTTPS Implementation**: Ensure all pages are served over HTTPS.
   - Obtain an SSL certificate (Let's Encrypt offers free certificates)
   - Configure your web server to redirect HTTP to HTTPS
   - Update all internal links to use HTTPS

3. **Cookie Security**: Review and update all cookies with proper security flags.
   - Add Secure flag to ensure cookies are only sent over HTTPS
   - Add HttpOnly flag to prevent JavaScript access to sensitive cookies
   - Set SameSite attribute to Lax or Strict to prevent CSRF attacks

This analysis was generated automatically based on the scan results. For a more comprehensive assessment, consider engaging a security professional.
`;
}