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
  try {
    // Try to use the Python deep analyzer first
    console.log("Attempting to use Python deep analyzer...");
    const pythonAnalysis = await callPythonAnalyzer(results);
    
    if (pythonAnalysis && !pythonAnalysis.error) {
      console.log("Successfully used Python deep analyzer.");
      return generateEnhancedSummary(results, pythonAnalysis);
    } else {
      console.log("Python analyzer failed or not available. Using fallback.");
      if (pythonAnalysis?.error) {
        console.error("Python analyzer error:", pythonAnalysis.error);
      }
      return generateFallbackSummary(results);
    }
  } catch (error) {
    console.error("Error in AI analysis:", error);
    return generateFallbackSummary(results);
  }
}

/**
 * Generate a fallback summary when AI analysis is not available
 * @param {Array} results - Security scan results
 * @returns {string} - Generated summary
 */
/**
 * Call the Python deep analyzer bridge to get enhanced analysis
 * @param {Array} results - Security scan results
 * @returns {Object} - Enhanced analysis from Python
 */
async function callPythonAnalyzer(results) {
  try {
    // Call the Python bridge API
    const response = await fetch('http://localhost:3002/analyze', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(results),
      timeout: 30000 // 30 second timeout
    });
    
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    
    return await response.json();
  } catch (error) {
    console.error('Error calling Python analyzer:', error);
    return { error: error.message, status: 'failed' };
  }
}

/**
 * Generate an enhanced summary using Python deep analyzer results
 * @param {Array} results - Original security scan results
 * @param {Object} pythonAnalysis - Enhanced analysis from Python
 * @returns {string} - Generated enhanced summary
 */
function generateEnhancedSummary(results, pythonAnalysis) {
  const totalUrls = results.length;
  const domain = results[0]?.url ? new URL(results[0].url).hostname : "the website";
  
  // Use the enhanced issues if available
  const enhancedIssues = pythonAnalysis.enhanced_issues || [];
  
  // Use the Python-generated risk level and score
  const riskLevel = pythonAnalysis.risk_level || "medium";
  const riskScore = pythonAnalysis.risk_score || 50;
  
  // Use the Python-generated recommendations or fall back to default ones
  const recommendations = pythonAnalysis.recommendations || [
    "Implement all missing security headers in your web server configuration.",
    "Ensure all pages are served over HTTPS with proper certificates.",
    "Review and update all cookies with proper security flags."
  ];
  
  // Use the severity counts from Python analysis
  const issuesBySeverity = pythonAnalysis.severity_counts || {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0
  };
  
  // Group issues by type for the summary
  const issuesByType = {};
  enhancedIssues.forEach(issue => {
    const id = issue.id;
    if (!issuesByType[id]) {
      issuesByType[id] = {
        count: 0,
        severity: issue.severity,
        details: issue.details
      };
    }
    issuesByType[id].count++;
  });
  
  // Sort issues by severity and then by count
  const sortedIssues = Object.entries(issuesByType)
    .map(([id, data]) => ({ id, ...data }))
    .sort((a, b) => {
      const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
      if (severityOrder[a.severity] !== severityOrder[b.severity]) {
        return severityOrder[a.severity] - severityOrder[b.severity];
      }
      return b.count - a.count;
    });
  
  // Generate the enhanced summary
  return `
## Enhanced Security Scan Summary

### Executive Summary

The deep security scan of ${domain} revealed an overall security score of **${Math.round(riskScore)}%** with a **${riskLevel.toUpperCase()}** risk level. The scan identified ${issuesBySeverity.critical} critical, ${issuesBySeverity.high} high, ${issuesBySeverity.medium} medium, and ${issuesBySeverity.low} low severity issues across ${totalUrls} URLs.

### Key Findings

${sortedIssues.slice(0, 5).map(issue => `- **${issue.id}** (${issue.severity}): ${issue.details} - Found on ${issue.count} pages`).join("\n")}

### Top Recommendations

${recommendations.slice(0, 5).map((rec, i) => `${i + 1}. ${rec}`).join("\n")}

### Remediation Steps

1. **Critical Vulnerabilities**: Address all critical vulnerabilities immediately.
   - Fix SQL injection vulnerabilities by using parameterized queries
   - Resolve path traversal issues by validating and sanitizing all file paths
   - Patch XSS vulnerabilities by implementing proper output encoding

2. **Security Headers**: Implement all missing security headers in your web server configuration.
   - Add Content-Security-Policy to restrict resource loading
   - Enable Strict-Transport-Security with a long max-age
   - Set X-Content-Type-Options to nosniff

3. **Data Protection**: Ensure sensitive data is properly protected.
   - Remove sensitive data from client-side code
   - Encrypt all sensitive data in transit and at rest
   - Implement proper access controls for sensitive information

This enhanced analysis was generated using advanced security scanning techniques. For a more comprehensive assessment, consider engaging a security professional.
`;
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