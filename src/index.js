import axios from "axios";
import * as cheerio from "cheerio";
import pLimit from "p-limit";
import { URL } from "url";
import fs from "fs/promises";
import path from "path";
import dotenv from "dotenv";

dotenv.config();

// Configuration
const config = {
  MAX_PAGES: process.env.MAX_PAGES || 200,
  CONCURRENCY: process.env.CONCURRENCY || 5,
  ORIGIN: process.env.TARGET_DOMAIN || "https://yourdomain.com",
  OUTPUT_DIR: process.env.OUTPUT_DIR || "./results"
};

// Initialize data structures
const visited = new Set();
const queue = [config.ORIGIN];
const results = [];

// Create a concurrency limit
const limit = pLimit(config.CONCURRENCY);

/**
 * Check if a URL belongs to the same origin as the target domain
 * @param {string} href - The URL to check
 * @returns {boolean} - Whether the URL is from the same origin
 */
function sameOrigin(href) {
  try {
    const u = new URL(href, config.ORIGIN);
    return u.origin === new URL(config.ORIGIN).origin;
  } catch {
    return false;
  }
}

/**
 * Format an issue for reporting
 * @param {string} id - Issue identifier
 * @param {string} severity - Issue severity (critical, high, medium, low)
 * @param {string} details - Issue details
 * @returns {Object} - Formatted issue
 */
function formatIssue(id, severity, details) {
  return { id, severity, details };
}

/**
 * Analyze HTTP headers for security issues
 * @param {string} url - The URL being analyzed
 * @param {Object} res - The HTTP response
 * @returns {Array} - List of security issues
 */
function analyzeHeaders(url, res) {
  const h = Object.fromEntries(
    Object.entries(res.headers || {}).map(([k, v]) => [k.toLowerCase(), v])
  );

  const issues = [];

  const isHttps = url.startsWith("https://");
  if (!isHttps) issues.push(formatIssue("no_https", "critical", "Page not served over HTTPS"));

  if (!h["strict-transport-security"])
    issues.push(formatIssue("missing_hsts", "high", "Add Strict-Transport-Security"));

  if (!h["content-security-policy"])
    issues.push(formatIssue("missing_csp", "high", "Add Content-Security-Policy"));

  if (h["x-content-type-options"]?.toLowerCase() !== "nosniff")
    issues.push(formatIssue("x_content_type_options", "medium", "Set X-Content-Type-Options: nosniff"));

  if (!h["x-frame-options"] && !h["content-security-policy"]?.includes("frame-ancestors"))
    issues.push(formatIssue("clickjacking", "medium", "Add X-Frame-Options or frame-ancestors in CSP"));

  if (!h["referrer-policy"])
    issues.push(formatIssue("missing_referrer_policy", "low", "Add Referrer-Policy"));

  if (!h["permissions-policy"])
    issues.push(formatIssue("missing_permissions_policy", "low", "Add Permissions-Policy"));

  // Cookie checks
  const setCookie = ([]).concat(h["set-cookie"] || []);
  const cookieIssues = [];
  setCookie.forEach(c => {
    const lower = c.toLowerCase();
    if (!lower.includes("secure")) cookieIssues.push("Secure");
    if (!lower.includes("httponly")) cookieIssues.push("HttpOnly");
    if (!/(samesite=lax|samesite=strict|samesite=none)/.test(lower)) cookieIssues.push("SameSite");
  });
  if (setCookie.length && cookieIssues.length)
    issues.push(formatIssue("cookie_flags", "high", `Missing cookie flags: ${[...new Set(cookieIssues)].join(", ")}`))

  return issues;
}

/**
 * Calculate security score based on issues
 * @param {Array} issues - List of security issues
 * @returns {Object} - Score details
 */
function score(issues) {
  const weights = {
    no_https: 20,
    missing_hsts: 10,
    missing_csp: 20,
    x_content_type_options: 5,
    clickjacking: 5,
    missing_referrer_policy: 5,
    missing_permissions_policy: 5,
    cookie_flags: 20,
    mixed_content: 10
  };
  const total = Object.values(weights).reduce((a, b) => a + b, 0);
  const penalty = issues.reduce((sum, i) => sum + (weights[i.id] || 0), 0);
  const pct = Math.max(0, Math.round(((total - penalty) / total) * 100));
  return { total, penalty, pct };
}

/**
 * Fetch and analyze a web page
 * @param {string} url - The URL to fetch
 * @returns {Object} - Analysis results
 */
async function fetchPage(url) {
  try {
    const res = await axios.get(url, {
      maxRedirects: 5,
      validateStatus: () => true,
      timeout: 15000,
    });

    const issues = analyzeHeaders(url, res);

    // Discover links (HTML only)
    let links = [];
    const ctype = (res.headers["content-type"] || "").toLowerCase();
    if (ctype.includes("text/html") && typeof res.data === "string") {
      const $ = cheerio.load(res.data);
      links = $("a[href]")
        .map((_, a) => {
          try {
            return new URL($(a).attr("href"), url).toString();
          } catch {
            return null;
          }
        })
        .get()
        .filter(link => link && sameOrigin(link));
    }

    return { url, status: res.status, issues, links };
  } catch (e) {
    return { url, status: "error", issues: [formatIssue("request_failed", "medium", e.message)], links: [] };
  }
}

/**
 * Generate an AI summary of the security findings
 * @param {Array} results - Analysis results
 * @returns {string} - AI-generated summary
 */
async function generateAISummary(results) {
  // This is a placeholder for the AI summary generation
  // In a real implementation, you would use OpenAI or another AI service
  
  // Example implementation with OpenAI (commented out)
  /*
  const { Configuration, OpenAIApi } = require("openai");
  const configuration = new Configuration({
    apiKey: process.env.OPENAI_API_KEY,
  });
  const openai = new OpenAIApi(configuration);
  
  const prompt = `Analyze these website security findings and provide a summary with recommendations:\n${JSON.stringify(results, null, 2)}`;
  
  const response = await openai.createCompletion({
    model: "text-davinci-003",
    prompt,
    max_tokens: 500,
  });
  
  return response.data.choices[0].text.trim();
  */
  
  // For now, return a simple summary
  const totalIssues = results.reduce((sum, r) => sum + r.issues.length, 0);
  const criticalIssues = results.reduce((sum, r) => sum + r.issues.filter(i => i.severity === "critical").length, 0);
  const highIssues = results.reduce((sum, r) => sum + r.issues.filter(i => i.severity === "high").length, 0);
  const mediumIssues = results.reduce((sum, r) => sum + r.issues.filter(i => i.severity === "medium").length, 0);
  const lowIssues = results.reduce((sum, r) => sum + r.issues.filter(i => i.severity === "low").length, 0);
  
  const avgScore = results.reduce((sum, r) => sum + (r.score?.pct || 0), 0) / results.length;
  
  return `
## Security Scan Summary

- Total URLs scanned: ${results.length}
- Overall security score: ${Math.round(avgScore)}%
- Total issues found: ${totalIssues}
  - Critical: ${criticalIssues}
  - High: ${highIssues}
  - Medium: ${mediumIssues}
  - Low: ${lowIssues}

### Top Recommendations

1. Implement HTTPS across all pages
2. Add proper security headers (CSP, HSTS, etc.)
3. Ensure all cookies have proper security flags
4. Review and fix any critical and high severity issues
  `;
}

/**
 * Save results to a file
 * @param {Array} results - Analysis results
 * @param {string} summary - AI-generated summary
 */
async function saveResults(results, summary) {
  try {
    // Create output directory if it doesn't exist
    await fs.mkdir(config.OUTPUT_DIR, { recursive: true });
    
    // Save detailed results
    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
    const resultsPath = path.join(config.OUTPUT_DIR, `scan-results-${timestamp}.json`);
    await fs.writeFile(resultsPath, JSON.stringify(results, null, 2));
    
    // Save summary
    const summaryPath = path.join(config.OUTPUT_DIR, `scan-summary-${timestamp}.md`);
    await fs.writeFile(summaryPath, summary);
    
    console.log(`Results saved to ${resultsPath}`);
    console.log(`Summary saved to ${summaryPath}`);
  } catch (error) {
    console.error("Error saving results:", error);
  }
}

/**
 * Main function to run the security scan
 */
async function run() {
  console.log(`Starting security scan of ${config.ORIGIN}`);
  console.log(`Max pages: ${config.MAX_PAGES}, Concurrency: ${config.CONCURRENCY}`);
  
  while (queue.length && visited.size < config.MAX_PAGES) {
    const url = queue.shift();
    if (visited.has(url)) continue;
    visited.add(url);
    
    console.log(`Scanning (${visited.size}/${config.MAX_PAGES}): ${url}`);
    
    // Use p-limit to control concurrency
    const result = await limit(() => fetchPage(url));
    
    // Add new links to the queue
    for (const link of result.links) {
      if (!visited.has(link) && !queue.includes(link)) {
        queue.push(link);
      }
    }
    
    // Calculate score for this page
    result.score = score(result.issues);
    
    // Add to results
    results.push(result);
  }
  
  console.log(`Scan complete. Visited ${visited.size} pages.`);
  
  // Generate AI summary
  console.log("Generating AI summary...");
  const summary = await generateAISummary(results);
  
  // Save results
  await saveResults(results, summary);
  
  // Print summary to console
  console.log(summary);
}

// Run the security scan
run().catch(error => {
  console.error("Error running security scan:", error);
  process.exit(1);
});