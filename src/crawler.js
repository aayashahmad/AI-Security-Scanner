import * as cheerio from "cheerio";
import { URL } from "url";
import https from "https";
import http from "http";
import { formatIssue, analyzeHeaders, score } from "./security-utils.js";

/**
 * Check if a URL belongs to the same origin as the target domain
 * @param {string} href - The URL to check
 * @param {string} origin - The origin to compare against
 * @returns {boolean} - Whether the URL is from the same origin
 */
export function sameOrigin(href, origin) {
  try {
    const u = new URL(href, origin);
    return u.origin === new URL(origin).origin;
  } catch {
    return false;
  }
}

/**
 * Extract links from HTML content
 * @param {string} html - HTML content
 * @param {string} baseUrl - Base URL for resolving relative links
 * @param {string} origin - Origin for same-origin check
 * @returns {Array} - List of discovered links
 */
export function extractLinks(html, baseUrl, origin) {
  try {
    const $ = cheerio.load(html);
    return $("a[href]")
      .map((_, a) => {
        try {
          return new URL($(a).attr("href"), baseUrl).toString();
        } catch {
          return null;
        }
      })
      .get()
      .filter(link => link && sameOrigin(link, origin));
  } catch (error) {
    console.error(`Error extracting links from ${baseUrl}:`, error);
    return [];
  }
}

/**
 * Fetch and analyze a web page
 * @param {string} url - The URL to fetch
 * @param {string} origin - The origin for same-origin check
 * @returns {Object} - Analysis results
 */
export async function fetchPage(url, origin) {
  try {
    // Use native http/https modules instead of axios
    const parsedUrl = new URL(url);
    const protocol = parsedUrl.protocol === 'https:' ? https : http;
    
    const response = await new Promise((resolve, reject) => {
      const req = protocol.get(url, {
        headers: {
          "User-Agent": "AI-Security-Agent/1.0 (passive scan; contact: admin@example.com)"
        },
        timeout: 15000
      }, (res) => {
        let data = '';
        res.on('data', (chunk) => {
          data += chunk;
        });
        res.on('end', () => {
          resolve({
            status: res.statusCode,
            headers: res.headers,
            data: data
          });
        });
      });
      
      req.on('error', (e) => {
        reject(e);
      });
      
      req.on('timeout', () => {
        req.destroy();
        reject(new Error('Request timed out'));
      });
    });

    const issues = analyzeHeaders(url, response);

    // Discover links (HTML only)
    let links = [];
    const ctype = (response.headers["content-type"] || "").toLowerCase();
    if (ctype.includes("text/html") && typeof response.data === "string") {
      links = extractLinks(response.data, url, origin);
    }

    return { url, status: response.statusCode, issues, links };
  } catch (e) {
    return { 
      url, 
      status: "error", 
      issues: [formatIssue("request_failed", "medium", e.message)], 
      links: [] 
    };
  }
}

/**
 * Crawl a website starting from a seed URL
 * @param {string} seedUrl - The starting URL
 * @param {number} maxPages - Maximum number of pages to crawl
 * @param {Function} limit - Concurrency limiter function
 * @param {Function} progressCallback - Callback for reporting progress
 * @returns {Array} - Crawl results
 */
export async function crawlWebsite(seedUrl, maxPages, limit, progressCallback = () => {}) {
  const visited = new Set();
  const queue = [seedUrl];
  const results = [];
  const origin = new URL(seedUrl).origin;

  while (queue.length && visited.size < maxPages) {
    const url = queue.shift();
    if (visited.has(url)) continue;
    visited.add(url);
    
    progressCallback(visited.size, maxPages, url);
    
    // Use p-limit to control concurrency
    const result = await limit(() => fetchPage(url, origin));
    
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
  
  return results;
}