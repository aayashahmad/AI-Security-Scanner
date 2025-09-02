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
    const links = new Set();
    
    // Extract links from anchor tags
    $("a[href]").each((_, a) => {
      try {
        const href = $(a).attr("href");
        if (href) {
          const resolvedUrl = new URL(href, baseUrl).toString();
          if (sameOrigin(resolvedUrl, origin)) {
            links.add(resolvedUrl);
          }
        }
      } catch (error) {
        // Skip invalid URLs
      }
    });
    
    // Extract links from other elements that might contain URLs
    // Forms
    $("form[action]").each((_, form) => {
      try {
        const action = $(form).attr("action");
        if (action) {
          const resolvedUrl = new URL(action, baseUrl).toString();
          if (sameOrigin(resolvedUrl, origin)) {
            links.add(resolvedUrl);
          }
        }
      } catch (error) {
        // Skip invalid URLs
      }
    });
    
    // Image maps
    $("area[href]").each((_, area) => {
      try {
        const href = $(area).attr("href");
        if (href) {
          const resolvedUrl = new URL(href, baseUrl).toString();
          if (sameOrigin(resolvedUrl, origin)) {
            links.add(resolvedUrl);
          }
        }
      } catch (error) {
        // Skip invalid URLs
      }
    });
    
    // Frames and iframes
    $("frame[src], iframe[src]").each((_, frame) => {
      try {
        const src = $(frame).attr("src");
        if (src) {
          const resolvedUrl = new URL(src, baseUrl).toString();
          if (sameOrigin(resolvedUrl, origin)) {
            links.add(resolvedUrl);
          }
        }
      } catch (error) {
        // Skip invalid URLs
      }
    });
    
    return Array.from(links);
  } catch (error) {
    console.error(`Error extracting links from ${baseUrl}:`, error);
    return [];
  }
}

/**
 * Extract content from HTML that might be hidden or loaded dynamically
 * @param {string} html - HTML content
 * @param {string} baseUrl - Base URL for resolving relative links
 * @returns {Object} - Additional content and links
 */
export function extractHiddenContent(html, baseUrl) {
  try {
    const $ = cheerio.load(html);
    const additionalContent = [];
    
    // Look for content in hidden divs
    $("div[style*='display:none'], div[style*='display: none'], div[hidden], .hidden, .d-none").each((_, el) => {
      const content = $(el).text().trim();
      if (content) {
        additionalContent.push({
          type: 'hidden_div',
          content: content
        });
      }
    });
    
    // Look for JavaScript URLs that might be used for navigation
    const jsLinks = [];
    $("a[href^='javascript:']").each((_, el) => {
      const href = $(el).attr('href');
      if (href) {
        jsLinks.push(href);
      }
    });
    
    // Look for data attributes that might contain URLs
    const dataUrls = [];
    $("[data-url], [data-href], [data-src], [data-link]").each((_, el) => {
      const dataUrl = $(el).attr('data-url') || $(el).attr('data-href') || 
                     $(el).attr('data-src') || $(el).attr('data-link');
      if (dataUrl) {
        try {
          const resolvedUrl = new URL(dataUrl, baseUrl).toString();
          dataUrls.push(resolvedUrl);
        } catch (error) {
          // Skip invalid URLs
        }
      }
    });
    
    return {
      additionalContent,
      jsLinks,
      dataUrls
    };
  } catch (error) {
    console.error(`Error extracting hidden content from ${baseUrl}:`, error);
    return {
      additionalContent: [],
      jsLinks: [],
      dataUrls: []
    };
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
      // Extract visible links
      links = extractLinks(response.data, url, origin);
      
      // Extract hidden content and potential additional links
      const hiddenContent = extractHiddenContent(response.data, url);
      
      // Add data URLs to links if they're from the same origin
      hiddenContent.dataUrls.forEach(dataUrl => {
        if (sameOrigin(dataUrl, origin) && !links.includes(dataUrl)) {
          links.push(dataUrl);
        }
      });
      
      // Check for potential security issues in hidden content
      if (hiddenContent.additionalContent.length > 0) {
        issues.push(formatIssue(
          "hidden_content", 
          "low", 
          `Found ${hiddenContent.additionalContent.length} hidden elements that might contain sensitive information`
        ));
      }
      
      // Check for JavaScript URLs (potential security risk)
      if (hiddenContent.jsLinks.length > 0) {
        issues.push(formatIssue(
          "javascript_urls", 
          "medium", 
          `Found ${hiddenContent.jsLinks.length} JavaScript URLs that might be used for malicious purposes`
        ));
      }
    }

    // Include headers and content in the result for deep analysis
    return { 
      url, 
      status: response.statusCode, 
      issues, 
      links,
      headers: response.headers,
      content: ctype.includes("text/html") ? response.data : null
    };
  } catch (e) {
    return { 
      url, 
      status: "error", 
      issues: [formatIssue("request_failed", "medium", e.message)], 
      links: [],
      headers: {},
      content: null
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