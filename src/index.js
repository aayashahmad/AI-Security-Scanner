import pLimit from "p-limit";
import fs from "fs/promises";
import path from "path";
import dotenv from "dotenv";
import { crawlWebsite } from "./crawler.js";
import { groupIssuesByType, calculateOverallScore } from "./security-utils.js";
import { analyzeWithAI } from "./ai-utils.js";
import { generatePDFReport } from "./pdf-utils.js";

dotenv.config();

// Configuration
const config = {
  MAX_PAGES: parseInt(process.env.MAX_PAGES || "200"),
  CONCURRENCY: parseInt(process.env.CONCURRENCY || "5"),
  ORIGIN: process.env.TARGET_DOMAIN || "https://yourdomain.com",
  OUTPUT_DIR: process.env.OUTPUT_DIR || "./results"
};

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
    
    // Generate PDF report
    const pdfPath = path.join(config.OUTPUT_DIR, `scan-report-${timestamp}.pdf`);
    await generatePDFReport(summary, pdfPath);
    
    console.log(`Results saved to ${resultsPath}`);
    console.log(`Summary saved to ${summaryPath}`);
    console.log(`PDF report saved to ${pdfPath}`);
  } catch (error) {
    console.error("Error saving results:", error);
  }
}

/**
 * Progress callback for the crawler
 * @param {number} current - Current page count
 * @param {number} total - Total page limit
 * @param {string} url - Current URL being processed
 */
function progressCallback(current, total, url) {
  console.log(`Scanning (${current}/${total}): ${url}`);
}

/**
 * Main function to run the security scan
 */
async function run() {
  console.log(`Starting security scan of ${config.ORIGIN}`);
  console.log(`Max pages: ${config.MAX_PAGES}, Concurrency: ${config.CONCURRENCY}`);
  
  // Create a concurrency limit
  const limit = pLimit(config.CONCURRENCY);
  
  // Crawl the website
  const results = await crawlWebsite(
    config.ORIGIN, 
    config.MAX_PAGES, 
    limit, 
    progressCallback
  );
  
  console.log(`Scan complete. Scanned ${results.length} pages.`);
  
  // Group issues by type
  const groupedIssues = groupIssuesByType(results);
  
  // Calculate overall score
  const overallScore = calculateOverallScore(results);
  
  console.log(`Overall security score: ${overallScore}%`);
  console.log(`Found ${groupedIssues.length} unique issue types.`);
  
  // Generate AI summary
  console.log("Generating AI summary...");
  const summary = await analyzeWithAI(results);
  
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