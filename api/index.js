import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs/promises';
import dotenv from 'dotenv';
import { crawlWebsite } from '../src/crawler.js';
import { groupIssuesByType, calculateOverallScore } from '../src/security-utils.js';
import { analyzeWithAI } from '../src/ai-utils.js';
import { generatePDFReport } from '../src/pdf-utils.js';
import pLimit from 'p-limit';

dotenv.config();

const app = express();

// Configuration
const config = {
  MAX_PAGES: parseInt(process.env.MAX_PAGES || '200'),
  CONCURRENCY: parseInt(process.env.CONCURRENCY || '5'),
  OUTPUT_DIR: process.env.OUTPUT_DIR || './results'
};

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Routes
app.post('/scan', async (req, res) => {
  try {
    const targetUrl = req.body.url;
    if (!targetUrl) {
      res.setHeader('Content-Type', 'application/json');
      return res.status(400).send(JSON.stringify({ error: 'URL is required' }));
    }

    // Get max pages from request or use default
    const maxPages = req.body.maxPages || config.MAX_PAGES;
    
    // Create a concurrency limit
    const limit = pLimit(config.CONCURRENCY);
    
    // Crawl the website (without WebSocket progress in serverless)
    const results = await crawlWebsite(
      targetUrl, 
      maxPages, 
      limit
    );
    
    // Group issues by type
    const groupedIssues = groupIssuesByType(results);
    
    // Calculate overall score
    const overallScore = calculateOverallScore(results);
    
    // Generate AI summary
    const summary = await analyzeWithAI(results);
    
    // Create output directory if it doesn't exist
    await fs.mkdir(config.OUTPUT_DIR, { recursive: true });
    
    // Save detailed results
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const resultsPath = path.join(config.OUTPUT_DIR, `scan-results-${timestamp}.json`);
    await fs.writeFile(resultsPath, JSON.stringify(results, null, 2));
    
    // Save summary
    const summaryPath = path.join(config.OUTPUT_DIR, `scan-summary-${timestamp}.md`);
    await fs.writeFile(summaryPath, summary);
    
    // Generate PDF report
    const pdfPath = path.join(config.OUTPUT_DIR, `scan-report-${timestamp}.pdf`);
    await generatePDFReport(summary, pdfPath, req.body.url);
    
    // Prepare issues breakdown
    const issuesBreakdown = {
      critical: groupedIssues.filter(i => i.severity === 'critical').length,
      high: groupedIssues.filter(i => i.severity === 'high').length,
      medium: groupedIssues.filter(i => i.severity === 'medium').length,
      low: groupedIssues.filter(i => i.severity === 'low').length
    };
    
    // Return the results and file paths
    res.setHeader('Content-Type', 'application/json');
    res.send(JSON.stringify({
      success: true,
      overallScore,
      issueCount: groupedIssues.length,
      pagesScanned: results.length,
      issuesBreakdown,
      summary,
      pdfPath: `/download?file=${encodeURIComponent(path.basename(pdfPath))}`
    }));
  } catch (error) {
    console.error('Error during scan:', error);
    res.setHeader('Content-Type', 'application/json');
    res.status(500).send(JSON.stringify({ error: 'An error occurred during the scan' }));
  }
});

// Route to download the PDF report
app.get('/download', async (req, res) => {
  try {
    const fileName = req.query.file;
    if (!fileName) {
      res.setHeader('Content-Type', 'text/plain');
      return res.status(400).send('File name is required');
    }
    
    const filePath = path.join(config.OUTPUT_DIR, fileName);
    
    // Check if file exists
    try {
      await fs.access(filePath);
    } catch (error) {
      res.setHeader('Content-Type', 'text/plain');
      return res.status(404).send('File not found');
    }
    
    // Set headers for file download
    res.setHeader('Content-Disposition', `attachment; filename=${fileName}`);
    res.setHeader('Content-Type', 'application/pdf');
    
    // Stream the file to the response
    const fileStream = await fs.readFile(filePath);
    res.end(fileStream);
  } catch (error) {
    console.error('Error downloading file:', error);
    res.setHeader('Content-Type', 'text/plain');
    res.status(500).send('An error occurred while downloading the file');
  }
});

// Export the Express API as default
export default function handler(req, res) {
  return app(req, res);
}