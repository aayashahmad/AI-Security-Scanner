import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import { crawlWebsite } from '../src/crawler.js';
import { groupIssuesByType, calculateOverallScore } from '../src/security-utils.js';
import { analyzeWithAI } from '../src/ai-utils.js';
import pLimit from 'p-limit';

dotenv.config();

const app = express();

// Configuration
const config = {
  MAX_PAGES: parseInt(process.env.MAX_PAGES || '200'),
  CONCURRENCY: parseInt(process.env.CONCURRENCY || '5')
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
    
    // In serverless environment, we don't save files
    // Instead, we return the data directly
    
    // Prepare issues breakdown
    const issuesBreakdown = {
      critical: groupedIssues.filter(i => i.severity === 'critical').length,
      high: groupedIssues.filter(i => i.severity === 'high').length,
      medium: groupedIssues.filter(i => i.severity === 'medium').length,
      low: groupedIssues.filter(i => i.severity === 'low').length
    };
    
    // Return the results without file paths
    res.setHeader('Content-Type', 'application/json');
    res.send(JSON.stringify({
      success: true,
      overallScore,
      issueCount: groupedIssues.length,
      pagesScanned: results.length,
      issuesBreakdown,
      summary
      // No PDF path in serverless environment
    }));
  } catch (error) {
    console.error('Error during scan:', error);
    res.setHeader('Content-Type', 'application/json');
    res.status(500).send(JSON.stringify({ error: 'An error occurred during the scan: ' + error.message }));
  }
});

// No download route needed in serverless environment

// Export the Express API as default
export default function handler(req, res) {
  return app(req, res);
}