import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import { crawlWebsite } from '../src/crawler.js';
import { groupIssuesByType, calculateOverallScore } from '../src/security-utils.js';
import { analyzeWithAI } from '../src/ai-utils.js';
import pLimit from 'p-limit';
// Replace markdown-pdf with jspdf and html-to-text
import { jsPDF } from 'jspdf';
import { convert } from 'html-to-text';

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

/**
 * Generate a PDF report from markdown content
 * @param {string} markdownContent - The markdown content to convert to PDF
 * @returns {Promise<Buffer>} - The PDF as a buffer
 */
async function generatePDFBuffer(markdownContent) {
  try {
    // Create a new PDF document
    const doc = new jsPDF();
    
    // Add header with creator information
    doc.setFontSize(16);
    doc.text('Security Scan Report', 20, 20);
    
    doc.setFontSize(12);
    doc.text('Created by: Ayash Ahmad', 20, 30);
    doc.text('Email: bhatashu666@gmail.com', 20, 40);
    
    doc.line(20, 45, 190, 45);
    
    // Convert markdown to plain text for simplicity
    const textOptions = {
      wordwrap: 130,
      preserveNewlines: true
    };
    
    const text = convert(markdownContent, textOptions);
    
    // Add the content
    doc.setFontSize(10);
    const textLines = doc.splitTextToSize(text, 170);
    doc.text(textLines, 20, 55);
    
    // Return the PDF as a buffer
    return Buffer.from(doc.output('arraybuffer'));
  } catch (error) {
    console.error('Error generating PDF report:', error);
    throw error;
  }
}

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
    
    // Generate PDF buffer
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const pdfFileName = `scan-report-${timestamp}.pdf`;
    
    // Prepare issues breakdown
    const issuesBreakdown = {
      critical: groupedIssues.filter(i => i.severity === 'critical').length,
      high: groupedIssues.filter(i => i.severity === 'high').length,
      medium: groupedIssues.filter(i => i.severity === 'medium').length,
      low: groupedIssues.filter(i => i.severity === 'low').length
    };
    
    // Return the results with PDF path
    res.setHeader('Content-Type', 'application/json');
    res.send(JSON.stringify({
      success: true,
      overallScore,
      issueCount: groupedIssues.length,
      pagesScanned: results.length,
      issuesBreakdown,
      summary,
      pdfPath: `/download?file=${encodeURIComponent(pdfFileName)}`
    }));
  } catch (error) {
    console.error('Error during scan:', error);
    res.setHeader('Content-Type', 'application/json');
    res.status(500).send(JSON.stringify({ error: 'An error occurred during the scan: ' + error.message }));
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
    
    // Extract timestamp from filename
    const timestampMatch = fileName.match(/scan-report-(.*?)\.pdf/);
    if (!timestampMatch) {
      res.setHeader('Content-Type', 'text/plain');
      return res.status(400).send('Invalid file name format');
    }
    
    const timestamp = timestampMatch[1];
    
    // Get the scan summary from the request query
    const scanUrl = req.query.url;
    if (!scanUrl) {
      res.setHeader('Content-Type', 'text/plain');
      return res.status(400).send('URL parameter is required');
    }
    
    // Get the summary from the query
    const summary = req.query.summary;
    if (!summary) {
      res.setHeader('Content-Type', 'text/plain');
      return res.status(400).send('Summary parameter is required');
    }
    
    // Generate PDF buffer
    const pdfBuffer = await generatePDFBuffer(summary);
    
    // Set headers for file download
    res.setHeader('Content-Disposition', `attachment; filename=${fileName}`);
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Length', pdfBuffer.length);
    
    // Send the buffer
    res.end(pdfBuffer);
  } catch (error) {
    console.error('Error downloading file:', error);
    res.setHeader('Content-Type', 'text/plain');
    res.status(500).send('An error occurred while generating the PDF file');
  }
});

// Export the Express API as default
export default function handler(req, res) {
  return app(req, res);
}