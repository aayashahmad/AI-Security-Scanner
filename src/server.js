import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs/promises';
import dotenv from 'dotenv';
import { crawlWebsite } from './crawler.js';
import { groupIssuesByType, calculateOverallScore } from './security-utils.js';
import { analyzeWithAI } from './ai-utils.js';
import { generatePDFReport } from './pdf-utils.js';
import pLimit from 'p-limit';
import http from 'http';
import { WebSocketServer } from 'ws';
import { spawn } from 'child_process';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const port = process.env.PORT || 3001;

// Create HTTP server
const server = http.createServer(app);

// Create WebSocket server
const wss = new WebSocketServer({ server });

// Store active connections
const clients = new Map();

// WebSocket connection handler
wss.on('connection', (ws) => {
  const id = Date.now();
  clients.set(id, ws);
  
  console.log(`New WebSocket connection: ${id}`);
  
  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message);
      console.log(`Received message from ${id}:`, data);
    } catch (error) {
      console.error('Error parsing WebSocket message:', error);
    }
  });
  
  ws.on('close', () => {
    clients.delete(id);
    console.log(`WebSocket connection closed: ${id}`);
  });
});

// Configuration
const config = {
  MAX_PAGES: parseInt(process.env.MAX_PAGES || '200'),
  CONCURRENCY: parseInt(process.env.CONCURRENCY || '5'),
  OUTPUT_DIR: process.env.OUTPUT_DIR || './results'
};

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, '../public')));

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

app.post('/scan', async (req, res) => {
  try {
    const targetUrl = req.body.url;
    if (!targetUrl) {
      return res.status(400).json({ error: 'URL is required' });
    }

    // Get max pages from request or use default
    const maxPages = req.body.maxPages || config.MAX_PAGES;
    
    // Create a concurrency limit
    const limit = pLimit(config.CONCURRENCY);
    
    // Crawl the website with progress reporting via WebSocket
    const results = await crawlWebsite(
      targetUrl, 
      maxPages, 
      limit, 
      (current, total, url) => {
        console.log(`Scanning (${current}/${total}): ${url}`);
        
        // Broadcast progress to all connected clients
        clients.forEach((client) => {
          if (client.readyState === 1) { // OPEN
            client.send(JSON.stringify({
              type: 'progress',
              current,
              total,
              url
            }));
          }
        });
      }
    );
    
    // Notify clients that scan is complete
    clients.forEach((client) => {
      if (client.readyState === 1) { // OPEN
        client.send(JSON.stringify({
          type: 'complete'
        }));
      }
    });
    
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
    res.json({
      success: true,
      overallScore,
      issueCount: groupedIssues.length,
      pagesScanned: results.length,
      issuesBreakdown,
      summary,
      pdfPath: `/download?file=${encodeURIComponent(path.basename(pdfPath))}`
    });
  } catch (error) {
    console.error('Error during scan:', error);
    res.status(500).json({ error: 'An error occurred during the scan' });
  }
});

// Route to download the PDF report
app.get('/download', async (req, res) => {
  try {
    const fileName = req.query.file;
    if (!fileName) {
      return res.status(400).send('File name is required');
    }
    
    const filePath = path.join(config.OUTPUT_DIR, fileName);
    
    // Check if file exists
    try {
      await fs.access(filePath);
    } catch (error) {
      return res.status(404).send('File not found');
    }
    
    // Set headers for file download
    res.setHeader('Content-Disposition', `attachment; filename=${fileName}`);
    res.setHeader('Content-Type', 'application/pdf');
    
    // Stream the file to the response
    const fileStream = await fs.readFile(filePath);
    res.send(fileStream);
  } catch (error) {
    console.error('Error downloading file:', error);
    res.status(500).send('An error occurred while downloading the file');
  }
});

/**
 * Start the Python bridge for deep security analysis
 */
function startPythonBridge() {
  try {
    const pythonBridgePath = path.join(__dirname, 'python', 'bridge.py');
    console.log(`Starting Python bridge from: ${pythonBridgePath}`);
    
    // Start the Python bridge process
    const pythonProcess = spawn('python3', [pythonBridgePath]);
    
    // Handle process output
    pythonProcess.stdout.on('data', (data) => {
      console.log(`Python bridge: ${data}`);
    });
    
    pythonProcess.stderr.on('data', (data) => {
      console.error(`Python bridge error: ${data}`);
    });
    
    pythonProcess.on('close', (code) => {
      console.log(`Python bridge process exited with code ${code}`);
      // Restart the bridge if it crashes
      if (code !== 0) {
        console.log('Restarting Python bridge...');
        setTimeout(startPythonBridge, 5000); // Restart after 5 seconds
      }
    });
    
    return pythonProcess;
  } catch (error) {
    console.error('Failed to start Python bridge:', error);
    return null;
  }
}

// Start the server
server.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
  
  // Start the Python bridge
  const pythonBridge = startPythonBridge();
  if (pythonBridge) {
    console.log('Python bridge started successfully');
  } else {
    console.warn('Python bridge failed to start. Deep analysis features will be limited.');
  }
});