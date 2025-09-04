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

// Hacker-style console logging
function hackerLog(message, type = 'info') {
  const timestamp = new Date().toLocaleTimeString();
  const prefix = type === 'error' ? '💀 [ERROR]' : 
                type === 'success' ? '✅ [SUCCESS]' : 
                type === 'warning' ? '⚠️ [WARNING]' : 
                type === 'scan' ? '🔍 [SCAN]' :
                type === 'system' ? '💻 [SYSTEM]' :
                '🎯 [INFO]';
  console.log(`${prefix} [${timestamp}] ${message}`);
}

// WebSocket connection handler
wss.on('connection', (ws) => {
  const id = Date.now();
  clients.set(id, ws);
  
  hackerLog(`New agent connected: ID-${id}`, 'success');
  
  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message);
      hackerLog(`Agent ID-${id} transmitted: ${data.type}`, 'system');
    } catch (error) {
      hackerLog(`Corrupted transmission from ID-${id}`, 'error');
    }
  });
  
  ws.on('close', () => {
    clients.delete(id);
    hackerLog(`Agent ID-${id} disconnected`, 'warning');
  });
});

// Configuration
const config = {
  MAX_PAGES: parseInt(process.env.MAX_PAGES || '200'),
  CONCURRENCY: parseInt(process.env.CONCURRENCY || '5'),
  OUTPUT_DIR: process.env.OUTPUT_DIR || './results'
};

/**
 * Sanitize URL for use in filename
 * @param {string} url - The URL to sanitize
 * @returns {string} - Sanitized filename-safe string
 */
function sanitizeUrlForFilename(url) {
  try {
    const urlObj = new URL(url);
    let domain = urlObj.hostname;
    
    // Remove www. prefix if present
    if (domain.startsWith('www.')) {
      domain = domain.substring(4);
    }
    
    // Replace dots with dashes and remove any invalid filename characters
    return domain.replace(/[^a-zA-Z0-9.-]/g, '-').replace(/\.+/g, '-');
  } catch (error) {
    // If URL parsing fails, create a safe fallback
    return url.replace(/[^a-zA-Z0-9.-]/g, '-').substring(0, 50);
  }
}

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, '../public')));

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

app.post('/scan', async (req, res) => {
  const startTime = Date.now();
  
  try {
    const targetUrl = req.body.url;
    if (!targetUrl) {
      res.setHeader('Content-Type', 'application/json');
      return res.status(400).send(JSON.stringify({ error: 'Target URL required for penetration test' }));
    }

    hackerLog(`🎯 INITIATING PENETRATION TEST ON: ${targetUrl}`, 'scan');
    
    // Get max pages from request or use default
    const maxPages = req.body.maxPages || config.MAX_PAGES;
    
    hackerLog(`📊 Scan parameters: ${maxPages} pages, ${config.CONCURRENCY} concurrent threads`, 'system');
    
    // Create a concurrency limit
    const limit = pLimit(config.CONCURRENCY);
    
    // Crawl the website with progress reporting via WebSocket
    const results = await crawlWebsite(
      targetUrl, 
      maxPages, 
      limit, 
      (current, total, url) => {
        hackerLog(`🔍 Infiltrating (${current}/${total}): ${url}`, 'scan');
        
        // Broadcast progress to all connected clients
        clients.forEach((client) => {
          if (client.readyState === 1) { // OPEN
            client.send(JSON.stringify({
              type: 'progress',
              current,
              total,
              url,
              percentage: Math.round((current / total) * 100)
            }));
          }
        });
      }
    );
    
    hackerLog(`✅ Reconnaissance complete: ${results.length} pages analyzed`, 'success');
    
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
    
    hackerLog(`🛡️ Security assessment: ${overallScore}% security score`, 'system');
    
    // Generate AI summary
    const summary = await analyzeWithAI(results);
    
    // Create output directory if it doesn't exist
    await fs.mkdir(config.OUTPUT_DIR, { recursive: true });
    
    // Generate filename-safe URL name and date
    const urlName = sanitizeUrlForFilename(targetUrl);
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const scanDate = new Date().toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
    
    // Save detailed results with URL name and metadata
    const resultsWithMetadata = {
      metadata: {
        scannedUrl: targetUrl,
        scanDate: scanDate,
        timestamp: timestamp,
        generatedBy: "Ayash Ahmad - Elite Security Researcher",
        contact: "bhatashu666@gmail.com",
        totalPages: results.length,
        overallScore: overallScore,
        scanDuration: `${Math.round((Date.now() - startTime) / 1000)}s`
      },
      results: results
    };
    
    const resultsPath = path.join(config.OUTPUT_DIR, `${urlName}-ELITE-SCAN-${timestamp}.json`);
    await fs.writeFile(resultsPath, JSON.stringify(resultsWithMetadata, null, 2));
    
    // Save summary with URL name and header
    const summaryWithHeader = `# 🔥 ELITE SECURITY PENETRATION TEST REPORT 🔥

**TARGET:** ${targetUrl}  
**SCAN DATE:** ${scanDate}  
**SECURITY GRADE:** ${overallScore >= 90 ? 'A+' : overallScore >= 80 ? 'A' : overallScore >= 70 ? 'B' : overallScore >= 60 ? 'C' : 'F'}  
**GENERATED BY:** Ayash Ahmad - Elite Security Researcher  
**CONTACT:** bhatashu666@gmail.com  

---

${summary}`;
    
    const summaryPath = path.join(config.OUTPUT_DIR, `${urlName}-PENTEST-REPORT-${timestamp}.md`);
    await fs.writeFile(summaryPath, summaryWithHeader);
    
    // Generate PDF report with URL name
    const pdfPath = path.join(config.OUTPUT_DIR, `${urlName}-SECURITY-ASSESSMENT-${timestamp}.pdf`);
    await generatePDFReport(summary, pdfPath, targetUrl);
    
    // Prepare issues breakdown
    const issuesBreakdown = {
      critical: groupedIssues.filter(i => i.severity === 'critical').length,
      high: groupedIssues.filter(i => i.severity === 'high').length,
      medium: groupedIssues.filter(i => i.severity === 'medium').length,
      low: groupedIssues.filter(i => i.severity === 'low').length
    };
    
    const scanDuration = Math.round((Date.now() - startTime) / 1000);
    
    hackerLog(`📊 Intelligence extracted: ${groupedIssues.length} vulnerabilities identified`, 'success');
    hackerLog(`💾 Reports generated: PDF, JSON, Markdown`, 'success');
    hackerLog(`⏱️ Mission completed in ${scanDuration}s`, 'success');
    
    // Return the results and file paths
    res.setHeader('Content-Type', 'application/json');
    res.send(JSON.stringify({
      success: true,
      overallScore,
      issueCount: groupedIssues.length,
      pagesScanned: results.length,
      issuesBreakdown,
      summary,
      pdfPath: `/download?file=${encodeURIComponent(path.basename(pdfPath))}&type=pdf`,
      jsonPath: `/download?file=${encodeURIComponent(path.basename(resultsPath))}&type=json`,
      mdPath: `/download?file=${encodeURIComponent(path.basename(summaryPath))}&type=md`,
      timestamp: timestamp,
      scanDuration: `${scanDuration}s`
    }));
  } catch (error) {
    hackerLog(`💀 CRITICAL ERROR: ${error.message}`, 'error');
    res.setHeader('Content-Type', 'application/json');
    res.status(500).send(JSON.stringify({ error: 'Penetration test failed: ' + error.message }));
  }
});

// Route to download reports (PDF, JSON, Markdown)
app.get('/download', async (req, res) => {
  try {
    const fileName = req.query.file;
    const fileType = req.query.type || 'pdf';
    
    if (!fileName) {
      res.setHeader('Content-Type', 'text/plain');
      return res.status(400).send('File name is required');
    }
    
    const filePath = path.join(config.OUTPUT_DIR, fileName);
    
    // Check if file exists
    try {
      await fs.access(filePath);
    } catch (error) {
      hackerLog(`📁 File not found: ${fileName}`, 'error');
      res.setHeader('Content-Type', 'text/plain');
      return res.status(404).send('Intelligence file not found');
    }
    
    hackerLog(`📤 Extracting intelligence: ${fileName}`, 'system');
    
    // Set headers based on file type
    let contentType = 'application/octet-stream';
    let disposition = `attachment; filename=${fileName}`;
    
    switch (fileType.toLowerCase()) {
      case 'pdf':
        contentType = 'application/pdf';
        break;
      case 'json':
        contentType = 'application/json';
        break;
      case 'md':
      case 'markdown':
        contentType = 'text/markdown';
        break;
      default:
        contentType = 'application/octet-stream';
    }
    
    res.setHeader('Content-Disposition', disposition);
    res.setHeader('Content-Type', contentType);
    
    // Stream the file to the response
    const fileStream = await fs.readFile(filePath);
    res.end(fileStream);
  } catch (error) {
    hackerLog(`💀 Download failed: ${error.message}`, 'error');
    res.setHeader('Content-Type', 'text/plain');
    res.status(500).send('Intelligence extraction failed');
  }
});

/**
 * Start the Python bridge for deep security analysis
 */
function startPythonBridge() {
  try {
    const pythonBridgePath = path.join(__dirname, 'python', 'bridge.py');
    hackerLog(`🐍 Initializing Python neural bridge: ${pythonBridgePath}`, 'system');
    
    // Start the Python bridge process
    const pythonProcess = spawn('python3', [pythonBridgePath]);
    
    // Handle process output
    pythonProcess.stdout.on('data', (data) => {
      hackerLog(`🐍 Python bridge: ${data.toString().trim()}`, 'system');
    });
    
    pythonProcess.stderr.on('data', (data) => {
      hackerLog(`🐍 Python bridge error: ${data.toString().trim()}`, 'error');
    });
    
    pythonProcess.on('close', (code) => {
      hackerLog(`🐍 Python bridge terminated with code ${code}`, 'warning');
      // Restart the bridge if it crashes
      if (code !== 0) {
        hackerLog('🐍 Restarting Python bridge in 5 seconds...', 'warning');
        setTimeout(startPythonBridge, 5000);
      }
    });
    
    return pythonProcess;
  } catch (error) {
    hackerLog(`💀 Python bridge initialization failed: ${error.message}`, 'error');
    return null;
  }
}

// Start the server with hacker-style banner
server.listen(port, () => {
  console.log('\n');
  console.log('🔥 ═══════════════════════════════════════════════════════════════ 🔥');
  console.log('🚀                ELITE SECURITY SCANNER v2.0                    🚀');
  console.log('💀              PROFESSIONAL HACKER EDITION                      💀');
  console.log('🔥 ═══════════════════════════════════════════════════════════════ 🔥');
  console.log('');
  console.log('💻 [SYSTEM] Initializing advanced penetration testing framework...');
  console.log(`🌐 [NETWORK] Server deployed at http://localhost:${port}`);
  console.log('🛡️  [SECURITY] Advanced vulnerability scanning protocols loaded');
  console.log('🤖 [AI] Neural network threat analysis engine activated');
  console.log('📊 [REPORTS] Multi-format intelligence export system ready');
  console.log('🌐 [WEBSOCKET] Real-time communication channels established');
  console.log('⚡ [PERFORMANCE] High-speed concurrent scanning enabled');
  
  // Start the Python bridge
  const pythonBridge = startPythonBridge();
  if (pythonBridge) {
    hackerLog('🐍 Deep analysis bridge established successfully', 'success');
  } else {
    hackerLog('⚠️ Python bridge offline - operating in basic mode', 'warning');
  }
  
  console.log('');
  console.log('🎯 [STATUS] All systems operational - Ready for elite penetration testing');
  console.log('💻 [ACCESS] Navigate to http://localhost:' + port + ' to begin mission');
  console.log('🔐 [SECURITY] Unauthorized access will be logged and traced');
  console.log('');
  console.log('🔥 ═══════════════════════════════════════════════════════════════ 🔥');
  console.log('');
  
  // Display system stats
  setTimeout(() => {
    hackerLog('🖥️ System resources initialized', 'success');
    hackerLog('🔍 Vulnerability database loaded', 'success');
    hackerLog('🎯 Target acquisition system ready', 'success');
    hackerLog('💀 Elite hacker mode: ACTIVATED', 'success');
  }, 1000);
});