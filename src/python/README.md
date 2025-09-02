# Deep Security Analyzer - Python Integration

## Overview

This directory contains Python scripts that enhance the AI Security Agent with deeper security analysis capabilities. The Python integration provides more advanced pattern matching, content analysis, and security recommendations than what's possible with JavaScript alone.

## Components

- `deep_analyzer.py`: Core analysis engine that performs deep security scanning
- `bridge.py`: HTTP server that bridges between JavaScript and Python
- `requirements.txt`: Python dependencies

## How It Works

1. When the Node.js server starts, it spawns the Python bridge as a subprocess
2. The bridge starts an HTTP server on port 3002 (default)
3. During security scans, the JavaScript code sends scan results to the Python bridge
4. The Python analyzer performs deep analysis on the content and headers
5. Enhanced results are returned to JavaScript for inclusion in the final report

## Installation

Install the required Python dependencies:

```bash
pip install -r requirements.txt
```

## Manual Testing

You can manually test the Python bridge by starting it directly:

```bash
python3 bridge.py
```

Then send a test request:

```bash
curl -X POST -H "Content-Type: application/json" -d '[{"url":"https://example.com","content":"<html>test</html>","headers":{"server":"nginx"}}]' http://localhost:3002/analyze
```

## Extending

To add new security checks:

1. Add new regex patterns to the `patterns` dictionary in `DeepSecurityAnalyzer.__init__`
2. Add corresponding severity mappings
3. Add new recommendation logic in the `generate_recommendations` method