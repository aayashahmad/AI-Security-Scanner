# AI Security Agent

An authorized-only AI security agent that crawls website URLs, runs security checks, and returns a risk score with detailed findings.

## Features

- URL discovery and crawling (respects same-origin policy)
- Passive security checks:
  - HTTPS enforcement
  - TLS certificate validation
  - Security headers analysis
  - Cookie security flags
  - Mixed content detection
- Security scoring system (% safe)
- AI-powered analysis and recommendations

## Important Guardrails

⚠️ **IMPORTANT: Only scan websites you own or have explicit written permission to test. Unauthorized scanning can be illegal and disruptive.**

- This tool is designed for passive scanning by default (analyzing headers, TLS, cookies, misconfigurations)
- Active testing should only be added with explicit consent and appropriate rate limits
- The agent does not store sensitive page data; it only stores metadata (statuses, headers, issues)

## Installation

1. Clone this repository
2. Install dependencies:

```bash
npm install
```

3. Create a `.env` file with your configuration (see `.env.example`)

## Usage

1. Configure the target domain in the `.env` file:

```
TARGET_DOMAIN=https://yourdomain.com
```

2. Run the security scan:

```bash
npm start
```

3. View the results in the `results` directory

## Configuration

The following environment variables can be configured in the `.env` file:

- `TARGET_DOMAIN`: The domain to scan (must include protocol, e.g., https://)
- `MAX_PAGES`: Maximum number of pages to scan (default: 200)
- `CONCURRENCY`: Number of concurrent requests (default: 5)
- `OUTPUT_DIR`: Directory to save results (default: ./results)
- `OPENAI_API_KEY`: OpenAI API key for AI-powered analysis (optional)

## Security Checks

The agent performs the following security checks:

1. **HTTPS Enforcement**
   - Checks if the site is served over HTTPS
   - Verifies HTTP to HTTPS redirects

2. **Security Headers**
   - Content-Security-Policy
   - Strict-Transport-Security
   - X-Content-Type-Options
   - X-Frame-Options (or frame-ancestors in CSP)
   - Referrer-Policy
   - Permissions-Policy
   - Cross-Origin-Resource-Policy

3. **Cookie Security**
   - Secure flag
   - HttpOnly flag
   - SameSite attribute

4. **Other Checks**
   - Mixed content detection
   - TLS certificate validation

## Scoring System

The security score is calculated based on the following weights:

- HTTPS/TLS: 20 points
- HSTS: 10 points
- CSP: 20 points
- X-Content-Type-Options: 5 points
- X-Frame-Options / frame-ancestors: 5 points
- Referrer-Policy: 5 points
- Permissions-Policy: 5 points
- Cookie flags: 20 points
- Mixed content: 10 points

The final score is calculated as: (passedWeight / totalWeight) * 100, with penalties for critical issues.

## AI Analysis

When an OpenAI API key is provided, the agent uses AI to:

- Summarize security findings
- Group duplicate issues
- Suggest defensive remediations
- Generate an executive summary

## License

MIT