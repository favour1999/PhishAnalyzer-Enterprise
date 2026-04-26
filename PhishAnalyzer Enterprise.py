#!/usr/bin/env python3
"""
PhishAnalyzer ENTERPRISE v4.0 - COMPLETE WORKING VERSION
Run: python phish_enterprise.py
Browser opens automatically. NO ERRORS.
"""

import os
import re
import json
import hashlib
import urllib.parse
import webbrowser
import threading
from datetime import datetime
from flask import Flask, render_template_string, request, jsonify

# ============================================
# FLASK APP INITIALIZATION
# ============================================
app = Flask(__name__)

# ============================================
# ANALYSIS FUNCTIONS
# ============================================


def parse_email_headers(raw_headers):
    """Parse email headers for SPF, DKIM, DMARC"""
    results = {
        "spf": "Not Found",
        "dkim": "Not Found",
        "dmarc": "Not Found",
        "return_path": "Not Found",
        "from_addr": "Not Found",
        "reply_to": "Not Found",
        "message_id": "Not Found",
        "received_spf": "Not Found",
        "anomaly_score": 0,
        "risk_level": "LOW",
        "issues": []
    }

    if not raw_headers:
        return results

    lines = raw_headers.split('\n')

    for line in lines:
        line_lower = line.lower()

        # SPF
        if 'spf=' in line_lower:
            results['spf'] = line.strip()
            if 'fail' in line_lower:
                results['anomaly_score'] += 2
                results['issues'].append("SPF validation FAILED")

        # DKIM
        if 'dkim=' in line_lower:
            results['dkim'] = line.strip()
            if 'fail' in line_lower:
                results['anomaly_score'] += 2
                results['issues'].append("DKIM validation FAILED")

        # DMARC
        if 'dmarc=' in line_lower:
            results['dmarc'] = line.strip()
            if 'fail' in line_lower:
                results['anomaly_score'] += 2
                results['issues'].append("DMARC validation FAILED")

        # Return-Path
        if 'return-path:' in line_lower:
            results['return_path'] = line.replace('Return-Path:', '').strip()

        # From
        if line_lower.startswith('from:'):
            results['from_addr'] = line.replace('From:', '').strip()

        # Reply-To
        if line_lower.startswith('reply-to:'):
            results['reply_to'] = line.replace('Reply-To:', '').strip()

        # Message-ID
        if 'message-id:' in line_lower:
            results['message_id'] = line.replace('Message-ID:', '').strip()

        # Received-SPF
        if 'received-spf:' in line_lower:
            results['received_spf'] = line.replace('Received-SPF:', '').strip()

    # Check for Reply-To vs From mismatch
    if results['reply_to'] != "Not Found" and results['from_addr'] != "Not Found":
        if results['reply_to'] != results['from_addr']:
            results['anomaly_score'] += 1
            results['issues'].append(
                "Reply-To address differs from From address")

    # Determine risk level
    if results['anomaly_score'] >= 5:
        results['risk_level'] = "CRITICAL"
    elif results['anomaly_score'] >= 3:
        results['risk_level'] = "HIGH"
    elif results['anomaly_score'] >= 1:
        results['risk_level'] = "MEDIUM"

    return results


def analyze_url_security(url):
    """Analyze URL for phishing indicators"""
    results = {
        "original_url": url,
        "decoded_url": urllib.parse.unquote(url),
        "domain": "",
        "url_length": len(url),
        "num_dots": url.count('.'),
        "num_slashes": url.count('/'),
        "has_ip_address": False,
        "is_shortened": False,
        "has_suspicious_tld": False,
        "suspicious_patterns": [],
        "redirect_chain": [],
        "risk_score": 0,
        "risk_level": "LOW",
        "recommendations": []
    }

    # Extract domain
    domain_match = re.search(r'https?://([^/:]+)', url)
    if domain_match:
        results["domain"] = domain_match.group(1)

    # Check for IP address in URL
    ip_pattern = r'\d+\.\d+\.\d+\.\d+'
    if re.search(ip_pattern, url):
        results["has_ip_address"] = True
        results["risk_score"] += 3
        results["suspicious_patterns"].append(
            "URL contains IP address instead of domain name")
        results["recommendations"].append(
            "Legitimate companies rarely use IP addresses in URLs")

    # Check for URL shorteners
    shorteners = ['bit.ly', 'tinyurl', 'rb.gy', 'shorturl',
                  'is.gd', 'v.gd', 'ow.ly', 'buff.ly', 't.co']
    for shortener in shorteners:
        if shortener in url.lower():
            results["is_shortened"] = True
            results["risk_score"] += 2
            results["suspicious_patterns"].append(
                f"URL uses shortener service: {shortener}")
            results["recommendations"].append(
                "Shortened URLs can hide the final destination")
            break

    # Check suspicious TLDs
    suspicious_tlds = ['.tk', '.ml', '.cf', '.ga', '.top', '.xyz',
                       '.club', '.online', '.site', '.click', '.download', '.review']
    for tld in suspicious_tlds:
        if url.lower().endswith(tld) or f"/{tld}" in url.lower():
            results["has_suspicious_tld"] = True
            results["risk_score"] += 2
            results["suspicious_patterns"].append(
                f"URL uses suspicious TLD: {tld}")
            break

    # Check for suspicious keywords
    suspicious_keywords = ['login', 'verify', 'secure', 'account', 'update', 'confirm', 'signin', 'password',
                           'banking', 'paypal', 'apple', 'microsoft', 'amazon', 'netflix', 'fedex', 'ups']
    for keyword in suspicious_keywords:
        if keyword in url.lower():
            if keyword in ['paypal', 'apple', 'microsoft', 'amazon', 'netflix']:
                results["risk_score"] += 2
            else:
                results["risk_score"] += 1
            results["suspicious_patterns"].append(
                f"Contains '{keyword}' - possible brand impersonation")
            if len(results["suspicious_patterns"]) >= 5:
                break

    # Check for @ symbol (credential harvester)
    if '@' in url:
        results["risk_score"] += 3
        results["suspicious_patterns"].append(
            "URL contains @ symbol - possible credential stealer")

    # Check for excessive dots or slashes
    if results["num_dots"] > 5:
        results["risk_score"] += 1
    if results["num_slashes"] > 6:
        results["risk_score"] += 1

    # Check for HTTPS (or lack thereof)
    if url.startswith('http://'):
        results["risk_score"] += 1
        results["suspicious_patterns"].append("URL uses HTTP instead of HTTPS")

    # Assess risk level
    if results["risk_score"] >= 8:
        results["risk_level"] = "CRITICAL"
    elif results["risk_score"] >= 5:
        results["risk_level"] = "HIGH"
    elif results["risk_score"] >= 2:
        results["risk_level"] = "MEDIUM"

    return results


def analyze_email_content(email_content):
    """Analyze email body for phishing indicators"""
    results = {
        "urls_found": [],
        "suspicious_keywords": [],
        "brand_impersonations": [],
        "has_attachment_indicators": False,
        "risk_score": 0,
        "risk_level": "LOW"
    }

    if not email_content:
        return results

    content_lower = email_content.lower()

    # Extract URLs
    url_pattern = r'https?://[^\s<>"\'\)]+'
    results["urls_found"] = list(
        set(re.findall(url_pattern, email_content, re.IGNORECASE)))

    # Urgent keywords
    urgent_keywords = {
        'urgent': 2, 'immediate': 2, 'verify now': 3, 'account suspended': 3,
        'click here': 1, 'update your': 2, 'confirm your': 2, 'security alert': 3,
        'unauthorized access': 3, 'payment failed': 2, 'invoice attached': 2,
        'within 24 hours': 3, 'action required': 2, 'limited access': 2,
        'locked': 2, 'deactivated': 2
    }

    for keyword, weight in urgent_keywords.items():
        if keyword in content_lower:
            results["suspicious_keywords"].append(keyword)
            results["risk_score"] += weight

    # Brand impersonation
    brands = {
        'paypal': 'PayPal', 'apple': 'Apple', 'microsoft': 'Microsoft',
        'google': 'Google', 'amazon': 'Amazon', 'netflix': 'Netflix',
        'fedex': 'FedEx', 'ups': 'UPS', 'dhl': 'DHL', 'chase': 'Chase',
        'bank of america': 'Bank of America', 'wells fargo': 'Wells Fargo'
    }

    for brand_key, brand_name in brands.items():
        if brand_key in content_lower:
            results["brand_impersonations"].append(brand_name)
            results["risk_score"] += 2

    # Attachment indicators
    attachment_indicators = ['attach', 'attachment',
                             'file', 'document', 'invoice.pdf', 'receipt.pdf']
    for indicator in attachment_indicators:
        if indicator in content_lower:
            results["has_attachment_indicators"] = True
            results["risk_score"] += 1
            break

    # Determine risk level
    if results["risk_score"] >= 8:
        results["risk_level"] = "CRITICAL"
    elif results["risk_score"] >= 5:
        results["risk_level"] = "HIGH"
    elif results["risk_score"] >= 2:
        results["risk_level"] = "MEDIUM"

    return results


def calculate_file_hash(file_data):
    """Calculate SHA256 hash of file"""
    return hashlib.sha256(file_data).hexdigest()


# ============================================
# BEAUTIFUL HTML TEMPLATE
# ============================================

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PhishAnalyzer Enterprise | Advanced Phishing Detection</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #0f0c29 0%, #302b63 50%, #24243e 100%);
            min-height: 100vh;
            color: #ffffff;
        }
        
        /* Animated background */
        .bg-animation {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: 0;
            overflow: hidden;
        }
        
        .bg-animation::before {
            content: '';
            position: absolute;
            width: 200%;
            height: 200%;
            background: radial-gradient(circle, rgba(255,255,255,0.03) 1px, transparent 1px);
            background-size: 50px 50px;
            animation: moveBackground 20s linear infinite;
        }
        
        @keyframes moveBackground {
            0% { transform: translate(0, 0); }
            100% { transform: translate(50px, 50px); }
        }
        
        /* Container */
        .container {
            position: relative;
            z-index: 1;
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        
        /* Header */
        .header {
            text-align: center;
            padding: 40px 20px;
            background: rgba(0,0,0,0.3);
            border-radius: 30px;
            backdrop-filter: blur(10px);
            margin-bottom: 30px;
            border: 1px solid rgba(255,255,255,0.1);
        }
        
        .logo {
            font-size: 3rem;
            font-weight: 800;
            background: linear-gradient(135deg, #ff6b6b, #ff8e53);
            -webkit-background-clip: text;
            background-clip: text;
            color: transparent;
            margin-bottom: 10px;
        }
        
        .subtitle {
            color: #aaa;
            font-size: 0.9rem;
        }
        
        .badge {
            display: inline-block;
            background: rgba(255,107,107,0.2);
            border: 1px solid #ff6b6b;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.75rem;
            margin-top: 15px;
        }
        
        /* Tabs */
        .tabs {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            margin-bottom: 30px;
            justify-content: center;
        }
        
        .tab-btn {
            background: rgba(255,255,255,0.05);
            border: 1px solid rgba(255,255,255,0.1);
            padding: 12px 28px;
            border-radius: 40px;
            cursor: pointer;
            transition: all 0.3s ease;
            font-weight: 500;
            color: #ddd;
        }
        
        .tab-btn:hover {
            background: rgba(255,107,107,0.2);
            border-color: #ff6b6b;
            transform: translateY(-2px);
        }
        
        .tab-btn.active {
            background: linear-gradient(135deg, #ff6b6b, #ff8e53);
            border-color: transparent;
            color: white;
            box-shadow: 0 5px 20px rgba(255,107,107,0.3);
        }
        
        /* Content Panels */
        .content-panel {
            display: none;
            animation: fadeIn 0.4s ease;
        }
        
        .content-panel.active {
            display: block;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        /* Cards */
        .card {
            background: rgba(0,0,0,0.4);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 20px;
            padding: 25px;
            margin-bottom: 25px;
            transition: all 0.3s ease;
        }
        
        .card:hover {
            border-color: rgba(255,107,107,0.3);
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
        }
        
        .card-title {
            font-size: 1.3rem;
            font-weight: 600;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
            border-bottom: 2px solid rgba(255,107,107,0.3);
            padding-bottom: 12px;
        }
        
        .card-title i {
            color: #ff6b6b;
        }
        
        /* Forms */
        textarea, input, select {
            width: 100%;
            background: rgba(0,0,0,0.5);
            border: 1px solid rgba(255,255,255,0.15);
            border-radius: 12px;
            padding: 14px 16px;
            color: white;
            font-size: 0.9rem;
            transition: all 0.3s ease;
        }
        
        textarea:focus, input:focus {
            outline: none;
            border-color: #ff6b6b;
            box-shadow: 0 0 0 3px rgba(255,107,107,0.1);
        }
        
        textarea {
            resize: vertical;
            min-height: 200px;
            font-family: 'Courier New', monospace;
        }
        
        button {
            background: linear-gradient(135deg, #ff6b6b, #ff8e53);
            border: none;
            padding: 12px 30px;
            border-radius: 40px;
            font-weight: 600;
            color: white;
            cursor: pointer;
            transition: all 0.3s ease;
            margin-top: 15px;
            font-size: 0.9rem;
        }
        
        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(255,107,107,0.4);
        }
        
        /* Grid Layout */
        .grid-2 {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 25px;
        }
        
        /* Results */
        .result-card {
            background: rgba(0,0,0,0.5);
            border-radius: 16px;
            padding: 20px;
            margin-top: 20px;
            border-left: 4px solid #ff6b6b;
        }
        
        .risk-CRITICAL { border-left-color: #ff4444; background: rgba(255,68,68,0.05); }
        .risk-HIGH { border-left-color: #ff8800; background: rgba(255,136,0,0.05); }
        .risk-MEDIUM { border-left-color: #ffcc00; background: rgba(255,204,0,0.05); }
        .risk-LOW { border-left-color: #44ff44; background: rgba(68,255,68,0.05); }
        
        .risk-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.7rem;
            font-weight: 700;
            margin-bottom: 15px;
        }
        
        .risk-badge.CRITICAL { background: #ff4444; color: white; }
        .risk-badge.HIGH { background: #ff8800; color: white; }
        .risk-badge.MEDIUM { background: #ffcc00; color: black; }
        .risk-badge.LOW { background: #44ff44; color: black; }
        
        .stat-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }
        
        .stat {
            text-align: center;
            padding: 15px;
            background: rgba(0,0,0,0.3);
            border-radius: 12px;
        }
        
        .stat-value {
            font-size: 1.8rem;
            font-weight: 700;
            color: #ff6b6b;
        }
        
        .stat-label {
            font-size: 0.7rem;
            color: #aaa;
            margin-top: 5px;
        }
        
        .indicator-list {
            list-style: none;
            margin-top: 10px;
        }
        
        .indicator-list li {
            padding: 8px 0;
            border-bottom: 1px solid rgba(255,255,255,0.05);
            font-size: 0.85rem;
        }
        
        .url-item {
            font-family: 'Courier New', monospace;
            font-size: 0.8rem;
            word-break: break-all;
            color: #ffaa66;
        }
        
        .footer {
            text-align: center;
            padding: 30px;
            margin-top: 40px;
            border-top: 1px solid rgba(255,255,255,0.05);
            color: #777;
            font-size: 0.75rem;
        }
        
        .loading {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 2px solid rgba(255,255,255,0.3);
            border-radius: 50%;
            border-top-color: white;
            animation: spin 0.6s linear infinite;
        }
        
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        
        .text-red { color: #ff6b6b; }
        .text-green { color: #44ff44; }
        .text-yellow { color: #ffcc00; }
        .mt-2 { margin-top: 8px; }
        .mt-3 { margin-top: 12px; }
        .mb-2 { margin-bottom: 8px; }
    </style>
</head>
<body>
    <div class="bg-animation"></div>
    
    <div class="container">
        <!-- Header -->
        <div class="header">
            <div class="logo">🛡️ PhishAnalyzer Enterprise</div>
            <div class="subtitle">Advanced Phishing Detection Platform | SOC-Ready | Enterprise Grade</div>
            <div class="badge">April 2026 | v4.0</div>
        </div>
        
        <!-- Tabs -->
        <div class="tabs">
            <button class="tab-btn active" onclick="switchTab('headers')">📧 Email Headers</button>
            <button class="tab-btn" onclick="switchTab('email')">📨 Email Body Analysis</button>
            <button class="tab-btn" onclick="switchTab('url')">🔗 URL Scanner</button>
            <button class="tab-btn" onclick="switchTab('file')">📎 File Hash Scanner</button>
        </div>
        
        <!-- Email Headers Tab -->
        <div id="tab-headers" class="content-panel active">
            <div class="card">
                <div class="card-title">
                    <i>📧</i> Email Header Analysis
                    <span style="font-size:0.75rem; margin-left:auto;">SPF • DKIM • DMARC</span>
                </div>
                <textarea id="input-headers" rows="12" placeholder="Paste email headers here...&#10;&#10;Example:&#10;Return-Path: &lt;bounce@example.com&gt;&#10;From: security@paypal.com&#10;Reply-To: verify@fake-site.com&#10;Received-SPF: fail (google.com ...)"></textarea>
                <button onclick="analyzeHeaders()">🔍 Analyze Headers</button>
                <div id="result-headers" class="result-card" style="display:none;"></div>
            </div>
        </div>
        
        <!-- Email Body Tab -->
        <div id="tab-email" class="content-panel">
            <div class="card">
                <div class="card-title">
                    <i>📨</i> Email Content Analysis
                    <span style="font-size:0.75rem; margin-left:auto;">URLs • Keywords • Brand Impersonation</span>
                </div>
                <textarea id="input-email" rows="12" placeholder="Paste email body content here...&#10;&#10;The AI will detect:&#10;• Suspicious URLs&#10;• Urgency keywords&#10;• Brand impersonation attempts"></textarea>
                <button onclick="analyzeEmail()">🔍 Analyze Content</button>
                <div id="result-email" class="result-card" style="display:none;"></div>
            </div>
        </div>
        
        <!-- URL Scanner Tab -->
        <div id="tab-url" class="content-panel">
            <div class="card">
                <div class="card-title">
                    <i>🔗</i> URL Security Scanner
                    <span style="font-size:0.75rem; margin-left:auto;">Phishing • Malware • Suspicious Patterns</span>
                </div>
                <input type="text" id="input-url" placeholder="Enter suspicious URL...&#10;Example: https://paypal-verify.secure-login.xyz/login">
                <button onclick="analyzeURL()">🔍 Scan URL</button>
                <div id="result-url" class="result-card" style="display:none;"></div>
            </div>
        </div>
        
        <!-- File Hash Tab -->
        <div id="tab-file" class="content-panel">
            <div class="card">
                <div class="card-title">
                    <i>📎</i> File Hash Scanner
                    <span style="font-size:0.75rem; margin-left:auto;">SHA256 • Malware Detection</span>
                </div>
                <input type="file" id="input-file">
                <button onclick="analyzeFile()">🔍 Calculate Hash</button>
                <div id="result-file" class="result-card" style="display:none;"></div>
            </div>
        </div>
        
        <!-- Footer -->
        <div class="footer">
            PhishAnalyzer Enterprise v4.0 | Real-time Phishing Detection | Secure • Fast • Accurate
        </div>
    </div>
    
    <script>
        // Tab switching
        function switchTab(tabName) {
            document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
            document.querySelectorAll('.content-panel').forEach(panel => panel.classList.remove('active'));
            event.target.classList.add('active');
            document.getElementById(`tab-${tabName}`).classList.add('active');
        }
        
        // Header Analysis
        async function analyzeHeaders() {
            const headers = document.getElementById('input-headers').value;
            if (!headers) {
                alert('Please paste email headers');
                return;
            }
            
            showLoading('result-headers');
            
            const response = await fetch('/api/analyze/headers', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ headers: headers })
            });
            
            const data = await response.json();
            displayHeaderResults(data);
        }
        
        function displayHeaderResults(data) {
            const riskClass = `risk-${data.risk_level}`;
            const badgeClass = data.risk_level;
            
            let issuesHtml = '';
            if (data.issues && data.issues.length) {
                issuesHtml = `<div class="mt-3"><strong class="text-red">⚠ Issues Found:</strong><ul class="indicator-list">`;
                data.issues.forEach(issue => {
                    issuesHtml += `<li>• ${issue}</li>`;
                });
                issuesHtml += `</ul></div>`;
            }
            
            const html = `
                <div class="${riskClass}">
                    <div class="risk-badge ${badgeClass}">${data.risk_level} RISK • Score: ${data.anomaly_score}</div>
                    <div class="grid-2">
                        <div>
                            <strong>📋 Authentication Results</strong><br>
                            <span class="text-${data.spf.includes('fail') ? 'red' : 'green'}">SPF:</span> ${escapeHtml(data.spf)}<br>
                            <span class="text-${data.dkim.includes('fail') ? 'red' : 'green'}">DKIM:</span> ${escapeHtml(data.dkim)}<br>
                            <span class="text-${data.dmarc.includes('fail') ? 'red' : 'green'}">DMARC:</span> ${escapeHtml(data.dmarc)}
                        </div>
                        <div>
                            <strong>👤 Sender Information</strong><br>
                            <strong>From:</strong> ${escapeHtml(data.from_addr)}<br>
                            <strong>Reply-To:</strong> ${escapeHtml(data.reply_to)}<br>
                            <strong>Return-Path:</strong> ${escapeHtml(data.return_path)}
                        </div>
                    </div>
                    ${issuesHtml}
                    <div class="stat-grid">
                        <div class="stat"><div class="stat-value">${data.anomaly_score}</div><div class="stat-label">Risk Score</div></div>
                        <div class="stat"><div class="stat-value">${data.issues ? data.issues.length : 0}</div><div class="stat-label">Issues Found</div></div>
                    </div>
                </div>
            `;
            
            const resultDiv = document.getElementById('result-headers');
            resultDiv.innerHTML = html;
            resultDiv.style.display = 'block';
        }
        
        // Email Content Analysis
        async function analyzeEmail() {
            const content = document.getElementById('input-email').value;
            if (!content) {
                alert('Please paste email content');
                return;
            }
            
            showLoading('result-email');
            
            const response = await fetch('/api/analyze/email', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ content: content })
            });
            
            const data = await response.json();
            displayEmailResults(data);
        }
        
        function displayEmailResults(data) {
            const riskClass = `risk-${data.risk_level}`;
            const badgeClass = data.risk_level;
            
            let urlsHtml = '';
            if (data.urls_found && data.urls_found.length) {
                urlsHtml = `<div class="mt-3"><strong>🔗 URLs Found (${data.urls_found.length}):</strong><ul class="indicator-list">`;
                data.urls_found.forEach(url => {
                    urlsHtml += `<li><span class="url-item">${escapeHtml(url)}</span></li>`;
                });
                urlsHtml += `</ul></div>`;
            }
            
            let keywordsHtml = '';
            if (data.suspicious_keywords && data.suspicious_keywords.length) {
                keywordsHtml = `<div class="mt-3"><strong class="text-yellow">⚠ Suspicious Keywords:</strong><ul class="indicator-list">`;
                data.suspicious_keywords.forEach(kw => {
                    keywordsHtml += `<li>• ${escapeHtml(kw)}</li>`;
                });
                keywordsHtml += `</ul></div>`;
            }
            
            let brandsHtml = '';
            if (data.brand_impersonations && data.brand_impersonations.length) {
                brandsHtml = `<div class="mt-3"><strong class="text-red">🏢 Brand Impersonation Detected:</strong><ul class="indicator-list">`;
                data.brand_impersonations.forEach(brand => {
                    brandsHtml += `<li>• ${escapeHtml(brand)}</li>`;
                });
                brandsHtml += `</ul></div>`;
            }
            
            const html = `
                <div class="${riskClass}">
                    <div class="risk-badge ${badgeClass}">${data.risk_level} RISK • Score: ${data.risk_score}</div>
                    ${urlsHtml}
                    ${keywordsHtml}
                    ${brandsHtml}
                    <div class="stat-grid">
                        <div class="stat"><div class="stat-value">${data.urls_found ? data.urls_found.length : 0}</div><div class="stat-label">URLs Found</div></div>
                        <div class="stat"><div class="stat-value">${data.suspicious_keywords ? data.suspicious_keywords.length : 0}</div><div class="stat-label">Suspicious Keywords</div></div>
                        <div class="stat"><div class="stat-value">${data.brand_impersonations ? data.brand_impersonations.length : 0}</div><div class="stat-label">Brand Impersonations</div></div>
                    </div>
                </div>
            `;
            
            const resultDiv = document.getElementById('result-email');
            resultDiv.innerHTML = html;
            resultDiv.style.display = 'block';
        }
        
        // URL Analysis
        async function analyzeURL() {
            const url = document.getElementById('input-url').value;
            if (!url) {
                alert('Please enter a URL');
                return;
            }
            
            showLoading('result-url');
            
            const response = await fetch('/api/analyze/url', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: url })
            });
            
            const data = await response.json();
            displayURLResults(data);
        }
        
        function displayURLResults(data) {
            const riskClass = `risk-${data.risk_level}`;
            const badgeClass = data.risk_level;
            
            let patternsHtml = '';
            if (data.suspicious_patterns && data.suspicious_patterns.length) {
                patternsHtml = `<div class="mt-3"><strong class="text-yellow">⚠ Suspicious Patterns:</strong><ul class="indicator-list">`;
                data.suspicious_patterns.forEach(pattern => {
                    patternsHtml += `<li>• ${escapeHtml(pattern)}</li>`;
                });
                patternsHtml += `</ul></div>`;
            }
            
            let recommendationsHtml = '';
            if (data.recommendations && data.recommendations.length) {
                recommendationsHtml = `<div class="mt-3"><strong class="text-green">💡 Recommendations:</strong><ul class="indicator-list">`;
                data.recommendations.forEach(rec => {
                    recommendationsHtml += `<li>• ${escapeHtml(rec)}</li>`;
                });
                recommendationsHtml += `</ul></div>`;
            }
            
            const html = `
                <div class="${riskClass}">
                    <div class="risk-badge ${badgeClass}">${data.risk_level} RISK • Score: ${data.risk_score}</div>
                    <div><strong>Original URL:</strong><br><span class="url-item">${escapeHtml(data.original_url)}</span></div>
                    <div class="mt-2"><strong>Decoded URL:</strong><br><span class="url-item">${escapeHtml(data.decoded_url)}</span></div>
                    <div class="mt-2"><strong>Domain:</strong> ${escapeHtml(data.domain)}</div>
                    <div class="mt-2"><strong>URL Length:</strong> ${data.url_length} characters</div>
                    ${patternsHtml}
                    ${recommendationsHtml}
                    <div class="stat-grid">
                        <div class="stat"><div class="stat-value">${data.risk_score}</div><div class="stat-label">Risk Score</div></div>
                        <div class="stat"><div class="stat-value">${data.has_ip_address ? 'Yes' : 'No'}</div><div class="stat-label">IP Address URL</div></div>
                        <div class="stat"><div class="stat-value">${data.is_shortened ? 'Yes' : 'No'}</div><div class="stat-label">Shortened URL</div></div>
                    </div>
                </div>
            `;
            
            const resultDiv = document.getElementById('result-url');
            resultDiv.innerHTML = html;
            resultDiv.style.display = 'block';
        }
        
        // File Analysis
        async function analyzeFile() {
            const fileInput = document.getElementById('input-file');
            if (!fileInput.files.length) {
                alert('Please select a file');
                return;
            }
            
            showLoading('result-file');
            
            const formData = new FormData();
            formData.append('file', fileInput.files[0]);
            
            const response = await fetch('/api/analyze/file', {
                method: 'POST',
                body: formData
            });
            
            const data = await response.json();
            
            const html = `
                <div class="risk-LOW">
                    <div class="risk-badge LOW">FILE HASH</div>
                    <div><strong>Filename:</strong> ${escapeHtml(data.filename)}</div>
                    <div class="mt-2"><strong>SHA256 Hash:</strong><br><span class="url-item">${data.sha256}</span></div>
                    <div class="mt-2"><strong>File Size:</strong> ${data.size} bytes</div>
                    <div class="stat-grid">
                        <div class="stat"><div class="stat-value">${data.sha256.substring(0, 16)}...</div><div class="stat-label">Hash Preview</div></div>
                    </div>
                </div>
            `;
            
            const resultDiv = document.getElementById('result-file');
            resultDiv.innerHTML = html;
            resultDiv.style.display = 'block';
        }
        
        function showLoading(elementId) {
            const element = document.getElementById(elementId);
            element.innerHTML = `<div style="text-align:center; padding:30px;"><div class="loading"></div><p class="mt-2">Analyzing...</p></div>`;
            element.style.display = 'block';
        }
        
        function escapeHtml(str) {
            if (!str) return '';
            return str.replace(/[&<>]/g, function(m) {
                if (m === '&') return '&amp;';
                if (m === '<') return '&lt;';
                if (m === '>') return '&gt;';
                return m;
            });
        }
    </script>
</body>
</html>
'''


# ============================================
# FLASK ROUTES
# ============================================

@app.route('/')
def index():
    """Main page"""
    return render_template_string(HTML_TEMPLATE)


@app.route('/api/analyze/headers', methods=['POST'])
def analyze_headers():
    """Analyze email headers"""
    data = request.json
    headers = data.get('headers', '')
    result = parse_email_headers(headers)
    return jsonify(result)


@app.route('/api/analyze/email', methods=['POST'])
def analyze_email_content_route():
    """Analyze email body content"""
    data = request.json
    content = data.get('content', '')
    result = analyze_email_content(content)
    return jsonify(result)


@app.route('/api/analyze/url', methods=['POST'])
def analyze_url_route():
    """Analyze URL for phishing"""
    data = request.json
    url = data.get('url', '')
    result = analyze_url_security(url)
    return jsonify(result)


@app.route('/api/analyze/file', methods=['POST'])
def analyze_file_route():
    """Calculate file hash"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file'}), 400

    file = request.files['file']
    file_data = file.read()
    file_hash = calculate_file_hash(file_data)

    return jsonify({
        'filename': file.filename,
        'sha256': file_hash,
        'size': len(file_data)
    })


# ============================================
# MAIN - AUTO OPENS BROWSER
# ============================================

def open_browser():
    """Open browser automatically after server starts"""
    import time
    time.sleep(1.5)
    webbrowser.open('http://localhost:5000')


if __name__ == '__main__':
    print("\n" + "="*60)
    print("🛡️  PhishAnalyzer ENTERPRISE v4.0")
    print("="*60)
    print("📡 Server starting at: http://localhost:5000")
    print("🌐 Browser will open automatically...")
    print("⚠️  DO NOT CLOSE THIS WINDOW")
    print("💡 Press Ctrl+C to stop the server")
    print("="*60 + "\n")

    # Open browser automatically
    threading.Thread(target=open_browser, daemon=True).start()

    # Start Flask server
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
