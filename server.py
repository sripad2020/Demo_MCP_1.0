import socket
import asyncio
from typing import Dict, List, Optional, Any, Union
import dns
import whois
import aiohttp
from flask import Flask, request, jsonify
import json
import logging
import re
from bs4 import BeautifulSoup
from datetime import datetime, UTC
from urllib.parse import urljoin, urlparse
import dns.reversename
import dns.resolver
from aiohttp import ClientSession
from flask.wrappers import Response

app = Flask(__name__)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('scan.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger: logging.Logger = logging.getLogger(__name__)

TOOLS: Dict[str, Dict[str, Any]] = {
    'resolve_target': {
        'description': 'Resolve the target domain to an IP address and perform reverse DNS lookup.',
        'schema': {
            'type': 'object',
            'properties': {
                'target': {'type': 'string',
                           'description': 'The target URL or domain to resolve (e.g., https://example.com or example.com)'}
            },
            'required': ['target']
        }
    },
    'scan_whois': {
        'description': 'Perform a WHOIS lookup to gather domain registration details and check for expiration.',
        'schema': {
            'type': 'object',
            'properties': {
                'domain': {'type': 'string', 'description': 'The domain to perform WHOIS lookup on (e.g., example.com)'}
            },
            'required': ['domain']
        }
    },
    'scan_web_vuln': {
        'description': 'Perform web vulnerability scanning for XSS, SQLi, and other common web vulnerabilities.',
        'schema': {
            'type': 'object',
            'properties': {
                'url': {'type': 'string',
                        'description': 'The target URL to scan for vulnerabilities (e.g., https://example.com)'}
            },
            'required': ['url']
        }
    }
}

@app.route('/mcp', methods=['GET', 'POST'])
def mcp() -> Response:
    req: Optional[Dict[str, Any]] = request.get_json(silent=True)
    if not req or 'jsonrpc' not in req or 'method' not in req:
        return jsonify({
            'jsonrpc': '2.0',
            'error': {'code': -32600, 'message': 'Invalid Request'},
            'id': req.get('id') if req else None
        })

    method: str = req['method']
    params: Dict[str, Any] = req.get('params', {})
    req_id: Optional[Any] = req.get('id')

    try:
        if method == 'initialize':
            return jsonify({
                'jsonrpc': '2.0',
                'result': {
                    'protocolVersion': '2024-11-05',
                    'serverInfo': {'name': 'Simple MCP Server', 'version': '1.0.0'},
                    'capabilities': {'tools': {}}
                },
                'id': req_id
            })

        elif method == 'tools/list':
            tools: List[Dict[str, Any]] = []
            for tool_name, tool_information in TOOLS.items():
                tools.append({
                    "name": tool_name,
                    "description": tool_information['description'],
                    "schema": tool_information['schema']
                })
            return jsonify({
                'jsonrpc': '2.0',
                'result': {'tools': tools},
                'id': req_id
            })

        elif method == 'tools/call':
            tool_name: Optional[str] = params.get('name')
            args: Dict[str, str] = params.get('arguments', {})

            if tool_name == 'resolve_target':
                target: str = args.get('target') if isinstance(args, dict) else args
                result = asyncio.run(resolve_target(target))
                return jsonify({
                    'jsonrpc': '2.0',
                    'result': {'content': [{'type': 'text', 'text': json.dumps(result)}]},
                    'id': req_id
                })

            elif tool_name == 'scan_whois':
                domain: str = args.get('domain') if isinstance(args, dict) else args
                result = asyncio.run(scan_whois(domain))
                return jsonify({
                    'jsonrpc': '2.0',
                    'result': {'content': [{'type': 'text', 'text': json.dumps(result)}]},
                    'id': req_id
                })

            elif tool_name == 'scan_web_vuln':
                url: str = args.get('url') if isinstance(args, dict) else args

                async def run_scan() -> Dict[str, Any]:
                    async with aiohttp.ClientSession() as client:
                        parsed_domain = urlparse(url).netloc
                        config = {
                            "max_depth": 2,
                            "rate_limit_delay": 1.0
                        }
                        payloads = {
                            "xss": ["<script>alert(1)</script>"],
                            "sql_injection": ["' OR '1'='1", "' UNION SELECT NULL --"]
                        }
                        return await scan_web_vulnerabilities_extended(url, client, config, payloads)

                result = asyncio.run(run_scan())
                return jsonify({
                    'jsonrpc': '2.0',
                    'result': {'content': [{'type': 'text', 'text': json.dumps(result)}]},
                    'id': req_id
                })

            else:
                return jsonify({
                    'jsonrpc': '2.0',
                    'error': {'code': -32601, 'message': f'Tool {tool_name} not found'},
                    'id': req_id
                })

        else:
            return jsonify({
                'jsonrpc': '2.0',
                'error': {'code': -32601, 'message': 'Method not found'},
                'id': req_id
            })

    except Exception as e:
        return jsonify({
            'jsonrpc': '2.0',
            'error': {'code': -32000, 'message': str(e)},
            'id': req_id
        })

async def resolve_target(target: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        'target_ip': None,
        'dns_info': {
            'reverse_dns': []
        },
        'error': None,
        'error_type': None
    }

    try:
        if target.startswith(('http://', 'https://')):
            target = urlparse(target).netloc

        target_ip: str = socket.gethostbyname(target)
        result['target_ip'] = target_ip

        try:
            rev_name = dns.reversename.from_address(target_ip)
            reversed_dns = dns.resolver.resolve(rev_name, "PTR")
            result['dns_info']['reverse_dns'] = [str(r) for r in reversed_dns]
        except Exception as e:
            logger.warning(f"Reverse DNS lookup failed: {str(e)}")
            result['dns_info']['reverse_dns'] = []

    except socket.gaierror as e:
        result['error'] = f'Could not resolve {target} to an IP address'
        result['error_type'] = 'ResolutionError'
        logger.error(f"DNS resolution failed for {target}: {str(e)}")

    return result

def make_json_serializable(whois_data: Any) -> Dict[str, Any]:
    """Convert WHOIS data to a JSON-serializable dictionary."""
    serializable: Dict[str, Any] = {}
    for key, value in whois_data.items():
        if isinstance(value, datetime):
            serializable[key] = value.isoformat()
        elif isinstance(value, list):
            serializable[key] = [v.isoformat() if isinstance(v, datetime) else str(v) for v in value]
        else:
            serializable[key] = str(value)
    return serializable

async def scan_whois(domain: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        'whois_info': {},
        'vulnerabilities': []
    }

    try:
        if domain.startswith(('http://', 'https://')):
            domain = urlparse(domain).netloc

        w = whois.whois(domain)
        result['whois_info'] = make_json_serializable(w)

        if w.expiration_date:
            expiry_date = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
            if expiry_date < datetime.now(UTC):
                result['vulnerabilities'].append({
                    'type': 'domain_expired',
                    'details': f"Domain expired on {expiry_date.isoformat()}",
                    'severity': 'high',
                    'cvss_score': 9.0,
                    'mitigation': "Renew the domain immediately."
                })
    except Exception as e:
        logger.warning(f"WHOIS lookup failed for {domain}: {str(e)}")
        result['whois_info'] = {'error': str(e)}

    return result

async def scan_web_vulnerabilities_extended(
    base_url: str,
    http_client: ClientSession,
    config: Dict[str, Any],
    additional_payloads: Dict[str, List[str]]
) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        'vulnerabilities': [],
        'security_headers': {},
        'cookies': {}
    }

    urls: set = {base_url}
    visited: set = set()
    forms: List[Dict[str, Any]] = []
    seen_forms: set = set()
    parsed_url = urlparse(base_url)

    SECURITY_HEADERS: List[str] = [
        'Content-Security-Policy',
        'X-Frame-Options',
        'X-Content-Type-Options',
        'Strict-Transport-Security',
        'X-XSS-Protection',
        'Referrer-Policy',
        'Feature-Policy',
        'Permissions-Policy'
    ]

    async def analyze_headers(response_headers: Dict[str, str]) -> Dict[str, Dict[str, Any]]:
        headers_analysis: Dict[str, Dict[str, Any]] = {}
        for header in SECURITY_HEADERS:
            if header in response_headers:
                headers_analysis[header] = {
                    'present': True,
                    'value': response_headers[header]
                }
            else:
                headers_analysis[header] = {
                    'present': False,
                    'severity': 'medium' if header in ['Content-Security-Policy',
                                                       'Strict-Transport-Security'] else 'low'
                }
        return headers_analysis

    async def analyze_cookies(cookies: Any) -> Dict[str, Dict[str, Any]]:
        cookie_analysis: Dict[str, Dict[str, Any]] = {}
        for cookie in cookies:
            cookie_analysis[cookie.name] = {
                'secure': cookie.secure,
                'httponly': cookie.get('httponly', False),
                'samesite': cookie.get('samesite', 'None'),
                'domain': cookie.domain,
                'path': cookie.path,
                'expires': cookie.expires
            }
            if not cookie.secure:
                result['vulnerabilities'].append({
                    'type': 'cookie_security',
                    'details': f"Cookie '{cookie.name}' missing Secure flag",
                    'severity': 'medium',
                    'cvss_score': 5.3,
                    'mitigation': "Set Secure flag for cookies"
                })
            if not cookie.get('httponly'):
                result['vulnerabilities'].append({
                    'type': 'cookie_security',
                    'details': f"Cookie '{cookie.name}' missing HttpOnly flag",
                    'severity': 'medium',
                    'cvss_score': 4.8,
                    'mitigation': "Set HttpOnly flag for cookies"
                })
        return cookie_analysis

    async def crawl(url: str, depth: int = 0) -> None:
        if depth > config.get('max_depth', 2) or url in visited:
            return
        visited.add(url)
        try:
            headers: Dict[str, str] = config.get('headers', {})
            async with http_client.get(url, headers=headers) as response:
                if response.status != 200:
                    return

                result['security_headers'][url] = await analyze_headers(response.headers)
                result['cookies'][url] = await analyze_cookies(response.cookies)

                text: str = await response.text()
                soup = BeautifulSoup(text, 'html.parser')

                for form in soup.find_all('form'):
                    action: str = form.get('action', '')
                    form_url: str = urljoin(url, action)
                    method: str = form.get('method', 'get').lower()
                    form_key: str = f"{form_url}:{method}"
                    if form_key in seen_forms:
                        continue
                    seen_forms.add(form_key)
                    inputs: List[Dict[str, str]] = []
                    for inp in form.find_all('input'):
                        if inp.get('name'):
                            inputs.append({
                                'name': inp.get('name'),
                                'type': inp.get('type', 'text')
                            })
                    if inputs:
                        forms.append({
                            'url': form_url,
                            'inputs': inputs,
                            'method': method,
                            'headers': dict(response.headers)
                        })

                for a in soup.find_all('a', href=True):
                    next_url: str = urljoin(url, a['href'])
                    if urlparse(next_url).netloc == parsed_url.netloc:
                        urls.add(next_url)
                        await crawl(next_url, depth + 1)
        except Exception as e:
            logger.warning(f"Crawling failed for {url}: {str(e)}")

    await crawl(base_url)

    for form in forms:
        for input_field in form['inputs']:
            input_name: str = input_field['name']
            input_type: str = input_field['type']

            if input_type == 'file':
                continue

            for vuln_type, payloads in additional_payloads.items():
                for payload in payloads:
                    try:
                        headers: Dict[str, str] = form.get('headers', {})
                        headers.update(config.get('headers', {}))

                        if form['method'] == 'post':
                            async with http_client.post(
                                    form['url'],
                                    data={input_name: payload},
                                    headers=headers
                            ) as response:
                                text: str = await response.text()
                                response_headers = response.headers
                        else:
                            async with http_client.get(
                                    form['url'],
                                    params={input_name: payload},
                                    headers=headers
                            ) as response:
                                text: str = await response.text()
                                response_headers = response.headers

                        if vuln_type == 'xss' and payload in text:
                            result['vulnerabilities'].append({
                                'type': 'xss',
                                'details': f"Reflected XSS at {form['url']} with input {input_name}",
                                'severity': 'high',
                                'cvss_score': 7.5,
                                'mitigation': "Sanitize inputs and use CSP.",
                                'payload': payload,
                                'response_headers': dict(response_headers)
                            })

                        elif vuln_type == 'sql_injection' and re.search(
                                r"(sql|mysql|database|syntax|error)", text, re.IGNORECASE):
                            result['vulnerabilities'].append({
                                'type': 'sql_injection',
                                'details': f"Potential SQLi at {form['url']} with input {input_name}",
                                'severity': 'critical',
                                'cvss_score': 9.8,
                                'mitigation': "Use parameterized queries and validate input.",
                                'payload': payload,
                                'response_headers': dict(response_headers)
                            })

                        elif vuln_type == 'command_injection' and re.search(
                                r"(root|sh:|bash|cmd|command)", text, re.IGNORECASE):
                            result['vulnerabilities'].append({
                                'type': 'command_injection',
                                'details': f"Potential command injection at {form['url']} with input {input_name}",
                                'severity': 'critical',
                                'cvss_score': 9.1,
                                'mitigation': "Validate and sanitize all user inputs.",
                                'payload': payload,
                                'response_headers': dict(response_headers)
                            })

                        await asyncio.sleep(config.get('rate_limit_delay', 0.5))

                    except Exception as e:
                        logger.warning(f"Vulnerability test failed: {str(e)}")

    return result

if __name__ == '__main__':
    app.run(debug=True)
