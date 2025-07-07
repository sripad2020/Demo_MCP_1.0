import socket, asyncio, dns, whois
import aiohttp
from flask import Flask, request, jsonify
import json, logging, re
from bs4 import BeautifulSoup
from datetime import datetime, UTC
from urllib.parse import urljoin, urlparse
import dns.reversename
import dns.resolver

app = Flask(__name__)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('scan.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

TOOLS = {
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
def mcp():
    req = request.get_json()
    if not req or 'jsonrpc' not in req or 'method' not in req:
        return jsonify({
            'jsonrpc': '2.0',
            'error': {'code': -32600, 'message': 'Invalid Request'},
            'id': req.get('id') if req else None
        })

    method = req['method']
    params = req.get('params', {})  # Fixed: was ['params'] instead of 'params'
    req_id = req.get('id')

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

        elif method == 'tools/list':  # Fixed: was 'tool/list'
            tools = []
            for tool_name, tool_information in TOOLS.items():
                tools.append({
                    "name": tool_name,
                    "description": tool_information['description'],
                    "schema": tool_information['schema']
                })
            return jsonify({
                'jsonrpc': '2.0',
                'result': {'tools': tools},  # Fixed: was 'results'
                'id': req_id
            })

        elif method == 'tools/call':
            tool_name = params.get('name')
            args = params.get('arguments', {})

            if tool_name == 'resolve_target':
                target = args.get('target') if isinstance(args, dict) else args
                result = asyncio.run(resolve_target(target))
                return jsonify({
                    'jsonrpc': '2.0',
                    'result': {'content': [{'type': 'text', 'text': json.dumps(result)}]},
                    # Fixed: was 'result' instead of 'text'
                    'id': req_id
                })

            elif tool_name == 'scan_whois':
                domain = args.get('domain') if isinstance(args, dict) else args
                result = asyncio.run(scan_whois(domain))
                return jsonify({
                    'jsonrpc': '2.0',
                    'result': {'content': [{'type': 'text', 'text': json.dumps(result)}]},
                    'id': req_id
                })

            elif tool_name == 'scan_web_vuln':
                url = args.get('url') if isinstance(args, dict) else args

                async def run_scan():
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


async def resolve_target(target):
    result = {
        'target_ip': None,
        'dns_info': {
            'reverse_dns': []
        },
        'error': None,
        'error_type': None
    }

    try:
        # Clean the target (remove http/https if present)
        if target.startswith(('http://', 'https://')):
            target = urlparse(target).netloc

        target_ip = socket.gethostbyname(target)
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


def make_json_serializable(whois_data):
    """Convert WHOIS data to a JSON-serializable dictionary."""
    serializable = {}
    for key, value in whois_data.items():
        if isinstance(value, datetime):
            serializable[key] = value.isoformat()
        elif isinstance(value, list):
            serializable[key] = [v.isoformat() if isinstance(v, datetime) else str(v) for v in value]
        else:
            serializable[key] = str(value)
    return serializable


async def scan_whois(domain):
    result = {
        'whois_info': {},
        'vulnerabilities': []
    }

    try:
        # Clean the domain (remove http/https if present)
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


async def scan_web_vulnerabilities_extended(base_url, http_client, config, additional_payloads):
    result = {
        'vulnerabilities': [],
        'security_headers': {},
        'cookies': {}
    }

    urls = {base_url}
    visited = set()
    forms = []
    seen_forms = set()
    parsed_url = urlparse(base_url)

    # Common security headers to check
    SECURITY_HEADERS = [
        'Content-Security-Policy',
        'X-Frame-Options',
        'X-Content-Type-Options',
        'Strict-Transport-Security',
        'X-XSS-Protection',
        'Referrer-Policy',
        'Feature-Policy',
        'Permissions-Policy'
    ]

    async def analyze_headers(response_headers):
        headers_analysis = {}
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

    async def analyze_cookies(cookies):
        cookie_analysis = {}
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

    async def crawl(url, depth=0):
        if depth > config.get('max_depth', 2) or url in visited:
            return
        visited.add(url)
        try:
            # Add custom headers if specified in config
            headers = config.get('headers', {})
            async with http_client.get(url, headers=headers) as response:
                if response.status != 200:
                    return

                # Analyze security headers
                result['security_headers'][url] = await analyze_headers(response.headers)

                # Analyze cookies
                result['cookies'][url] = await analyze_cookies(response.cookies)

                text = await response.text()
                soup = BeautifulSoup(text, 'html.parser')

                for form in soup.find_all('form'):
                    action = form.get('action', '')
                    form_url = urljoin(url, action)
                    method = form.get('method', 'get').lower()
                    form_key = f"{form_url}:{method}"
                    if form_key in seen_forms:
                        continue
                    seen_forms.add(form_key)
                    inputs = []
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
                    next_url = urljoin(url, a['href'])
                    if urlparse(next_url).netloc == parsed_url.netloc:
                        urls.add(next_url)
                        await crawl(next_url, depth + 1)
        except Exception as e:
            logger.warning(f"Crawling failed for {url}: {str(e)}")

    await crawl(base_url)

    for form in forms:
        for input_field in form['inputs']:
            input_name = input_field['name']
            input_type = input_field['type']

            # Skip file inputs for XSS/SQLi tests
            if input_type == 'file':
                continue

            for vuln_type, payloads in additional_payloads.items():
                for payload in payloads:
                    try:
                        # Include original headers plus any custom ones
                        headers = form.get('headers', {})
                        headers.update(config.get('headers', {}))

                        if form['method'] == 'post':
                            async with http_client.post(
                                    form['url'],
                                    data={input_name: payload},
                                    headers=headers
                            ) as response:
                                text = await response.text()
                                response_headers = response.headers
                        else:
                            async with http_client.get(
                                    form['url'],
                                    params={input_name: payload},
                                    headers=headers
                            ) as response:
                                text = await response.text()
                                response_headers = response.headers

                        # Check for reflected XSS
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

                        # Check for SQL injection
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

                        # Check for command injection
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