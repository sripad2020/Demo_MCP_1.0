Documentation for Network and Web Vulnerability Scanning Functions
This document provides an in-depth explanation of three Python functions used for network and web vulnerability scanning: resolve_target, make_json_serializable, and scan_web_vulnerabilities_extended. Each function is designed to perform specific tasks in the context of network analysis and web security testing. The documentation includes detailed descriptions, parameter explanations, code logic, error handling, use cases, and best practices to ensure clarity and applicability across various scenarios.

Table of Contents

Introduction
Function: resolve_target
Overview
Parameters
Return Value
Logic and Workflow
Error Handling
Use Cases
Best Practices
Example Usage


Function: make_json_serializable
Overview
Parameters
Return Value
Logic and Workflow
Error Handling
Use Cases
Best Practices
Example Usage


Function: scan_web_vulnerabilities_extended
Overview
Parameters
Return Value
Logic and Workflow
Error Handling
Use Cases
Best Practices
Example Usage


Security Considerations
Conclusion


Introduction
The provided functions are part of a Python-based toolkit for network analysis and web security testing. They are designed to work in an asynchronous environment, leveraging Python's asyncio for non-blocking operations. The functions are:

resolve_target: Resolves a domain or URL to its IP address and performs reverse DNS lookup.
make_json_serializable: Converts WHOIS data into a JSON-serializable format.
scan_web_vulnerabilities_extended: Performs a comprehensive web vulnerability scan, including header analysis, cookie security checks, and testing for common vulnerabilities like XSS, SQL injection, and command injection.

These functions are useful for security researchers, penetration testers, and developers who need to assess the security posture of web applications and network targets. The documentation below provides a detailed breakdown of each function, ensuring that users can understand and apply them effectively in various contexts.

Function: resolve_target
Overview
The resolve_target function is an asynchronous Python function that resolves a given target (domain or URL) to its IP address and performs a reverse DNS lookup to identify associated hostnames. It is designed for network reconnaissance, providing essential information about a target's network presence.
Parameters

target (str): The domain name or URL to resolve (e.g., "example.com" or "https://example.com").
If the input is a URL, the function extracts the netloc (hostname) using the urlparse function from the urllib.parse module.
Example inputs: "example.com", "https://example.com", "subdomain.example.com".



Return Value
The function returns a dictionary containing the following keys:

target_ip (str or None): The resolved IP address of the target, or None if resolution fails.
dns_info (dict): Contains a list of reverse DNS entries under the key reverse_dns.
reverse_dns (list): A list of hostnames associated with the IP address, obtained via reverse DNS lookup.


error (str or None): A description of any error that occurred during resolution, or None if successful.
error_type (str or None): The type of error (e.g., "ResolutionError"), or None if successful.

Example return value:
{
    "target_ip": "93.184.216.34",
    "dns_info": {
        "reverse_dns": ["example.com", "www.example.com"]
    },
    "error": null,
    "error_type": null
}

Logic and Workflow

Initialization:

A dictionary result is initialized with default values for target_ip, dns_info, error, and error_type.


URL Cleaning:

If the target starts with "http://" or "https://", the function uses urlparse to extract the hostname (netloc) from the URL.
Example: "https://example.com/path" becomes "example.com".


IP Resolution:

The function uses socket.gethostbyname to resolve the target hostname to an IP address.
The resolved IP is stored in result['target_ip'].


Reverse DNS Lookup:

Using the dns.reversename.from_address function from the dnspython library, the IP address is converted to a reverse DNS name (e.g., "34.216.184.93.in-addr.arpa").
The function then performs a PTR record query using dns.resolver.resolve to retrieve associated hostnames.
The results are stored as a list of strings in result['dns_info']['reverse_dns'].


Error Handling:

If the IP resolution fails (e.g., due to a non-existent domain), a socket.gaierror is caught, and an error message is logged using a logger object.
If the reverse DNS lookup fails, a warning is logged, and an empty list is assigned to reverse_dns.


Return:

The function returns the result dictionary with the resolved data or error information.



Error Handling

socket.gaierror: Occurs when the target cannot be resolved to an IP address (e.g., invalid domain). The function sets error and error_type in the result dictionary and logs the error.
Reverse DNS Lookup Errors: Any exception during the reverse DNS lookup is caught, logged as a warning, and results in an empty reverse_dns list.
Logging: The function assumes a logger object (e.g., from the logging module) is available for logging errors and warnings.

Use Cases

Network Reconnaissance: Identify the IP address and associated hostnames for a target domain during security assessments.
Incident Response: Verify the legitimacy of a domain by checking its IP and reverse DNS records.
Infrastructure Mapping: Map out the network infrastructure of a target by resolving domains and subdomains.
Penetration Testing: Gather initial information about a target's network presence before further testing.

Best Practices

Input Validation: Ensure the target parameter is a valid string to avoid unexpected errors.
Logging Configuration: Configure a proper logging mechanism (e.g., logging module) to capture errors and warnings effectively.
Rate Limiting: Implement rate limiting for DNS queries to avoid overwhelming DNS servers, especially in large-scale scans.
Error Handling: Handle additional exceptions (e.g., network timeouts) if the function is used in unreliable network environments.
Dependency Management: Ensure the dnspython library is installed (pip install dnspython) for reverse DNS lookups.

Example Usage
import asyncio
import logging
from urllib.parse import urlparse
import socket
import dns.reversename
import dns.resolver

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def main():
    target = "example.com"
    result = await resolve_target(target)
    print(result)

# Run the async function
asyncio.run(main())

Expected output:
{
    "target_ip": "93.184.216.34",
    "dns_info": {
        "reverse_dns": ["example.com"]
    },
    "error": null,
    "error_type": null
}


Function: make_json_serializable
Overview
The make_json_serializable function converts WHOIS data, which may contain non-serializable objects like datetime, into a JSON-serializable format. This is critical for storing or transmitting WHOIS data in JSON format, such as in APIs or reports.
Parameters

whois_data (dict): A dictionary containing WHOIS data, typically returned by the whois.whois function from the python-whois library.
The dictionary may contain keys like domain_name, registrar, expiration_date, etc., with values that may include datetime objects, lists, or other types.



Return Value
A dictionary where all values are JSON-serializable (strings or lists of strings). Non-serializable values, such as datetime objects, are converted to ISO format strings, and other values are converted to strings.
Example return value:
{
    "domain_name": "example.com",
    "registrar": "Example Registrar",
    "expiration_date": "2026-01-01T00:00:00"
}

Logic and Workflow

Initialization:

A new dictionary serializable is created to store the converted data.


Iteration:

The function iterates through each key-value pair in whois_data.


Type Conversion:

If the value is a datetime object, it is converted to an ISO format string using value.isoformat().
If the value is a list, each element is processed:
datetime objects are converted to ISO format strings.
Other elements are converted to strings using str().


All other values are converted to strings using str().


Return:

The function returns the serializable dictionary with all values in a JSON-serializable format.



Error Handling

The function is designed to be robust and does not raise exceptions for invalid data types, as it converts all non-serializable values to strings.
If whois_data is not a dictionary, the function may raise a TypeError, which should be handled by the caller.

Use Cases

API Development: Convert WHOIS data for inclusion in JSON-based API responses.
Data Storage: Store WHOIS data in JSON files or databases that require serializable formats.
Reporting: Generate reports with WHOIS data in a format suitable for serialization and sharing.
Security Analysis: Process WHOIS data for domain expiration checks or registrar analysis.

Best Practices

Input Validation: Verify that whois_data is a dictionary before passing it to the function.
Type Safety: Ensure that the WHOIS library used (python-whois) returns consistent data structures.
Handling Nested Data: If WHOIS data contains nested dictionaries, consider extending the function to handle recursive conversion.
Logging: Log any unexpected data types for debugging purposes.

Example Usage
from datetime import datetime
import json

# Example WHOIS data
whois_data = {
    "domain_name": "example.com",
    "registrar": "Example Registrar",
    "expiration_date": datetime(2026, 1, 1)
}

# Convert to JSON-serializable format
serializable_data = make_json_serializable(whois_data)
print(json.dumps(serializable_data, indent=2))

Expected output:
{
  "domain_name": "example.com",
  "registrar": "Example Registrar",
  "expiration_date": "2026-01-01T00:00:00"
}


Function: scan_web_vulnerabilities_extended
Overview
The scan_web_vulnerabilities_extended function is an asynchronous Python function that performs a comprehensive web vulnerability scan on a given URL. It crawls the website, analyzes security headers and cookies, and tests forms for common vulnerabilities such as XSS, SQL injection, and command injection. This function is designed for security testing and penetration testing workflows.
Parameters

base_url (str): The starting URL for the scan (e.g., "https://example.com").
http_client (aiohttp.ClientSession): An asynchronous HTTP client session for making requests.
config (dict): Configuration settings for the scan, including:
max_depth (int): Maximum crawling depth (default: 2).
headers (dict): Custom HTTP headers to include in requests.
rate_limit_delay (float): Delay between requests to avoid overwhelming the server (default: 0.5 seconds).


additional_payloads (dict): A dictionary of vulnerability types and their test payloads, e.g., {'xss': ['<script>alert(1)</script>'], 'sql_injection': ["' OR 1=1 --"]}.

Return Value
A dictionary containing the scan results:

vulnerabilities (list): A list of detected vulnerabilities, each with keys:
type: Type of vulnerability (e.g., "xss", "sql_injection", "cookie_security").
details: Description of the vulnerability.
severity: Severity level ("low", "medium", "high", "critical").
cvss_score: CVSS score for the vulnerability.
mitigation: Recommended mitigation steps.
payload: The payload that triggered the vulnerability (if applicable).
response_headers: Headers from the response (if applicable).


security_headers (dict): A dictionary mapping URLs to their security header analysis.
cookies (dict): A dictionary mapping URLs to their cookie analysis.

Example return value:
{
    "vulnerabilities": [
        {
            "type": "xss",
            "details": "Reflected XSS at https://example.com/form with input query",
            "severity": "high",
            "cvss_score": 7.5,
            "mitigation": "Sanitize inputs and use CSP.",
            "payload": "<script>alert(1)</script>",
            "response_headers": {"Content-Type": "text/html"}
        }
    ],
    "security_headers": {
        "https://example.com": {
            "Content-Security-Policy": {"present": false, "severity": "medium"},
            "X-Frame-Options": {"present": true, "value": "DENY"}
        }
    },
    "cookies": {
        "https://example.com": {
            "session_id": {
                "secure": false,
                "httponly": true,
                "samesite": "Lax",
                "domain": "example.com",
                "path": "/",
                "expires": null
            }
        }
    }
}

Logic and Workflow

Initialization:

A result dictionary is initialized to store vulnerabilities, security headers, and cookies.
Sets and lists are created to track URLs, visited pages, forms, and seen forms to avoid duplicates.


Security Header Analysis:

The analyze_headers helper function checks for the presence of common security headers (e.g., Content-Security-Policy, Strict-Transport-Security).
Missing headers are flagged with appropriate severity levels.


Cookie Analysis:

The analyze_cookies helper function examines cookies for security attributes (Secure, HttpOnly, SameSite).
Vulnerabilities are added for cookies missing Secure or HttpOnly flags.


Web Crawling:

The crawl helper function recursively crawls the website starting from base_url, up to the specified max_depth.
It uses aiohttp to make HTTP requests and BeautifulSoup to parse HTML.
Forms and links are extracted, and only URLs within the same domain are followed.


Form Analysis:

Forms are identified, and their action URLs, methods, and input fields are stored.
Duplicate forms are skipped using a unique form key.


Vulnerability Testing:

For each form input (except file inputs), the function tests payloads from additional_payloads.
GET or POST requests are sent with the payload, depending on the form's method.
Responses are analyzed for:
XSS: Checks if the payload is reflected in the response.
SQL Injection: Searches for database-related error messages.
Command Injection: Looks for command execution indicators.


Detected vulnerabilities are added to the vulnerabilities list with details and mitigation recommendations.


Rate Limiting:

A delay (specified by rate_limit_delay) is applied between requests to avoid overwhelming the server.


Return:

The function returns the result dictionary with all collected data.



Error Handling

HTTP Request Errors: Exceptions during HTTP requests are caught and logged, allowing the scan to continue with other URLs or forms.
Parsing Errors: HTML parsing errors with BeautifulSoup are handled gracefully to avoid crashes.
Vulnerability Testing Errors: Exceptions during payload testing are logged, and the scan proceeds to the next test.
Logging: Assumes a logger object for logging warnings and errors.

Use Cases

Penetration Testing: Identify vulnerabilities in web applications during security assessments.
Security Audits: Evaluate the security posture of a website, including headers and cookies.
Compliance Testing: Check for compliance with security standards (e.g., OWASP recommendations).
Development: Assist developers in identifying and fixing security issues in web applications.

Best Practices

Ethical Use: Obtain permission before scanning websites to avoid legal issues.
Configuration: Provide a detailed config dictionary to control crawling depth and rate limiting.
Payload Management: Use carefully curated payloads in additional_payloads to avoid false positives.
Dependency Management: Ensure required libraries (aiohttp, beautifulsoup4) are installed.
Rate Limiting: Adjust rate_limit_delay based on the target server's capacity to avoid denial-of-service conditions.
Error Logging: Implement robust logging to track issues during scans.

Example Usage
import asyncio
import aiohttp
from bs4 import BeautifulSoup
import logging
import re

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def main():
    async with aiohttp.ClientSession() as http_client:
        base_url = "https://example.com"
        config = {"max_depth": 2, "rate_limit_delay": 0.5, "headers": {"User-Agent": "SecurityScanner"}}
        additional_payloads = {
            "xss": ["<script>alert(1)</script>", "'><img src=x onerror=alert(1)>"],
            "sql_injection": ["' OR 1=1 --", "1; DROP TABLE users --"],
            "command_injection": ["; ls", "| whoami"]
        }
        result = await scan_web_vulnerabilities_extended(base_url, http_client, config, additional_payloads)
        print(result)

# Run the async function
asyncio.run(main())

Expected output (simplified):
{
    "vulnerabilities": [],
    "security_headers": {
        "https://example.com": {
            "Content-Security-Policy": {"present": false, "severity": "medium"},
            "X-Frame-Options": {"present": true, "value": "DENY"}
        }
    },
    "cookies": {}
}


Security Considerations

Ethical Scanning: Always obtain explicit permission from the website owner before performing vulnerability scans.
Data Privacy: Handle sensitive data (e.g., cookies, WHOIS information) securely and comply with data protection regulations.
Rate Limiting: Implement appropriate delays to avoid overwhelming target servers.
Payload Safety: Use safe payloads for testing to avoid unintended damage to the target system.
Dependency Security: Ensure all libraries (dnspython, python-whois, aiohttp, beautifulsoup4) are up-to-date to avoid vulnerabilities.


Conclusion
The resolve_target, make_json_serializable, and scan_web_vulnerabilities_extended functions provide a robust toolkit for network reconnaissance and web security testing. By combining DNS resolution, WHOIS data processing, and comprehensive web vulnerability scanning, these functions enable security professionals to assess and improve the security of network targets and web applications. Following the best practices and ethical guidelines outlined in this document ensures effective and responsible use of these tools.