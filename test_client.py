import requests
import json
import os
from datetime import datetime
from typing import Dict, List, Optional, Union, Any
import nltk
import string
from nltk.tokenize import word_tokenize
from nltk.corpus import stopwords

server_url: str = ''
session: Optional[requests.Session] = None
initialized: bool = False
req_id: int = 1
def client(url: str) -> None:
    global server_url, session, initialized, req_id
    server_url = url
    initialized = False
    session = requests.Session()
    req_id = 1

def send_request(method: str, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    global req_id

    payload = {
        "jsonrpc": "2.0",
        "method": method,
        "params": params or {},
        "id": req_id
    }
    req_id += 1

    try:
        resp = session.post(url=server_url, json=payload,
                           headers={'Content-Type': 'application/json'},
                           timeout=10)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.RequestException as req_e:
        print("The Handshake Failed")
        return None

def initialize() -> bool:
    global initialized

    response = send_request("initialize", {
        "protocolVersion": "2024-11-05",
        "clientInfo": {
            "name": "MCP Python Client",
            "version": "1.0.0"
        }
    })
    if response and 'result' in response:
        initialized = True
        server_info = response['result']['serverInfo']
        print(f"Connected to {server_info['name']} v{server_info['version']}")
        return True
    elif response and 'error' in response:
        print(f"Initialization failed: {response['error']['message']}")
    return False

def list_tools() -> List[Dict[str, Any]]:
    if not initialized:
        print("Error: Connection not initialized")
        return []
    response = send_request("tools/list", {
        "protocolVersion": "2024-11-05",
        "clientInfo": {
            "name": "MCP Python Client",
            "version": "1.0.0"
        }
    })

    if response and 'result' in response:
        return response['result'].get('tools', [])
    elif response and 'error' in response:
        print(f"Error listing tools: {response['error']['message']}")
    return []

def call_tool(tool_name: str, arguments: Dict[str, str]) -> Optional[Dict[str, Any]]:
    """Call a tool with given arguments"""
    if not initialized:
        print("Error: Connection not initialized")
        return None

    response = send_request("tools/call", {
        "name": tool_name,
        "arguments": arguments
    })

    if response and 'result' in response:
        return response['result']
    elif response and 'error' in response:
        print(f"Error calling tool: {response['error']['message']}")
    return None

def read_readme_descriptions(readme_path: str = "readme (1).md") -> Dict[str, str]:
    descriptions: Dict[str, str] = {}
    current_tool: Optional[str] = None
    try:
        with open(readme_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line.startswith("###"):
                    current_tool = line.strip('# ').strip()
                    descriptions[current_tool] = ""
                elif current_tool:
                    descriptions[current_tool] += line + " "
    except FileNotFoundError:
        print("README file not found.")
    return descriptions

nltk.download('punkt')
nltk.download('stopwords')
stop_words: set = set(stopwords.words('english'))
punctuation: set = set(string.punctuation)
def preprocess_tool_output(tool_name: str, result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not result or 'content' not in result or not result['content']:
        return {
            "tool": tool_name,
            "raw_output": "No valid output",
            "entities": [],
            "cleaned_text": ""
        }

    try:
        content = result['content'][0]['text']
        parsed_content = json.loads(content)
        raw_text = json.dumps(parsed_content, indent=2)

        tokens = word_tokenize(raw_text)
        filtered_tokens = [word for word in tokens if word.lower() not in stop_words and word not in punctuation]
        entities = [(word, "") for word in filtered_tokens if word[0].isupper()]
        cleaned_text = " ".join(filtered_tokens)

        return {
            "tool": tool_name,
            "raw_output": parsed_content,
            "entities": entities,
            "cleaned_text": cleaned_text
        }
    except (json.JSONDecodeError, KeyError, IndexError) as e:
        return {
            "tool": tool_name,
            "raw_output": f"Error parsing output - {str(e)}",
            "entities": [],
            "cleaned_text": ""
        }
def format_output(raw_output: Any) -> str:
    return json.dumps(raw_output, indent=2) if isinstance(raw_output, dict) else str(raw_output)

def generate_text_report(
    knowledge_base: Dict[str, Dict[str, Any]],
    tool_descriptions: Dict[str, str],
    output_dir: str = "reports",
    filename: str = "full_scan_report.txt"
) -> Optional[str]:
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, filename)
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write("Comprehensive Vulnerability Tool Results Report\n")
            f.write("=" * 60 + "\n")
            f.write(f"Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            report_sections = [
                (
                    f"Tool: {tool_name}\n"
                    f"{'-' * 60}\n"
                    f"Explanation:\n{tool_descriptions.get(tool_name, 'No detailed explanation available.')}\n\n"
                    f"Output:\n{format_output(data['raw_output'])}\n\n"
                    f"Entities Detected:\n{''.join(f'- {ent[0]} ({ent[1]})\n' for ent in data.get('entities', [])) or 'No entities extracted.\n'}"
                    f"\n{'=' * 60}\n\n"
                )
                for tool_name, data in knowledge_base.items()
            ]

            # Write all sections at once
            f.write("".join(report_sections))

        return output_path
    except Exception as e:
        print(f"Error generating report: {e}")
        return None

def main() -> None:
    print("=== MCP Client (Functional Style) ===")

    client("http://127.0.0.1:5000/mcp")
    if not initialize():
        print("Failed to initialize MCP connection")
        return
    tools = list_tools()
    tool_names = {tool['name']: tool['description'] for tool in tools}
    if not tool_names:
        print("No tools available")
        return
    target_url = input("\nEnter the target URL or domain: ").strip()
    if not target_url:
        print("No URL provided")
        return
    print(f"\nEthical Reminder: Ensure you have explicit permission to scan {target_url}")
    TOOL_ARGS = {
        'resolve_target': {'target': target_url},
        'scan_whois': {'domain': target_url},
        'scan_web_vuln': {'url': target_url}
    }
    tool_descriptions = read_readme_descriptions("README (1).md")
    knowledge_base: Dict[str, Dict[str, Any]] = {}
    results = [
        (tool_name, preprocess_tool_output(tool_name, call_tool(tool_name, TOOL_ARGS.get(tool_name, {'url': target_url}))))
        for tool_name in tool_names
    ]
    knowledge_base.update({
        tool_name: {**result, 'description': tool_names[tool_name]}
        for tool_name, result in results
    })
    output_path = generate_text_report(knowledge_base, tool_descriptions)
    if output_path:
        print(f"\nReport generated and saved at: {os.path.abspath(output_path)}")
    else:
        print("\nFailed to generate text report")

if __name__ == "__main__":
    main()
