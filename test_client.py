import requests,json,os
from datetime import datetime
import nltk
import string
import os
import json
from datetime import datetime
from nltk.tokenize import word_tokenize
from nltk.corpus import stopwords


server_url=''
session = None
initialized = False
req_id = 1

def client(url:str):
    global server_url, session, initialized, req_id
    server_url = url
    initialized = False
    session=requests.Session()
    req_id = 1

def send_request(method:str, params: dict):
    global  req_id

    payload = {
        "jsonrpc": "2.0",
        "method": method,
        "params": params or {},
        "id": req_id
    }
    req_id +=1

    try:
        resp=session.post(url=server_url,json=payload,
                          headers={'Content-Type':'application/json'},
                          timeout=10)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.RequestException as req_e:
        print("The Handshake Failed")
        return None

def initialize()->bool:
    global initialized

    # Send initialization request to server
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

def list_tools() -> list[dict]:
    if not initialized:
        print("Error: Connection not initialized")
        return []
    response = send_request("tools/list", {
        "protocolVersion": "2024-11-05",
        "clientInfo": {
            "name": "MCP Python Client",
            "version": "1.0.0"
        }})

    if response and 'result' in response:
        return response['result'].get('tools', [])
    elif response and 'error' in response:
        print(f"Error listing tools: {response['error']['message']}")
    return []

def call_tool(tool_name: str, arguments: dict):
    """Call a tool with given arguments"""
    if not initialized:
        print("Error: Connection not initialized")
        return None

    # Send tool call request
    response = send_request("tools/call", {
        "name": tool_name,
        "arguments": arguments
    })

    # Process the response
    if response and 'result' in response:
        return response['result']
    elif response and 'error' in response:
        print(f"Error calling tool: {response['error']['message']}")
    return None


def read_readme_descriptions(readme_path="readme (1).md"):
    descriptions = {}
    current_tool = None
    try:
        with open(readme_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line.startswith("###"):  # Assume tool section headers are like ### ToolName
                    current_tool = line.strip('# ').strip()
                    descriptions[current_tool] = ""
                elif current_tool:
                    descriptions[current_tool] += line + " "
    except FileNotFoundError:
        print("README file not found.")
    return descriptions

nltk.download('punkt')
nltk.download('stopwords')

stop_words = set(stopwords.words('english'))
punctuation = set(string.punctuation)


def preprocess_tool_output(tool_name, result):
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


def generate_text_report(knowledge_base, tool_descriptions, output_dir="reports", filename="full_scan_report.txt"):
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, filename)

    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write("Comprehensive Vulnerability Tool Results Report\n")
            f.write("=" * 60 + "\n")
            f.write(f"Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

            for tool_name in knowledge_base:
                data = knowledge_base[tool_name]
                f.write(f"Tool: {tool_name}\n")
                f.write("-" * 60 + "\n")

                # Tool description from README
                description = tool_descriptions.get(tool_name, "No detailed explanation available.")
                f.write(f"Explanation:\n{description}\n\n")

                # Raw output
                f.write("Output:\n")
                if isinstance(data['raw_output'], dict):
                    f.write(json.dumps(data['raw_output'], indent=2) + "\n\n")
                else:
                    f.write(str(data['raw_output']) + "\n\n")

                # Cleaned text and entities
                f.write("Entities Detected:\n")
                if data.get('entities'):
                    for ent in data['entities']:
                        f.write(f"- {ent[0]} ({ent[1]})\n")
                else:
                    f.write("No entities extracted.\n")
                f.write("\n" + "=" * 60 + "\n\n")

        return output_path
    except Exception as e:
        print(f"Error generating report: {e}")
        return None
def main():
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

    knowledge_base = {}
    tool_descriptions = read_readme_descriptions("README (1).md")

    for tool_name, description in tool_names.items():
        print(f"\n--- Testing {tool_name} ---")

        args = (
            {'target': target_url} if tool_name == 'resolve_target'
            else {'domain': target_url} if tool_name == 'scan_whois'
            else {'url': target_url}
        )

        result = call_tool(tool_name, args)

        processed_output = preprocess_tool_output(tool_name, result)
        processed_output['description'] = description
        knowledge_base[tool_name] = processed_output

    output_path = generate_text_report(knowledge_base, tool_descriptions)
    if output_path:
        print(f"\nReport generated and saved at: {os.path.abspath(output_path)}")
    else:
        print("\nFailed to generate text report")


if __name__ == "__main__":
    main()
