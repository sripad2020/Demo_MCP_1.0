import requests
from typing import Dict, Any, List, Optional
import json

# Global variables to maintain state
server_url = ""
session = None
initialized = False
request_id = 1


def init_client(url: str):
    global server_url, session, initialized, request_id
    server_url = url.rstrip('/')
    session = requests.Session()
    initialized = False
    request_id = 1


def send_request(method: str, params: Dict = None) -> Optional[Dict]:
    global request_id

    payload = {
        "jsonrpc": "2.0",
        "method": method,
        "params": params or {},
        "id": request_id
    }
    request_id += 1
    try:
        response = session.post(
            f"{server_url}/mcp",
            json=payload,
            headers={'Content-Type': 'application/json'},
            timeout=10
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
        return None

def initialize() -> bool:
    """Initialize MCP connection with handshake"""
    global initialized

    # Send initialization request to server
    response = send_request("initialize", {
        "protocolVersion": "2024-11-05",
        "clientInfo": {
            "name": "MCP Python Client",
            "version": "1.0.0"
        }
    })

    # Check if initialization was successful
    if response and 'result' in response:
        initialized = True
        server_info = response['result']['serverInfo']
        print(f"Connected to {server_info['name']} v{server_info['version']}")
        return True
    elif response and 'error' in response:
        print(f"Initialization failed: {response['error']['message']}")
    return False


def list_tools() -> List[Dict]:
    """List available tools from the server"""
    if not initialized:
        print("Error: Connection not initialized")
        return []

    # Request list of available tools
    response = send_request("tools/list")

    if response and 'result' in response:
        return response['result'].get('tools', [])
    elif response and 'error' in response:
        print(f"Error listing tools: {response['error']['message']}")
    return []


def call_tool(tool_name: str, arguments: Dict) -> Optional[Any]:
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


def health_check() -> bool:
    """Check if server is healthy and responding"""
    try:
        response = session.get(f"{server_url}/health", timeout=5)
        return response.status_code == 200
    except requests.exceptions.RequestException:
        return False


def main():
    """Main function to demonstrate MCP client usage"""
    print("=== MCP Client (Functional Style) ===")

    # Initialize the client
    init_client("http://127.0.0.1:5000")

    # Check server health first
    if not health_check():
        print("Server is not responding. Make sure the MCP server is running.")
        return

    # Initialize connection with handshake
    if not initialize():
        print("Failed to initialize MCP connection")
        return

    # List available tools
    tools = list_tools()
    print("\nAvailable Tools:")
    for tool in tools:
        print(f"- {tool['name']}: {tool['description']}")

    # Example tool usage - calculator
    print("\nUsing calculator tool:")
    try:
        # Get user input
        a = float(input('Enter the first number: '))
        b = float(input('Enter the second number: '))
        operation = input("Enter the operation (add, subtract, multiply, divide): ").strip().lower()

        # Validate operation
        if operation not in ['add', 'subtract', 'multiply', 'divide']:
            print("Invalid operation. Please use: add, subtract, multiply, or divide")
            return

        # Call the calculator tool
        result = call_tool("calculator", {
            "a": a,
            "b": b,
            "operation": operation
        })

        # Display result
        if result:
            print(f"Result: {result['content'][0]['text']}")
        else:
            print("Failed to get result from calculator")

    except ValueError:
        print("Invalid number input")
    except KeyboardInterrupt:
        print("\nExiting...")
    except Exception as e:
        print(f"Error: {e}")


if __name__ == '__main__':
    main()