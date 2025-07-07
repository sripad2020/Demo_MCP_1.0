from flask import Flask, request, jsonify

# Create Flask application instance
app = Flask(__name__)

# Tool registry - stores all available tools and their metadata
TOOLS = {
    'calculator': {
        'description': 'Perform basic arithmetic operations',
        'schema': {
            'type': 'object',
            'properties': {
                'a': {'type': 'number'},
                'b': {'type': 'number'},
                'operation': {'type': 'string', 'enum': ['add', 'subtract', 'multiply', 'divide']}
            },
            'required': ['a', 'b', 'operation']
        }
    }
}

@app.route('/mcp', methods=['POST'])
def mcp_handler():
    """Main MCP endpoint handling JSON-RPC 2.0 requests"""
    # Get JSON data from request
    req = request.get_json()

    # Validate basic JSON-RPC structure
    if not req or 'jsonrpc' not in req or 'method' not in req:
        return jsonify({
            'jsonrpc': '2.0',
            'error': {'code': -32600, 'message': 'Invalid Request'},
            'id': req.get('id')
        })

    # Extract request components
    method = req['method']
    params = req.get('params', {})
    req_id = req.get('id')

    try:
        # Handle MCP initialization - handshake between client and server
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

        # List available tools - allows client to discover what tools are available
        elif method == 'tools/list':
            tools = []
            # Build tool list from registry
            for name, info in TOOLS.items():
                tools.append({
                    'name': name,
                    'description': info['description'],
                    'inputSchema': info['schema']
                })
            return jsonify({
                'jsonrpc': '2.0',
                'result': {'tools': tools},
                'id': req_id
            })

        # Call a tool - execute a specific tool with given arguments
        elif method == 'tools/call':
            tool_name = params.get('name')
            arguments = params.get('arguments', {})

            # Check if tool exists and handle calculator
            if tool_name == 'calculator':
                result = handle_calculator(arguments)
                return jsonify({
                    'jsonrpc': '2.0',
                    'result': {
                        'content': [{'type': 'text', 'text': str(result)}]
                    },
                    'id': req_id
                })
            else:
                # Tool not found error
                return jsonify({
                    'jsonrpc': '2.0',
                    'error': {'code': -32601, 'message': f'Tool {tool_name} not found'},
                    'id': req_id
                })

        else:
            # Unknown method error
            return jsonify({
                'jsonrpc': '2.0',
                'error': {'code': -32601, 'message': 'Method not found'},
                'id': req_id
            })

    except Exception as e:
        # Internal server error
        return jsonify({
            'jsonrpc': '2.0',
            'error': {'code': -32000, 'message': str(e)},
            'id': req_id
        })

def handle_calculator(args):
    """Handle calculator operations - performs arithmetic calculations"""
    # Extract arguments
    op = args.get('operation')
    a = args.get('a')
    b = args.get('b')

    # Perform calculation based on operation
    if op == 'add':
        return a + b
    elif op == 'subtract':
        return a - b
    elif op == 'multiply':
        return a * b
    elif op == 'divide':
        # Check for division by zero
        if b == 0:
            raise ValueError("Division by zero")
        return a / b
    else:
        raise ValueError(f"Unknown operation: {op}")

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint - allows clients to verify server is running"""
    return jsonify({"status": "healthy"})

if __name__ == '__main__':
    print("Simple MCP Server running on http://127.0.0.1:5000/mcp")
    # Start the Flask development server
    app.run(host='127.0.0.1', port=5000)