#!/bin/bash

# Test script for GhidraMCP headless server
# This script tests the various endpoints to ensure the server is working

SERVER_URL="${1:-http://127.0.0.1:8080}"

echo "Testing GhidraMCP server at $SERVER_URL"
echo "========================================="

# Test ping endpoint
echo -n "Ping test: "
if curl -s -f "$SERVER_URL/ping" > /dev/null; then
    echo "✓ Server is responding"
else
    echo "✗ Server is not responding"
    exit 1
fi

# Test project status
echo -n "Project status: "
STATUS=$(curl -s "$SERVER_URL/project_status")
if echo "$STATUS" | grep -q "Status:"; then
    echo "✓ Project status endpoint working"
    echo "  Status: $(echo "$STATUS" | head -1 | cut -d: -f2-)"
else
    echo "✗ Project status endpoint failed"
fi

# Test functions endpoint
echo -n "Functions endpoint: "
FUNCTIONS=$(curl -s "$SERVER_URL/functions")
if [ $? -eq 0 ]; then
    echo "✓ Functions endpoint accessible"
    FUNC_COUNT=$(echo "$FUNCTIONS" | wc -l)
    echo "  Response: $FUNC_COUNT lines"
else
    echo "✗ Functions endpoint failed"
fi

# Test methods endpoint (alias for functions)
echo -n "Methods endpoint: "
METHODS=$(curl -s "$SERVER_URL/methods")
if [ $? -eq 0 ]; then
    echo "✓ Methods endpoint accessible"
else
    echo "✗ Methods endpoint failed"
fi

echo ""
echo "Server test completed!"
echo "For full functionality, ensure a Ghidra project is open."