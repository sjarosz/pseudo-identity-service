#!/bin/bash

# Define file paths
TEMPLATE_FILE="template.yaml"
APP_FILE="app.py"
DATA_FILE="data.json"
OUTPUT_FILE="k8s.yaml"

# Ensure required files exist
if [[ ! -f "$APP_FILE" || ! -f "$DATA_FILE" || ! -f "$TEMPLATE_FILE" ]]; then
    echo "Error: One or more files are missing."
    exit 1
fi

# Base64 encode the files using macOS-compatible syntax
base64 -i "$APP_FILE" -b 0 -o "app.py.b64"
base64 -i "$DATA_FILE" -b 0 -o "data.json.b64"

# Read the Base64 encoded content into variables
BASE64_APP=$(cat app.py.b64)
BASE64_DATA=$(cat data.json.b64)

# Replace placeholders in the template file
sed "s|{{app}}|$BASE64_APP|g; s|{{data}}|$BASE64_DATA|g" "$TEMPLATE_FILE" > "$OUTPUT_FILE"

# Cleanup temporary Base64 files
rm -f app.py.b64 data.json.b64

echo "Output file '$OUTPUT_FILE' generated successfully!"
