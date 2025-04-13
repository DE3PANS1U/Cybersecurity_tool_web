from flask import Flask, request, jsonify, render_template, send_file
import requests
import json
import pandas as pd
import re
import time
import os

app = Flask(__name__)

# List of API keys (modify accordingly)
API_KEYS = [
    "64d7d06aa998e956f477df17e005153a3c4ffd4affae3eb036afc21bd65af507"
]  # Replace with actual API keys

# Dictionary to track API usage per key
api_usage = {key: 0 for key in API_KEYS}

# Function to get available API key
def get_available_api_key():
    for key, count in api_usage.items():
        if count < 500:  # Daily limit per key
            return key
    return None

# Function to extract IP addresses
def extract_ips(input_text):
    ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    return ip_pattern.findall(input_text)

# Function to check IP reputation
def check_ip(ip):
    api_key = get_available_api_key()
    if not api_key:
        return {"id": ip, "malicious": "Error", "as_label": "Error"}

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"accept": "application/json", "x-apikey": api_key}
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json().get('data', {})
            api_usage[api_key] += 1
            return {
                "id": data.get('id', 'N/A'),
                "malicious": data.get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 'N/A'),
                "as_label": data.get('attributes', {}).get('as_owner', 'N/A')
            }
    except Exception as e:
        print(f"Error checking IP {ip}: {str(e)}")
    
    return {"id": ip, "malicious": "Error", "as_label": "Error"}

# Function to process uploaded file
def read_ips_from_file(file_path):
    try:
        df = pd.read_excel(file_path)
        return df['Client Ip'].dropna().tolist() if 'Client Ip' in df.columns else []
    except Exception as e:
        print(f"Error reading file: {str(e)}")
        return []

# Route for Homepage
@app.route('/')
def index():
    return render_template('index.html')

# Route to process IP input
@app.route('/process_ips', methods=['POST'])
def process_ips():
    try:
        input_text = request.form['input_text']
        ip_addresses = extract_ips(input_text)
        
        results = []
        for ip in ip_addresses:
            result = check_ip(ip)
            results.append(result)
            time.sleep(1)  # Rate limiting
        
        df = pd.DataFrame(results)
        df.to_excel('ip_scan_results.xlsx', index=False)
        
        return jsonify(results)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Route for file uploads
@app.route('/upload', methods=['POST'])
def upload_file():
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No file uploaded"}), 400
            
        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "No file selected"}), 400
            
        file_path = "uploaded.xlsx"
        file.save(file_path)
        
        ip_addresses = read_ips_from_file(file_path)
        results = []
        for ip in ip_addresses:
            result = check_ip(ip)
            results.append(result)
            time.sleep(1)  # Rate limiting
        
        df = pd.DataFrame(results)
        df.to_excel('ip_scan_results.xlsx', index=False)
        
        return jsonify(results)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Route to download results
@app.route('/download')
def download_file():
    try:
        return send_file('ip_scan_results.xlsx', 
                        as_attachment=True,
                        download_name='ip_scan_results.xlsx')
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True, port=5001) 