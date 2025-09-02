import re
import csv
import io
from flask import Flask, request, jsonify, render_template_string
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

# Create Presidio instances
analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()

def deidentify_data(input_csv_content):
    """
    Processes CSV content to detect and de-identify PII using Presidio.
    Returns the de-identified data and a summary report.
    """
    deidentified_lines = []
    total_pii_found = {}
    
    csv_file = io.StringIO(input_csv_content)
    reader = csv.reader(csv_file)
    header = next(reader)
    deidentified_lines.append(header)
    
    for row in reader:
        deidentified_row = list(row)
        for i, cell in enumerate(row):
            if cell.strip() == "":
                continue

            # Analyze the text for PII entities
            results = analyzer.analyze(text=cell, language='en')
            
            if results:
                # Anonymize the detected PII
                anonymized_result = anonymizer.anonymize(
                    text=cell,
                    analyzer_results=results,
                    operators={"DEFAULT": OperatorConfig("replace", {"new_value": "XXXXXX"})},
                )
                deidentified_row[i] = anonymized_result.text

                # Update the summary report counts
                for entity in results:
                    entity_type = entity.entity_type
                    total_pii_found[entity_type] = total_pii_found.get(entity_type, 0) + 1
        
        deidentified_lines.append(deidentified_row)

    report_content = "Summary Report\n"
    report_content += "--------------\n"
    if total_pii_found:
        for key, count in total_pii_found.items():
            report_content += f"Total {key.replace('_', ' ').title()} found: {count}\n"
    else:
        report_content += "No PII found in the provided data.\n"
    
    output_buffer = io.StringIO()
    writer = csv.writer(output_buffer)
    writer.writerows(deidentified_lines)
    deidentified_csv = output_buffer.getvalue()

    return deidentified_csv, report_content

# --- Flask Web Application ---

app = Flask(__name__)

# This is the HTML template for the web application
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PII De-identifier</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600&display=swap');
        body {
            font-family: 'Inter', sans-serif;
            background-color: #f3f4f6;
        }
        .container {
            max-width: 900px;
        }
        .card {
            background-color: white;
            border-radius: 0.75rem;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
    </style>
</head>
<body class="bg-gray-100 flex items-center justify-center min-h-screen p-4">
    <div class="container mx-auto p-6 lg:p-10 card">
        <h1 class="text-3xl font-bold text-gray-800 text-center mb-6">PII De-identification Tool</h1>
        <p class="text-center text-gray-600 mb-8">
            Upload a CSV file to automatically detect and mask Personally Identifiable Information (PII) such as credit card numbers, emails, and Aadhaar numbers.
        </p>

        <div class="space-y-6">
            <div class="flex flex-col items-center p-6 bg-gray-50 rounded-lg border-2 border-dashed border-gray-300">
                <label for="file-upload" class="cursor-pointer">
                    <svg class="w-12 h-12 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"></path>
                    </svg>
                    <p class="text-gray-500 text-sm mt-2"><span class="font-medium text-indigo-600 hover:text-indigo-500">Click to upload</span> or drag and drop</p>
                    <input id="file-upload" name="file-upload" type="file" class="sr-only" accept=".csv" />
                </label>
                <span id="file-name" class="mt-4 text-sm text-gray-600 font-semibold">No file selected</span>
            </div>

            <button id="process-btn" type="button" class="w-full flex justify-center items-center py-3 px-4 rounded-md shadow-sm text-white bg-indigo-600 hover:bg-indigo-700 transition-colors duration-200 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500">
                <span id="button-text">Process File</span>
                <div id="loading-spinner" class="hidden spinner-border animate-spin inline-block w-5 h-5 border-4 rounded-full" role="status"></div>
            </button>
        </div>

        <div id="results-container" class="mt-8 hidden space-y-6">
            <div class="bg-indigo-50 p-6 rounded-lg border border-indigo-200">
                <h2 class="text-xl font-semibold text-gray-700 mb-4">Summary Report</h2>
                <pre id="report-output" class="whitespace-pre-wrap text-sm text-gray-800 bg-white p-4 rounded-md border border-gray-200"></pre>
            </div>
            
            <div class="bg-green-50 p-6 rounded-lg border border-green-200">
                <h2 class="text-xl font-semibold text-gray-700 mb-4">De-identified Data</h2>
                <div class="flex space-x-2 mb-4">
                    <button id="copy-csv-btn" class="flex-1 py-2 px-3 bg-green-500 hover:bg-green-600 transition-colors duration-200 text-white font-medium rounded-md shadow-sm">Copy De-identified CSV</button>
                    <a id="download-csv-link" href="#" class="flex-1 text-center py-2 px-3 bg-blue-500 hover:bg-blue-600 transition-colors duration-200 text-white font-medium rounded-md shadow-sm">Download CSV</a>
                </div>
                <pre id="csv-output" class="whitespace-pre-wrap text-sm text-gray-800 bg-white p-4 rounded-md border border-gray-200 overflow-x-auto"></pre>
            </div>
        </div>

        <div id="message-box" class="fixed bottom-4 right-4 p-4 rounded-lg shadow-lg text-white bg-red-500 transition-transform duration-300 transform translate-x-full">
            <p id="message-text"></p>
        </div>
    </div>

    <script>
        document.addEventListener('DOMContentLoaded', () => {
            const fileInput = document.getElementById('file-upload');
            const fileNameSpan = document.getElementById('file-name');
            const processBtn = document.getElementById('process-btn');
            const buttonText = document.getElementById('button-text');
            const loadingSpinner = document.getElementById('loading-spinner');
            const resultsContainer = document.getElementById('results-container');
            const reportOutput = document.getElementById('report-output');
            const csvOutput = document.getElementById('csv-output');
            const copyCsvBtn = document.getElementById('copy-csv-btn');
            const downloadCsvLink = document.getElementById('download-csv-link');
            const messageBox = document.getElementById('message-box');
            const messageText = document.getElementById('message-text');

            fileInput.addEventListener('change', () => {
                if (fileInput.files.length > 0) {
                    fileNameSpan.textContent = fileInput.files[0].name;
                } else {
                    fileNameSpan.textContent = 'No file selected';
                }
            });

            processBtn.addEventListener('click', async () => {
                const file = fileInput.files[0];
                if (!file) {
                    showMessage("Please select a file first.");
                    return;
                }

                if (file.type !== 'text/csv') {
                    showMessage("Only CSV files are supported.");
                    return;
                }

                // Show loading state
                buttonText.textContent = 'Processing...';
                loadingSpinner.classList.remove('hidden');
                processBtn.disabled = true;

                const formData = new FormData();
                formData.append('file', file);

                try {
                    const response = await fetch('/process', {
                        method: 'POST',
                        body: formData,
                    });

                    if (!response.ok) {
                        throw new Error(`Server error: ${response.statusText}`);
                    }

                    const data = await response.json();

                    reportOutput.textContent = data.report;
                    csvOutput.textContent = data.deidentified_csv;
                    
                    const blob = new Blob([data.deidentified_csv], { type: 'text/csv' });
                    downloadCsvLink.href = URL.createObjectURL(blob);
                    downloadCsvLink.download = `deidentified_${file.name}`;

                    resultsContainer.classList.remove('hidden');
                    showMessage("Processing complete!", "bg-green-500");

                } catch (error) {
                    console.error('Error:', error);
                    showMessage(`An error occurred: ${error.message}`);
                } finally {
                    // Hide loading state
                    buttonText.textContent = 'Process File';
                    loadingSpinner.classList.add('hidden');
                    processBtn.disabled = false;
                }
            });

            copyCsvBtn.addEventListener('click', () => {
                const text = csvOutput.textContent;
                try {
                    const tempInput = document.createElement('textarea');
                    tempInput.value = text;
                    document.body.appendChild(tempInput);
                    tempInput.select();
                    document.execCommand('copy');
                    document.body.removeChild(tempInput);
                    showMessage("CSV content copied to clipboard!", "bg-green-500");
                } catch (err) {
                    console.error('Failed to copy text:', err);
                    showMessage("Failed to copy text. Please try again.");
                }
            });

            function showMessage(message, color = "bg-red-500") {
                messageText.textContent = message;
                messageBox.className = `fixed bottom-4 right-4 p-4 rounded-lg shadow-lg text-white transition-transform duration-300 transform translate-x-0 ${color}`;
                setTimeout(() => {
                    messageBox.className = `fixed bottom-4 right-4 p-4 rounded-lg shadow-lg text-white transition-transform duration-300 transform translate-x-full ${color}`;
                }, 3000);
            }
        });
    </script>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route("/process", methods=["POST"])
def process_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file part in the request"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
    
    if file:
        try:
            csv_content = file.read().decode('utf-8')
            deidentified_csv, report_content = deidentify_data(csv_content)
            
            return jsonify({
                "deidentified_csv": deidentified_csv,
                "report": report_content
            })
        except Exception as e:
            return jsonify({"error": f"An error occurred during processing: {e}"}), 500

if __name__ == "__main__":
    app.run(debug=True)
