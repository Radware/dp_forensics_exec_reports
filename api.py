#!/usr/bin/env python3
"""
DefensePro Forensics Report Generator API

Flask-based REST API for generating DefensePro forensics reports.
Supports CSV and ZIP file uploads with HTML/PDF report generation.

Endpoints:
    POST /api/dp-forensic/analyze - Upload file and generate report
    POST /api/dp-forensic/analyze-batch - Upload multiple files and generate batch report
    GET /api/dp-forensic/download/<file_id> - Download generated report file
    GET /api/dp-forensic/health - Health check endpoint
    GET / - API documentation
"""

import os
import json
import traceback
import tempfile
import shutil
import uuid
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List
from flask import Flask, request, jsonify, send_file, render_template_string
from werkzeug.utils import secure_filename
import logging

# Import the forensics analyzer modules
from analyzer import ForensicsAnalyzer
from data_processor import ForensicsDataProcessor
from report_generator import ReportGenerator
from config import OUTPUT_FORMATS

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size
app.config['UPLOAD_FOLDER'] = tempfile.gettempdir()
app.config['DOWNLOAD_FOLDER'] = os.path.join(os.getcwd(), 'report_files')

# Allowed file extensions
ALLOWED_EXTENSIONS = {'csv', 'zip'}

# In-memory storage for file metadata (in production, use Redis or a database)
FILE_REGISTRY = {}

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def allowed_file(filename: str) -> bool:
    """Check if the uploaded file has an allowed extension."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def extract_csv_from_zip(zip_path: Path) -> Dict[str, Any]:
    """
    Extract CSV file from ZIP archive.
    
    Args:
        zip_path: Path to the ZIP file
        
    Returns:
        dict: Result with extracted file path or error
    """
    result = {
        'success': False,
        'error': None,
        'csv_path': None
    }
    
    try:
        # Create temp directory for extraction
        extract_dir = zip_path.parent / f"{zip_path.stem}_extracted"
        extract_dir.mkdir(exist_ok=True)
        
        # Extract ZIP file
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_dir)
        
        # Find CSV files
        csv_files = list(extract_dir.glob('**/*.csv'))
        
        if len(csv_files) == 0:
            result['error'] = 'No CSV files found in the ZIP archive'
            return result
        
        if len(csv_files) > 1:
            result['error'] = f'Multiple CSV files found in ZIP archive ({len(csv_files)} files). Please provide a ZIP with exactly one CSV file.'
            return result
        
        # Return the single CSV file
        result['success'] = True
        result['csv_path'] = csv_files[0]
        logger.info(f"Extracted CSV file: {csv_files[0].name}")
        
    except zipfile.BadZipFile:
        result['error'] = 'Invalid or corrupted ZIP file'
    except Exception as e:
        result['error'] = f'Error extracting ZIP file: {str(e)}'
        logger.error(f"ZIP extraction error: {e}")
    
    return result


def perform_analysis(file_path: Path, output_formats: List[str] = None) -> Dict[str, Any]:
    """
    Perform DefensePro forensics analysis on a single file.
    
    Args:
        file_path: Path to the input file (CSV or ZIP)
        output_formats: List of output formats ['html', 'pdf']
        
    Returns:
        dict: Result containing success status, report data, and any errors
    """
    if output_formats is None:
        output_formats = ['html']
    
    result = {
        'success': False,
        'error': None,
        'report_data': None,
        'stats': {},
        'generated_files': {},
        'download_urls': {}
    }
    
    try:
        # Handle ZIP files - extract and validate
        actual_file_path = file_path
        if file_path.suffix.lower() == '.zip':
            logger.info(f"Extracting ZIP file: {file_path.name}")
            extract_result = extract_csv_from_zip(file_path)
            
            if not extract_result['success']:
                result['error'] = extract_result['error']
                return result
            
            actual_file_path = extract_result['csv_path']
            logger.info(f"Using extracted CSV: {actual_file_path.name}")
        
        # Create temporary directories
        temp_dir = tempfile.mkdtemp()
        input_dir = Path(temp_dir) / 'input'
        output_dir = Path(temp_dir) / 'reports'
        input_dir.mkdir(parents=True, exist_ok=True)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Copy input file to temp input directory
        temp_input_path = input_dir / actual_file_path.name
        shutil.copy2(actual_file_path, temp_input_path)
        
        logger.info(f"Processing file: {actual_file_path.name}")
        
        # Initialize analyzer
        analyzer = ForensicsAnalyzer(
            input_dir=input_dir,
            output_dir=output_dir,
            verbose=False
        )
        
        # Process the file
        process_result = analyzer.process_single_file(
            file_path=temp_input_path,
            formats=output_formats
        )
        
        if not process_result['success']:
            result['error'] = process_result.get('error', 'Analysis failed')
            return result
        
        # Collect generated files and copy to persistent storage
        download_folder = Path(app.config['DOWNLOAD_FOLDER'])
        download_folder.mkdir(parents=True, exist_ok=True)
        
        for fmt in output_formats:
            if fmt in process_result.get('generated_files', {}):
                report_path = Path(process_result['generated_files'][fmt])
                if report_path.exists():
                    # Generate unique file ID
                    file_id = str(uuid.uuid4())
                    
                    # Copy to persistent storage
                    persistent_path = download_folder / f"{file_id}_{report_path.name}"
                    shutil.copy2(report_path, persistent_path)
                    
                    # Register file
                    FILE_REGISTRY[file_id] = {
                        'path': str(persistent_path),
                        'filename': report_path.name,
                        'format': fmt,
                        'created_at': datetime.now().isoformat()
                    }
                    
                    result['generated_files'][fmt] = str(report_path)
                    result['download_urls'][fmt] = f"/api/dp-forensic/download/{file_id}"
                    logger.info(f"Generated {fmt.upper()} report: {report_path}")
        
        # Clean up temp directory
        shutil.rmtree(temp_dir, ignore_errors=True)
        
        # Clean up extracted files if ZIP was processed
        if file_path.suffix.lower() == '.zip' and actual_file_path != file_path:
            extract_dir = actual_file_path.parent
            if extract_dir.exists():
                shutil.rmtree(extract_dir, ignore_errors=True)
        
        # Prepare result data
        result['success'] = len(result['generated_files']) > 0
        result['stats'] = {
            'total_events': process_result.get('total_events', 0),
            'date_range': process_result.get('date_range', {}),
            'complete_months': process_result.get('complete_months', 0),
            'processing_time': process_result.get('processing_time', 0)
        }
        result['report_data'] = {
            'file_name': file_path.name,
            'processed_at': datetime.now().isoformat(),
            'analysis_summary': process_result.get('summary', {})
        }
        
    except Exception as e:
        result['error'] = str(e)
        result['traceback'] = traceback.format_exc()
        logger.error(f"Analysis failed: {e}")
        logger.error(traceback.format_exc())
    
    return result


@app.route('/')
def index():
    """Display API documentation."""
    html_doc = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>DefensePro Forensics Report API</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 1200px; margin: 50px auto; padding: 20px; }
            h1 { color: #003f7f; border-bottom: 3px solid #6cb2eb; padding-bottom: 10px; }
            h2 { color: #34495e; margin-top: 30px; }
            .endpoint { background: #ecf0f1; padding: 15px; margin: 15px 0; border-radius: 5px; }
            .method { color: #27ae60; font-weight: bold; }
            .path { color: #003f7f; font-family: monospace; }
            code { background: #2c3e50; color: #ecf0f1; padding: 2px 6px; border-radius: 3px; }
            pre { background: #2c3e50; color: #ecf0f1; padding: 15px; border-radius: 5px; overflow-x: auto; }
        </style>
    </head>
    <body>
        <h1>🛡️ DefensePro Forensics Report Generator API</h1>
        <p>RESTful API for generating professional DefensePro forensics analysis reports with interactive visualizations.</p>
        
        <h2>Available Endpoints</h2>
        
        <div class="endpoint">
            <h3><span class="method">POST</span> <span class="path">/api/dp-forensic/analyze</span></h3>
            <p>Upload a DefensePro forensics file (CSV or ZIP) and generate an executive report.</p>
            <p><strong>Request:</strong> multipart/form-data</p>
            <ul>
                <li><code>file</code> - CSV or ZIP file containing forensics data</li>
                <li><code>format</code> (optional) - Output format: "html", "pdf", or "both" (default: "html")</li>
            </ul>
            <p><strong>Response:</strong> JSON with report metadata and download links</p>
        </div>
        
        <div class="endpoint">
            <h3><span class="method">POST</span> <span class="path">/api/dp-forensic/analyze-batch</span></h3>
            <p>Upload multiple forensics files and generate individual reports plus a batch summary.</p>
            <p><strong>Request:</strong> multipart/form-data</p>
            <ul>
                <li><code>files</code> - Multiple CSV or ZIP files</li>
                <li><code>format</code> (optional) - Output format: "html", "pdf", or "both" (default: "html")</li>
            </ul>
            <p><strong>Response:</strong> JSON with batch processing results</p>
        </div>
        
        <div class="endpoint">
            <h3><span class="method">GET</span> <span class="path">/api/dp-forensic/health</span></h3>
            <p>Health check endpoint for monitoring.</p>
            <p><strong>Response:</strong> JSON with service status</p>
        </div>
        
        <div class="endpoint">
            <h3><span class="method">GET</span> <span class="path">/api/dp-forensic/download/{file_id}</span></h3>
            <p>Download a generated report file using the file ID from the analyze response.</p>
            <p><strong>Response:</strong> File download (HTML or PDF)</p>
        </div>
        
        <h2>Example Usage</h2>
        <pre>
# Upload and analyze a single file
curl -X POST http://localhost:5000/api/dp-forensic/analyze \\
  -F "file=@forensics_data.csv" \\
  -F "format=html"

# Response includes download_urls:
# {
#   "success": true,
#   "download_urls": {
#     "html": "/api/dp-forensic/download/abc-123-def"
#   }
# }

# Download the generated report
curl -O -J http://localhost:5000/api/dp-forensic/download/abc-123-def

# Upload a ZIP file
curl -X POST http://localhost:5000/api/dp-forensic/analyze \\
  -F "file=@forensics_data.zip" \\
  -F "format=both"

# Check service health
curl http://localhost:5000/api/dp-forensic/health
        </pre>
        
        <h2>Supported File Formats</h2>
        <ul>
            <li>CSV (.csv) - DefensePro forensics data export</li>
            <li>ZIP (.zip) - Compressed CSV files</li>
        </ul>
        
        <h2>Report Formats</h2>
        <ul>
            <li><strong>HTML</strong> - Interactive report with Plotly charts</li>
            <li><strong>PDF</strong> - Static report for sharing (requires Playwright)</li>
        </ul>
    </body>
    </html>
    """
    return render_template_string(html_doc)


@app.route('/api/dp-forensic/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'service': 'dp-forensics-report-generator',
        'version': '1.0.0',
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/dp-forensic/download/<file_id>', methods=['GET'])
def download_file(file_id: str):
    """
    Download a generated report file.
    
    Args:
        file_id: Unique identifier for the generated file
    """
    try:
        if file_id not in FILE_REGISTRY:
            return jsonify({
                'success': False,
                'error': 'File not found or expired'
            }), 404
        
        file_info = FILE_REGISTRY[file_id]
        file_path = Path(file_info['path'])
        
        if not file_path.exists():
            return jsonify({
                'success': False,
                'error': 'File no longer available'
            }), 404
        
        # Determine mimetype based on format
        mimetype = 'text/html' if file_info['format'] == 'html' else 'application/pdf'
        
        logger.info(f"Serving file: {file_info['filename']} (ID: {file_id})")
        
        return send_file(
            file_path,
            mimetype=mimetype,
            as_attachment=True,
            download_name=file_info['filename']
        )
        
    except Exception as e:
        logger.error(f"Download error: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/dp-forensic/analyze', methods=['POST'])
def analyze_file():
    """
    Analyze a single DefensePro forensics file and generate report.
    
    Expects:
        - file: CSV or ZIP file (multipart/form-data)
        - format: Optional output format (html, pdf, both)
    """
    try:
        # Validate file presence
        if 'file' not in request.files:
            return jsonify({
                'success': False,
                'error': 'No file provided'
            }), 400
        
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({
                'success': False,
                'error': 'Empty filename'
            }), 400
        
        if not allowed_file(file.filename):
            return jsonify({
                'success': False,
                'error': f'Invalid file type. Allowed: {", ".join(ALLOWED_EXTENSIONS)}'
            }), 400
        
        # Get output format
        output_format = request.form.get('format', 'html').lower()
        if output_format == 'both':
            output_formats = ['html', 'pdf']
        else:
            output_formats = [output_format]
        
        # Save uploaded file
        filename = secure_filename(file.filename)
        temp_dir = tempfile.mkdtemp()
        file_path = Path(temp_dir) / filename
        file.save(str(file_path))
        
        logger.info(f"Received file: {filename} ({file_path.stat().st_size} bytes)")
        
        # Perform analysis
        result = perform_analysis(file_path, output_formats)
        
        # Clean up uploaded file
        if file_path.exists():
            file_path.unlink()
        
        if result['success']:
            return jsonify({
                'success': True,
                'message': 'Analysis completed successfully',
                'data': result['report_data'],
                'stats': result['stats'],
                'download_urls': result['download_urls']
            }), 200
        else:
            return jsonify({
                'success': False,
                'error': result.get('error', 'Analysis failed'),
                'details': result.get('traceback')
            }), 500
            
    except Exception as e:
        logger.error(f"API error: {e}")
        logger.error(traceback.format_exc())
        return jsonify({
            'success': False,
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 500


@app.route('/api/dp-forensic/analyze-batch', methods=['POST'])
def analyze_batch():
    """
    Analyze multiple DefensePro forensics files and generate batch report.
    
    Expects:
        - files: Multiple CSV or ZIP files (multipart/form-data)
        - format: Optional output format (html, pdf, both)
    """
    try:
        # Validate files presence
        if 'files' not in request.files:
            return jsonify({
                'success': False,
                'error': 'No files provided'
            }), 400
        
        files = request.files.getlist('files')
        
        if len(files) == 0:
            return jsonify({
                'success': False,
                'error': 'No files provided'
            }), 400
        
        # Get output format
        output_format = request.form.get('format', 'html').lower()
        if output_format == 'both':
            output_formats = ['html', 'pdf']
        else:
            output_formats = [output_format]
        
        # Process each file
        results = []
        temp_dir = tempfile.mkdtemp()
        
        for file in files:
            if file.filename == '' or not allowed_file(file.filename):
                continue
            
            filename = secure_filename(file.filename)
            file_path = Path(temp_dir) / filename
            file.save(str(file_path))
            
            logger.info(f"Processing batch file: {filename}")
            
            result = perform_analysis(file_path, output_formats)
            result['filename'] = filename
            results.append(result)
        
        # Calculate batch statistics
        successful = sum(1 for r in results if r['success'])
        failed = len(results) - successful
        
        return jsonify({
            'success': successful > 0,
            'message': f'Batch processing completed',
            'total_files': len(results),
            'successful': successful,
            'failed': failed,
            'results': results
        }), 200
        
    except Exception as e:
        logger.error(f"Batch API error: {e}")
        logger.error(traceback.format_exc())
        return jsonify({
            'success': False,
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 500


@app.errorhandler(413)
def request_entity_too_large(error):
    """Handle file too large error."""
    return jsonify({
        'success': False,
        'error': 'File too large. Maximum size: 100MB'
    }), 413


@app.errorhandler(500)
def internal_error(error):
    """Handle internal server errors."""
    logger.error(f"Internal error: {error}")
    return jsonify({
        'success': False,
        'error': 'Internal server error'
    }), 500


if __name__ == '__main__':
    # Create necessary directories
    os.makedirs('forensics_input', exist_ok=True)
    os.makedirs('report_files', exist_ok=True)
    os.makedirs('temp', exist_ok=True)
    
    # Run the Flask app
    logger.info("Starting DefensePro Forensics Report Generator API...")
    app.run(host='0.0.0.0', port=5000, debug=os.getenv('FLASK_DEBUG', 'False').lower() == 'true')
