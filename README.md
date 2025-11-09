# DefensePro Forensics Data Analysis & Report Generator

A professional Python-based tool that processes DefensePro forensics data from CSV files (raw or zipped) and generates comprehensive HTML and PDF reports with interactive visualizations for both technical and sales audiences.

## 🚀 Features

- **Memory-Efficient Processing**: Handles files from 1MB to 1GB+ using chunked processing
- **Intelligent Date Parsing**: Automatically detects and handles multiple date formats
- **Month-to-Month Trends**: Analyzes complete calendar months for accurate trend analysis
- **Interactive Visualizations**: Professional charts with configurable themes using Plotly
- **Comprehensive Chart Customization**: 6 color palettes and 11 configurable chart types
- **Dual Output Formats**: Generates both HTML (interactive) and PDF reports
- **Cross-Platform**: Works on Windows, Linux, and macOS
- **Comprehensive Analysis**: Both holistic (entire dataset) and trend (monthly) analysis
- **Batch Processing**: Process multiple files automatically
- **Professional Reports**: Executive summaries and detailed technical analysis

## 📋 Requirements

- Python 3.8 or higher
- 8-16GB RAM recommended for large files
- Internet connection for initial setup (package installation)

## 🛠️ Installation

### Option 1: Quick Setup (Recommended)

1. **Clone or download this repository**
   ```bash
   cd SE_new_report
   ```

2. **Create your configuration file**
   
   The script will automatically create `config.py` from `config_example.py` on first run. Alternatively, you can create it manually:
   ```bash
   # Windows PowerShell
   Copy-Item config_example.py config.py
   
   # Linux/Mac
   cp config_example.py config.py
   ```
   
   > **Note**: `config.py` is not tracked by git, so your custom settings will remain local.

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Install Playwright for PDF generation** (optional but recommended)
   ```bash
   playwright install chromium
   ```

### Option 2: Virtual Environment (Recommended for isolation)

1. **Create virtual environment**
   ```bash
   python -m venv forensics_env
   
   # Windows
   forensics_env\Scripts\activate
   
   # Linux/Mac
   source forensics_env/bin/activate
   ```

2. **Create your configuration file**
   ```bash
   # Windows PowerShell
   Copy-Item config_example.py config.py
   
   # Linux/Mac
   cp config_example.py config.py
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   playwright install chromium
   ```

### Dependencies

Core dependencies automatically installed:
- `polars` - High-performance data processing
- `plotly` - Interactive visualizations  
- `jinja2` - HTML templating
- `playwright` - PDF generation (or `weasyprint` as fallback)
- `python-dateutil` - Flexible date parsing
- `tqdm` - Progress bars
- `click` - Command-line interface
- `psutil` - Memory monitoring

## 📁 Project Structure

```
SE_new_report/
├── analyzer.py              # Main orchestrator script
├── data_processor.py        # CSV parsing and data processing
├── report_generator.py      # HTML/PDF generation
├── visualizations.py        # Chart creation logic
├── utils.py                 # Helper functions
├── config_example.py        # Configuration template (tracked in git)
├── config.py               # Your configuration (auto-created, not tracked)
├── requirements.txt        # Python dependencies
├── README.md               # This file
├── forensics_input/        # Input directory (place files here)
│   └── .gitkeep
└── report_files/           # Output directory
    └── .gitkeep
```

## 🎯 Quick Start

### 1. Prepare Input Data

Place your DefensePro forensics export files in the `forensics_input/` directory:
- **CSV files**: Direct forensics exports
- **ZIP files**: Compressed forensics exports (will be automatically extracted)

**Expected CSV columns** (some may be missing depending on device):
- S.No, Start Time, End Time, Device IP Address, Threat Category
- Attack Name, Policy Name, Action, Attack ID, Source IP Address
- Source Port, Destination IP Address, Destination Port, Direction
- Protocol, Radware ID, Duration, Total Packets, Packet Type
- Total Mbits, Max pps, Max bps, Physical Port, Risk, VLAN Tag
- Footprint, Device Name, Device Type, Workflow Rule Process
- Activation Id, Protected Object

### 2. Run Analysis

**Basic usage** (processes all files in forensics_input/):
```bash
python analyzer.py
```

**Advanced usage**:
```bash
# Specify custom directories
python analyzer.py --input-dir /path/to/files --output-dir /path/to/reports

# Generate only HTML reports
python analyzer.py --format html

# Generate only PDF reports  
python analyzer.py --format pdf

# Enable verbose logging
python analyzer.py --verbose

# Help
python analyzer.py --help
```

### 3. View Results

Reports are generated in the `report_files/` directory:
- `{filename}_report.html` - Interactive HTML report
- `{filename}_report.pdf` - PDF version for sharing
- `batch_summary_{timestamp}.html` - Summary when processing multiple files

## 📊 Report Contents

### Executive Summary
- Total events, date range, daily averages
- Top attack types and trends
- Business impact assessment

### Month-to-Month Trends (when available)
- Security events over time
- Top attack types by month
- Attack volume trends (Mbits, PPS, BPS)
- Attack intensity heatmap by hour and month

### Comprehensive Analysis (Entire Period)
- Attack type distribution
- Top source IP addresses
- Protocol distribution
- Daily attack timeline

### Detailed Analysis
- Top 10 attack types with percentages
- Top 10 source IPs
- Top 10 targeted destinations
- Data quality and methodology notes

## 🔧 Configuration

### Configuration File Setup

The tool uses `config.py` for all settings. On first run, this file is automatically created from `config_example.py` if it doesn't exist. Your `config.py` file is not tracked by git, allowing you to maintain custom settings without affecting version control.

To reset to default settings, simply delete `config.py` and run the script again, or manually copy from `config_example.py`.

### Performance Tuning

Edit `config.py` to adjust:
- `CHUNK_SIZE`: Rows processed per chunk (default: 50,000)
- `MAX_MEMORY_USAGE_GB`: Memory warning threshold (default: 2GB)

### Chart Customization

The tool provides extensive chart customization options in `config.py`:

**Color Themes**: Choose from 6 professionally designed color palettes:
- `ACTIVE_COLOR_PALETTE`: Switch between 'radware_corporate', 'professional_blue', 'modern_minimal', 'vibrant_corporate', 'high_contrast', 'colorblind_friendly'

**Chart Types**: Configure visualization types for each chart:
- `CHART_PREFERENCES`: Set chart types (line, bar, pie, donut, heatmap, area, etc.)

**Individual Overrides**: Customize specific chart colors:
- `CHART_COLOR_ASSIGNMENTS`: Override colors for individual charts while keeping global theme

**Example - Switch to Professional Blue theme:**
```python
ACTIVE_COLOR_PALETTE = 'professional_blue'  # Instead of 'radware_corporate'
```

**Example - Change chart types:**
```python
CHART_PREFERENCES = {
    'monthly_events_trend': {
        'default_type': 'line',  # Change from 'bar' to 'line'
        # ... other configuration
    },
    'attack_type_distribution': {
        'default_type': 'donut',  # Change from 'pie' to 'donut'
        # ... other configuration
    }
}
```

## 📈 Performance Guidance

### File Size Guidelines
- **Small files (< 10MB)**: Process in seconds
- **Medium files (10-100MB)**: Process in 1-2 minutes
- **Large files (100MB-1GB)**: Process in 2-15 minutes
- **Very large files (> 1GB)**: May take 15+ minutes

### Memory Management
- Tool automatically uses chunked processing
- Memory usage scales with chunk size, not file size
- Monitor memory warnings in verbose mode

### Troubleshooting Performance
1. **Reduce chunk size** if memory warnings appear
2. **Close other applications** when processing large files
3. **Use SSD storage** for better I/O performance

## 🐛 Troubleshooting

### Common Issues

**1. "No CSV or ZIP files found"**
- Ensure files are in the `forensics_input/` directory
- Check file extensions (.csv or .zip)
- Verify file permissions

**2. "Missing required columns"**
- Check CSV has required columns: Start Time, Attack Name, Source IP Address, Destination IP Address
- Verify CSV is a DefensePro forensics export (not traffic data)

**3. "Failed to parse dates"**
- Check date format in CSV (common: MM.DD.YYYY HH:MM:SS)
- Tool auto-detects formats but may need manual verification

**4. "PDF generation failed"**
- Install Playwright: `pip install playwright && playwright install chromium`
- Alternative: Install WeasyPrint: `pip install weasyprint`
- Manual fallback: Open HTML in browser and use "Print to PDF"

**5. "Memory errors"**
- Reduce `CHUNK_SIZE` in config.py
- Close other applications
- Process files individually instead of batch

**6. "Chart generation failed"**
- Install visualization dependencies: `pip install plotly kaleido`
- Check internet connection for initial Plotly setup

### Getting Help

1. **Enable verbose logging**: `python analyzer.py --verbose`
2. **Check log output** for specific error messages
3. **Verify file formats** match expected CSV structure
4. **Test with smaller files** first

## 📋 Input File Specifications

### Supported Formats
- **CSV files**: Direct DefensePro forensics exports
- **ZIP files**: Compressed CSV files (auto-extracted)

### Date Format Handling
Tool automatically detects common formats:
- MM.DD.YYYY HH:MM:SS (primary format)
- DD.MM.YYYY HH:MM:SS
- YYYY-MM-DD HH:MM:SS
- Various delimiter combinations (., /, -)

### File Size Limits
- **Tested**: Up to 10 million rows
- **Recommended**: Under 1GB per file
- **Memory**: Scales with chunk size, not file size

## 📈 Analysis Methodology

### Month-to-Month Trends
- **Complete months only**: Excludes partial months at dataset boundaries
- **Fair comparisons**: Ensures accurate trend analysis
- **Minimum requirement**: At least 1 complete month of data

### Holistic Analysis
- **Entire dataset**: Uses all available data regardless of month boundaries
- **Comprehensive statistics**: Full picture of security posture
- **No time filtering**: Maximum data utilization

### Data Quality
- **Intelligent parsing**: Handles missing columns gracefully
- **Validation**: Verifies data integrity throughout processing
- **Transparency**: Reports data quality issues and exclusions

## 🔐 Security & Privacy

- **Local processing**: All data remains on your machine
- **No network transmission**: Data never sent to external services
- **Temporary files**: Automatically cleaned up after processing
- **Memory management**: Sensitive data cleared from memory

## 🤝 Support & Contributing

### Reporting Issues
When reporting issues, please include:
1. Input file characteristics (size, date range, format)
2. Error messages from verbose logging
3. System specifications (OS, Python version, RAM)
4. Command used and expected vs actual behavior

### Performance Testing
Tool performance varies by:
- **Hardware**: CPU, RAM, storage type
- **File characteristics**: Size, date range, data density  
- **System load**: Other running applications

## 📄 License

This tool is designed for internal use with DefensePro forensics data. Please ensure compliance with your organization's data handling policies.

## 🔄 Version History

### Version History

| Version | Change/Fixes/Features                                                                      |
|---------|--------------------------------------------------------------------------------------------|
| v2.0.4  | - 11/7/25 - Fixed EXCLUDE_FILTER - was referenced twice in config.py example
| v2.0.3  | - 11/3/25 - Fixed 2 charts - Top 5 Attacks by Max Bandwidth and PPS. Added config_example.py and removed config.py from git tracking. Enhanced identification of the last full month.  |
| v2.0.2  | - 10/24/25 - Fixed CHART_PREFERENCES variables |
| v2.0.1  | - 10/24/25 - Major UX Enhancement: Added user-configurable control for chart types, layouts, and colors. Improved config.py architecture for intuitive customization. Introduced color palettes with individual chart override support if needed. Updated documentation with customization examples. |
| v2.0.0  | - 10/23/25 - Added new charts: 1.Top 5 attacks by Gbps 2. Top 5 attacks by PPS 3. Security Events by Policy  |
| v1.1.9  | - 10/21/25 - Enhanced identification of the first complete month(challenge with Packet Anomalies unfiltered) |
| v1.1.8  | - 10/21/25 - Enhanced Attack Type Distribution pie chart visualization, style and to avoid overlap between categories and title |
| v1.1.7  | - 10/21/25 - Updated height of the bar charts to not overlap legend with axis x text
- Added autofont adjustment if length of the text is too long (longest attack duration for example)
- Added days to longest attack duration
- Added excluded events text to the execs summary html  |
| v1.1.6  | - 10/21/25 Removed zoom from bar charts, removed vertical zoom from Daily Attack events |
| v1.1.5  | - 10/21/25 Bugfix- inconsistent statistics for Max Gbps and Max PPS in Summary statistics and Volume trends |
| v1.1.4  | - 10/20/25 Enhancment to better identify complete months |
| v1.1.3  | - Bugfix automatically detecting the date format |
| v1.1.2  | - Added configurable charts customizations |
| v1.1.1  | - Fixed/enhanced accuracy in automatic date identification 
- Added FORCE_DATE_FORMAT variable in config.py
- Fixed csv processing using lazy method
- Removed Data Quality Notes section |
| v1.1.0  | - Added configurable output format (html, pdf, both) in config.py variable OUTPUT_FORMATS
- Added support for columns header name variations for both 'Total Packets' and 'Total Packets Dropped', also 'Total Mbits' and 'Total Mbits Dropped'
- Added logic- If VOLUME_UNIT is MB -> show Mbps, if GB -> show Gbps, if TB -> show Gbps
- Added cdn mode - reduced HTML size from 37MB to 116Kb
- Added Expandable details for Summary statistics
   |
| v1.0.1  | - Added filtering. Use new EXCLUDE_FILTERS var under config.py |
| v1.0.0  | - Initial release<br>- Support for CSV and ZIP input files<br>- HTML and PDF report generation<br>- Interactive Plotly visualizations<br>- Memory-efficient processing<br>- Cross-platform compatibility<br>- Batch processing support |


## 🔄 Key Improvements & Features

### Core Analysis Engine
- **Memory-Efficient Processing**: Intelligent chunked processing handles files from MB to GB+ sizes
- **Smart Date Detection**: Automatic format recognition with manual override capabilities
- **Complete Month Analysis**: Sophisticated algorithm identifies and analyzes complete calendar months for accurate trending
- **Data Quality Validation**: Built-in validation and cleansing with transparent reporting

### Advanced Visualization System
- **Professional Color Palettes**: 6 scientifically designed themes including corporate branding, accessibility, and colorblind-friendly options
- **Flexible Chart Types**: 11 fully configurable visualization types (line, bar, pie, donut, heatmap, area, stacked, horizontal)
- **Granular Customization**: Individual chart color overrides while maintaining global theme consistency
- **Modern Configuration Architecture**: Clean separation of settings and logic with immediate hot-reload capability

### Comprehensive Security Analysis
- **Multi-Dimensional Trending**: Month-over-month analysis of attack patterns, volumes, and intensities
- **Attack Profiling**: Detailed breakdown by type, source, protocol, policy, and temporal patterns
- **Performance Metrics**: Bandwidth utilization, packet rates, and volume analysis with configurable units
- **Executive Reporting**: Professional summaries with expandable technical details

### User Experience Excellence
- **One-Click Theming**: Instantly switch color schemes across entire report suite
- **Cross-Platform Compatibility**: Seamless operation on Windows, Linux, and macOS
- **Dual Output Formats**: Interactive HTML and print-ready PDF with consistent styling
- **Batch Processing**: Multiple file analysis with consolidated summary reporting
- **Command-Line Flexibility**: Comprehensive CLI with format control and verbose logging

### Technical Architecture
- **Configuration-Driven**: All customization through centralized, well-documented configuration files
- **Performance Optimized**: CDN-based chart delivery reduces file sizes from 37MB to 116KB
- **Extensible Design**: Modular architecture supports easy addition of new chart types and analysis methods
- **Professional Deployment**: Ready for enterprise environments with comprehensive troubleshooting documentation

---

## 🚀 Quick Example

```bash
# 1. Place forensics CSV files in forensics_input/
# 2. Run analysis
python analyzer.py --verbose

# 3. Open generated reports in report_files/
# HTML: Interactive charts and analysis
# PDF: Print-ready version for sharing
```

For additional help: `python analyzer.py --help`