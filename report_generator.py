"""
Report generation module for creating HTML and PDF reports.

This module generates professional reports with embedded visualizations,
executive summaries, and comprehensive analysis for both technical and sales audiences.
"""

import logging
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime
import tempfile
import asyncio
from jinja2 import Template

from config import REPORT_CSS, EXCLUDE_FILTERS
from visualizations import ForensicsVisualizer
from utils import format_number, format_file_size, clean_filename

logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    Generates professional HTML and PDF reports from forensics analysis data.
    """
    
    def __init__(self, output_dir: Path):
        """
        Initialize the report generator.
        
        Args:
            output_dir: Directory to save reports
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.visualizer = ForensicsVisualizer()
        
        logger.info(f"Initialized ReportGenerator with output directory: {output_dir}")
    
    def generate_reports(
        self,
        input_filename: str,
        holistic_data: Dict[str, Any],
        monthly_data: Dict[str, Any],
        processing_summary: Dict[str, Any],
        formats: list = ['html', 'pdf']
    ) -> Dict[str, Path]:
        """
        Generate both HTML and PDF reports.
        
        Args:
            input_filename: Original input filename
            holistic_data: Holistic analysis results
            monthly_data: Monthly trend analysis results
            processing_summary: Processing statistics
            formats: List of formats to generate ('html', 'pdf', or both)
            
        Returns:
            Dictionary mapping format to generated file path
        """
        logger.info(f"Generating reports for {input_filename}")
        
        # Clean filename for output
        base_name = clean_filename(Path(input_filename).stem)
        
        generated_files = {}
        
        try:
            # Generate HTML report
            if 'html' in formats:
                html_path = self._generate_html_report(
                    base_name, holistic_data, monthly_data, processing_summary
                )
                generated_files['html'] = html_path
                logger.info(f"Generated HTML report: {html_path}")
            
            # Generate PDF report
            if 'pdf' in formats:
                if 'html' in generated_files:
                    # Use the HTML file we just generated
                    html_path = generated_files['html']
                else:
                    # Generate HTML first for PDF conversion
                    html_path = self._generate_html_report(
                        base_name, holistic_data, monthly_data, processing_summary
                    )
                
                pdf_path = self._generate_pdf_report(html_path, base_name)
                generated_files['pdf'] = pdf_path
                logger.info(f"Generated PDF report: {pdf_path}")
                
                # Clean up temporary HTML if we only wanted PDF
                if 'html' not in formats:
                    html_path.unlink()
            
            return generated_files
            
        except Exception as e:
            logger.error(f"Failed to generate reports: {e}")
            raise
    
    def _generate_html_report(
        self,
        base_name: str,
        holistic_data: Dict[str, Any],
        monthly_data: Dict[str, Any],
        processing_summary: Dict[str, Any]
    ) -> Path:
        """
        Generate HTML report with embedded visualizations.
        
        Args:
            base_name: Base filename for the report
            holistic_data: Holistic analysis results
            monthly_data: Monthly trend analysis results
            processing_summary: Processing statistics
            
        Returns:
            Path to generated HTML file
        """
        output_path = self.output_dir / f"{base_name}_report.html"
        
        try:
            # Generate all visualizations
            charts = self._generate_all_charts(holistic_data, monthly_data)
            
            # Create executive summary
            executive_summary = self._create_executive_summary(holistic_data, monthly_data)
            
            # Generate the HTML content
            html_content = self._create_html_content(
                base_name, holistic_data, monthly_data, charts,
                executive_summary, processing_summary
            )
            
            # Write to file
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            return output_path
            
        except Exception as e:
            logger.error(f"Failed to generate HTML report: {e}")
            raise
    
    def _generate_all_charts(self, holistic_data: Dict[str, Any], monthly_data: Dict[str, Any]) -> Dict[str, str]:
        """
        Generate all visualization charts.
        
        Args:
            holistic_data: Holistic analysis results
            monthly_data: Monthly trend analysis results
            
        Returns:
            Dictionary mapping chart names to HTML strings
        """
        charts = {}
        
        try:
            # Monthly trend charts
            charts['monthly_events'] = self.visualizer.create_monthly_events_trend(monthly_data)
            charts['attack_types_monthly'] = self.visualizer.create_attack_types_stacked_bar(monthly_data)
            charts['volume_trends'] = self.visualizer.create_attack_volume_trends(monthly_data)
            charts['hourly_heatmap'] = self.visualizer.create_hourly_heatmap(monthly_data)
            
            # Holistic analysis charts
            charts['attack_type_pie'] = self.visualizer.create_attack_type_pie_chart(holistic_data)
            charts['top_source_ips'] = self.visualizer.create_top_source_ips_bar(holistic_data)
            charts['protocol_distribution'] = self.visualizer.create_protocol_distribution_chart(holistic_data)
            charts['daily_timeline'] = self.visualizer.create_daily_timeline_chart(holistic_data)
            
            # New attack analysis charts
            charts['top_attacks_max_bps'] = self.visualizer.create_top_attacks_by_max_bps_bar(holistic_data)
            charts['top_attacks_max_pps'] = self.visualizer.create_top_attacks_by_max_pps_bar(holistic_data)
            charts['security_events_by_policy'] = self.visualizer.create_security_events_by_policy_pie(holistic_data)
            
            # Summary statistics
            charts['summary_stats'] = self.visualizer.create_summary_statistics_table(holistic_data, monthly_data)
            
            logger.debug(f"Generated {len(charts)} charts")
            return charts
            
        except Exception as e:
            logger.error(f"Failed to generate charts: {e}")
            # Return empty charts dict to prevent complete failure
            return {key: '<div class="warning">Chart generation failed</div>' for key in [
                'monthly_events', 'attack_types_monthly', 'volume_trends', 'hourly_heatmap',
                'attack_type_pie', 'top_source_ips', 'protocol_distribution', 'daily_timeline', 
                'top_attacks_max_bps', 'top_attacks_max_pps', 'security_events_by_policy', 'summary_stats'
            ]}
    
    def _create_executive_summary(self, holistic_data: Dict[str, Any], monthly_data: Dict[str, Any]) -> str:
        """
        Create executive summary text.
        
        Args:
            holistic_data: Holistic analysis results
            monthly_data: Monthly trend analysis results
            
        Returns:
            HTML string with executive summary
        """
        try:
            total_events = holistic_data.get('total_events', 0)
            date_range = holistic_data.get('date_range', {})
            unique_sources = holistic_data.get('unique_source_ips', 0)
            attack_types = holistic_data.get('attack_types', {})
            
            # Get top attack type
            if attack_types:
                top_attack_tuple = None
                max_count = 0
                for attack, attack_info in attack_types.items():
                    if isinstance(attack_info, dict):
                        count = attack_info.get('count', 0)
                    else:
                        # Handle old format (just count)
                        count = attack_info
                    if count > max_count:
                        max_count = count
                        top_attack_tuple = (attack, count)
                top_attack = top_attack_tuple if top_attack_tuple else ("N/A", 0)
            else:
                top_attack = ("N/A", 0)
            
            # Calculate daily average
            days = date_range.get('days', 1)
            daily_avg = total_events / days if days > 0 else 0
            
            # Trend analysis
            trend_analysis = ""
            if monthly_data.get('has_trends', False):
                months = list(monthly_data['months'].keys())
                if len(months) >= 2:
                    first_month_events = monthly_data['months'][months[0]]['total_events']
                    last_month_events = monthly_data['months'][months[-1]]['total_events']
                    
                    if last_month_events > first_month_events:
                        trend = "increasing"
                    elif last_month_events < first_month_events:
                        trend = "decreasing"
                    else:
                        trend = "stable"
                    
                    trend_analysis = f"<li>Security events show a <strong>{trend}</strong> trend over the analysis period.</li>"
            
            # Excluded filters
            excluded_filters = []
            for values in EXCLUDE_FILTERS.values():
                if isinstance(values, (list, tuple, set)):
                    excluded_filters.extend(map(str, values))
                else:
                    excluded_filters.append(str(values))
            excluded_filters_str = ', '.join(excluded_filters)

            if not excluded_filters_str:
                excluded_filters_str = 'None'
            
            summary = f"""
            <div class="section">
                <h2>Executive Summary</h2>
                <p>This report analyzes <strong>{format_number(total_events)}</strong> security events captured over 
                <strong>{days} days</strong> from {date_range.get('start', 'Unknown')} to {date_range.get('end', 'Unknown')}.</p>
                
                <h3>Key Findings:</h3>
                <ul>
                    <li>Total security events: <strong>{format_number(total_events)}</strong> (Excluded events: <strong>{excluded_filters_str}</strong>)</li>
                    <li>Daily average: <strong>{format_number(int(daily_avg))}</strong> events per day</li>
                    <li>Unique source IP addresses: <strong>{format_number(unique_sources)}</strong></li>
                    <li>Most common attack type: <strong>{top_attack[0]}</strong> ({format_number(top_attack[1])} events)</li>
                    <li>Total attack types observed: <strong>{format_number(len(attack_types))}</strong></li>
                    {trend_analysis}
                </ul>
                
                <h3>Business Impact:</h3>
                <p>The analysis reveals the organization's security posture and attack patterns that can inform 
                defense strategy and resource allocation. The data shows both the volume and variety of threats 
                facing the network infrastructure.</p>
            </div>
            """
            
            return summary
            
        except Exception as e:
            logger.error(f"Failed to create executive summary: {e}")
            return '<div class="warning">Failed to generate executive summary</div>'
    
    def _create_html_content(
        self,
        base_name: str,
        holistic_data: Dict[str, Any],
        monthly_data: Dict[str, Any],
        charts: Dict[str, str],
        executive_summary: str,
        processing_summary: Dict[str, Any]
    ) -> str:
        """
        Create the complete HTML content for the report.
        
        Args:
            base_name: Base filename
            holistic_data: Holistic analysis results
            monthly_data: Monthly trend analysis results
            charts: Dictionary of chart HTML strings
            executive_summary: Executive summary HTML
            data_quality_notes: Data quality notes HTML
            processing_summary: Processing statistics
            
        Returns:
            Complete HTML content string
        """
        generation_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Simplified HTML template as a string
        date_range = holistic_data.get('date_range', {})
        
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DefensePro Forensics Analysis Report - {base_name.replace('_', ' ').title()}</title>
    {REPORT_CSS}
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>DefensePro Forensics Analysis Report</h1>
            <p>{base_name.replace('_', ' ').title()}</p>
            <p>Generated on {generation_time}</p>
        </div>
        
        <div class="content">
            <!-- Executive Summary -->
            {executive_summary}
            
            <!-- Summary Statistics -->
            <div class="section">
                <h2>Summary Statistics</h2>
                {charts['summary_stats']}
            </div>
            
            <!-- Month-to-Month Trends -->
            <div class="section">
                <h2>Month-to-Month Trend Analysis</h2>
                {self._render_monthly_trends_section(monthly_data, charts)}
            </div>
            
            <!-- Holistic Analysis -->
            <div class="section">
                <h2>Comprehensive Analysis (Entire Period)</h2>
                <p>The following analysis covers the complete dataset from {date_range.get('start', 'Unknown')} to {date_range.get('end', 'Unknown')}.</p>
                
                <h3>Attack Type Distribution</h3>
                <div class="chart-container">
                    {charts['attack_type_pie']}
                </div>
                
                <h3>Top Source IP Addresses</h3>
                <div class="chart-container">
                    {charts['top_source_ips']}
                </div>
                
                <h3>Protocol Distribution</h3>
                <div class="chart-container">
                    {charts['protocol_distribution']}
                </div>
                
                <h3>Daily Attack Timeline</h3>
                <div class="chart-container">
                    {charts['daily_timeline']}
                </div>
            </div>
            
            <!-- New Attack Analysis Charts -->
            <div class="section">
                <h2>Top Attack Analysis</h2>
                <p>Analysis of the most impactful attacks by bandwidth and packet rate.</p>
                
                <h3>Top 5 Attacks by Maximum Bandwidth</h3>
                <div class="chart-container">
                    {charts['top_attacks_max_bps']}
                </div>
                
                <h3>Top 5 Attacks by Maximum PPS</h3>
                <div class="chart-container">
                    {charts['top_attacks_max_pps']}
                </div>
                
                <h3>Security Events by Policy</h3>
                <div class="chart-container">
                    {charts['security_events_by_policy']}
                </div>
            </div>
            
            <!-- Top Attack Details -->
            <div class="section">
                <h2>Detailed Attack Analysis</h2>
                
                <h3>Top 10 Attack Types</h3>
                {self._create_top_attacks_table(holistic_data)}
                
                <h3>Top 10 Source IPs</h3>
                {self._create_top_sources_table(holistic_data)}
                
                <h3>Top 10 Targeted Destinations</h3>
                {self._create_top_destinations_table(holistic_data)}
            </div>
        </div>
        
        <div class="footer">
            <p>Report generated by DefensePro Forensics Analysis Tool on {generation_time}</p>
            <p>Source: {processing_summary.get('file_info', {}).get('name', 'Unknown')}</p>
        </div>
    </div>
</body>
</html>
        """
        
        return html_content
    
    def _render_monthly_trends_section(self, monthly_data: Dict[str, Any], charts: Dict[str, str]) -> str:
        """
        Render the monthly trends section based on whether trends are available.
        
        Args:
            monthly_data: Monthly analysis data
            charts: Chart HTML strings
            
        Returns:
            HTML for monthly trends section
        """
        if monthly_data.get('has_trends', False):
            complete_months = len(monthly_data.get('months', {}))
            return f"""
                <p>The following charts show trends across {complete_months} complete months of data.</p>
                
                <h3>Security Events Over Time</h3>
                <div class="chart-container">
                    {charts['monthly_events']}
                </div>
                
                <h3>Top Attack Types by Month</h3>
                <div class="chart-container">
                    {charts['attack_types_monthly']}
                </div>
                
                <h3>Attack Volume Trends</h3>
                <div class="chart-container">
                    {charts['volume_trends']}
                </div>
                
                <h3>Attack Intensity Heatmap</h3>
                <div class="chart-container">
                    {charts['hourly_heatmap']}
                </div>
            """
        else:
            reason = monthly_data.get('reason', 'Insufficient data')
            return f"""
                <div class="warning">
                    <strong>Trend Analysis Unavailable:</strong> {reason}
                </div>
            """
    
    def _create_top_attacks_table(self, holistic_data: Dict[str, Any]) -> str:
        """
        Create HTML table for top attack types.
        
        Args:
            holistic_data: Holistic analysis results
            
        Returns:
            HTML table string
        """
        try:
            attack_types = holistic_data.get('attack_types', {})
            total_events = holistic_data.get('total_events', 1)
            
            if not attack_types:
                return '<p>No attack data available</p>'
            
            # Get top 10 attacks
            attack_counts = {}
            for attack, attack_info in attack_types.items():
                if isinstance(attack_info, dict):
                    count = attack_info.get('count', 0)
                else:
                    # Handle old format (just count)
                    count = attack_info
                attack_counts[attack] = count
            
            top_attacks = sorted(attack_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            
            html = """
            <table>
                <thead>
                    <tr>
                        <th>Rank</th>
                        <th>Attack Type</th>
                        <th>Event Count</th>
                        <th>Percentage</th>
                    </tr>
                </thead>
                <tbody>
            """
            
            for i, (attack, count) in enumerate(top_attacks, 1):
                percentage = (count / total_events) * 100
                html += f"""
                    <tr>
                        <td>{i}</td>
                        <td>{attack}</td>
                        <td>{format_number(count)}</td>
                        <td>{percentage:.1f}%</td>
                    </tr>
                """
            
            html += """
                </tbody>
            </table>
            """
            
            return html
            
        except Exception as e:
            logger.error(f"Failed to create top attacks table: {e}")
            return '<p>Error generating top attacks table</p>'
    
    def _create_top_sources_table(self, holistic_data: Dict[str, Any]) -> str:
        """
        Create HTML table for top source IPs.
        
        Args:
            holistic_data: Holistic analysis results
            
        Returns:
            HTML table string
        """
        try:
            source_ips = holistic_data.get('top_source_ips', {})
            
            if not source_ips:
                return '<p>No source IP data available</p>'
            
            # Get top 10 sources (already sorted)
            top_sources = list(source_ips.items())[:10]
            
            html = """
            <table>
                <thead>
                    <tr>
                        <th>Rank</th>
                        <th>Source IP Address</th>
                        <th>Event Count</th>
                    </tr>
                </thead>
                <tbody>
            """
            
            for i, (ip, count) in enumerate(top_sources, 1):
                html += f"""
                    <tr>
                        <td>{i}</td>
                        <td>{ip}</td>
                        <td>{format_number(count)}</td>
                    </tr>
                """
            
            html += """
                </tbody>
            </table>
            """
            
            return html
            
        except Exception as e:
            logger.error(f"Failed to create top sources table: {e}")
            return '<p>Error generating top sources table</p>'
    
    def _create_top_destinations_table(self, holistic_data: Dict[str, Any]) -> str:
        """
        Create HTML table for top destination IPs.
        
        Args:
            holistic_data: Holistic analysis results
            
        Returns:
            HTML table string
        """
        try:
            dest_ips = holistic_data.get('top_dest_ips', {})
            
            if not dest_ips:
                return '<p>No destination IP data available</p>'
            
            # Get top 10 destinations (already sorted)
            top_destinations = list(dest_ips.items())[:10]
            
            html = """
            <table>
                <thead>
                    <tr>
                        <th>Rank</th>
                        <th>Destination IP Address</th>
                        <th>Event Count</th>
                    </tr>
                </thead>
                <tbody>
            """
            
            for i, (ip, count) in enumerate(top_destinations, 1):
                html += f"""
                    <tr>
                        <td>{i}</td>
                        <td>{ip}</td>
                        <td>{format_number(count)}</td>
                    </tr>
                """
            
            html += """
                </tbody>
            </table>
            """
            
            return html
            
        except Exception as e:
            logger.error(f"Failed to create top destinations table: {e}")
            return '<p>Error generating top destinations table</p>'
    
    def _generate_pdf_report(self, html_path: Path, base_name: str) -> Path:
        """
        Generate PDF report from HTML using Playwright.
        
        Args:
            html_path: Path to HTML file
            base_name: Base filename for output
            
        Returns:
            Path to generated PDF file
        """
        output_path = self.output_dir / f"{base_name}_report.pdf"
        
        try:
            # Try to use Playwright for PDF generation
            try:
                from playwright.async_api import async_playwright
                
                async def generate_pdf():
                    async with async_playwright() as p:
                        browser = await p.chromium.launch()
                        page = await browser.new_page()
                        
                        # Load the HTML file
                        file_url = f"file://{html_path.absolute()}"
                        await page.goto(file_url, wait_until='networkidle')
                        
                        # Wait for charts to render
                        await page.wait_for_timeout(3000)
                        
                        # Generate PDF
                        await page.pdf(
                            path=str(output_path),
                            format='A4',
                            margin={
                                'top': '1in',
                                'right': '0.8in',
                                'bottom': '1in',
                                'left': '0.8in'
                            },
                            print_background=True
                        )
                        
                        await browser.close()
                
                # Run the async function
                asyncio.run(generate_pdf())
                
                logger.info(f"Generated PDF using Playwright: {output_path}")
                return output_path
                
            except ImportError:
                logger.warning("Playwright not available, trying alternative PDF generation")
                
                # Fallback to weasyprint if available
                try:
                    import weasyprint
                    
                    # Read HTML content
                    with open(html_path, 'r', encoding='utf-8') as f:
                        html_content = f.read()
                    
                    # Generate PDF
                    html_doc = weasyprint.HTML(string=html_content, base_url=str(html_path.parent))
                    html_doc.write_pdf(str(output_path))
                    
                    logger.info(f"Generated PDF using WeasyPrint: {output_path}")
                    return output_path
                    
                except ImportError:
                    logger.error("No PDF generation library available (Playwright or WeasyPrint)")
                    
                    # Create a text file with instructions instead
                    instructions_path = self.output_dir / f"{base_name}_pdf_instructions.txt"
                    
                    with open(instructions_path, 'w') as f:
                        f.write(f"""
PDF Generation Instructions
===========================

To generate a PDF from the HTML report, you can:

1. Install Playwright:
   pip install playwright
   playwright install chromium

2. Or install WeasyPrint:
   pip install weasyprint

3. Or manually:
   - Open the HTML file in a web browser: {html_path}
   - Use the browser's "Print to PDF" function
   - Save as: {output_path}

HTML Report Location: {html_path}
Desired PDF Location: {output_path}
                    """)
                    
                    logger.warning(f"Created PDF generation instructions: {instructions_path}")
                    return instructions_path
                    
        except Exception as e:
            logger.error(f"Failed to generate PDF: {e}")
            raise