"""
Data processing module for DefensePro forensics data.

This module handles memory-efficient processing of large CSV files using chunked
reading, intelligent date parsing, and month filtering logic.
"""

import logging
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Iterator
import polars as pl
import pandas as pd
from tqdm import tqdm

from utils import (
    parse_date_flexible, detect_date_format, get_complete_months,
    check_memory_usage, format_file_size, validate_csv_structure,
    detect_file_encoding, format_number
)
from config import CHUNK_SIZE, REQUIRED_COLUMNS, EXPECTED_COLUMNS, EXCLUDE_FILTERS

logger = logging.getLogger(__name__)


class ForensicsDataProcessor:
    """
    Processes DefensePro forensics data with memory-efficient chunked reading.
    """
    
    def __init__(self, file_path: Path, chunk_size: int = CHUNK_SIZE):
        """
        Initialize the data processor.
        
        Args:
            file_path: Path to the CSV file
            chunk_size: Number of rows to process per chunk
        """
        self.file_path = file_path
        self.chunk_size = chunk_size
        self.encoding = detect_file_encoding(file_path)
        self.date_format = None
        self.total_rows = 0
        self.data_start_date = None
        self.data_end_date = None
        self.complete_months = []
        self.column_mapping = {}
        
        # Handle both string and Path objects
        file_name = file_path.name if hasattr(file_path, 'name') else str(file_path)
        logger.info(f"Initializing processor for {file_name}")
    
    def analyze_file_structure(self) -> Dict[str, Any]:
        """
        Analyze the CSV file structure and detect date formats.
        
        Returns:
            Dictionary with file analysis results
        """
        logger.info("Analyzing file structure...")
        
        try:
            # Get schema overrides for problematic columns
            schema_overrides = self._get_schema_overrides()
            
            # Read a larger sample to analyze structure and get enough samples for date format detection
            # Use n_rows to ensure stratified sampling has diverse date coverage for date format detection
            df_sample = pl.read_csv(
                self.file_path,
                n_rows=3000,
                ignore_errors=True,
                schema_overrides=schema_overrides,
                infer_schema_length=10000
            )
            
            columns = df_sample.columns
            logger.info(f"Found {len(columns)} columns in CSV")
            
            # Check for required columns
            missing_required = [col for col in REQUIRED_COLUMNS if col not in columns]
            if missing_required:
                logger.error(f"Missing required columns: {missing_required}")
                raise ValueError(f"Missing required columns: {missing_required}")
            
            # Create column mapping for flexible column handling
            self.column_mapping = self._create_column_mapping(columns)
            
            # Detect date format from Start Time column
            if 'Start Time' in columns:
                sample_dates = df_sample['Start Time'].to_list()
                self.date_format = detect_date_format(sample_dates)
            
            # Get file statistics
            file_size = self.file_path.stat().st_size
            estimated_rows = self._estimate_row_count()
            
            analysis = {
                'file_size': file_size,
                'file_size_formatted': format_file_size(file_size),
                'estimated_rows': estimated_rows,
                'columns_found': len(columns),
                'columns_expected': len(EXPECTED_COLUMNS),
                'missing_columns': [col for col in EXPECTED_COLUMNS if col not in columns],
                'date_format': self.date_format,
                'encoding': self.encoding,
                'is_large_file': file_size > 100 * 1024 * 1024  # > 100MB
            }
            
            # logger.info(f"File analysis complete: {analysis['estimated_rows']:,} estimated rows")
            return analysis
            
        except Exception as e:
            logger.error(f"Failed to analyze file structure: {e}")
            raise
    
    def _get_schema_overrides(self) -> Dict[str, pl.DataType]:
        """
        Get schema overrides for columns that might have problematic data types.
        
        Returns:
            Dictionary mapping column names to polars data types
        """
        return {
            # Handle columns that might have mixed types
            'Physical Port': pl.Utf8,  # String to handle 'T-1' values
            'Source Port': pl.Utf8,    # String to handle non-numeric ports
            'Destination Port': pl.Utf8,  # String to handle non-numeric ports
            'VLAN Tag': pl.Utf8,       # String to handle mixed VLAN formats
            'Risk': pl.Utf8,           # String to handle risk levels
            'Packet Type': pl.Utf8,    # String for packet types
            'Protocol': pl.Utf8,       # String for protocol names
            'Direction': pl.Utf8,      # String for direction values
            'Action': pl.Utf8,         # String for action types
            'Device Type': pl.Utf8,    # String for device types
            'Workflow Rule Process': pl.Utf8,  # String for workflow data
            'Activation Id': pl.Utf8,  # String for activation IDs
            'Attack ID': pl.Utf8,      # String to handle mixed ID formats
            'Radware ID': pl.Utf8,     # String to handle mixed ID formats
        }
    
    def _apply_data_filters(self, chunk: pl.DataFrame) -> pl.DataFrame:
        """
        Filter out excluded data based on dynamic filters.
        
        Args:
            chunk: Data chunk to filter
            
        Returns:
            Filtered data chunk
        """
        try:
            # Apply dynamic filters
            if EXCLUDE_FILTERS:
                for column_name, excluded_values in EXCLUDE_FILTERS.items():
                    if column_name in chunk.columns and excluded_values:
                        # Filter out rows where column value is in the excluded list
                        chunk = chunk.filter(~pl.col(column_name).is_in(excluded_values))
            
            return chunk
            
        except Exception as e:
            logger.warning(f"Failed to apply data filters: {e}")
            return chunk
    
    def _create_column_mapping(self, columns: List[str]) -> Dict[str, str]:
        """
        Create a mapping for column name variations.
        
        Args:
            columns: List of actual column names
            
        Returns:
            Dictionary mapping standard names to actual names
        """
        mapping = {}
        
        # Handle common column name variations
        column_variants = {
            'Start Time': ['Start Time', 'StartTime', 'start_time', 'Start_Time'],
            'End Time': ['End Time', 'EndTime', 'end_time', 'End_Time'],
            'Attack Name': ['Attack Name', 'AttackName', 'attack_name', 'Attack_Name'],
            'Threat Category': ['Threat Category', 'ThreatCategory', 'threat_category', 'Threat_Category'],
            'Source IP Address': ['Source IP Address', 'Source IP', 'SourceIP', 'source_ip'],
            'Destination IP Address': ['Destination IP Address', 'Destination IP', 'DestIP', 'dest_ip'],
            'Total Packets': ['Total Packets', 'Total Packets Dropped', 'TotalPackets', 'total_packets', 'Packets'],
            'Total Mbits': ['Total Mbits', 'Total Mbits Dropped', 'TotalMbits', 'total_mbits', 'Mbits'],
            'Max pps': ['Max pps', 'MaxPPS', 'max_pps', 'Max_pps'],
            'Max bps': ['Max bps', 'MaxBPS', 'max_bps', 'Max_bps', 'Max Attack Rate in Kb'],
        }
        
        for standard_name, variants in column_variants.items():
            for variant in variants:
                if variant in columns:
                    mapping[standard_name] = variant
                    break
            
        return mapping
    
    def _estimate_row_count(self) -> int:
        """
        Estimate total number of rows in the file.
        
        Returns:
            Estimated row count
        """
        try:
            # Get schema overrides for problematic columns
            schema_overrides = self._get_schema_overrides()
            
            # Read first chunk to estimate row size
            df_chunk = pl.read_csv(
                self.file_path,
                n_rows=self.chunk_size,
                schema_overrides=schema_overrides,
                ignore_errors=True,
                infer_schema_length=10000
            )
            
            if len(df_chunk) == 0:
                return 0
            
            # Estimate based on file size and average row size
            file_size = self.file_path.stat().st_size
            
            # Read a portion to get average row size
            with open(self.file_path, 'r', encoding=self.encoding) as f:
                # Skip header
                f.readline()
                
                # Read sample lines
                sample_size = 0
                line_count = 0
                for _ in range(min(1000, len(df_chunk))):
                    line = f.readline()
                    if not line:
                        break
                    sample_size += len(line.encode(self.encoding))
                    line_count += 1
            
            if line_count > 0:
                avg_line_size = sample_size / line_count
                estimated_rows = int(file_size / avg_line_size)
                logger.debug(f"Estimated rows: {estimated_rows:,}")
                return estimated_rows
            
            return len(df_chunk)
            
        except Exception as e:
            logger.warning(f"Failed to estimate row count: {e}")
            return 0
    
    def scan_date_range(self) -> Tuple[datetime, datetime]:
        """
        Scan the entire file to determine the actual date range.
        
        Returns:
            Tuple of (start_date, end_date)
        """
        logger.info("Scanning file for date range...")
        
        min_date = None
        max_date = None
        processed_rows = 0
        
        try:
            # Get schema overrides for problematic columns
            schema_overrides = self._get_schema_overrides()
            
            # Process file in chunks to find date range
            with tqdm(desc="Scanning dates", unit="rows") as pbar:
                
                # Use scan and collect approach for batched processing
                try:
                    # Try the newer polars approach with auto-detected encoding
                    df_lazy = pl.scan_csv(
                        self.file_path,
                        schema_overrides=schema_overrides,
                        ignore_errors=True,
                        infer_schema_length=10000
                    )
                    
                    # Process in chunks using collect with slice
                    chunk_size = self.chunk_size
                    offset = 0
                    
                    while True:
                        chunk = df_lazy.slice(offset, chunk_size).collect()
                        
                        if len(chunk) == 0:
                            break
                            
                        if 'Start Time' not in chunk.columns:
                            offset += chunk_size
                            continue
                        
                        # Store original chunk size before filtering (important for accurate offset tracking)
                        original_chunk_size = len(chunk)
                        
                        # Filter out excluded data
                        chunk = self._apply_data_filters(chunk)
                        
                        if len(chunk) == 0:
                            offset += chunk_size
                            continue
                        
                        # Parse dates in this chunk
                        dates = []
                        for date_str in chunk['Start Time'].to_list():
                            parsed_date = parse_date_flexible(date_str, self.date_format)
                            if parsed_date:
                                dates.append(parsed_date)
                        
                        if dates:
                            chunk_min = min(dates)
                            chunk_max = max(dates)
                            
                            if min_date is None or chunk_min < min_date:
                                min_date = chunk_min
                            if max_date is None or chunk_max > max_date:
                                max_date = chunk_max
                        
                        processed_rows += len(chunk)
                        pbar.update(len(chunk))
                        
                        # Move to next chunk
                        offset += chunk_size
                        
                        # Break if we got less than expected (end of file)
                        if original_chunk_size < chunk_size:
                            break
                            
                except Exception as lazy_error:
                    logger.warning(f"Lazy processing failed, falling back to eager: {lazy_error}")
                    
                    # Fallback to eager reading in chunks with proper header handling
                    chunk_size = self.chunk_size
                    
                    # First, read just the header to get column names
                    header_df = pl.read_csv(
                        self.file_path,
                        n_rows=0,  # Just header
                        schema_overrides=schema_overrides,
                        ignore_errors=True,
                        infer_schema_length=10000
                    )
                    
                    if 'Start Time' not in header_df.columns:
                        logger.error("Start Time column not found in file")
                        return None, None
                    
                    column_names = header_df.columns
                    current_skip = 1  # Skip header for all chunks
                    
                    while True:
                        try:
                            # Read chunk without header (skip_rows includes header)
                            chunk = pl.read_csv(
                                self.file_path,
                                skip_rows=current_skip,
                                n_rows=chunk_size,
                                schema_overrides=schema_overrides,
                                ignore_errors=True,
                                infer_schema_length=10000
                            )
                            
                            if len(chunk) == 0:
                                break
                            
                            # Manually rename columns to match header if needed
                            if list(chunk.columns) != column_names:
                                chunk = chunk.rename({old: new for old, new in zip(chunk.columns, column_names)})
                            
                            # Store original chunk size before filtering
                            original_chunk_size = len(chunk)
                            
                            # Filter out excluded data
                            chunk = self._apply_data_filters(chunk)
                            
                            # Parse dates in this chunk
                            dates = []
                            for date_str in chunk['Start Time'].to_list():
                                parsed_date = parse_date_flexible(date_str, self.date_format)
                                if parsed_date:
                                    dates.append(parsed_date)
                            
                            if dates:
                                chunk_min = min(dates)
                                chunk_max = max(dates)
                                
                                if min_date is None or chunk_min < min_date:
                                    min_date = chunk_min
                                if max_date is None or chunk_max > max_date:
                                    max_date = chunk_max
                            
                            processed_rows += len(chunk)
                            pbar.update(len(chunk))
                            
                            # Update skip position for next chunk (use original size, not filtered size)
                            current_skip += original_chunk_size
                            
                            # Break if we got less than expected (end of file)
                            if original_chunk_size < chunk_size:
                                break
                                
                        except Exception as e:
                            logger.error(f"Error reading chunk at row {current_skip}: {e}")
                            break
            
            self.data_start_date = min_date
            self.data_end_date = max_date
            self.total_rows = processed_rows
            
            if min_date and max_date:
                logger.info(f"Date range: {min_date.date()} to {max_date.date()}")
                
                # Calculate complete months with Phase 2 validation
                self.complete_months = get_complete_months(
                    min_date, 
                    max_date, 
                    file_path=str(self.file_path), 
                    date_format=self.date_format
                )
                
                return min_date, max_date
            else:
                raise ValueError("No valid dates found in the data")
                
        except Exception as e:
            logger.error(f"Failed to scan date range: {e}")
            raise
    
    def process_monthly_trends(self) -> Dict[str, Any]:
        """
        Process data for month-to-month trend analysis.
        
        Returns:
            Dictionary with monthly trend data
        """
        if not self.complete_months:
            logger.warning("No complete months found for trend analysis")
            return {
                'has_trends': False,
                'reason': 'Insufficient data for trend analysis (requires at least 1 complete month)',
                'months': []
            }
        
        logger.info(f"Processing {len(self.complete_months)} complete months for trends")
        
        monthly_data = {}
        
        try:
            with tqdm(desc="Processing monthly trends", unit="months") as pbar:
                
                for month_start, month_end in self.complete_months:
                    month_key = month_start.strftime('%Y-%m')
                    month_stats = self._process_month_data(month_start, month_end)
                    monthly_data[month_key] = month_stats
                    pbar.update(1)
            
            return {
                'has_trends': True,
                'months': monthly_data,
                'excluded_note': self._get_excluded_months_note()
            }
            
        except Exception as e:
            logger.error(f"Failed to process monthly trends: {e}")
            raise
    
    def _process_month_data(self, month_start: datetime, month_end: datetime) -> Dict[str, Any]:
        """
        Process data for a specific month.
        
        Args:
            month_start: Start of month
            month_end: End of month
            
        Returns:
            Dictionary with month statistics
        """
        stats = {
            'month_name': month_start.strftime('%B %Y'),
            'total_events': 0,
            'unique_source_ips': set(),
            'unique_dest_ips': set(),
            'attack_types': {},
            'protocols': {},
            'actions': {},
            'max_packets': 0,
            'max_mbits': 0,
            'max_pps': 0,
            'max_bps': 0,
            'max_pps_details': None,
            'max_bps_details': None,
            'total_packets': 0,
            'total_mbits': 0,
            'devices': {},
            'policies': {},
            'hourly_distribution': [0] * 24
        }
        
        try:
            # Get schema overrides for problematic columns
            schema_overrides = self._get_schema_overrides()
            
            # Process file in chunks for this month using correct header approach
            chunk_size = self.chunk_size
            
            # First, read just the header to get column names
            header_df = pl.read_csv(
                self.file_path,
                n_rows=0,  # Just header
                schema_overrides=schema_overrides,
                ignore_errors=True,
                infer_schema_length=10000
            )
            
            if 'Start Time' not in header_df.columns:
                logger.error("Start Time column not found in file")
                return stats
            
            column_names = header_df.columns
            current_skip = 1  # Skip header for all chunks
            
            while True:
                try:
                    # Read chunk without header (skip_rows includes header)
                    chunk = pl.read_csv(
                        self.file_path,
                        skip_rows=current_skip,
                        n_rows=chunk_size,
                        schema_overrides=schema_overrides,
                        ignore_errors=True,
                        infer_schema_length=10000
                    )
                    
                    if len(chunk) == 0:
                        break
                    
                    # Manually rename columns to match header if needed
                    if list(chunk.columns) != column_names:
                        chunk = chunk.rename({old: new for old, new in zip(chunk.columns, column_names)})
                    
                    # Store original chunk size before filtering
                    original_chunk_size = len(chunk)
                    
                    # Filter out excluded data
                    chunk = self._apply_data_filters(chunk)
                    
                    # Filter chunk for this month's data
                    month_chunk = self._filter_chunk_by_date(chunk, month_start, month_end)
                    
                    if len(month_chunk) == 0:
                        current_skip += original_chunk_size
                        if original_chunk_size < chunk_size:
                            break
                        continue
                    
                    # Update statistics
                    self._update_month_stats(stats, month_chunk)
                    
                    # Update skip position for next chunk (use original size, not filtered size)
                    current_skip += original_chunk_size
                    
                    # Break if we got less than expected (end of file)
                    if original_chunk_size < chunk_size:
                        break
                        
                except Exception as e:
                    logger.error(f"Error reading chunk at row {current_skip}: {e}")
                    break
        
        except Exception as e:
            logger.error(f"Failed to process month {month_start.strftime('%Y-%m')}: {e}")
        
        # Convert sets to counts and lists
        stats['unique_source_ips'] = len(stats['unique_source_ips'])
        stats['unique_dest_ips'] = len(stats['unique_dest_ips'])
        
        return stats
    
    def _filter_chunk_by_date(self, chunk: pl.DataFrame, start_date: datetime, end_date: datetime) -> pl.DataFrame:
        """
        Filter chunk data by date range.
        
        Args:
            chunk: Data chunk
            start_date: Filter start date
            end_date: Filter end date
            
        Returns:
            Filtered dataframe
        """
        if 'Start Time' not in chunk.columns:
            return chunk.filter(pl.lit(False))  # Empty result
        
        try:
            # Parse dates and convert to polars datetime
            chunk = chunk.with_columns([
                pl.col('Start Time').map_elements(
                    lambda x: parse_date_flexible(x, self.date_format),
                    return_dtype=pl.Object
                ).alias('parsed_date_obj')
            ])
            
            # Convert Python datetime objects to polars datetime format
            chunk = chunk.with_columns([
                pl.col('parsed_date_obj').map_elements(
                    lambda x: x if x is None else x.replace(tzinfo=None),
                    return_dtype=pl.Datetime
                ).alias('parsed_date')
            ])
            
            # Convert start_date and end_date to polars datetime for comparison
            start_dt = start_date.replace(tzinfo=None) if start_date.tzinfo else start_date
            end_dt = end_date.replace(tzinfo=None) if end_date.tzinfo else end_date
            
            # Filter by date range
            filtered = chunk.filter(
                (pl.col('parsed_date') >= start_dt) &
                (pl.col('parsed_date') <= end_dt)
            )
            
            return filtered.drop(['parsed_date_obj', 'parsed_date'])
            
        except Exception as e:
            logger.warning(f"Failed to filter chunk by date: {e}")
            return chunk.filter(pl.lit(False))  # Empty result
    
    def _update_month_stats(self, stats: Dict[str, Any], chunk: pl.DataFrame) -> None:
        """
        Update monthly statistics with chunk data.
        
        Args:
            stats: Statistics dictionary to update
            chunk: Data chunk
        """
        try:
            stats['total_events'] += len(chunk)
            
            # Source and destination IPs (exclude "Multiple" and "0.0.0.0")
            if 'Source IP Address' in chunk.columns:
                source_ips = chunk['Source IP Address'].to_list()
                stats['unique_source_ips'].update([
                    str(ip).strip() for ip in source_ips 
                    if ip and str(ip) != 'nan' 
                    and str(ip).strip().lower() != 'multiple' 
                    and str(ip).strip() != '0.0.0.0'
                ])
            
            if 'Destination IP Address' in chunk.columns:
                dest_ips = chunk['Destination IP Address'].to_list()
                stats['unique_dest_ips'].update([
                    str(ip).strip() for ip in dest_ips 
                    if ip and str(ip) != 'nan' 
                    and str(ip).strip().lower() != 'multiple' 
                    and str(ip).strip() != '0.0.0.0'
                ])
            
            # Attack types with threat categories
            if 'Attack Name' in chunk.columns and 'Threat Category' in chunk.columns:
                attack_names = chunk['Attack Name'].to_list()
                threat_categories = chunk['Threat Category'].to_list()
                for attack, threat_cat in zip(attack_names, threat_categories):
                    if attack and str(attack) != 'nan' and threat_cat and str(threat_cat) != 'nan':
                        # Store both threat category and attack name
                        stats['attack_types'][attack] = {
                            'count': stats['attack_types'].get(attack, {}).get('count', 0) + 1,
                            'threat_category': str(threat_cat)
                        }
            elif 'Attack Name' in chunk.columns:
                # Fallback to just attack names if threat category is not available
                for attack in chunk['Attack Name'].to_list():
                    if attack and str(attack) != 'nan':
                        stats['attack_types'][attack] = {
                            'count': stats['attack_types'].get(attack, {}).get('count', 0) + 1,
                            'threat_category': 'N/A'
                        }
            
            # Protocols
            if 'Protocol' in chunk.columns:
                for protocol in chunk['Protocol'].to_list():
                    if protocol and str(protocol) != 'nan':
                        stats['protocols'][protocol] = stats['protocols'].get(protocol, 0) + 1
            
            # Actions
            if 'Action' in chunk.columns:
                for action in chunk['Action'].to_list():
                    if action and str(action) != 'nan':
                        stats['actions'][action] = stats['actions'].get(action, 0) + 1
            
            # Numeric statistics - use mapped column names
            # Get the actual column names from our mapping
            column_mapping = self._create_column_mapping(chunk.columns)
            
            numeric_columns = {
                column_mapping.get('Total Packets'): 'total_packets',
                column_mapping.get('Total Mbits'): 'total_mbits',
                column_mapping.get('Max pps'): 'max_pps',
                column_mapping.get('Max bps'): 'max_bps'
            }
            
            for col_name, stat_key in numeric_columns.items():
                if col_name and col_name in chunk.columns:
                    values = chunk[col_name].to_list()
                    numeric_values = [float(v) for v in values if v and str(v) != 'nan' and str(v).replace('.', '').isdigit()]
                    
                    if numeric_values:
                        if stat_key.startswith('total_'):
                            stats[stat_key] += sum(numeric_values)
                        elif stat_key.startswith('max_'):
                            current_max = max(numeric_values)
                            if current_max > stats[stat_key]:
                                stats[stat_key] = current_max
                                # Store the row details for max PPS and max BPS
                                try:
                                    # Find the index in the original values list (not numeric_values)
                                    max_index = None
                                    for i, val in enumerate(values):
                                        if val and str(val) != 'nan' and float(val) == current_max:
                                            max_index = i
                                            break
                                    
                                    if max_index is not None:
                                        if stat_key == 'max_pps':
                                            stats['max_pps_details'] = self._extract_attack_details_from_row(chunk, max_index)
                                        elif stat_key == 'max_bps':
                                            stats['max_bps_details'] = self._extract_attack_details_from_row(chunk, max_index)
                                except Exception as e:
                                    logger.warning(f"Failed to update max stats details: {e}")
                                    continue
            
            # Hourly distribution
            if 'Start Time' in chunk.columns:
                for date_str in chunk['Start Time'].to_list():
                    parsed_date = parse_date_flexible(date_str, self.date_format)
                    if parsed_date:
                        hour = parsed_date.hour
                        stats['hourly_distribution'][hour] += 1
            
            # Device statistics
            if 'Device Name' in chunk.columns:
                for device in chunk['Device Name'].to_list():
                    if device and str(device) != 'nan':
                        stats['devices'][device] = stats['devices'].get(device, 0) + 1
            
            # Policy statistics
            if 'Policy Name' in chunk.columns:
                for policy in chunk['Policy Name'].to_list():
                    if policy and str(policy) != 'nan':
                        stats['policies'][policy] = stats['policies'].get(policy, 0) + 1
        
        except Exception as e:
            logger.warning(f"Failed to update month stats: {e}")
    
    def process_holistic_analysis(self) -> Dict[str, Any]:
        """
        Process data for holistic analysis of the entire dataset.
        
        Returns:
            Dictionary with holistic analysis data
        """
        logger.info("Processing holistic analysis for entire dataset")
        
        holistic_stats = {
            'total_events': 0,
            'unique_source_ips': set(),
            'unique_dest_ips': set(),
            'attack_types': {},
            'protocols': {},
            'actions': {},
            'risk_levels': {},
            'devices': {},
            'policies': {},
            'hourly_distribution': [0] * 24,
            'daily_distribution': {},
            'total_packets': 0,
            'total_mbits': 0,
            'max_pps': 0,
            'max_bps': 0,
            'max_pps_details': None,
            'max_bps_details': None,
            'duration_stats': [],
            'longest_attack_details': None,  # Will store full details of the longest attack
            'top_source_ips': {},
            'top_dest_ips': {},
            'top_attacks_by_bps': [],  # List of (attack_name, bps, details) tuples for individual attacks
            'top_attacks_by_pps': [],  # List of (attack_name, pps, details) tuples for individual attacks
            'date_range': {
                'start': self.data_start_date,
                'end': self.data_end_date,
                'days': (self.data_end_date - self.data_start_date).days + 1 if self.data_start_date and self.data_end_date else 0
            }
        }
        
        try:
            processed_rows = 0
            
            # Get schema overrides for problematic columns
            schema_overrides = self._get_schema_overrides()
            
            with tqdm(desc="Processing holistic analysis", unit="rows") as pbar:
                
                # Process file in chunks with proper header handling
                chunk_size = self.chunk_size
                
                # First, read just the header to get column names
                header_df = pl.read_csv(
                    self.file_path,
                    n_rows=0,  # Just header
                    schema_overrides=schema_overrides,
                    ignore_errors=True,
                    infer_schema_length=10000
                )
                
                if 'Start Time' not in header_df.columns:
                    logger.error("Start Time column not found in file")
                    return holistic_stats
                
                column_names = header_df.columns
                current_skip = 1  # Skip header for all chunks
                
                while True:
                    try:
                        # Read chunk without header (skip_rows includes header)
                        chunk = pl.read_csv(
                            self.file_path,
                            skip_rows=current_skip,
                            n_rows=chunk_size,
                            schema_overrides=schema_overrides,
                            ignore_errors=True,
                            infer_schema_length=10000
                        )
                        
                        if len(chunk) == 0:
                            break
                        
                        # Manually rename columns to match header if needed
                        if list(chunk.columns) != column_names:
                            chunk = chunk.rename({old: new for old, new in zip(chunk.columns, column_names)})
                        
                        # Store original chunk size before filtering
                        original_chunk_size = len(chunk)
                        
                        # Filter out excluded data
                        chunk = self._apply_data_filters(chunk)
                        
                        self._update_holistic_stats(holistic_stats, chunk)
                        processed_rows += len(chunk)
                        pbar.update(len(chunk))
                        
                        # Update skip position for next chunk (use original size, not filtered size)
                        current_skip += original_chunk_size
                        
                        # Break if we got less than expected (end of file)
                        if original_chunk_size < chunk_size:
                            break
                            
                    except Exception as e:
                        logger.error(f"Error reading chunk at row {current_skip}: {e}")
                        break
            
            # Post-process statistics - store detailed lists before converting to counts
            holistic_stats['unique_source_ips_list'] = sorted(list(holistic_stats['unique_source_ips']))
            holistic_stats['unique_dest_ips_list'] = sorted(list(holistic_stats['unique_dest_ips']))
            
            # Create attack types list with threat category details
            attack_types_details = []
            for attack_name, attack_info in sorted(holistic_stats['attack_types'].items()):
                if isinstance(attack_info, dict):
                    threat_category = attack_info.get('threat_category', 'N/A')
                else:
                    # Handle old format (just count)
                    threat_category = 'N/A'
                attack_types_details.append((threat_category, attack_name))
            
            holistic_stats['attack_types_list'] = sorted(list(holistic_stats['attack_types'].keys()))
            holistic_stats['attack_types_details'] = attack_types_details
            holistic_stats['unique_source_ips'] = len(holistic_stats['unique_source_ips'])
            holistic_stats['unique_dest_ips'] = len(holistic_stats['unique_dest_ips'])
            
            # Get top source/dest IPs
            holistic_stats['top_source_ips'] = dict(
                sorted(holistic_stats['top_source_ips'].items(), key=lambda x: x[1], reverse=True)[:20]
            )
            holistic_stats['top_dest_ips'] = dict(
                sorted(holistic_stats['top_dest_ips'].items(), key=lambda x: x[1], reverse=True)[:20]
            )
            
            # Sort and keep only top N attacks by BPS and PPS
            holistic_stats['top_attacks_by_bps'] = sorted(
                holistic_stats['top_attacks_by_bps'], 
                key=lambda x: x[1], 
                reverse=True
            )[:100]  # Keep top 100 for flexibility
            
            holistic_stats['top_attacks_by_pps'] = sorted(
                holistic_stats['top_attacks_by_pps'], 
                key=lambda x: x[1], 
                reverse=True
            )[:100]  # Keep top 100 for flexibility
            
            # Format longest attack duration
            if holistic_stats['longest_attack_details']:
                max_duration_seconds = holistic_stats['longest_attack_details']['duration']
                # Convert seconds to days, hours, minutes, and seconds
                days = int(max_duration_seconds // 86400)
                hours = int((max_duration_seconds % 86400) // 3600)
                minutes = int((max_duration_seconds % 3600) // 60)
                seconds = int(max_duration_seconds % 60)
                holistic_stats['longest_attack_duration'] = f"{days}d:{hours:02d}h:{minutes:02d}m:{seconds:02d}s"
            else:
                holistic_stats['longest_attack_duration'] = "00h:00m:00s"
                holistic_stats['longest_attack_details'] = None

            logger.info(f"Holistic analysis complete: {processed_rows:,} total events processed")
            return holistic_stats
            
        except Exception as e:
            logger.error(f"Failed to process holistic analysis: {e}")
            raise
    
    def _update_holistic_stats(self, stats: Dict[str, Any], chunk: pl.DataFrame) -> None:
        """
        Update holistic statistics with chunk data.
        
        Args:
            stats: Statistics dictionary to update
            chunk: Data chunk
        """
        # Reuse the monthly stats update logic
        self._update_month_stats(stats, chunk)
        
        # Additional holistic-specific processing
        try:
            # Daily distribution
            if 'Start Time' in chunk.columns:
                for date_str in chunk['Start Time'].to_list():
                    parsed_date = parse_date_flexible(date_str, self.date_format)
                    if parsed_date:
                        day_key = parsed_date.strftime('%Y-%m-%d')
                        stats['daily_distribution'][day_key] = stats['daily_distribution'].get(day_key, 0) + 1
            
            # Risk levels
            if 'Risk' in chunk.columns:
                for risk in chunk['Risk'].to_list():
                    if risk and str(risk) != 'nan':
                        stats['risk_levels'][risk] = stats['risk_levels'].get(risk, 0) + 1
            
            # Duration statistics - capture longest attack details
            if 'Duration' in chunk.columns:
                for i, duration_str in enumerate(chunk['Duration'].to_list()):
                    if duration_str and str(duration_str) != 'nan' and str(duration_str).replace('.', '').isdigit():
                        duration = float(duration_str)
                        stats['duration_stats'].append(duration)
                        
                        # Check if this is the longest attack and capture full details
                        current_longest = 0
                        if stats['longest_attack_details']:
                            current_longest = stats['longest_attack_details'].get('duration', 0)
                        
                        if duration > current_longest:
                            # Capture full row details for the longest attack
                            row_dict = {}
                            for col in chunk.columns:
                                try:
                                    row_dict[col] = chunk[col].to_list()[i]
                                except (IndexError, KeyError):
                                    row_dict[col] = 'N/A'
                            
                            stats['longest_attack_details'] = {
                                'duration': duration,
                                'details': row_dict
                            }
            
            # Count source/dest IPs for top lists
            # Exclude "Multiple" and "0.0.0.0" from source IPs
            if 'Source IP Address' in chunk.columns:
                for ip in chunk['Source IP Address'].to_list():
                    if ip and str(ip) != 'nan':
                        ip_str = str(ip).strip()
                        # Exclude "Multiple" and "0.0.0.0"
                        if ip_str.lower() != 'multiple' and ip_str != '0.0.0.0':
                            stats['top_source_ips'][ip_str] = stats['top_source_ips'].get(ip_str, 0) + 1
            
            # Exclude "Multiple" and "0.0.0.0" from destination IPs
            if 'Destination IP Address' in chunk.columns:
                for ip in chunk['Destination IP Address'].to_list():
                    if ip and str(ip) != 'nan':
                        ip_str = str(ip).strip()
                        # Exclude "Multiple" and "0.0.0.0"
                        if ip_str.lower() != 'multiple' and ip_str != '0.0.0.0':
                            stats['top_dest_ips'][ip_str] = stats['top_dest_ips'].get(ip_str, 0) + 1
            
            # Track top individual attacks by BPS and PPS
            if 'Attack Name' in chunk.columns:
                column_mapping = self._create_column_mapping(chunk.columns)
                
                # Process individual attacks by Max BPS
                max_bps_col = column_mapping.get('Max bps')
                if max_bps_col and max_bps_col in chunk.columns:
                    for i in range(len(chunk)):
                        row = chunk[i]
                        attack_name = row['Attack Name'][0] if 'Attack Name' in chunk.columns else None
                        bps_val = row[max_bps_col][0] if max_bps_col in chunk.columns else None
                        
                        if attack_name and str(attack_name) != 'nan' and bps_val and str(bps_val) != 'nan':
                            try:
                                bps_float = float(bps_val)
                                # Extract minimal details for this attack
                                details = {
                                    'attack_name': attack_name,
                                    'bps': bps_float,
                                    'start_time': row['Start Time'][0] if 'Start Time' in chunk.columns else None,
                                    'source_ip': row['Source IP Address'][0] if 'Source IP Address' in chunk.columns else None,
                                    'dest_ip': row['Destination IP Address'][0] if 'Destination IP Address' in chunk.columns else None,
                                }
                                stats['top_attacks_by_bps'].append((attack_name, bps_float, details))
                            except (ValueError, TypeError, IndexError):
                                continue
                
                # Process individual attacks by Max PPS
                max_pps_col = column_mapping.get('Max pps')
                if max_pps_col and max_pps_col in chunk.columns:
                    for i in range(len(chunk)):
                        row = chunk[i]
                        attack_name = row['Attack Name'][0] if 'Attack Name' in chunk.columns else None
                        pps_val = row[max_pps_col][0] if max_pps_col in chunk.columns else None
                        
                        if attack_name and str(attack_name) != 'nan' and pps_val and str(pps_val) != 'nan':
                            try:
                                pps_float = float(pps_val)
                                # Extract minimal details for this attack
                                details = {
                                    'attack_name': attack_name,
                                    'pps': pps_float,
                                    'start_time': row['Start Time'][0] if 'Start Time' in chunk.columns else None,
                                    'source_ip': row['Source IP Address'][0] if 'Source IP Address' in chunk.columns else None,
                                    'dest_ip': row['Destination IP Address'][0] if 'Destination IP Address' in chunk.columns else None,
                                }
                                stats['top_attacks_by_pps'].append((attack_name, pps_float, details))
                            except (ValueError, TypeError, IndexError):
                                continue
        
        except Exception as e:
            logger.warning(f"Failed to update holistic stats: {e}")
    
    def _get_excluded_months_note(self) -> str:
        """
        Generate note about excluded incomplete months.
        
        Returns:
            Note string about excluded months
        """
        if not self.data_start_date or not self.data_end_date:
            return ""
        
        excluded_months = []
        
        # Check if first month is incomplete
        if self.data_start_date.day != 1:
            excluded_months.append(self.data_start_date.strftime('%B %Y'))
        
        # Check if last month is incomplete
        last_day_of_month = (self.data_end_date.replace(day=1) + timedelta(days=32)).replace(day=1) - timedelta(days=1)
        if self.data_end_date.day != last_day_of_month.day:
            excluded_months.append(self.data_end_date.strftime('%B %Y'))
        
        if excluded_months:
            return f"Trend analysis excludes incomplete months: {', '.join(excluded_months)}"
        
        return ""
    
    def _extract_attack_details_from_row(self, chunk: pl.DataFrame, row_index: int) -> Dict[str, Any]:
        """
        Extract attack details from a specific row in the chunk.
        
        Args:
            chunk: DataFrame chunk
            row_index: Index of the row to extract details from
            
        Returns:
            Dictionary containing attack details
        """
        try:
            row_dict = {}
            for col in chunk.columns:
                try:
                    row_dict[col] = chunk[col].to_list()[row_index]
                except (IndexError, KeyError):
                    row_dict[col] = 'N/A'
            
            return {'details': row_dict}
        except Exception as e:
            logger.warning(f"Failed to extract attack details from row {row_index}: {e}")
            return {'details': {}}

    def get_processing_summary(self) -> Dict[str, Any]:
        """
        Get summary of data processing results.
        
        Returns:
            Processing summary dictionary
        """
        memory_stats = check_memory_usage()
        
        return {
            'file_info': {
                'name': self.file_path.name,
                'size': format_file_size(self.file_path.stat().st_size),
                'encoding': self.encoding
            },
            'data_info': {
                'total_rows': format_number(self.total_rows),
                'date_range': {
                    'start': self.data_start_date.strftime('%Y-%m-%d') if self.data_start_date else 'Unknown',
                    'end': self.data_end_date.strftime('%Y-%m-%d') if self.data_end_date else 'Unknown',
                    'days': (self.data_end_date - self.data_start_date).days + 1 if self.data_start_date and self.data_end_date else 0
                },
                'complete_months': len(self.complete_months),
                'date_format': self.date_format or 'Auto-detected'
            },
            'processing_info': {
                'chunk_size': format_number(self.chunk_size),
                'memory_usage_mb': f"{memory_stats['process_mb']:.1f}",
                'memory_warning': memory_stats['warning']
            }
        }