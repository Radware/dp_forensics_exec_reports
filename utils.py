"""
Utility functions for the Forensics Data Analysis & Report Generator

This module provides helper functions for date parsing, validation, 
file handling, and other common operations.
"""

import logging
import re
import zipfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional, Tuple, Union, Dict, Any
import chardet
import psutil
from dateutil import parser as date_parser

from config import DATE_FORMATS, MAX_MEMORY_USAGE_GB

logger = logging.getLogger(__name__)


def setup_logging(verbose: bool = False) -> None:
    """
    Set up logging configuration.
    
    Args:
        verbose: Enable debug level logging
    """
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


def detect_file_encoding(file_path: Path) -> str:
    """
    Detect the encoding of a text file.
    
    Args:
        file_path: Path to the file
        
    Returns:
        Detected encoding string
    """
    try:
        with open(file_path, 'rb') as f:
            # Read first 100KB for encoding detection
            raw_data = f.read(100000)
        
        result = chardet.detect(raw_data)
        encoding = result.get('encoding', 'utf-8')
        
        # Fallback to common encodings if detection fails
        if not encoding or result.get('confidence', 0) < 0.7:
            # Try common encodings
            for test_encoding in ['utf-8', 'utf-8-sig', 'latin1', 'cp1252']:
                try:
                    raw_data.decode(test_encoding)
                    encoding = test_encoding
                    break
                except UnicodeDecodeError:
                    continue
            else:
                encoding = 'utf-8'  # Final fallback
        
        file_name = file_path.name if hasattr(file_path, 'name') else str(file_path)
        logger.debug(f"Detected encoding for {file_name}: {encoding}")
        return encoding
        
    except Exception as e:
        file_name = file_path.name if hasattr(file_path, 'name') else str(file_path)
        logger.warning(f"Failed to detect encoding for {file_name}: {e}")
        return 'utf-8'


def parse_date_flexible(date_str: str, detected_format: Optional[str] = None) -> Optional[datetime]:
    """
    Parse date string using multiple format attempts.
    
    Args:
        date_str: Date string to parse
        detected_format: Specific format detected by format detection (tried first)
        
    Returns:
        Parsed datetime object or None if parsing fails
    """
    if not date_str or pd.isna(date_str):
        return None
    
    # Clean the date string
    date_str = str(date_str).strip()
    
    # Try detected format first if provided
    if detected_format:
        try:
            return datetime.strptime(date_str, detected_format)
        except ValueError:
            pass
    
    # Try predefined formats
    for fmt in DATE_FORMATS:
        # Skip detected format if we already tried it
        if fmt == detected_format:
            continue
            
        try:
            return datetime.strptime(date_str, fmt)
        except ValueError:
            continue
    
    # Try dateutil parser as fallback (more flexible but slower)
    try:
        return date_parser.parse(date_str)
    except (ValueError, TypeError):
        pass
    
    logger.warning(f"Failed to parse date: {date_str}")
    return None


def detect_date_format(sample_dates: List[str]) -> Optional[str]:
    """
    Detect the most likely date format using efficient stratified sampling.
    
    Strategy:
    1. Use stratified sampling across dataset for better coverage
    2. Look for unambiguous evidence (day > 12) to resolve DD/MM vs MM/DD
    3. If found, return immediately for speed
    4. Fall back to parsing success rate on small sample
    
    Args:
        sample_dates: List of sample date strings
        
    Returns:
        Most likely format string or None
    """
    from datetime import datetime
    from config import FORCE_DATE_FORMAT
    
    # Check for forced format override
    if FORCE_DATE_FORMAT:
        logger.info(f"Using forced date format from config: {FORCE_DATE_FORMAT}")
        test_count = 0
        success_count = 0
        for date_str in sample_dates[:10]:
            if date_str and str(date_str).strip():
                test_count += 1
                try:
                    datetime.strptime(str(date_str).strip(), FORCE_DATE_FORMAT)
                    success_count += 1
                except ValueError:
                    pass
        
        if test_count > 0 and success_count / test_count > 0.5:
            logger.info(f"Forced format validation: {success_count}/{test_count} samples parsed successfully")
            return FORCE_DATE_FORMAT
        else:
            logger.warning(f"Forced format failed validation ({success_count}/{test_count} success), falling back to auto-detection")
    
    # Clean and validate sample dates  
    all_valid_samples = []
    for date_str in sample_dates:
        if date_str and isinstance(date_str, str):
            cleaned = str(date_str).strip()
            if len(cleaned) > 8:  # Minimum reasonable date length (MM/DD/YY)
                all_valid_samples.append(cleaned)
                
    if not all_valid_samples:
        logger.warning("No valid date samples found after cleaning")
        return None

    total_samples = len(all_valid_samples)
    logger.info(f"Starting intelligent date format detection with {total_samples} total samples")

    # Smart sampling strategy based on dataset size
    if total_samples <= 500:
        # Small dataset: use all samples
        working_samples = all_valid_samples
        logger.debug(f"Small dataset: using all {len(working_samples)} samples")
    else:
        # Large dataset: progressive random sampling
        import random
        # Start with diverse random sample, expand if needed
        initial_size = min(300, total_samples // 3)
        working_samples = random.sample(all_valid_samples, initial_size)
        logger.debug(f"Large dataset: starting with {len(working_samples)} random samples")

    # Progressive detection with up to 3 iterations
    max_samples = min(1000, total_samples)  # Cap for performance

    for iteration in range(3):
        logger.debug(f"Detection iteration {iteration + 1} with {len(working_samples)} samples")

        # Check for unambiguous evidence in current sample
        unambiguous_evidence = _find_unambiguous_evidence(working_samples)

        if unambiguous_evidence:
            best_format = max(unambiguous_evidence.items(), key=lambda x: x[1])
            logger.info(f"Unambiguous evidence found: {best_format[0]} ({best_format[1]} clear samples)")
            return best_format[0]

        # If no unambiguous evidence and we can expand the sample, do so
        if total_samples > 500 and len(working_samples) < max_samples and iteration < 2:
            additional_size = min(300, max_samples - len(working_samples))
            remaining_samples = [s for s in all_valid_samples if s not in working_samples]

            if remaining_samples and additional_size > 0:
                import random
                new_samples = random.sample(remaining_samples, min(additional_size, len(remaining_samples)))
                working_samples.extend(new_samples)
                logger.debug(f"Expanded sample to {len(working_samples)} for better evidence")
                continue  # Try again with larger sample

        # No more expansion possible or small dataset - proceed to parsing test
        break

    logger.debug(f"No unambiguous evidence found in {len(working_samples)} samples (all dates had day/month ≤ 12)")

    # Use working samples for format detection (limit for parsing test performance)
    valid_samples = working_samples[:200]
    logger.debug(f"Using {len(valid_samples)} samples for parsing validation")
    
    return _detect_format_from_samples(valid_samples)


def _find_unambiguous_evidence(samples):
    """Find unambiguous evidence for date format in sample data."""
    unambiguous_evidence = {}
    
    for date_str in samples:
        try:
            date_part = date_str.split()[0]
            if '.' in date_part:
                parts = [int(x) for x in date_part.split('.')]
                if len(parts) >= 2:
                    first, second = parts[0], parts[1]
                    # Only count unambiguous cases where one part is definitely > 12
                    if first > 12 and second <= 12:  # Must be DD.MM format
                        unambiguous_evidence['%d.%m.%Y %H:%M:%S'] = unambiguous_evidence.get('%d.%m.%Y %H:%M:%S', 0) + 1
                    elif second > 12 and first <= 12:  # Must be MM.DD format
                        unambiguous_evidence['%m.%d.%Y %H:%M:%S'] = unambiguous_evidence.get('%m.%d.%Y %H:%M:%S', 0) + 1
        except (ValueError, IndexError):
            continue
            
    return unambiguous_evidence


def _detect_format_from_samples(valid_samples):
    """Detect format from samples using parsing success rate and chronological validation."""
    from datetime import datetime, timedelta
    
    # Phase 1: Check for any remaining unambiguous evidence in our samples
    unambiguous_evidence = _find_unambiguous_evidence(valid_samples)
    
    if unambiguous_evidence:
        best_format = max(unambiguous_evidence.items(), key=lambda x: x[1])
        logger.info(f"Unambiguous evidence found in parsing phase: {best_format[0]} ({best_format[1]} samples)")
        return best_format[0]
    
    # If no unambiguous evidence, proceed with parsing test
    logger.debug(f"No unambiguous evidence found in {len(valid_samples)} parsing samples")
    
    # Phase 2: Enhanced parsing test with chronological validation
    logger.debug("No unambiguous evidence found, testing formats with chronological validation")
    
    # Test with larger sample for better reliability
    test_samples = valid_samples[:100] if len(valid_samples) > 100 else valid_samples
    
    format_scores = {}
    for fmt in DATE_FORMATS:
        successes = 0
        parsed_dates = []
        
        for date_str in test_samples:
            try:
                parsed_date = datetime.strptime(date_str, fmt)
                successes += 1
                parsed_dates.append(parsed_date)
            except ValueError:
                pass
                
        success_rate = successes / len(test_samples)
        
        # Additional validation: check if dates are chronologically reasonable
        chronology_score = 1.0  # Default to perfect score
        if len(parsed_dates) >= 2:
            # Check if dates are in reasonable chronological order (allow some variance)
            sorted_dates = sorted(parsed_dates)
            original_vs_sorted = sum(1 for i, d in enumerate(parsed_dates) if i < len(sorted_dates) and abs((d - sorted_dates[i]).days) <= 30) / len(parsed_dates)
            chronology_score = original_vs_sorted
        
        # Check for future dates (likely indicates wrong format)
        current_date = datetime.now()
        future_dates = sum(1 for d in parsed_dates if d > current_date + timedelta(days=30))
        future_penalty = future_dates / len(parsed_dates) if parsed_dates else 0
        
        # Combined score: success rate * chronology * (1 - future_penalty)
        combined_score = success_rate * chronology_score * (1 - future_penalty * 0.5)
        
        format_scores[fmt] = {
            'success_rate': success_rate,
            'chronology_score': chronology_score,
            'future_penalty': future_penalty,
            'combined_score': combined_score,
            'successes': successes
        }
        
        logger.debug(f"Format {fmt}: {successes}/{len(test_samples)} ({success_rate:.1%}), chronology: {chronology_score:.1%}, future_penalty: {future_penalty:.1%}, combined: {combined_score:.1%}")
    
    # Select best format based on combined score
    if format_scores:
        best_format = max(format_scores.items(), key=lambda x: x[1]['combined_score'])
        best_fmt, best_stats = best_format
        
        if best_stats['combined_score'] > 0.7:  # 70% combined threshold
            logger.info(f"Selected format: {best_fmt} (success rate: {best_stats['success_rate']:.1%}, combined score: {best_stats['combined_score']:.1%})")
            return best_fmt
    
    # Fallback to config preference
    logger.warning("Could not reliably detect format, using config default")
    return DATE_FORMATS[0] if DATE_FORMATS else None





def get_complete_months(start_date: datetime, end_date: datetime, 
                       file_path: str = None, date_format: str = None) -> List[Tuple[datetime, datetime]]:
    """
    Get list of complete calendar months within the date range, with optional validation.
    
    Phase 1: Identify calendar-complete months (full months like Jan 1-31, Feb 1-28, etc.)
    Phase 2: validate months contain attacks that start and end within the same month
    
    Args:
        start_date: Start of data range
        end_date: End of data range
        file_path: Optional path to CSV file for attack validation
        date_format: Optional date format for parsing (required if file_path provided)
        
    Returns:
        List of (month_start, month_end) tuples for complete months
    """
    # Phase 1: Calendar-based complete months identification
    complete_months = []
    
    # Find first complete month
    if start_date.day == 1:
        current_month = start_date
    else:
        # Move to next month if we don't start on the 1st
        if start_date.month == 12:
            current_month = datetime(start_date.year + 1, 1, 1)
        else:
            current_month = datetime(start_date.year, start_date.month + 1, 1)
    
    while current_month <= end_date:
        # Calculate month end - set to end of the last day of the month
        if current_month.month == 12:
            month_end = datetime(current_month.year + 1, 1, 1) - timedelta(seconds=1)
        else:
            month_end = datetime(current_month.year, current_month.month + 1, 1) - timedelta(seconds=1)
        
        # Check if this is a complete month within our data range
        if month_end <= end_date:
            complete_months.append((current_month, month_end))
            
            # Move to next month
            if current_month.month == 12:
                current_month = datetime(current_month.year + 1, 1, 1)
            else:
                current_month = datetime(current_month.year, current_month.month + 1, 1)
        else:
            break
    
    logger.info(f"Phase 1: Found {len(complete_months)} calendar-complete months between {start_date.date()} and {end_date.date()}")
    
    # Phase 2: Validate months contain fully-contained attacks (if file path provided)
    if file_path and date_format and complete_months:
        validated_months = validate_complete_months(complete_months, file_path, date_format)
        return validated_months
    else:
        logger.debug("Skipping Phase 2 validation (no file path or date format provided)")
        return complete_months


def validate_complete_months(candidate_months: List[Tuple[datetime, datetime]], 
                           file_path: str, 
                           date_format: str) -> List[Tuple[datetime, datetime]]:
    """
    Validate that candidate months contain at least one attack started and ended in the same month.
    
    Once we find the first month with attack started and ended in the same month, all subsequent months
    are assumed to be valid from phase 1 (no need to check them individually).
    
    Args:
        candidate_months: List of (month_start, month_end) tuples from calendar analysis
        file_path: Path to the CSV file containing attack data
        date_format: Date format string for parsing attack timestamps
        
    Returns:
        Filtered list of months that contain fully-contained attacks
    """
    import polars as pl
    
    if not candidate_months:
        logger.info("No candidate months to validate")
        return []
    
    logger.info(f"Phase 2: Further validating {len(candidate_months)} candidate complete months")
    
    try:
        # Schema overrides for robust CSV reading
        schema_overrides = {
            'Physical Port': pl.Utf8,
            'Source Port': pl.Utf8, 
            'Destination Port': pl.Utf8,
            'VLAN Tag': pl.Utf8,
            'Risk': pl.Utf8,
            'Packet Type': pl.Utf8,
            'Protocol': pl.Utf8,
            'Direction': pl.Utf8,
            'Action': pl.Utf8,
            'Device Type': pl.Utf8,
            'Workflow Rule Process': pl.Utf8,
            'Activation Id': pl.Utf8,
            'Attack ID': pl.Utf8,
            'Radware ID': pl.Utf8,
        }
        
        # Start with all candidate months as potentially valid
        validated_months = list(candidate_months)
        excluded_months = []
        first_valid_month_found = False
        
        for i, (month_start, month_end) in enumerate(candidate_months):
            month_name = month_start.strftime('%Y-%m (%B)')
            
            # If we already found a valid month, all subsequent months are automatically valid(from phase 1)
            if first_valid_month_found:
                logger.debug(f"  ✅ {month_name}: Auto-validated (after first valid month)")
                continue
            
            logger.debug(f"Validating month: {month_name}")
            
            # Read only start/end time columns with lazy loading
            df_month = pl.scan_csv(
                file_path,
                schema_overrides=schema_overrides,
                ignore_errors=True
            ).select(['Start Time', 'End Time'])
            
            # Parse dates and filter for this specific month in one efficient operation
            month_attacks = df_month.with_columns([
                pl.col('Start Time').str.strptime(pl.Datetime, date_format, strict=False).alias('start_parsed'),
                pl.col('End Time').str.strptime(pl.Datetime, date_format, strict=False).alias('end_parsed')
            ]).filter(
                # Only include records where parsing succeeded AND overlaps with this month
                pl.col('start_parsed').is_not_null() & 
                pl.col('end_parsed').is_not_null() &
                (
                    # Attack overlaps with month (starts before/during month AND ends during/after month)
                    (pl.col('start_parsed') <= month_end) &
                    (pl.col('end_parsed') >= month_start)
                )
            ).collect()
            
            if month_attacks.height == 0:
                logger.debug(f"  ❌ {month_name}: No attacks found in month - EXCLUDED")
                excluded_months.append((month_start, month_end))
                continue
            
            # Check for fully-contained attacks (start AND end within month)
            fully_contained = month_attacks.filter(
                (pl.col('start_parsed') >= month_start) &
                (pl.col('end_parsed') <= month_end)
            )
            
            contained_count = fully_contained.height
            total_count = month_attacks.height
            
            if contained_count > 0:
                logger.debug(f"  ✅ {month_name}: {contained_count}/{total_count} fully-contained attacks - FIRST VALID MONTH")
                first_valid_month_found = True
                # From this point on, all subsequent months are automatically valid
                remaining_months = len(candidate_months) - i - 1
                if remaining_months > 0:
                    logger.info(f"First fully-contained month found. Auto-validating {remaining_months} subsequent months.")
                break
            else:
                logger.debug(f"  ❌ {month_name}: 0/{total_count} fully-contained attacks (all spillover) - EXCLUDED")
                excluded_months.append((month_start, month_end))
        
        # Remove excluded months from validated list
        for excluded_month in excluded_months:
            if excluded_month in validated_months:
                validated_months.remove(excluded_month)
        
        excluded_count = len(excluded_months)
        logger.info(f"Month validation complete: {len(validated_months)} valid months, {excluded_count} excluded")
        
        if excluded_count > 0:
            excluded_month_names = [month_start.strftime('%Y-%m') for month_start, month_end in excluded_months]
            logger.info(f"Excluded months (no fully-contained attacks): {', '.join(excluded_month_names)}")
        
        return validated_months
        
    except Exception as e:
        logger.error(f"Error during month validation: {e}")
        logger.warning("Falling back to calendar-only validation")
        return candidate_months


def format_file_size(size_bytes: int) -> str:
    """
    Format file size in human readable format.
    
    Args:
        size_bytes: Size in bytes
        
    Returns:
        Formatted size string
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} PB"


def format_duration(seconds: float) -> str:
    """
    Format duration in human readable format.
    
    Args:
        seconds: Duration in seconds
        
    Returns:
        Formatted duration string
    """
    if seconds < 60:
        return f"{seconds:.1f} seconds"
    elif seconds < 3600:
        return f"{seconds/60:.1f} minutes"
    else:
        return f"{seconds/3600:.1f} hours"


def format_number(number: Union[int, float]) -> str:
    """
    Format number with thousands separators.
    
    Args:
        number: Number to format
        
    Returns:
        Formatted number string
    """
    if isinstance(number, float):
        if number >= 1000000:
            return f"{number/1000000:.1f}M"
        elif number >= 1000:
            return f"{number/1000:.1f}K"
        else:
            return f"{number:.1f}"
    else:
        return f"{number:,}"


def check_memory_usage() -> Dict[str, Any]:
    """
    Check current memory usage.
    
    Returns:
        Dictionary with memory statistics
    """
    process = psutil.Process()
    memory_info = process.memory_info()
    system_memory = psutil.virtual_memory()
    
    memory_stats = {
        'process_mb': memory_info.rss / (1024 * 1024),
        'system_used_percent': system_memory.percent,
        'system_available_gb': system_memory.available / (1024 * 1024 * 1024),
        'warning': memory_info.rss / (1024 * 1024 * 1024) > MAX_MEMORY_USAGE_GB
    }
    
    if memory_stats['warning']:
        logger.warning(f"High memory usage: {memory_stats['process_mb']:.1f} MB")
    
    return memory_stats


def extract_zip_files(zip_path: Path, extract_to: Path) -> List[Path]:
    """
    Extract CSV files from ZIP archive.
    
    Args:
        zip_path: Path to ZIP file
        extract_to: Directory to extract to
        
    Returns:
        List of extracted CSV file paths
    """
    extracted_files = []
    
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            # Get list of CSV files in the archive
            csv_files = [f for f in zip_ref.namelist() if f.lower().endswith('.csv')]
            
            if not csv_files:
                logger.warning(f"No CSV files found in {zip_path}")
                return []
            
            logger.info(f"Found {len(csv_files)} CSV files in {zip_path}")
            
            # Extract CSV files
            for csv_file in csv_files:
                extracted_path = extract_to / Path(csv_file).name
                
                # Extract the file
                with zip_ref.open(csv_file) as source, open(extracted_path, 'wb') as target:
                    target.write(source.read())
                
                extracted_files.append(extracted_path)
                logger.debug(f"Extracted: {csv_file} -> {extracted_path}")
    
    except Exception as e:
        logger.error(f"Failed to extract ZIP file {zip_path}: {e}")
        return []
    
    return extracted_files


def validate_csv_structure(file_path: Path, required_columns: List[str]) -> Tuple[bool, List[str]]:
    """
    Validate that CSV file has required columns.
    
    Args:
        file_path: Path to CSV file
        required_columns: List of required column names
        
    Returns:
        Tuple of (is_valid, missing_columns)
    """
    try:
        import polars as pl
        
        # Schema overrides for problematic columns
        schema_overrides = {
            'Physical Port': pl.Utf8,
            'Source Port': pl.Utf8,
            'Destination Port': pl.Utf8,
            'VLAN Tag': pl.Utf8,
            'Risk': pl.Utf8,
            'Packet Type': pl.Utf8,
            'Protocol': pl.Utf8,
            'Direction': pl.Utf8,
            'Action': pl.Utf8,
            'Device Type': pl.Utf8,
            'Workflow Rule Process': pl.Utf8,
            'Activation Id': pl.Utf8,
            'Attack ID': pl.Utf8,
            'Radware ID': pl.Utf8,
        }
        
        # Read just the header to check columns
        df = pl.read_csv(
            file_path, 
            n_rows=0,
            schema_overrides=schema_overrides,
            ignore_errors=True,
            infer_schema_length=10000
        )
        actual_columns = df.columns
        
        missing_columns = [col for col in required_columns if col not in actual_columns]
        
        if missing_columns:
            logger.warning(f"Missing required columns in {file_path.name}: {missing_columns}")
            return False, missing_columns
        
        logger.debug(f"CSV structure validation passed for {file_path.name}")
        return True, []
        
    except Exception as e:
        logger.error(f"Failed to validate CSV structure for {file_path}: {e}")
        return False, required_columns


def clean_filename(filename: str) -> str:
    """
    Clean filename for safe filesystem usage.
    
    Args:
        filename: Original filename
        
    Returns:
        Cleaned filename
    """
    # Remove or replace invalid characters
    invalid_chars = r'<>:"/\\|?*'
    for char in invalid_chars:
        filename = filename.replace(char, '_')
    
    # Remove multiple consecutive underscores
    filename = re.sub(r'_+', '_', filename)
    
    # Remove leading/trailing underscores and dots
    filename = filename.strip('_.')
    
    return filename


def get_file_info(file_path: Path) -> Dict[str, Any]:
    """
    Get comprehensive file information.
    
    Args:
        file_path: Path to file
        
    Returns:
        Dictionary with file information
    """
    try:
        stat = file_path.stat()
        
        return {
            'name': file_path.name,
            'size_bytes': stat.st_size,
            'size_formatted': format_file_size(stat.st_size),
            'modified': datetime.fromtimestamp(stat.st_mtime),
            'is_large': stat.st_size > 100 * 1024 * 1024,  # > 100MB
            'extension': file_path.suffix.lower()
        }
    except Exception as e:
        logger.error(f"Failed to get file info for {file_path}: {e}")
        return {
            'name': file_path.name,
            'size_bytes': 0,
            'size_formatted': 'Unknown',
            'modified': datetime.now(),
            'is_large': False,
            'extension': file_path.suffix.lower() if file_path.suffix else ''
        }


def create_progress_callback(description: str = "Processing"):
    """
    Create a progress callback function using tqdm.
    
    Args:
        description: Description for the progress bar
        
    Returns:
        Progress callback function
    """
    from tqdm import tqdm
    
    pbar = None
    
    def callback(current: int, total: int = None, update: bool = False):
        nonlocal pbar
        
        if pbar is None and total is not None:
            pbar = tqdm(total=total, desc=description, unit='rows')
        
        if pbar is not None:
            if update:
                pbar.update(current - pbar.n)
            else:
                pbar.n = current
                pbar.refresh()
        
        if current >= total and pbar is not None:
            pbar.close()
            pbar = None
    
    return callback


def safe_divide(numerator: Union[int, float], denominator: Union[int, float]) -> float:
    """
    Safely divide two numbers, returning 0 if denominator is 0.
    
    Args:
        numerator: Numerator value
        denominator: Denominator value
        
    Returns:
        Division result or 0 if denominator is 0
    """
    try:
        if denominator == 0:
            return 0.0
        return float(numerator) / float(denominator)
    except (TypeError, ValueError):
        return 0.0


def calculate_percentage(part: Union[int, float], total: Union[int, float]) -> float:
    """
    Calculate percentage with safe division.
    
    Args:
        part: Part value
        total: Total value
        
    Returns:
        Percentage value (0-100)
    """
    return safe_divide(part, total) * 100


# Add pandas import here for compatibility
import pandas as pd