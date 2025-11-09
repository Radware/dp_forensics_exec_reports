"""
Configuration constants for the Forensics Data Analysis & Report Generator

This file contains all user-configurable options for the Forensics Report Generator.
Users can modify these settings to customize report appearance and chart types without 
modifying the core code.

Configuration sections are organized by importance and usage frequency:
1. Core Settings (most important, commonly changed)
2. Data Processing & Input/Output
3. Visualization Configuration
4. Advanced Chart Settings
5. Report Styling
"""

# ============================================================================
# 1. CORE SETTINGS - MOST IMPORTANT & COMMONLY CHANGED
# ============================================================================

# Output format configuration - Controls what file formats are generated
# DEFAULT OUTPUT FORMATS - used when no specific format is requested
# Command-line overrides: --format html, --format pdf, --format both
OUTPUT_FORMATS = ['html']  # Options: 'html', 'pdf', or ['html', 'pdf'] for both

# Data filtering options - exclude rows where column equals specified values
# Multiple filters use AND logic (row must match ALL conditions to be excluded)
EXCLUDE_FILTERS = {
    # 'Threat Category': ['Anomalies'],     # Example: exclude Packet Anomalies and OOS detection
    # 'Policy Name': ['Packet Anomalies'],  # Example: exclude specific policy
    # 'Attack Name': ['DNS RFC-compliance violation'],  # Example: exclude specific attacks
    # 'Risk': ['Low'],                      # Example: exclude low-risk events
    # 'Direction': ['Internal'],            # Example: exclude internal traffic
}

# Volume and packet display units - Controls how data is displayed in charts and statistics
VOLUME_UNIT = 'GB'  # Options: 'MB', 'GB', 'TB' - affects bandwidth display (MB→Mbps, GB→Gbps, TB→Gbps)
PACKET_UNIT = 'M'   # Options: 'M' (millions), 'B' (billions), '' (no conversion)


# Active color scheme - Change this to switch between color themes
ACTIVE_COLOR_PALETTE = 'radware_corporate'  # Options: 'radware_corporate', 'professional_blue', 'modern_minimal', 'vibrant_corporate', 'high_contrast', 'colorblind_friendly'

# ============================================================================
# 3. VISUALIZATION CONFIGURATION - CHART TYPES & COLORS
# ============================================================================

# Color palette definitions - Choose colors for different themes
COLOR_PALETTES = {
    # Radware Corporate (default)
    'radware_corporate': [
        '#003f7f', '#6cb2eb', '#ff6b35', '#28a745', '#ffc107',
        '#dc3545', '#17a2b8', '#6f42c1', '#e83e8c', '#fd7e14',
        '#20c997', '#6610f2', '#e91e63', '#795548', '#607d8b'
    ],
    
    # Professional Blue Theme
    'professional_blue': [
        '#1f4e79', '#2e75b6', '#5b9bd5', '#9fc5e8', '#cfe2f3',
        '#003f7f', '#34495e', '#6cb2eb', '#3a6ea5', '#b4c6e7',
        '#1a2634', '#274472', '#41729f', '#5885af', '#bfd7ed'
    ],

    # Modern Minimal
    'modern_minimal': [
        '#2c3e50', '#34495e', '#95a5a6', '#bdc3c7', '#ecf0f1',
        '#e74c3c', '#e67e22', '#f39c12', '#27ae60', '#3498db'
    ],
    
    # Vibrant Corporate
    'vibrant_corporate': [
        '#e74c3c', '#3498db', '#2ecc71', '#f39c12', '#9b59b6',
        '#1abc9c', '#34495e', '#e67e22', '#95a5a6', '#f1c40f'
    ],
    
    # High Contrast (accessibility friendly)
    'high_contrast': [
        '#000000', '#ffffff', '#ff0000', '#00ff00', '#0000ff',
        '#ffff00', '#ff00ff', '#00ffff', '#800000', '#008000'
    ],
    
    # Colorblind Friendly (deuteranopia/protanopia safe)
    'colorblind_friendly': [
        '#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd',
        '#8c564b', '#e377c2', '#7f7f7f', '#bcbd22', '#17becf'
    ]
}

# Chart preferences - Complete chart configuration in one place
# Each chart has a 'default_type' and type-specific configurations

# Specific color assignments for chart elements (optional overrides, uncomment only if you want to modify specific colors)
CHART_COLOR_ASSIGNMENTS = {
    # # 1. Monthly trends chart colors
    # 'monthly_events_trend_colors': ['#003f7f'],  # Main trend line/bar color
    
    # # 2. Attack types stacked bar colors (monthly)
    # 'attack_types_stacked_bar_colors': ['#003f7f', '#6cb2eb', '#ff6b35', '#28a745', '#ffc107', '#dc3545', '#17a2b8', '#6f42c1', '#e83e8c', '#fd7e14'],
    
    # # 3. Attack volume trends colors (4 different metrics)
    # 'attack_volume_trends_colors': {
    #     'volume': '#003f7f',       # Total Volume color
    #     'packets': '#6cb2eb',      # Total Packets color  
    #     'pps': '#ff6b35',          # Max PPS color
    #     'bandwidth': '#28a745',    # Max Bandwidth color
    # },
    
    # # 4. Hourly heatmap colors
    # 'hourly_heatmap_colors': {'colorscale': 'Reds'},  # Options: 'Blues', 'Reds', 'Viridis', 'Plasma'
    
    # # 5. Attack type distribution colors (pie chart)
    # 'attack_type_distribution_colors': ['#e74c3c', '#3498db', '#2ecc71', '#f39c12', '#9b59b6', '#1abc9c', '#34495e', '#e67e22', '#95a5a6', '#f1c40f'],
    
    # # 6. Top source IPs colors
    # 'top_source_ips_colors': ['#f1440f'],
    
    # # 7. Protocol distribution colors
    # 'protocol_distribution_colors': ['#ee131e'],
    
    # # 8. Daily timeline colors
    # 'daily_timeline_colors': ['#ff9500'],
    
    # # 9. Top attacks by max BPS colors
    # 'top_attacks_max_bps_colors': ['#15ec32'],
    
    # # 10. Top attacks by max PPS colors
    # 'top_attacks_max_pps_colors': ['#230cf7'],
    
    # # 11. Security events by policy colors (pie chart)
    # 'policy_distribution_colors': ["#1c0ab9", '#9b99ae', '#8b899e', '#7b7996', '#6b698e', '#5b5986', '#4b497e', '#3b3976', '#2b296e', '#1b1966'],

}


# Chart preferences - Complete chart configuration
CHART_PREFERENCES = {
    # Monthly trends chart
    'monthly_events_trend': {
        'default_type': 'bar',  # Options: 'line', 'bar', 'area'
        'line': {
            'mode': 'lines+markers',
            'line_width': 3,
            'marker_size': 8,
            'show_trend': True  # Show trend line for line charts
        },
        'bar': {
            'show_values': True,  # Show values on bars
            'show_trend': True,   # Show trend line for bar charts too
            'bar_width': 0.6,
            'values_text_size': 12  # Font size for values displayed on bars
        },
        'area': {
            'fill': 'tonexty',
            'line_width': 2,
            'show_trend': True
        }
    },

    # Top attack types per month (stacked visualization)
    'attack_types_monthly': {
        'default_type': 'stacked_bar',  # Options: 'stacked_bar', 'stacked_area', 'line'
        'top_n': 5,  # Number of top attack types to display
        'stacked_bar': {
            'bar_width': 0.8,
            'show_values': False,  # Values on stacked bars can be cluttered
            'values_text_size': 12  # Font size if show_values is enabled
        },
        'stacked_area': {
            'line_width': 2,
            'fill': 'tonexty', # options : 'tozeroy', 'tonexty'
            'opacity': 0.7  # Transparency for overlapping areas
        },
        'line': {
            'mode': 'lines+markers',
            'line_width': 2,
            'marker_size': 6
        }
    },

    # Attack volume trends (4 subplots)
    'attack_volume_trends': {
        'default_type': 'bar',  # Options: 'line', 'bar'
        'line': {
            'mode': 'lines+markers',
            'line_width': 2,
            'marker_size': 6,
            'show_trend': True  # Show trend lines on all 4 subplots
        },
        'bar': {
            'bar_width': 0.7,
            'show_values': True,  # Too cluttered with 4 subplots
            'values_text_size': 12,  # Font size for values displayed on bars
            'show_trend': False,  # Show trend lines on all 4 subplots
        }
    },
    
    # Distribution charts (pie, donut, bar)
    'attack_type_distribution': {
        'default_type': 'pie',  # Options: 'pie', 'donut', 'bar', 'horizontal_bar'
        'pie': {
            'hole': 0.0,  # Options: 0.0 (full pie) to 0.9 (ring)
            'textinfo': 'label+percent', # Options: 'label+percent', 'percent', 'label', 'value', 'label+value'
            'textposition': 'outside' # Options: 'inside', 'outside'
        },
        'donut': {
            'hole': 0.4,  # Donut hole size
            'textinfo': 'label+percent', # Options: 'label+percent', 'percent', 'label', 'value', 'label+value'
            'textposition': 'outside'
        },
        'bar': {
            'show_values': True,
            'sort_values': 'descending', # Options: 'ascending', 'descending'
            'values_text_size': 12  # Font size for values displayed on bars
        }
    },
    

    
    # Ranking charts (source IPs, protocols, top attacks)
    'top_source_ips': {
        'default_type': 'horizontal_bar',  # Options: 'bar', 'horizontal_bar'
        'bar': {
            'show_values': True,
            'values_text_size': 12,  # Font size for values displayed on bars
            'sort_values': 'descending',
        },
        'horizontal_bar': {
            'show_values': True,
            'values_text_size': 12,  # Font size for values displayed on bars
            'sort_values': 'descending'
        }
    },
    
    'protocol_distribution': {
        'default_type': 'bar',  # Options: 'bar', 'horizontal_bar'
        'bar': {
            'show_values': True, 
            'values_text_size': 12,  # Font size for values displayed on bars
            'sort_values': 'descending'
        },
        'horizontal_bar': {
            'show_values': True,
            'values_text_size': 12,  # Font size for values displayed on bars
            'sort_values': 'descending'
        }
    },

    # Timeline chart
    'daily_timeline': {
        'default_type': 'area',  # Options: 'line', 'area'
        'line': {
            'mode': 'lines+markers', # Options: 'lines', 'markers', 'lines+markers'
            'line_width': 2,
            'marker_size': 4
        },
        'area': {
            'line_width': 2,
            'marker_size': 4,
            'mode': 'lines+markers'
        }
    },
 
    'top_attacks_max_bps': {
        'default_type': 'bar',  # Options: 'bar', 'horizontal_bar'
        'bar': {
            'show_values': True,
            'values_text_size': 12,  # Font size for values displayed on bars
            'sort_values': 'descending'
        },
        'horizontal_bar': {
            'show_values': True,
            'sort_values': 'descending',
            'values_text_size': 12  # Font size for values displayed on bars
        }
    },
    
    'top_attacks_max_pps': {
        'default_type': 'bar',  # Options: 'bar', 'horizontal_bar'
        'bar': {
            'show_values': True,
            'sort_values': 'descending',
            'values_text_size': 12  # Font size for values displayed on bars
        },
        'horizontal_bar': {
            'show_values': True, 
            'sort_values': 'descending',
            'values_text_size': 12  # Font size for values displayed on bars
        }
    },
    

    
    # Policy distribution (same options as attack type)
    'policy_distribution': {
        'default_type': 'pie',  # Options: 'pie', 'donut', 'bar', 'horizontal_bar'
        'pie': {
            'hole': 0.0, # Options: 0.0 (full pie) to 0.9 (ring)
            'textinfo': 'label+percent', # Options: 'label+percent', 'percent', 'label', 'value', 'label+value'
            'textposition': 'outside'
        },
        'donut': {
            'hole': 0.4,
            'textinfo': 'label+percent', # Options: 'label+percent', 'percent', 'label', 'value', 'label+value'
            'textposition': 'outside'
        },
        'bar': {
            'show_values': True,
            'sort_values': 'descending',
            'values_text_size': 12  # Font size for values displayed on bars
        }
    }

}



# Chart rendering configuration
CHART_CONFIG = {
    'displayModeBar': False, # Hide the mode bar (toolbar) by default
    'responsive': True # Make charts responsive to container size
}

"""
CHART_LAYOUT configuration for Plotly chart rendering.
This dictionary defines the default layout settings for all charts generated by the report generator.
Each key controls a specific aspect of chart appearance and behavior.
Keys and their options:
- 'font': Dict specifying font family for all chart text.
    Example: {'family': 'Segoe UI, Tahoma, Geneva, Verdana, sans-serif'}
- 'plot_bgcolor': Background color of the plotting area (inside axes).
    Example: 'white'
- 'paper_bgcolor': Background color of the entire chart (outside axes).
    Example: 'white'
- 'margin': Dict specifying margins (in pixels) around the chart.
    Keys: 'l' (left), 'r' (right), 't' (top), 'b' (bottom)
    Example: {'l': 60, 'r': 60, 't': 80, 'b': 80}
- 'showlegend': Boolean to show/hide the legend.
    Example: True
- 'legend': Dict configuring legend appearance and position.
    - 'orientation': 'h' for horizontal, 'v' for vertical legend layout.
    - 'yanchor': Vertical anchor point for legend ('top', 'middle', 'bottom').
    - 'y': Vertical position (float, 0 = bottom, 1 = top, can be negative for below chart).
    - 'xanchor': Horizontal anchor point for legend ('left', 'center', 'right').
    - 'x': Horizontal position (float, 0 = left, 1 = right, 0.5 = center).
    Example:
        {
These settings ensure a consistent, professional appearance for all charts and can be customized as needed.
"""

CHART_LAYOUT = {
    'font': {'family': 'Segoe UI, Tahoma, Geneva, Verdana, sans-serif'},
    'plot_bgcolor': 'white',
    'paper_bgcolor': 'white',
    'margin': {'l': 60, 'r': 60, 't': 80, 'b': 80},
    'showlegend': True,
    'legend': {
        'orientation': 'h',
        'yanchor': 'bottom',
        'y': -0.2,
        'xanchor': 'center',
        'x': 0.5
    }
}


# ============================================================================
# ADVANCED CHART SETTINGS & UNIT CONFIGURATIONS
# ============================================================================

# Volume unit configuration details
VOLUME_UNIT_CONFIGS = {
    'MB': {
        'divider': 1,           # Mbits to MB: divide by 1 (already in Mbits, then divide by 8 for bytes)
        'display_name': 'MB',
        'chart_title': 'Aggregate Attack Volume (MB)',
        'stats_label': 'Aggregate Attack Volume (MB)'
    },
    'GB': {
        'divider': 1000,        # Mbits to GB: divide by 1000, then by 8 for bytes
        'display_name': 'GB', 
        'chart_title': 'Aggregate Attack Volume (GB)',
        'stats_label': 'Aggregate Attack Volume (GB)'
    },
    'TB': {
        'divider': 1000000,     # Mbits to TB: divide by 1,000,000, then by 8 for bytes
        'display_name': 'TB',
        'chart_title': 'Aggregate Attack Volume (TB)', 
        'stats_label': 'Aggregate Attack Volume (TB)'
    }
}

# Packet unit configuration details
PACKET_UNIT_CONFIGS = {
    'M': {
        'divider': 1_000_000,   # Convert to millions
        'display_name': 'M',
        'chart_title': 'Aggregate Attack Packets (Millions)',
        'stats_label': 'Aggregate Attack Packets (Millions)'
    },
    'B': {
        'divider': 1_000_000_000,  # Convert to billions
        'display_name': 'B',
        'chart_title': 'Aggregate Attack Packets (Billions)', 
        'stats_label': 'Aggregate Attack Packets (Billions)'
    },
    '': {
        'divider': 1,           # No conversion
        'display_name': '',
        'chart_title': 'Aggregate Attack Packets',
        'stats_label': 'Aggregate Attack Packets'
    }
}

# Bandwidth unit configuration (automatically tied to VOLUME_UNIT)
BANDWIDTH_UNIT_CONFIGS = {
    'MB': {
        'divider': 1_000_000,       # bps to Mbps: divide by 1,000,000
        'unit_name': 'Mbps',
        'chart_title': 'Attack Max Mbps',
        'stats_label': 'Attack Max Mbps',
        'chart_name': 'Max Mbps',
        'hover_template': '<b>%{x}</b><br>Max Mbps: %{y:,.2f}<extra></extra>'
    },
    'GB': {
        'divider': 1_000_000_000,   # bps to Gbps: divide by 1,000,000,000
        'unit_name': 'Gbps',
        'chart_title': 'Attack Max Gbps',
        'stats_label': 'Attack Max Gbps',
        'chart_name': 'Max Gbps',
        'hover_template': '<b>%{x}</b><br>Max Gbps: %{y:,.2f}<extra></extra>'
    },
    'TB': {
        'divider': 1_000_000_000,   # bps to Gbps: divide by 1,000,000,000 (keep as Gbps for TB)
        'unit_name': 'Gbps',
        'chart_title': 'Attack Max Gbps',
        'stats_label': 'Attack Max Gbps',
        'chart_name': 'Max Gbps',
        'hover_template': '<b>%{x}</b><br>Max Gbps: %{y:,.2f}<extra></extra>'
    }
}


# ============================================================================
# DATA PROCESSING & INPUT/OUTPUT CONFIGURATION
# ============================================================================

# Data processing performance settings
CHUNK_SIZE = 50000              # Number of rows to process at once
MAX_MEMORY_USAGE_GB = 2         # Maximum memory usage in GB before warning

# CSV column configuration
EXPECTED_COLUMNS = [
    'S.No', 'Start Time', 'End Time', 'Device IP Address', 'Threat Category',
    'Attack Name', 'Policy Name', 'Action', 'Attack ID', 'Source IP Address',
    'Source Port', 'Destination IP Address', 'Destination Port', 'Direction',
    'Protocol', 'Radware ID', 'Duration', 'Total Packets', 'Packet Type',
    'Total Mbits', 'Max pps', 'Max bps', 'Physical Port', 'Risk', 'VLAN Tag',
    'Footprint', 'Device Name', 'Device Type', 'Workflow Rule Process',
    'Activation Id', 'Protected Object'
]

REQUIRED_COLUMNS = [
    'Start Time', 'Attack Name', 'Source IP Address', 'Destination IP Address'
]

# Date parsing configuration
DATE_FORMATS = [
    '%d.%m.%Y %H:%M:%S',  # DD.MM.YYYY HH:MM:SS (preferred for European format)
    '%m.%d.%Y %H:%M:%S',  # MM.DD.YYYY HH:MM:SS (example format)
]

# Force specific date format (overrides auto-detection)
# Set to None for auto-detection, or specify exact format string
FORCE_DATE_FORMAT = None  # Example: '%d.%m.%Y %H:%M:%S' or None for auto-detection

# Logging configuration
LOG_FORMAT = '%(asctime)s - %(levelname)s - %(message)s'
LOG_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'

# Chart size optimization - Balance between file size and offline capability
CHART_PLOTLYJS_MODE = 'cdn'  # Options: 'inline' (largest, offline), 'cdn' (smallest, needs internet), 'directory', False


# ============================================================================
# 5. REPORT STYLING & HTML TEMPLATE
# ============================================================================

# Report CSS styling
REPORT_CSS = """
<style>
    body {
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        margin: 0;
        padding: 20px;
        background-color: #f8f9fa;
        color: #333;
        line-height: 1.6;
    }
    
    .container {
        max-width: 1200px;
        margin: 0 auto;
        background-color: white;
        box-shadow: 0 0 20px rgba(0,0,0,0.1);
        border-radius: 8px;
        overflow: hidden;
    }
    
    .header {
        background: linear-gradient(135deg, #003f7f 0%, #6cb2eb 100%);
        color: white;
        padding: 30px;
        text-align: center;
    }
    
    .header h1 {
        margin: 0;
        font-size: 2.5em;
        font-weight: 300;
    }
    
    .header p {
        margin: 10px 0 0 0;
        font-size: 1.2em;
        opacity: 0.9;
    }
    
    .content {
        padding: 30px;
    }
    
    .section {
        margin-bottom: 40px;
        border-bottom: 1px solid #e9ecef;
        padding-bottom: 30px;
    }
    
    .section:last-child {
        border-bottom: none;
    }
    
    .section h2 {
        color: #003f7f;
        border-left: 4px solid #ff6b35;
        padding-left: 15px;
        margin-bottom: 20px;
        font-size: 1.8em;
    }
    
    .section h3 {
        color: #495057;
        margin-top: 30px;
        margin-bottom: 15px;
    }
    
    .stats-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
        gap: 20px;
        margin-bottom: 30px;
    }
    
    .stat-card {
        background: #f8f9fa;
        border: 1px solid #dee2e6;
        border-radius: 8px;
        padding: 20px;
        text-align: center;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    
    .stat-value {
        font-size: 2em;
        font-weight: bold;
        color: #003f7f;
        margin-bottom: 5px;
        word-break: break-word;
        line-height: 1.2;
    }
    
    /* Dynamic font sizing classes for long stat values */
    .stat-value.long-stat {
        font-size: 1.6em;
    }
    
    .stat-value.very-long-stat {
        font-size: 1.3em;
    }
    
    .stat-value.extremely-long-stat {
        font-size: 1.1em;
        line-height: 1.1;
    }
    
    .stat-label {
        color: #6c757d;
        font-size: 0.9em;
        text-transform: uppercase;
        letter-spacing: 1px;
    }
    
    .chart-container {
        margin: 20px 0;
        padding: 15px;
        background: white;
        border-radius: 8px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    
    .warning {
        background: #fff3cd;
        border: 1px solid #ffeaa7;
        border-radius: 4px;
        padding: 15px;
        margin: 20px 0;
        color: #856404;
    }
    
    .info {
        background: #d1ecf1;
        border: 1px solid #bee5eb;
        border-radius: 4px;
        padding: 15px;
        margin: 20px 0;
        color: #0c5460;
    }
    
    .footer {
        background: #f8f9fa;
        border-top: 1px solid #dee2e6;
        padding: 20px 30px;
        text-align: center;
        color: #6c757d;
        font-size: 0.9em;
    }
    
    table {
        width: 100%;
        border-collapse: collapse;
        margin: 20px 0;
        background: white;
        border-radius: 8px;
        overflow: hidden;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    
    th, td {
        padding: 12px 15px;
        text-align: left;
        border-bottom: 1px solid #dee2e6;
    }
    
    th {
        background: #003f7f;
        color: white;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        font-size: 0.9em;
    }
    
    tr:hover {
        background: #f8f9fa;
    }
    
    .progress-bar {
        background: #e9ecef;
        border-radius: 4px;
        overflow: hidden;
        height: 20px;
        margin: 10px 0;
    }
    
    .progress {
        background: linear-gradient(90deg, #003f7f, #6cb2eb);
        height: 100%;
        transition: width 0.3s ease;
    }
    
    @media (max-width: 768px) {
        .container {
            margin: 10px;
            border-radius: 0;
        }
        
        .header {
            padding: 20px;
        }
        
        .header h1 {
            font-size: 2em;
        }
        
        .content {
            padding: 20px;
        }
        
        .stats-grid {
            grid-template-columns: 1fr;
        }
    }
    
    /* Expandable stat card styles */
    .expandable-card {
        position: relative;
    }
    
    .expandable-trigger {
        transition: background-color 0.2s ease;
    }
    
    .expandable-trigger:hover {
        background-color: rgba(0, 63, 127, 0.05);
        border-radius: 4px;
    }
    
    .expand-icon {
        position: absolute;
        right: 10px;
        top: 50%;
        transform: translateY(-50%);
        font-size: 12px;
        color: #6c757d;
        transition: transform 0.3s ease;
    }
    
    .expand-icon.rotated {
        transform: translateY(-50%) rotate(180deg);
    }
    
    .attack-details {
        margin-top: 15px;
        padding: 0;
        max-height: 0;
        overflow: hidden;
        transition: max-height 0.3s ease-out, padding 0.3s ease-out;
    }
    
    .attack-details.expanded {
        max-height: 500px;
        padding: 15px 0;
        overflow-y: auto;
    }
    
    .details-container {
        background: #f8f9fa;
        border: 1px solid #dee2e6;
        border-radius: 6px;
        padding: 15px;
        font-size: 13px;
    }
    
    .detail-row {
        margin-bottom: 12px;
        padding: 8px 0;
        border-bottom: 1px solid #f1f3f4;
    }
    
    .detail-row:last-child {
        margin-bottom: 0;
        border-bottom: none;
        padding-bottom: 0;
    }
    
    .detail-label {
        font-weight: 600;
        color: #495057;
        font-size: 12px;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        margin-bottom: 4px;
        display: block;
    }
    
    .detail-value {
        color: #003f7f;
        font-size: 14px;
        font-weight: 500;
        display: block;
        margin-left: 0;
        background-color: #f8f9fa;
        padding: 6px 10px;
        border-radius: 4px;
        border-left: 3px solid #003f7f;
        word-break: break-word;
    }
    
    /* Mobile responsiveness for expandable cards */
    @media (max-width: 768px) {
        .detail-value {
            font-size: 13px;
            padding: 5px 8px;
        }
        
        .detail-label {
            font-size: 11px;
        }
        
        .expand-icon {
            right: 5px;
        }
    }
</style>

<script>
function toggleDetails(detailsId) {
    const detailsElement = document.getElementById(detailsId);
    const iconElement = document.getElementById(detailsId + '-icon');
    
    if (detailsElement.classList.contains('expanded')) {
        // Collapse
        detailsElement.classList.remove('expanded');
        iconElement.classList.remove('rotated');
    } else {
        // Expand
        detailsElement.classList.add('expanded');
        iconElement.classList.add('rotated');
        
        // Apply dynamic font sizing after expansion
        setTimeout(() => {
            adjustStatValueFontSizes();
        }, 100);
    }
}

function adjustStatValueFontSizes() {
    // Adjust stat values (main stat numbers)
    const statValues = document.querySelectorAll('.stat-value');
    
    statValues.forEach(element => {
        // Reset classes
        element.classList.remove('long-stat', 'very-long-stat', 'extremely-long-stat');
        
        const text = element.textContent || element.innerText;
        // Remove icon text from measurement
        const cleanText = text.replace('▼', '').trim();
        const textLength = cleanText.length;
        
        // Apply classes based on text length for stat values
        if (textLength > 18) {
            element.classList.add('extremely-long-stat');
        } else if (textLength > 16) {
            element.classList.add('very-long-stat');
        } else if (textLength > 10) {
            element.classList.add('long-stat');
        }
        
        // Additional overflow detection for stat values
        setTimeout(() => {
            let attempts = 0;
            while (element.scrollWidth > element.clientWidth && attempts < 3) {
                if (element.classList.contains('extremely-long-stat')) {
                    // Already at smallest size
                    break;
                } else if (element.classList.contains('very-long-stat')) {
                    element.classList.remove('very-long-stat');
                    element.classList.add('extremely-long-stat');
                } else if (element.classList.contains('long-stat')) {
                    element.classList.remove('long-stat');
                    element.classList.add('very-long-stat');
                } else {
                    element.classList.add('long-stat');
                }
                attempts++;
            }
        }, 50);
    });
}

// Apply font sizing on page load
document.addEventListener('DOMContentLoaded', function() {
    adjustStatValueFontSizes();
});
</script>
"""


