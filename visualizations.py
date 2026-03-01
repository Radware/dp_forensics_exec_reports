"""
Visualization module for creating interactive charts and graphs.

This module creates professional, interactive visualizations using Plotly
with Radware branding and styling for both technical and sales audiences.

EXPANDABLE STAT CARDS:
This module includes functionality for creating expandable stat cards that 
show detailed information when clicked. Use cases include:
- Longest Attack Duration (shows full attack details)
- Top Source IP (shows attack breakdown)
- Highest Volume Attack (shows attack characteristics)

To create custom expandable cards:
    custom_fields = [
        ('Field Name', 'Field Value'),
        ('Source IP', '192.168.1.100'),
        ('Volume (MB)', '1,250.5')
    ]
    html = visualizer.create_expandable_stat_card_for_custom_data(
        "Card Title", "Main Value", custom_fields, "unique-id"
    )
"""

import logging
from typing import Dict, List, Any, Optional, Tuple
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import pandas as pd
from datetime import datetime, timedelta

from config import (
    CHART_COLOR_ASSIGNMENTS, CHART_PREFERENCES, CHART_CONFIG, CHART_LAYOUT,
    VOLUME_UNIT, VOLUME_UNIT_CONFIGS, PACKET_UNIT, PACKET_UNIT_CONFIGS,
    CHART_PLOTLYJS_MODE
)
from utils import (
    format_number, calculate_percentage, get_active_color_palette, 
    get_chart_colors, get_bandwidth_unit_config
)

logger = logging.getLogger(__name__)


class ForensicsVisualizer:
    """
    Creates interactive visualizations for forensics data analysis.
    """
    
    def __init__(self):
        """Initialize the visualizer with user-configurable styling."""
        self.active_palette = get_active_color_palette()
        self.chart_colors = self.active_palette  # Default to active palette
        self.base_layout = CHART_LAYOUT.copy()
        self.chart_preferences = CHART_PREFERENCES
        self.color_assignments = CHART_COLOR_ASSIGNMENTS
        
        logger.info("Initialized ForensicsVisualizer with configurable styling")
    
    def _get_chart_color(self, chart_name: str, color_key: str = 'primary', fallback_index: int = 0):
        """
        Get color for a specific chart element.
        
        Args:
            chart_name: Name of the chart (e.g., 'monthly_trends', 'attack_type')
            color_key: Specific color key (e.g., 'primary', 'volume', 'packets') or index for list format
            fallback_index: Index in palette to use as fallback
            
        Returns:
            Color string (hex code)
        """
        # Check for specific color assignment
        color_assignment_key = f'{chart_name}_colors'
        if color_assignment_key in self.color_assignments:
            chart_colors = self.color_assignments[color_assignment_key]
            
            # Handle list format (new approach)
            if isinstance(chart_colors, list):
                if isinstance(fallback_index, int) and 0 <= fallback_index < len(chart_colors):
                    return chart_colors[fallback_index]
                elif len(chart_colors) > 0:
                    return chart_colors[0]  # Default to first color
                    
            # Handle dict format (backward compatibility)
            elif isinstance(chart_colors, dict) and color_key in chart_colors:
                return chart_colors[color_key]
        
        # Fall back to active palette
        return self.active_palette[fallback_index % len(self.active_palette)]
    
    def _get_chart_colors_list(self, chart_name: str):
        """
        Get list of colors for a chart that needs multiple colors.
        
        Args:
            chart_name: Name of the chart
            
        Returns:
            List of color strings
        """
        # Check for specific color assignment
        color_assignment_key = f'{chart_name}_colors'
        if color_assignment_key in self.color_assignments:
            chart_colors = self.color_assignments[color_assignment_key]
            
            # Handle list format (new approach) - return the list directly
            if isinstance(chart_colors, list):
                return chart_colors
                
            # Handle dict format (backward compatibility) - extract color values
            elif isinstance(chart_colors, dict) and len(chart_colors) > 1:
                # Return the values if they're colors
                color_values = [v for v in chart_colors.values() if isinstance(v, str) and v.startswith('#')]
                if color_values:
                    return color_values
        
        # Fall back to active palette
        return self.active_palette
    
    def _get_chart_type(self, chart_name: str) -> str:
        """
        Get configured chart type for a specific chart.
        
        Args:
            chart_name: Name of chart in CHART_PREFERENCES
            
        Returns:
            Chart type string
        """
        # Check for runtime preference override first
        if chart_name in self.chart_preferences and 'type' in self.chart_preferences[chart_name]:
            return self.chart_preferences[chart_name]['type']
        
        # Get default type from CHART_PREFERENCES
        if chart_name in self.chart_preferences and 'default_type' in self.chart_preferences[chart_name]:
            return self.chart_preferences[chart_name]['default_type']
            
        # Final fallback
        return 'bar'
    
    def _convert_to_html(self, fig, custom_config=None):
        """
        Convert Plotly figure to HTML with optimized Plotly inclusion.
        
        Args:
            fig: Plotly figure object
            custom_config: Optional custom configuration to override CHART_CONFIG
            
        Returns:
            HTML string of the chart
        """
        config = custom_config if custom_config is not None else CHART_CONFIG
        return fig.to_html(config=config, include_plotlyjs=CHART_PLOTLYJS_MODE)
    
    def _create_trace_by_type(self, chart_type: str, chart_name: str, x_data, y_data, 
                             color_key: str = 'primary', name: str = None, 
                             hovertemplate: str = None, **kwargs):
        """
        Create a trace based on chart type configuration.
        
        Args:
            chart_type: Type of chart ('line', 'bar', etc.)
            chart_name: Name of chart config in CHART_PREFERENCES
            x_data: X-axis data
            y_data: Y-axis data
            color_key: Key for color in chart preferences
            name: Trace name
            hovertemplate: Hover template
            **kwargs: Additional trace parameters
            
        Returns:
            Plotly trace object
        """
        # Get color using new system
        color = self._get_chart_color(chart_name, color_key, 0)
        
        # Get chart style configuration
        chart_style = self.get_chart_style(chart_name, chart_type)
        
        if chart_type == 'line':
            # Get line-specific styling from configuration
            line_width = chart_style.get('line_width', 3)
            marker_size = chart_style.get('marker_size', 8)
            mode = chart_style.get('mode', 'lines+markers')
            
            return go.Scatter(
                x=x_data,
                y=y_data,
                mode=mode,
                line=dict(color=color, width=line_width),
                marker=dict(size=marker_size, color=color),
                name=name,
                hovertemplate=hovertemplate,
                **kwargs
            )
        elif chart_type == 'bar':
            # Get bar-specific styling from configuration
            bar_width = chart_style.get('bar_width', None)
            show_values = chart_style.get('show_values', False)
            values_text_size = chart_style.get('values_text_size', 10)  # Default to 10 if not specified
            
            # Build bar trace
            bar_trace = go.Bar(
                x=x_data,
                y=y_data,
                marker=dict(color=color),
                name=name,
                hovertemplate=hovertemplate,
                width=bar_width,  # Will be None if not specified, which is fine
                **kwargs
            )
            
            # Add text on bars if show_values is enabled
            if show_values:
                bar_trace.text = [f'{val:,.0f}' if isinstance(val, (int, float)) else str(val) for val in y_data]
                bar_trace.textposition = 'outside'
                bar_trace.textfont = dict(size=values_text_size)  # Use configured text size
            
            return bar_trace
            
        elif chart_type == 'area':
            # Get area-specific styling from configuration
            line_width = chart_style.get('line_width', 2)
            
            # Convert hex color to rgba for fill
            if color.startswith('#'):
                # Convert hex to rgb
                hex_color = color.lstrip('#')
                rgb = tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))
                fill_color = f'rgba({rgb[0]}, {rgb[1]}, {rgb[2]}, 0.3)'
            else:
                fill_color = color
                
            return go.Scatter(
                x=x_data,
                y=y_data,
                mode='lines',
                line=dict(color=color, width=line_width),
                fill='tonexty',
                fillcolor=fill_color,
                name=name,
                hovertemplate=hovertemplate,
                **kwargs
            )
        else:
            # Default to bar chart
            return go.Bar(
                x=x_data,
                y=y_data,
                marker=dict(color=color),
                name=name,
                hovertemplate=hovertemplate,
                **kwargs
            )
    
    def _add_bar_chart_margin(self, fig, y_data, chart_type: str = 'bar', show_values: bool = False):
        """
        Add top margin to y-axis for bar charts with outside text to prevent cutoff.
        
        Args:
            fig: Plotly figure object
            y_data: Y-axis data (list or single value)
            chart_type: Type of chart
            show_values: Whether values are shown outside bars
        """
        # Only add margin for bar charts with outside text
        if chart_type == 'bar' and show_values:
            # Handle both list and single value
            if isinstance(y_data, (list, tuple)):
                max_val = max(y_data) if y_data else 0
            else:
                max_val = y_data
            
            # Add 15% margin at the top
            if max_val > 0:
                fig.update_yaxes(range=[0, max_val * 1.15])
    
    def _get_chart_type(self, chart_name: str) -> str:
        """
        Get configured chart type for a specific chart.
        
        Args:
            chart_name: Name of chart in CHART_PREFERENCES
            
        Returns:
            Chart type string
        """
        # Get default type from CHART_PREFERENCES
        if chart_name in self.chart_preferences and 'default_type' in self.chart_preferences[chart_name]:
            return self.chart_preferences[chart_name]['default_type']
        return 'bar'
    
    def create_monthly_events_trend(self, monthly_data: Dict[str, Any]) -> str:
        """
        Create a line chart showing total events per month.
        
        Args:
            monthly_data: Dictionary with monthly statistics
            
        Returns:
            HTML string of the chart
        """
        try:
            if not monthly_data.get('has_trends', False):
                return self._create_no_data_chart("Month-to-Month Trends", monthly_data.get('reason', 'No data available'))
            
            months = list(monthly_data['months'].keys())
            events = [monthly_data['months'][month]['total_events'] for month in months]
            
            # Create formatted month labels
            month_labels = [monthly_data['months'][month]['month_name'] for month in months]
            
            fig = go.Figure()
            
            # Get chart type from configuration
            chart_type = self._get_chart_type('monthly_events_trend')
            
            # Get chart style configuration
            chart_style = self.get_chart_style('monthly_events_trend', chart_type)
            
            # Create trace based on configuration
            trace = self._create_trace_by_type(
                chart_type=chart_type,
                chart_name='monthly_events_trend',
                x_data=month_labels,
                y_data=events,
                color_key='primary',
                name='Total Events',
                hovertemplate='<b>%{x}</b><br>Events: %{y:,}<extra></extra>'
            )
            
            fig.add_trace(trace)
            
            # Add trend line if enabled in chart style
            if chart_style.get('show_trend', False) and len(events) > 1:
                # Calculate linear trend
                x_numeric = list(range(len(events)))
                try:
                    # Simple linear regression
                    import numpy as np
                    z = np.polyfit(x_numeric, events, 1)
                    trend_line = np.poly1d(z)
                    trend_values = [trend_line(x) for x in x_numeric]
                    
                    # Add trend line trace
                    trend_trace = go.Scatter(
                        x=month_labels,
                        y=trend_values,
                        mode='lines',
                        name='Trend',
                        line=dict(
                            color='rgba(255, 107, 53, 0.8)',  # Orange trend line
                            width=2,
                            dash='dash'
                        ),
                        hovertemplate='<b>%{x}</b><br>Trend: %{y:,.0f}<extra></extra>'
                    )
                    fig.add_trace(trend_trace)
                except ImportError:
                    # Fallback if numpy is not available - simple moving average
                    if len(events) >= 2:
                        # Calculate simple moving average as trend
                        trend_values = []
                        for i in range(len(events)):
                            if i == 0:
                                trend_values.append(events[0])
                            else:
                                trend_values.append(sum(events[:i+1]) / (i+1))
                        
                        trend_trace = go.Scatter(
                            x=month_labels,
                            y=trend_values,
                            mode='lines',
                            name='Moving Average',
                            line=dict(
                                color='rgba(255, 107, 53, 0.8)',
                                width=2,
                                dash='dash'
                            ),
                            hovertemplate='<b>%{x}</b><br>Avg: %{y:,.0f}<extra></extra>'
                        )
                        fig.add_trace(trend_trace)
            
            # Add margin for bar charts with outside text
            show_values = chart_style.get('show_values', False)
            self._add_bar_chart_margin(fig, events, chart_type, show_values)
            
            layout = self.base_layout.copy()
            layout.update({
                'title': {
                    'text': 'Security Events Per Month',
                    'font': {'size': 18, 'color': '#000000'},
                    'x': 0.5
                },
                'xaxis': {
                    'title': 'Month',
                    'showgrid': True,
                    'gridcolor': '#f0f0f0'
                },
                'yaxis': {
                    'title': 'Number of Events',
                    'showgrid': True,
                    'gridcolor': '#f0f0f0'
                },
                'hovermode': 'x unified',
                'height': 500
            })
            
            fig.update_layout(layout)
            
            # Disable zoom on axes for bar charts
            fig.update_xaxes(fixedrange=True)
            fig.update_yaxes(fixedrange=True)
            
            # Bar chart config - disable all zoom
            bar_config = {
                'displayModeBar': False,
                'responsive': True,
                'scrollZoom': False,
                'doubleClick': False
            }
            
            return self._convert_to_html(fig, bar_config)
            
        except Exception as e:
            logger.error(f"Failed to create monthly events trend: {e}")
            return self._create_error_chart("Monthly Events Trend", str(e))
    
    def create_attack_types_stacked_bar(self, monthly_data: Dict[str, Any], top_n: int = None) -> str:
        """
        Create a chart showing top attack types per month.
        Supports multiple visualization types: stacked bar, stacked area, or lines.
        
        Args:
            monthly_data: Dictionary with monthly statistics
            top_n: Number of top attack types to show (None = use config default)
            
        Returns:
            HTML string of the chart
        """
        try:
            # Get chart configuration
            chart_type = self.get_chart_type('attack_types_monthly')
            chart_style = self.get_chart_style('attack_types_monthly', chart_type)
            
            # Get top_n from config if not specified
            if top_n is None:
                top_n = self.chart_preferences.get('attack_types_monthly', {}).get('top_n', 5)
            
            if not monthly_data.get('has_trends', False):
                return self._create_no_data_chart("Top Attack Types Per Month", monthly_data.get('reason', 'No data available'))
            
            months = list(monthly_data['months'].keys())
            month_labels = [monthly_data['months'][month]['month_name'] for month in months]
            
            # Get top attack types across all months
            all_attacks = {}
            for month in months:
                attacks = monthly_data['months'][month]['attack_types']
                for attack, attack_info in attacks.items():
                    if isinstance(attack_info, dict):
                        count = attack_info.get('count', 0)
                    else:
                        # Handle old format (just count)
                        count = attack_info
                    all_attacks[attack] = all_attacks.get(attack, 0) + count
            
            top_attacks = sorted(all_attacks.items(), key=lambda x: x[1], reverse=True)[:top_n]
            top_attack_names = [attack[0] for attack in top_attacks]
            
            # Get colors for attack types
            colors = self._get_chart_colors_list('attack_types_stacked_bar')
            
            fig = go.Figure()
            
            # Create traces based on chart type
            for i, attack_name in enumerate(top_attack_names):
                values = []
                for month in months:
                    attacks = monthly_data['months'][month]['attack_types']
                    attack_info = attacks.get(attack_name, 0)
                    if isinstance(attack_info, dict):
                        count = attack_info.get('count', 0)
                    else:
                        # Handle old format (just count)
                        count = attack_info
                    values.append(count)
                
                color = colors[i % len(colors)]
                
                if chart_type == 'stacked_area':
                    # Stacked area chart
                    line_width = chart_style.get('line_width', 1)
                    opacity = chart_style.get('opacity', 0.7)
                    
                    # Convert hex color to rgba for fill
                    if color.startswith('#'):
                        hex_color = color.lstrip('#')
                        rgb = tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))
                        fill_color = f'rgba({rgb[0]}, {rgb[1]}, {rgb[2]}, {opacity})'
                    else:
                        fill_color = color
                    
                    fig.add_trace(go.Scatter(
                        x=month_labels,
                        y=values,
                        name=attack_name,
                        mode='lines',
                        line=dict(color=color, width=line_width),
                        fill='tonexty',
                        fillcolor=fill_color,
                        stackgroup='one',  # Enable stacking
                        hovertemplate=f'<b>{attack_name}</b><br>%{{x}}<br>Events: %{{y:,}}<extra></extra>'
                    ))
                    
                elif chart_type == 'line':
                    # Line chart - individual trends
                    mode = chart_style.get('mode', 'lines+markers')
                    line_width = chart_style.get('line_width', 2)
                    marker_size = chart_style.get('marker_size', 6)
                    
                    fig.add_trace(go.Scatter(
                        x=month_labels,
                        y=values,
                        name=attack_name,
                        mode=mode,
                        line=dict(color=color, width=line_width),
                        marker=dict(size=marker_size, color=color),
                        hovertemplate=f'<b>{attack_name}</b><br>%{{x}}<br>Events: %{{y:,}}<extra></extra>'
                    ))
                    
                else:  # Default to stacked_bar
                    # Stacked bar chart
                    bar_width = chart_style.get('bar_width', 0.8)
                    show_values = chart_style.get('show_values', False)
                    
                    bar_trace = go.Bar(
                        x=month_labels,
                        y=values,
                        name=attack_name,
                        marker_color=color,
                        width=bar_width,
                        hovertemplate=f'<b>{attack_name}</b><br>%{{x}}<br>Events: %{{y:,}}<extra></extra>'
                    )
                    
                    # Add text on bars if show_values is enabled
                    if show_values:
                        values_text_size = chart_style.get('values_text_size', 10)
                        # Only show value if segment is large enough (more than 5% of max value or > 50)
                        max_value = max(values) if values else 0
                        threshold = max(max_value * 0.05, 50)  # 5% of max or 50, whichever is larger
                        bar_trace.text = [f'{val:,}' if val >= threshold else '' for val in values]
                        bar_trace.textposition = 'inside'  # Position in the middle of the bar segment
                        bar_trace.textfont = dict(size=values_text_size, color='white')
                        bar_trace.insidetextanchor = 'middle'  # Center text within bar segment
                        bar_trace.textangle = 0  # Prevent text rotation - keep horizontal or hide if no room
                        bar_trace.constraintext = 'none'  # Don't constrain or rotate text, hide if no room
                    
                    fig.add_trace(bar_trace)
            
            layout = self.base_layout.copy()
            
            # Determine chart title based on type
            if chart_type == 'stacked_area':
                chart_title = f'Top {top_n} Attack Types Per Month (Stacked Area)'
            elif chart_type == 'line':
                chart_title = f'Top {top_n} Attack Types Per Month (Trends)'
            else:
                chart_title = f'Top {top_n} Attack Types Per Month'
            
            layout.update({
                'title': {
                    'text': chart_title,
                    'font': {'size': 18, 'color': '#000000'},
                    'x': 0.5
                },
                'xaxis': {'title': 'Month'},
                'yaxis': {'title': 'Number of Events'},
                'hovermode': 'x unified',
                'height': 500
            })
            
            # Set barmode for bar charts
            if chart_type == 'stacked_bar':
                layout['barmode'] = 'stack'
            
            fig.update_layout(layout)
            
            # Disable zoom on axes
            fig.update_xaxes(fixedrange=True)
            fig.update_yaxes(fixedrange=True)
            
            # Chart config - disable all zoom
            chart_config = {
                'displayModeBar': False,
                'responsive': True,
                'scrollZoom': False,
                'doubleClick': False
            }
            
            return self._convert_to_html(fig, chart_config)
            
        except Exception as e:
            logger.error(f"Failed to create attack types chart: {e}")
            return self._create_error_chart("Attack Types Per Month", str(e))
    
    def create_attack_volume_trends(self, monthly_data: Dict[str, Any]) -> str:
        """
        Create line charts for attack volume metrics over time.
        
        Args:
            monthly_data: Dictionary containing monthly statistics
            
        Returns:
            HTML string of the chart
        """
        try:
            if not monthly_data.get('has_trends', False):
                return self._create_no_data_chart("Attack Volume Trends", monthly_data.get('reason', 'No data available'))
            
            months = list(monthly_data['months'].keys())
            month_labels = [monthly_data['months'][month]['month_name'] for month in months]
            
            # Extract volume and packet metrics
            total_mbits = [monthly_data['months'][month]['total_mbits'] for month in months]
            total_packets = [monthly_data['months'][month]['total_packets'] for month in months]
            max_pps = [monthly_data['months'][month]['max_pps'] for month in months]
            max_bps = [monthly_data['months'][month]['max_bps'] for month in months]
            
            # Convert volume to configured unit
            volume_config = VOLUME_UNIT_CONFIGS[VOLUME_UNIT]
            # Convert Mbits to bytes first (divide by 8), then to target unit
            total_volume = [mbits / 8 / volume_config['divider'] for mbits in total_mbits]
            
            # Convert packets to configured unit
            packet_config = PACKET_UNIT_CONFIGS[PACKET_UNIT]
            converted_packets = [packets / packet_config['divider'] for packets in total_packets]
            
            # Convert max_bps to configured bandwidth unit
            bandwidth_config = get_bandwidth_unit_config()
            max_bandwidth_values = [bps / bandwidth_config['divider'] for bps in max_bps]
            
            # Create subplots with 4 rows now
            fig = make_subplots(
                rows=4, cols=1,
                subplot_titles=(
                    volume_config['chart_title'], 
                    packet_config['chart_title'],
                    'Attack Max PPS', 
                    bandwidth_config['chart_title']
                ),
                vertical_spacing=0.10,
                row_heights=[0.25, 0.25, 0.25, 0.25]
            )
            
            # Get chart type and style from configuration
            chart_type = self._get_chart_type('attack_volume_trends')
            chart_style = self.get_chart_style('attack_volume_trends')
            
            # Check if trend lines should be shown
            show_trend = chart_style.get('show_trend', False)
            
            # Create numeric x values for trend calculations
            x_numeric = list(range(len(month_labels)))
            
            # Total Volume in configured unit (Row 1)
            volume_trace = self._create_trace_by_type(
                chart_type=chart_type,
                chart_name='attack_volume_trends',
                x_data=month_labels,
                y_data=total_volume,
                color_key='volume',
                name=f'Total {volume_config["display_name"]}',
                hovertemplate=f'<b>%{{x}}</b><br>Total {volume_config["display_name"]}: %{{y:,.2f}}<extra></extra>'
            )
            fig.add_trace(volume_trace, row=1, col=1)
            
            # Add trend line for volume if enabled
            if show_trend and len(month_labels) > 1:
                try:
                    import numpy as np
                    # Linear regression
                    z = np.polyfit(x_numeric, total_volume, 1)
                    trend_line = np.poly1d(z)
                    trend_values = [trend_line(x) for x in x_numeric]
                    
                    trend_trace = go.Scatter(
                        x=month_labels,
                        y=trend_values,
                        mode='lines',
                        name='Trend',
                        line=dict(color='rgba(255, 107, 53, 0.8)', width=2, dash='dash'),
                        hovertemplate='<b>%{x}</b><br>Trend: %{y:,.2f}<extra></extra>'
                    )
                    fig.add_trace(trend_trace, row=1, col=1)
                except ImportError:
                    # Fallback to simple moving average
                    if len(total_volume) >= 3:
                        trend_values = [sum(total_volume[max(0, i-1):min(len(total_volume), i+2)]) / 
                                      len(total_volume[max(0, i-1):min(len(total_volume), i+2)]) 
                                      for i in range(len(total_volume))]
                        trend_trace = go.Scatter(
                            x=month_labels,
                            y=trend_values,
                            mode='lines',
                            name='Trend',
                            line=dict(color='rgba(255, 107, 53, 0.8)', width=2, dash='dash'),
                            hovertemplate='<b>%{x}</b><br>Trend: %{y:,.2f}<extra></extra>'
                        )
                        fig.add_trace(trend_trace, row=1, col=1)
            
            # Total Packets in configured unit (Row 2) 
            packets_trace = self._create_trace_by_type(
                chart_type=chart_type,
                chart_name='attack_volume_trends',
                x_data=month_labels,
                y_data=converted_packets,
                color_key='packets',
                name=f'Total Packets {packet_config["display_name"]}',
                hovertemplate=f'<b>%{{x}}</b><br>Packets {packet_config["display_name"]}: %{{y:,.2f}}<extra></extra>'
            )
            fig.add_trace(packets_trace, row=2, col=1)
            
            # Add trend line for packets if enabled
            if show_trend and len(month_labels) > 1:
                try:
                    import numpy as np
                    z = np.polyfit(x_numeric, converted_packets, 1)
                    trend_line = np.poly1d(z)
                    trend_values = [trend_line(x) for x in x_numeric]
                    
                    trend_trace = go.Scatter(
                        x=month_labels,
                        y=trend_values,
                        mode='lines',
                        name='Trend',
                        line=dict(color='rgba(255, 107, 53, 0.8)', width=2, dash='dash'),
                        hovertemplate=f'<b>%{{x}}</b><br>Trend: %{{y:,.2f}}<extra></extra>'
                    )
                    fig.add_trace(trend_trace, row=2, col=1)
                except ImportError:
                    if len(converted_packets) >= 3:
                        trend_values = [sum(converted_packets[max(0, i-1):min(len(converted_packets), i+2)]) / 
                                      len(converted_packets[max(0, i-1):min(len(converted_packets), i+2)]) 
                                      for i in range(len(converted_packets))]
                        trend_trace = go.Scatter(
                            x=month_labels,
                            y=trend_values,
                            mode='lines',
                            name='Trend',
                            line=dict(color='rgba(255, 107, 53, 0.8)', width=2, dash='dash'),
                            hovertemplate=f'<b>%{{x}}</b><br>Trend: %{{y:,.2f}}<extra></extra>'
                        )
                        fig.add_trace(trend_trace, row=2, col=1)
            
            # Max PPS (Row 3)
            pps_trace = self._create_trace_by_type(
                chart_type=chart_type,
                chart_name='attack_volume_trends',
                x_data=month_labels,
                y_data=max_pps,
                color_key='pps',
                name='Max PPS',
                hovertemplate='<b>%{x}</b><br>Max PPS: %{y:,.0f}<extra></extra>'
            )
            fig.add_trace(pps_trace, row=3, col=1)
            
            # Add trend line for PPS if enabled
            if show_trend and len(month_labels) > 1:
                try:
                    import numpy as np
                    z = np.polyfit(x_numeric, max_pps, 1)
                    trend_line = np.poly1d(z)
                    trend_values = [trend_line(x) for x in x_numeric]
                    
                    trend_trace = go.Scatter(
                        x=month_labels,
                        y=trend_values,
                        mode='lines',
                        name='Trend',
                        line=dict(color='rgba(255, 107, 53, 0.8)', width=2, dash='dash'),
                        hovertemplate='<b>%{x}</b><br>Trend: %{y:,.0f}<extra></extra>'
                    )
                    fig.add_trace(trend_trace, row=3, col=1)
                except ImportError:
                    if len(max_pps) >= 3:
                        trend_values = [sum(max_pps[max(0, i-1):min(len(max_pps), i+2)]) / 
                                      len(max_pps[max(0, i-1):min(len(max_pps), i+2)]) 
                                      for i in range(len(max_pps))]
                        trend_trace = go.Scatter(
                            x=month_labels,
                            y=trend_values,
                            mode='lines',
                            name='Trend',
                            line=dict(color='rgba(255, 107, 53, 0.8)', width=2, dash='dash'),
                            hovertemplate='<b>%{x}</b><br>Trend: %{y:,.0f}<extra></extra>'
                        )
                        fig.add_trace(trend_trace, row=3, col=1)
            
            # Max bandwidth (Row 4)
            bandwidth_trace = self._create_trace_by_type(
                chart_type=chart_type,
                chart_name='attack_volume_trends',
                x_data=month_labels,
                y_data=max_bandwidth_values,
                color_key='bandwidth',
                name=bandwidth_config['chart_name'],
                hovertemplate=bandwidth_config['hover_template']
            )
            fig.add_trace(bandwidth_trace, row=4, col=1)
            
            # Add trend line for bandwidth if enabled
            if show_trend and len(month_labels) > 1:
                try:
                    import numpy as np
                    z = np.polyfit(x_numeric, max_bandwidth_values, 1)
                    trend_line = np.poly1d(z)
                    trend_values = [trend_line(x) for x in x_numeric]
                    
                    trend_trace = go.Scatter(
                        x=month_labels,
                        y=trend_values,
                        mode='lines',
                        name='Trend',
                        line=dict(color='rgba(255, 107, 53, 0.8)', width=2, dash='dash'),
                        hovertemplate=bandwidth_config['hover_template'].replace('Max ', 'Trend: ')
                    )
                    fig.add_trace(trend_trace, row=4, col=1)
                except ImportError:
                    if len(max_bandwidth_values) >= 3:
                        trend_values = [sum(max_bandwidth_values[max(0, i-1):min(len(max_bandwidth_values), i+2)]) / 
                                      len(max_bandwidth_values[max(0, i-1):min(len(max_bandwidth_values), i+2)]) 
                                      for i in range(len(max_bandwidth_values))]
                        trend_trace = go.Scatter(
                            x=month_labels,
                            y=trend_values,
                            mode='lines',
                            name='Trend',
                            line=dict(color='rgba(255, 107, 53, 0.8)', width=2, dash='dash'),
                            hovertemplate=bandwidth_config['hover_template'].replace('Max ', 'Trend: ')
                        )
                        fig.add_trace(trend_trace, row=4, col=1)
            
            # Add margin for bar charts with outside text positioning
            show_values = chart_style.get('show_values', False)
            if chart_type == 'bar' and show_values:
                # Calculate max values for each subplot and add 15% margin
                max_volume = max(total_volume) if total_volume else 0
                max_packets = max(converted_packets) if converted_packets else 0
                max_pps_val = max(max_pps) if max_pps else 0
                max_bandwidth = max(max_bandwidth_values) if max_bandwidth_values else 0
                
                # Update each subplot's y-axis range with margin
                if max_volume > 0:
                    fig.update_yaxes(range=[0, max_volume * 1.15], row=1, col=1)
                if max_packets > 0:
                    fig.update_yaxes(range=[0, max_packets * 1.15], row=2, col=1)
                if max_pps_val > 0:
                    fig.update_yaxes(range=[0, max_pps_val * 1.15], row=3, col=1)
                if max_bandwidth > 0:
                    fig.update_yaxes(range=[0, max_bandwidth * 1.15], row=4, col=1)
            
            # Update layout to match monthly events styling
            layout = self.base_layout.copy()
            layout.update({
                'title': {
                    'text': 'Attack Volume Trends Over Time',
                    'font': {'size': 18, 'color': '#000000'},
                    'x': 0.5
                },
                'height': 1700,  # Increased height for 4 subplots
                'showlegend': False,
                'legend': {
                    'orientation': 'h',
                    'yanchor': 'bottom',
                    'y': -0.08,
                    'xanchor': 'center',
                    'x': 0.5,
                    'font': {'size': 11}
                },
                'hovermode': 'x unified'
            })
            
            fig.update_layout(layout)
            
            # Update axes to match monthly events styling
            fig.update_xaxes(showgrid=True, gridcolor='#f0f0f0', fixedrange=True)
            fig.update_yaxes(showgrid=True, gridcolor='#f0f0f0', fixedrange=True)
            
            # Bar chart config - disable all zoom
            bar_config = {
                'displayModeBar': False,
                'responsive': True,
                'scrollZoom': False,
                'doubleClick': False
            }
            
            return self._convert_to_html(fig, bar_config)
            
        except Exception as e:
            logger.error(f"Failed to create attack volume trends: {e}")
            return self._create_error_chart("Attack Volume Trends", str(e))
    
    def create_hourly_heatmap(self, monthly_data: Dict[str, Any]) -> str:
        """
        Create a heatmap showing attack intensity by month and hour of day.
        
        Args:
            monthly_data: Dictionary with monthly statistics
            
        Returns:
            HTML string of the chart
        """
        try:
            if not monthly_data.get('has_trends', False):
                return self._create_no_data_chart("Attack Intensity Heatmap", monthly_data.get('reason', 'No data available'))
            
            months = list(monthly_data['months'].keys())
            month_labels = [monthly_data['months'][month]['month_name'] for month in months]
            
            # Create matrix for heatmap (months x hours)
            heatmap_data = []
            for month in months:
                hourly_dist = monthly_data['months'][month]['hourly_distribution']
                heatmap_data.append(hourly_dist)
            
            hours = list(range(24))
            
            # Get colorscale from color assignments configuration
            color_assignment_key = 'hourly_heatmap_colors'
            colorscale = 'Blues'  # Default
            if color_assignment_key in self.color_assignments:
                chart_colors = self.color_assignments[color_assignment_key]
                if isinstance(chart_colors, dict) and 'colorscale' in chart_colors:
                    colorscale = chart_colors['colorscale']
            
            fig = go.Figure(data=go.Heatmap(
                z=heatmap_data,
                x=hours,
                y=month_labels,
                colorscale=colorscale,  # Use configured colorscale
                hovertemplate='<b>%{y}</b><br>Hour: %{x}:00<br>Events: %{z:,}<extra></extra>',
                colorbar=dict(title='Number of Events')
            ))
            
            layout = self.base_layout.copy()
            layout.update({
                'title': {
                    'text': 'Attack Intensity by Month and Hour of Day',
                    'font': {'size': 18, 'color': '#000000'},
                    'x': 0.5
                },
                'xaxis': {
                    'title': 'Hour of Day',
                    'tickvals': list(range(0, 24, 2)),
                    'ticktext': [f'{h:02d}:00' for h in range(0, 24, 2)]
                },
                'yaxis': {'title': 'Month'},
                'height': 400
            })
            
            fig.update_layout(layout)
            
            return self._convert_to_html(fig)
            
        except Exception as e:
            logger.error(f"Failed to create hourly heatmap: {e}")
            return self._create_error_chart("Hourly Attack Heatmap", str(e))
    
    def create_attack_type_pie_chart(self, holistic_data: Dict[str, Any], top_n: int = 10) -> str:
        """
        Create a chart showing attack type distribution (pie, donut, bar, or horizontal bar).
        
        Args:
            holistic_data: Dictionary with holistic analysis data
            top_n: Number of top attack types to show
            
        Returns:
            HTML string of the chart
        """
        try:
            attack_types = holistic_data.get('attack_types', {})
            
            if not attack_types:
                return self._create_no_data_chart("Attack Type Distribution", "No attack data available")
            
            # Get top attack types
            attack_counts = {}
            for attack, attack_info in attack_types.items():
                if isinstance(attack_info, dict):
                    count = attack_info.get('count', 0)
                else:
                    # Handle old format (just count)
                    count = attack_info
                attack_counts[attack] = count
            
            # Get chart type and style configuration first to check sort order
            chart_type = self._get_chart_type('attack_type_distribution')
            chart_style = self.get_chart_style('attack_type_distribution', chart_type)
            
            # Apply sort order from configuration
            sort_order = chart_style.get('sort_values', 'descending')
            reverse_sort = (sort_order == 'descending')
            
            sorted_attacks = sorted(attack_counts.items(), key=lambda x: x[1], reverse=reverse_sort)
            top_attacks = sorted_attacks[:top_n]
            
            # Group remaining attacks as "Others"
            if len(sorted_attacks) > top_n:
                others_count = sum(count for _, count in sorted_attacks[top_n:])
                top_attacks.append(("Others", others_count))
            
            labels = [attack[0] for attack in top_attacks]
            values = [attack[1] for attack in top_attacks]
            colors = self._get_chart_colors_list('attack_type_distribution')[:len(labels)]
            # If we need more colors than provided, extend with palette colors
            if len(colors) < len(labels):
                colors.extend(self.active_palette[len(colors):len(labels)])
            
            # Handle bar charts
            if chart_type in ['bar', 'horizontal_bar']:
                orientation = chart_style.get('orientation', 'vertical')
                show_values = chart_style.get('show_values', True)
                values_text_size = chart_style.get('values_text_size', 11)
                
                if orientation == 'horizontal':
                    # Horizontal bar chart - reverse order so top value is at top
                    labels_reversed = list(reversed(labels))
                    values_reversed = list(reversed(values))
                    colors_reversed = list(reversed(colors))
                    
                    bar_trace = go.Bar(
                        x=values_reversed,
                        y=labels_reversed,
                        orientation='h',
                        marker=dict(color=colors_reversed),
                        hovertemplate='<b>%{y}</b><br>Events: %{x:,}<extra></extra>'
                    )
                    
                    if show_values:
                        bar_trace.text = [f'{val:,}' for val in values_reversed]
                        bar_trace.textposition = 'outside'
                        bar_trace.textfont = dict(size=values_text_size)
                    
                    fig = go.Figure(data=[bar_trace])
                    
                    layout = self.base_layout.copy()
                    layout.update({
                        'title': {
                            'text': 'Attack Type Distribution',
                            'font': {'size': 18, 'color': '#000000'},
                            'x': 0.5
                        },
                        'xaxis': {'title': 'Number of Events'},
                        'yaxis': {'title': 'Attack Type'},
                        'showlegend': False,
                        'height': max(400, len(labels) * 40)  # Dynamic height based on number of items
                    })
                    
                    fig.update_layout(layout)
                    fig.update_xaxes(fixedrange=True)
                    fig.update_yaxes(fixedrange=True)
                    
                else:
                    # Vertical bar chart
                    bar_trace = go.Bar(
                        x=labels,
                        y=values,
                        marker=dict(color=colors),
                        hovertemplate='<b>%{x}</b><br>Events: %{y:,}<extra></extra>'
                    )
                    
                    if show_values:
                        bar_trace.text = [f'{val:,}' for val in values]
                        bar_trace.textposition = 'outside'
                        bar_trace.textfont = dict(size=values_text_size)
                    
                    fig = go.Figure(data=[bar_trace])
                    
                    # Add margin for bar charts with outside text
                    max_value = max(values) if values else 0
                    
                    layout = self.base_layout.copy()
                    layout.update({
                        'title': {
                            'text': 'Attack Type Distribution',
                            'font': {'size': 18, 'color': '#000000'},
                            'x': 0.5
                        },
                        'xaxis': {'title': 'Attack Type'},
                        'yaxis': {
                            'title': 'Number of Events',
                            'range': [0, max_value * 1.15] if show_values and max_value > 0 else None
                        },
                        'showlegend': False,
                        'height': 500
                    })
                    
                    fig.update_layout(layout)
                    fig.update_xaxes(fixedrange=True)
                    fig.update_yaxes(fixedrange=True)
                
                bar_config = {
                    'displayModeBar': False,
                    'responsive': True,
                    'scrollZoom': False,
                    'doubleClick': False
                }
                
                return self._convert_to_html(fig, bar_config)
            
            # Handle pie/donut charts
            # Handle pie/donut charts
            else:
                hole_size = chart_style.get('hole', 0.4)
                textinfo = chart_style.get('textinfo', 'label+percent')
                textposition = chart_style.get('textposition', 'outside')
                
                # Build texttemplate based on textinfo configuration
                if textinfo == 'label+percent':
                    texttemplate = '%{label}, %{percent}'
                elif textinfo == 'percent':
                    texttemplate = '%{percent}'
                elif textinfo == 'label':
                    texttemplate = '%{label}'
                elif textinfo == 'value':
                    texttemplate = '%{value}'
                elif textinfo == 'label+value':
                    texttemplate = '%{label}, %{value}'
                else:
                    # Default to label+percent for any other value
                    texttemplate = '%{label}, %{percent}'
                
                fig = go.Figure(data=[go.Pie(
                    labels=labels,
                    values=values,
                    hole=hole_size,  # Use configured hole size
                    marker=dict(colors=colors),
                    textposition=textposition,  # Use configured text position
                    texttemplate=texttemplate,  # Dynamic based on textinfo config
                    textfont=dict(size=11),  # Smaller text to fit better
                    hovertemplate='<b>%{label}</b><br>Events: %{value:,}<br>Percentage: %{percent}<extra></extra>',
                    # Prevent text overlap by using pull for small slices
                    pull=[0.1 if value / sum(values) < 0.05 else 0 for value in values],
                    # Move the pie chart further left to avoid title overlap
                    domain={'x': [0.0, 0.55], 'y': [0.1, 0.9]}  # Move pie chart further left
                )])
                
                layout = self.base_layout.copy()
                layout.update({
                    'title': {
                        'text': 'Attack Type Distribution',
                        'font': {'size': 18, 'color': '#000000'},
                        'x': 0.5,
                        'y': 0.95  # Keep title high
                    },
                    'showlegend': True,
                    'legend': {
                        'orientation': 'v',
                        'yanchor': 'middle',
                        'y': 0.5,
                        'xanchor': 'left',
                        'x': 10  # Adjust legend position for moved pie chart
                    },
                    'height': 600,
                    'margin': {'t': 80, 'b': 40, 'l': 10, 'r': 120}  # Adjusted margins - less left margin, more right for legend
                })
                
                fig.update_layout(layout)
                
                return self._convert_to_html(fig)
            
        except Exception as e:
            logger.error(f"Failed to create attack type pie chart: {e}")
            return self._create_error_chart("Attack Type Distribution", str(e))
    
    def create_top_source_ips_bar(self, holistic_data: Dict[str, Any], top_n: int = 20) -> str:
        """
        Create a bar chart showing top source IPs (supports both vertical and horizontal).
        
        Args:
            holistic_data: Dictionary with holistic analysis data
            top_n: Number of top IPs to show
            
        Returns:
            HTML string of the chart
        """
        try:
            source_ips = holistic_data.get('top_source_ips', {})
            
            if not source_ips:
                return self._create_no_data_chart("Top Source IPs", "No source IP data available")
            
            # Get chart type and configuration
            chart_type = self._get_chart_type('top_source_ips')
            chart_style = self.get_chart_style('top_source_ips', chart_type)
            
            # Get top IPs (already sorted in data processing)
            top_ips = list(source_ips.items())[:top_n]
            
            # Apply sort order from configuration
            sort_order = chart_style.get('sort_values', 'descending')
            if sort_order == 'descending':
                top_ips = sorted(top_ips, key=lambda x: x[1], reverse=True)
            else:
                top_ips = sorted(top_ips, key=lambda x: x[1], reverse=False)
            
            ips = [ip[0] for ip in top_ips]
            counts = [ip[1] for ip in top_ips]
            
            # Get configuration options
            show_values = chart_style.get('show_values', True)
            values_text_size = chart_style.get('values_text_size', 11)
            color = self._get_chart_color('top_source_ips', 'primary')
            
            if chart_type == 'horizontal_bar':
                # Horizontal bar chart - reverse for top-to-bottom display
                ips_reversed = list(reversed(ips))
                counts_reversed = list(reversed(counts))
                
                bar_trace = go.Bar(
                    x=counts_reversed,
                    y=ips_reversed,
                    orientation='h',
                    marker=dict(color=color),
                    hovertemplate='<b>%{y}</b><br>Events: %{x:,}<extra></extra>'
                )
                
                if show_values:
                    bar_trace.text = [f'{val:,}' for val in counts_reversed]
                    bar_trace.textposition = 'outside'
                    bar_trace.textfont = dict(size=values_text_size)
                
                fig = go.Figure(data=[bar_trace])
                
                layout = self.base_layout.copy()
                layout.update({
                    'title': {
                        'text': f'Top {min(len(ips), top_n)} Source IP Addresses',
                        'font': {'size': 18, 'color': '#000000'},
                        'x': 0.5
                    },
                    'xaxis': {'title': 'Number of Events'},
                    'yaxis': {'title': 'Source IP Address'},
                    'height': max(400, len(ips) * 25),
                    'showlegend': False
                })
            else:
                # Vertical bar chart
                bar_trace = go.Bar(
                    x=ips,
                    y=counts,
                    marker=dict(color=color),
                    hovertemplate='<b>%{x}</b><br>Events: %{y:,}<extra></extra>'
                )
                
                if show_values:
                    bar_trace.text = [f'{val:,}' for val in counts]
                    bar_trace.textposition = 'outside'
                    bar_trace.textfont = dict(size=values_text_size)
                
                fig = go.Figure(data=[bar_trace])
                
                # Add margin if showing values outside
                if show_values:
                    self._add_bar_chart_margin(fig, counts, 'bar', True)
                
                layout = self.base_layout.copy()
                layout.update({
                    'title': {
                        'text': f'Top {min(len(ips), top_n)} Source IP Addresses',
                        'font': {'size': 18, 'color': '#000000'},
                        'x': 0.5
                    },
                    'xaxis': {'title': 'Source IP Address'},
                    'yaxis': {'title': 'Number of Events'},
                    'height': 500,
                    'showlegend': False
                })
            
            fig.update_layout(layout)
            
            # Disable zoom on axes for bar charts
            fig.update_xaxes(fixedrange=True)
            fig.update_yaxes(fixedrange=True)
            
            # Bar chart config - disable all zoom
            bar_config = {
                'displayModeBar': False,
                'responsive': True,
                'scrollZoom': False,
                'doubleClick': False
            }
            
            return self._convert_to_html(fig, bar_config)
            
        except Exception as e:
            logger.error(f"Failed to create top source IPs bar chart: {e}")
            return self._create_error_chart("Top Source IPs", str(e))
    
    def create_protocol_distribution_chart(self, holistic_data: Dict[str, Any]) -> str:
        """
        Create a bar chart showing protocol distribution (supports both vertical and horizontal).
        
        Args:
            holistic_data: Dictionary with holistic analysis data
            
        Returns:
            HTML string of the chart
        """
        try:
            protocols = holistic_data.get('protocols', {})
            
            if not protocols:
                return self._create_no_data_chart("Protocol Distribution", "No protocol data available")
            
            # Get chart type and configuration
            chart_type = self._get_chart_type('protocol_distribution')
            chart_style = self.get_chart_style('protocol_distribution', chart_type)
            
            # Apply sort order from configuration
            sort_order = chart_style.get('sort_values', 'descending')
            reverse_sort = (sort_order == 'descending')
            
            # Sort protocols by count
            sorted_protocols = sorted(protocols.items(), key=lambda x: x[1], reverse=reverse_sort)
            
            protocol_names = [p[0] for p in sorted_protocols]
            protocol_counts = [p[1] for p in sorted_protocols]
            
            # Get configuration options
            show_values = chart_style.get('show_values', True)
            values_text_size = chart_style.get('values_text_size', 11)
            color = self._get_chart_color('protocol_distribution', 'primary')
            
            if chart_type == 'horizontal_bar':
                # Horizontal bar chart - reverse for top-to-bottom display
                names_reversed = list(reversed(protocol_names))
                counts_reversed = list(reversed(protocol_counts))
                
                bar_trace = go.Bar(
                    x=counts_reversed,
                    y=names_reversed,
                    orientation='h',
                    marker=dict(color=color),
                    hovertemplate='<b>%{y}</b><br>Events: %{x:,}<extra></extra>'
                )
                
                if show_values:
                    bar_trace.text = [f'{val:,}' for val in counts_reversed]
                    bar_trace.textposition = 'outside'
                    bar_trace.textfont = dict(size=values_text_size)
                
                fig = go.Figure(data=[bar_trace])
                
                layout = self.base_layout.copy()
                layout.update({
                    'title': {
                        'text': 'Attack Distribution by Protocol',
                        'font': {'size': 18, 'color': '#000000'},
                        'x': 0.5
                    },
                    'xaxis': {'title': 'Number of Events'},
                    'yaxis': {'title': 'Protocol'},
                    'height': max(400, len(protocol_names) * 25),
                    'showlegend': False
                })
            else:
                # Vertical bar chart
                bar_trace = go.Bar(
                    x=protocol_names,
                    y=protocol_counts,
                    marker=dict(color=color),
                    hovertemplate='<b>%{x}</b><br>Events: %{y:,}<extra></extra>'
                )
                
                if show_values:
                    bar_trace.text = [f'{val:,}' for val in protocol_counts]
                    bar_trace.textposition = 'outside'
                    bar_trace.textfont = dict(size=values_text_size)
                
                fig = go.Figure(data=[bar_trace])
                
                # Add margin if showing values outside
                if show_values:
                    self._add_bar_chart_margin(fig, protocol_counts, 'bar', True)
                
                layout = self.base_layout.copy()
                layout.update({
                    'title': {
                        'text': 'Attack Distribution by Protocol',
                        'font': {'size': 18, 'color': '#000000'},
                        'x': 0.5
                    },
                    'xaxis': {'title': 'Protocol'},
                    'yaxis': {'title': 'Number of Events'},
                    'height': 500,
                    'showlegend': False
                })
            
            fig.update_layout(layout)
            
            # Disable zoom on axes for bar charts
            fig.update_xaxes(fixedrange=True)
            fig.update_yaxes(fixedrange=True)
            
            # Bar chart config - disable all zoom
            bar_config = {
                'displayModeBar': False,
                'responsive': True,
                'scrollZoom': False,
                'doubleClick': False
            }
            
            return self._convert_to_html(fig, bar_config)
            
        except Exception as e:
            logger.error(f"Failed to create protocol distribution chart: {e}")
            return self._create_error_chart("Protocol Distribution", str(e))
    
    def create_daily_timeline_chart(self, holistic_data: Dict[str, Any]) -> str:
        """
        Create a timeline chart showing daily attack events.
        
        Args:
            holistic_data: Dictionary with holistic analysis data
            
        Returns:
            HTML string of the chart
        """
        try:
            daily_data = holistic_data.get('daily_distribution', {})
            
            if not daily_data:
                return self._create_no_data_chart("Daily Attack Timeline", "No daily data available")
            
            # Sort dates
            sorted_dates = sorted(daily_data.items())
            dates = [datetime.strptime(date_str, '%Y-%m-%d') for date_str, _ in sorted_dates]
            counts = [count for _, count in sorted_dates]
            
            # Get chart type and style configuration
            chart_type = self._get_chart_type('daily_timeline')
            chart_style = self.get_chart_style('daily_timeline', chart_type)
            
            # Get configuration values with defaults
            line_width = chart_style.get('line_width', 2)
            marker_size = chart_style.get('marker_size', 4)
            mode = chart_style.get('mode', 'lines+markers')
            
            # Create scatter trace based on chart type
            scatter_trace = go.Scatter(
                x=dates,
                y=counts,
                mode=mode,  # Use configured mode
                line=dict(color=self._get_chart_color('daily_timeline', 'primary'), width=line_width),
                marker=dict(size=marker_size),
                hovertemplate='<b>%{x|%Y-%m-%d}</b><br>Events: %{y:,}<extra></extra>'
            )
            
            # Add fill ONLY for area chart type
            if chart_type == 'area':
                scatter_trace.fill = 'tonexty'
                scatter_trace.fillcolor = f'rgba(0, 63, 127, 0.1)'
            
            fig = go.Figure(data=[scatter_trace])
            
            layout = self.base_layout.copy()
            layout.update({
                'title': {
                    'text': 'Daily Attack Events Timeline',
                    'font': {'size': 18, 'color': '#000000'},
                    'x': 0.5
                },
                'xaxis': {
                    'title': 'Date',
                    'showgrid': True,
                    'gridcolor': '#f0f0f0'
                },
                'yaxis': {
                    'title': 'Number of Events',
                    'showgrid': True,
                    'gridcolor': '#f0f0f0'
                },
                'showlegend': False
            })
            
            fig.update_layout(layout)
            
            # Disable vertical zoom but keep horizontal zoom for timeline
            fig.update_yaxes(fixedrange=True)  # Disable vertical zoom
            
            # Timeline config - disable vertical zoom but keep horizontal zoom
            timeline_config = {
                'displayModeBar': False,
                'responsive': True,
                'scrollZoom': 'x',  # Only horizontal zoom
                'doubleClick': 'reset+autosize'
            }
            
            return self._convert_to_html(fig, timeline_config)
            
        except Exception as e:
            logger.error(f"Failed to create daily timeline chart: {e}")
            return self._create_error_chart("Daily Timeline", str(e))
    
    def create_summary_statistics_table(self, holistic_data: Dict[str, Any], monthly_data: Dict[str, Any]) -> str:
        """
        Create an HTML table with summary statistics.
        
        Args:
            holistic_data: Dictionary with holistic analysis data
            monthly_data: Dictionary with monthly analysis data
            
        Returns:
            HTML string of the statistics table
        """
        try:
            date_range = holistic_data.get('date_range', {})
            volume_config = VOLUME_UNIT_CONFIGS[VOLUME_UNIT]
            packet_config = PACKET_UNIT_CONFIGS[PACKET_UNIT]
            
            # Convert volume to configured unit (Mbits to bytes first, then to target unit)
            total_volume_converted = holistic_data.get('total_mbits', 0) / 8 / volume_config['divider']
            
            # Convert packets to configured unit
            total_packets_converted = holistic_data.get('total_packets', 0) / packet_config['divider']
            
            # Prepare stats with special handling for expandable fields
            # Regular stats (non-expandable)
            stats = [
                ("Total Security Events", format_number(holistic_data.get('total_events', 0))),
                ("Total Days", format_number(date_range.get('days', 0))),
                (volume_config['stats_label'], f"{total_volume_converted:,.2f}"),
                (packet_config['stats_label'], f"{total_packets_converted:,.2f}")
            ]
            
            # Expandable stats data
            expandable_stats = [
                {
                    'label': 'Unique Attack Source IPs',
                    'value': format_number(holistic_data.get('unique_source_ips', 0)),
                    'details': holistic_data.get('unique_source_ips_list', []),
                    'id': 'unique-source-ips-details',
                    'type': 'list'
                },
                {
                    'label': 'Unique Attacked Destination IPs', 
                    'value': format_number(holistic_data.get('unique_dest_ips', 0)),
                    'details': holistic_data.get('unique_dest_ips_list', []),
                    'id': 'unique-dest-ips-details',
                    'type': 'list'
                },
                {
                    'label': 'Unique Attack Types',
                    'value': format_number(len(holistic_data.get('attack_types', {}))),
                    'details': holistic_data.get('attack_types_details', []),
                    'id': 'unique-attack-types-details', 
                    'type': 'attack_types_details'
                },
                {
                    'label': 'Attack Max PPS',
                    'value': format_number(holistic_data.get('max_pps', 0)),
                    'details': holistic_data.get('max_pps_details'),
                    'id': 'max-pps-details',
                    'type': 'attack_details'
                },
                {
                    'label': get_bandwidth_unit_config()['stats_label'], 
                    'value': f"{format_number(round(holistic_data.get('max_bps', 0) / get_bandwidth_unit_config()['divider'], 2))} {get_bandwidth_unit_config()['unit_name']}",
                    'details': holistic_data.get('max_bps_details'),
                    'id': 'max-bps-details',
                    'type': 'attack_details'
                },
                {
                    'label': 'Complete Months for Trends',
                    'value': format_number(len(monthly_data.get('months', {}))),
                    'details': self._convert_month_keys_to_names(monthly_data.get('months', {})) if monthly_data.get('months') else [],
                    'id': 'months-trends-details',
                    'type': 'list'
                }
            ]
            
            # Special expandable field for Longest Attack Duration
            longest_attack_details = holistic_data.get('longest_attack_details')
            longest_attack_duration = holistic_data.get('longest_attack_duration', '00:00:00')
            
            html = """
            <div class="stats-grid">
            """
            
            # Add regular (non-expandable) stats
            for label, value in stats:
                html += f"""
                <div class="stat-card">
                    <div class="stat-value">{value}</div>
                    <div class="stat-label">{label}</div>
                </div>
                """
            
            # Add expandable stats
            for stat_config in expandable_stats:
                if stat_config['type'] == 'list' and stat_config['details']:
                    # Create list of (display_name, value) tuples for list-type expandables
                    details_list = [(item, item) for item in stat_config['details']]
                    html += self.create_expandable_stat_card_for_custom_data(
                        stat_config['label'],
                        stat_config['value'],
                        details_list,
                        stat_config['id']
                    )
                elif stat_config['type'] == 'attack_types_details' and stat_config['details']:
                    # For attack types with threat categories, format as (threat_category, attack_name) tuples
                    html += self.create_expandable_stat_card_for_custom_data(
                        stat_config['label'],
                        stat_config['value'],
                        stat_config['details'],  # Already in (threat_category, attack_name) format
                        stat_config['id']
                    )
                elif stat_config['type'] == 'attack_details' and stat_config['details']:
                    # For attack details, use the existing method
                    html += self._create_expandable_stat_card(
                        stat_config['label'],
                        stat_config['value'],
                        stat_config['details'],
                        stat_config['id']
                    )
                else:
                    # Fallback to regular card if no details available
                    html += f"""
                    <div class="stat-card">
                        <div class="stat-value">{stat_config['value']}</div>
                        <div class="stat-label">{stat_config['label']}</div>
                    </div>
                    """
            
            # Add expandable Longest Attack Duration card
            if longest_attack_details:
                html += self._create_expandable_stat_card(
                    "Longest Attack Duration",
                    longest_attack_duration,
                    longest_attack_details,
                    "longest-attack-details"
                )
            else:
                html += f"""
                <div class="stat-card">
                    <div class="stat-value">{longest_attack_duration}</div>
                    <div class="stat-label">Longest Attack Duration</div>
                </div>
                """
            
            html += """
            </div>
            """
            
            return html
            
        except Exception as e:
            logger.error(f"Failed to create summary statistics table: {e}")
            return f'<div class="warning">Failed to generate summary statistics: {e}</div>'
    
    def _create_no_data_chart(self, title: str, message: str) -> str:
        """
        Create a placeholder chart for when no data is available.
        
        Args:
            title: Chart title
            message: Message to display
            
        Returns:
            HTML string of placeholder chart
        """
        fig = go.Figure()
        
        fig.add_annotation(
            x=0.5, y=0.5,
            xref="paper", yref="paper",
            text=message,
            showarrow=False,
            font=dict(size=16, color='#000000'),
            align="center"
        )
        
        layout = self.base_layout.copy()
        layout.update({
            'title': {
                'text': title,
                'font': {'size': 18, 'color': '#000000'},
                'x': 0.5
            },
            'xaxis': {'visible': False},
            'yaxis': {'visible': False},
            'height': 300
        })
        
        fig.update_layout(layout)
        
        return self._convert_to_html(fig)
    
    def _create_error_chart(self, title: str, error: str) -> str:
        """
        Create an error chart when chart generation fails.
        
        Args:
            title: Chart title
            error: Error message
            
        Returns:
            HTML string of error chart
        """
        return f"""
        <div class="chart-container">
            <h3>{title}</h3>
            <div class="warning">
                <strong>Error generating chart:</strong> {error}
            </div>
        </div>
        """
    
    def _create_expandable_stat_card(self, label: str, value: str, details_data: Dict[str, Any], details_id: str) -> str:
        """
        Create an expandable stat card with detailed information.
        
        Args:
            label: Display label for the stat
            value: Main value to display
            details_data: Dictionary containing detailed information
            details_id: Unique ID for the expandable section
            
        Returns:
            HTML string for expandable stat card
        """
        if not details_data or not details_data.get('details'):
            # Return normal stat card if no details available
            return f"""
                <div class="stat-card">
                    <div class="stat-value">{value}</div>
                    <div class="stat-label">{label}</div>
                </div>
                """
        
        # Extract relevant details for display
        attack_details = details_data['details']
        
        # Define the fields we want to display
        display_fields = [
            ('Start Time', 'Start Time'),
            ('End Time', 'End Time'),
            ('Device IP Address', 'Device IP Address'),
            ('Attack Name', 'Attack Name'),
            ('Policy Name', 'Policy Name'),
            ('Action', 'Action'),
            ('Attack ID', 'Attack ID'),
            ('Source IP Address', 'Source IP Address'),
            ('Source Port', 'Source Port'),
            ('Destination IP Address', 'Destination IP Address'),
            ('Protocol', 'Protocol'),
            ('Max pps', 'Max pps'),
            ('Max bps', 'Max bps')
        ]
        
        # Build details HTML
        details_html = ""
        for display_name, field_key in display_fields:
            field_value = attack_details.get(field_key, 'N/A')
            if field_value is None or str(field_value) == 'nan':
                field_value = 'N/A'
            details_html += f"""
                <div class="detail-row">
                    <span class="detail-label">{display_name}:</span>
                    <span class="detail-value">{field_value}</span>
                </div>
            """
        
        return f"""
            <div class="stat-card expandable-card">
                <div class="stat-value expandable-trigger" onclick="toggleDetails('{details_id}')" style="cursor: pointer; position: relative;">
                    {value}
                    <span class="expand-icon" id="{details_id}-icon">▼</span>
                </div>
                <div class="stat-label">{label} <small style="color: #6c757d;">(click to expand)</small></div>
                <div id="{details_id}" class="attack-details">
                    <div class="details-container">
                        <h4 style="margin: 0 0 10px 0; color: #003f7f; font-size: 14px;">Attack Details</h4>
                        {details_html}
                    </div>
                </div>
            </div>
        """
    
    def create_expandable_stat_card_for_custom_data(self, label: str, value: str, custom_fields: List[tuple], details_id: str) -> str:
        """
        Create an expandable stat card with custom field data.
        
        This is a helper method for creating expandable cards for other fields like 
        "Top Source IP", "Highest Volume Attack", etc.
        
        Args:
            label: Display label for the stat
            value: Main value to display  
            custom_fields: List of (display_name, field_value) tuples for the details
            details_id: Unique ID for the expandable section
            
        Returns:
            HTML string for expandable stat card
            
        Example usage:
            custom_fields = [
                ('Attack Name', 'DDoS Flood'),
                ('Source IP', '192.168.1.100'),
                ('Volume (MB)', '1,250.5'),
                ('Duration', '2h:15m:30s')
            ]
            html = visualizer.create_expandable_stat_card_for_custom_data(
                "Highest Volume Attack", "1,250.5 MB", custom_fields, "highest-volume-attack"
            )
        """
        if not custom_fields:
            # Return normal stat card if no details available
            return f"""
                <div class="stat-card">
                    <div class="stat-value">{value}</div>
                    <div class="stat-label">{label}</div>
                </div>
                """
        
        # Check if this is a simple list (all tuples have same display_name as field_value)
        is_simple_list = all(display_name == field_value for display_name, field_value in custom_fields)
        
        if is_simple_list:
            # Create compact list format - single block with all values (no duplicate label)
            values_list = [str(field_value) for display_name, field_value in custom_fields if field_value and str(field_value) != 'N/A']
            details_html = f"""
                <div class="detail-value" style="white-space: pre-line; margin: 0; padding: 0;">{chr(10).join(values_list)}</div>
            """
        else:
            # Build details HTML from custom fields (for non-list data)
            details_html = ""
            for display_name, field_value in custom_fields:
                if field_value is None or str(field_value) == 'nan':
                    field_value = 'N/A'
                details_html += f"""
                    <div class="detail-row">
                        <span class="detail-label">{display_name}:</span>
                        <span class="detail-value">{field_value}</span>
                    </div>
                """
        
        return f"""
            <div class="stat-card expandable-card">
                <div class="stat-value expandable-trigger" onclick="toggleDetails('{details_id}')" style="cursor: pointer; position: relative;">
                    {value}
                    <span class="expand-icon" id="{details_id}-icon">▼</span>
                </div>
                <div class="stat-label">{label} <small style="color: #6c757d;">(click to expand)</small></div>
                <div id="{details_id}" class="attack-details">
                    <div class="details-container">
                        <h4 style="margin: 0 0 10px 0; color: #003f7f; font-size: 14px;">Details</h4>
                        {details_html}
                    </div>
                </div>
            </div>
        """
    
    def _convert_month_keys_to_names(self, months_dict: dict) -> list:
        """
        Convert month keys like '2025-08' to readable month names like 'August 2025'.
        
        Args:
            months_dict: Dictionary with month keys in YYYY-MM format
            
        Returns:
            List of readable month names sorted chronologically
        """
        import datetime
        
        month_names = []
        for month_key in sorted(months_dict.keys()):
            try:
                # Parse the month key (format: YYYY-MM)
                year, month = month_key.split('-')
                # Create a date object to get the month name
                date_obj = datetime.date(int(year), int(month), 1)
                # Format as "Month Year" (e.g., "August 2025")
                month_name = date_obj.strftime('%B %Y')
                month_names.append(month_name)
            except (ValueError, IndexError):
                # Fallback to original key if parsing fails
                month_names.append(month_key)
        
        return month_names

    def get_chart_type(self, chart_name: str) -> str:
        """
        Get configured chart type for a specific chart.
        
        Args:
            chart_name: Name of chart in CHART_PREFERENCES
            
        Returns:
            Chart type string
        """
        # Get default type from CHART_PREFERENCES
        if chart_name in self.chart_preferences and 'default_type' in self.chart_preferences[chart_name]:
            return self.chart_preferences[chart_name]['default_type']
        return 'bar'
    
    def get_chart_color(self, chart_name: str, color_key: str = 'primary', fallback_index: int = 0) -> str:
        """
        Get color for a specific chart element.
        
        Args:
            chart_name: Name of the chart (e.g., 'monthly_trends', 'attack_type')
            color_key: Specific color key (e.g., 'primary', 'volume', 'packets')
            fallback_index: Index in palette to use as fallback
            
        Returns:
            Color string (hex code)
        """
        return self._get_chart_color(chart_name, color_key, fallback_index)
    
    def get_chart_colors_list(self, chart_name: str) -> List[str]:
        """
        Get list of colors for a chart that needs multiple colors.
        
        Args:
            chart_name: Name of the chart
            
        Returns:
            List of color strings
        """
        return self._get_chart_colors_list(chart_name)
    
    def get_active_color_palette(self) -> List[str]:
        """
        Get the currently active color palette.
        
        Returns:
            List of color strings
        """
        return self.active_palette.copy()
    
    def get_chart_style(self, chart_name: str, chart_type: str = None) -> Dict[str, Any]:
        """
        Get style configuration for a specific chart.
        
        Args:
            chart_name: Name of the chart
            chart_type: Type of chart (if None, uses configured type)
            
        Returns:
            Dictionary with style configuration
        """
        if chart_type is None:
            chart_type = self._get_chart_type(chart_name)
        
        # Check for chart-specific preferences first
        if chart_name in self.chart_preferences:
            chart_prefs = self.chart_preferences[chart_name]
            if isinstance(chart_prefs, dict) and chart_type in chart_prefs:
                return chart_prefs[chart_type]
        
        # Fall back to type-specific preferences (e.g., 'line_charts', 'bar_charts')
        type_category = f"{chart_type}_charts"
        if type_category in self.chart_preferences:
            return self.chart_preferences[type_category]
            
        # Default empty dict if no configuration found
        return {}
    
    def get_chart_preferences(self, chart_name: str = None) -> Dict[str, Any]:
        """
        Get chart preferences for a specific chart or all charts.
        
        Args:
            chart_name: Name of chart (None for all charts)
            
        Returns:
            Dictionary with chart preferences
        """
        if chart_name:
            return self.chart_preferences.get(chart_name, {})
        return self.chart_preferences.copy()
    
    def create_top_attacks_by_max_bps_bar(self, holistic_data: Dict[str, Any], top_n: int = 5) -> str:
        """
        Create a bar chart showing top N individual attacks by maximum BPS (supports both vertical and horizontal).
        
        Args:
            holistic_data: Dictionary with holistic analysis data
            top_n: Number of top attacks to show
            
        Returns:
            HTML string of the chart
        """
        try:
            top_attacks_list = holistic_data.get('top_attacks_by_bps', [])
            
            if not top_attacks_list:
                return self._create_no_data_chart("Top Attacks by Max BPS", "No BPS data available for attacks")
            
            # Get chart type and configuration
            chart_type = self._get_chart_type('top_attacks_max_bps')
            chart_style = self.get_chart_style('top_attacks_max_bps', chart_type)
            
            # Apply sort order from configuration
            sort_order = chart_style.get('sort_values', 'descending')
            if sort_order == 'ascending':
                top_attacks_list = sorted(top_attacks_list, key=lambda x: x[1])[:top_n]
            else:
                top_attacks_list = top_attacks_list[:top_n]  # Already sorted descending
            
            # Extract attack names and BPS values
            # Make labels unique by adding invisible zero-width spaces to prevent stacking
            attack_labels = []
            max_bps_values = []
            hover_texts = []
            for idx, (attack_name, bps, details) in enumerate(top_attacks_list):
                # Add invisible zero-width spaces to make each label unique (prevents bar stacking)
                # These are invisible but make Plotly treat each bar as separate
                unique_label = attack_name + ('\u200b' * idx)  # Zero-width space
                attack_labels.append(unique_label)
                max_bps_values.append(bps)
                # Build hover text with timestamp
                start_time = details.get('start_time', 'N/A')
                hover_text = f"<b>{attack_name}</b><br>Time: {start_time}"
                hover_texts.append(hover_text)
            
            # Convert to configured bandwidth unit
            bandwidth_config = get_bandwidth_unit_config()
            converted_bps = [bps / bandwidth_config['divider'] for bps in max_bps_values]
            
            # Get configuration options
            show_values = chart_style.get('show_values', True)
            values_text_size = chart_style.get('values_text_size', 11)
            color = self._get_chart_color('top_attacks_max_bps', 'primary')
            
            if chart_type == 'horizontal_bar':
                # Horizontal bar chart - reverse for top-to-bottom display
                names_reversed = list(reversed(attack_labels))
                bps_reversed = list(reversed(converted_bps))
                hover_reversed = list(reversed(hover_texts))
                
                bar_trace = go.Bar(
                    x=bps_reversed,
                    y=names_reversed,
                    orientation='h',
                    marker=dict(color=color),
                    hovertext=hover_reversed,
                    hovertemplate=f'%{{hovertext}}<br>Max {bandwidth_config["unit_name"]}: %{{x:,.2f}}<extra></extra>'
                )
                
                if show_values:
                    bar_trace.text = [f'{val:,.2f}' for val in bps_reversed]
                    bar_trace.textposition = 'outside'
                    bar_trace.textfont = dict(size=values_text_size)
                
                fig = go.Figure(data=[bar_trace])
                
                layout = self.base_layout.copy()
                layout.update({
                    'title': {
                        'text': f'Top {top_n} Attacks by Maximum {bandwidth_config["unit_name"]}',
                        'font': {'size': 18, 'color': '#000000'},
                        'x': 0.5
                    },
                    'xaxis': {'title': f'Maximum {bandwidth_config["unit_name"]}'},
                    'yaxis': {'title': 'Attack Name'},
                    'height': max(400, len(attack_labels) * 35),
                    'showlegend': False
                })
            else:
                # Vertical bar chart
                bar_trace = go.Bar(
                    x=attack_labels,
                    y=converted_bps,
                    marker=dict(color=color),
                    hovertext=hover_texts,
                    hovertemplate=f'%{{hovertext}}<br>Max {bandwidth_config["unit_name"]}: %{{y:,.2f}}<extra></extra>'
                )
                
                if show_values:
                    bar_trace.text = [f'{val:,.2f}' for val in converted_bps]
                    bar_trace.textposition = 'outside'
                    bar_trace.textfont = dict(size=values_text_size)
                
                fig = go.Figure(data=[bar_trace])
                
                # Add margin if showing values outside
                if show_values:
                    self._add_bar_chart_margin(fig, converted_bps, 'bar', True)
                
                layout = self.base_layout.copy()
                layout.update({
                    'title': {
                        'text': f'Top {top_n} Attacks by Maximum {bandwidth_config["unit_name"]}',
                        'font': {'size': 18, 'color': '#000000'},
                        'x': 0.5
                    },
                    'xaxis': {'title': 'Attack Name'},
                    'yaxis': {'title': f'Maximum {bandwidth_config["unit_name"]}'},
                    'height': 500,
                    'showlegend': False
                })
            
            fig.update_layout(layout)
            
            # Disable zoom on axes for bar charts
            fig.update_xaxes(fixedrange=True)
            fig.update_yaxes(fixedrange=True)
            
            # Bar chart config - disable all zoom
            bar_config = {
                'displayModeBar': False,
                'responsive': True,
                'scrollZoom': False,
                'doubleClick': False
            }
            
            return self._convert_to_html(fig, bar_config)
            
        except Exception as e:
            logger.error(f"Failed to create top attacks by max BPS bar chart: {e}")
            return self._create_error_chart("Top Attacks by Max BPS", str(e))
    
    def create_top_attacks_by_max_pps_bar(self, holistic_data: Dict[str, Any], top_n: int = 5) -> str:
        """
        Create a bar chart showing top N individual attacks by maximum PPS (supports both vertical and horizontal).
        
        Args:
            holistic_data: Dictionary with holistic analysis data
            top_n: Number of top attacks to show
            
        Returns:
            HTML string of the chart
        """
        try:
            top_attacks_list = holistic_data.get('top_attacks_by_pps', [])
            
            if not top_attacks_list:
                return self._create_no_data_chart("Top Attacks by Max PPS", "No PPS data available for attacks")
            
            # Get chart type and configuration
            chart_type = self._get_chart_type('top_attacks_max_pps')
            chart_style = self.get_chart_style('top_attacks_max_pps', chart_type)
            
            # Apply sort order from configuration
            sort_order = chart_style.get('sort_values', 'descending')
            if sort_order == 'ascending':
                top_attacks_list = sorted(top_attacks_list, key=lambda x: x[1])[:top_n]
            else:
                top_attacks_list = top_attacks_list[:top_n]  # Already sorted descending
            
            # Extract attack names and PPS values
            # Make labels unique by adding invisible zero-width spaces to prevent stacking
            attack_labels = []
            max_pps_values = []
            hover_texts = []
            for idx, (attack_name, pps, details) in enumerate(top_attacks_list):
                # Add invisible zero-width spaces to make each label unique (prevents bar stacking)
                # These are invisible but make Plotly treat each bar as separate
                unique_label = attack_name + ('\u200b' * idx)  # Zero-width space
                attack_labels.append(unique_label)
                max_pps_values.append(pps)
                # Build hover text with timestamp
                start_time = details.get('start_time', 'N/A')
                hover_text = f"<b>{attack_name}</b><br>Time: {start_time}"
                hover_texts.append(hover_text)
            
            # Get configuration options
            show_values = chart_style.get('show_values', True)
            values_text_size = chart_style.get('values_text_size', 11)
            color = self._get_chart_color('top_attacks_max_pps', 'primary')
            
            if chart_type == 'horizontal_bar':
                # Horizontal bar chart - reverse for top-to-bottom display
                names_reversed = list(reversed(attack_labels))
                pps_reversed = list(reversed(max_pps_values))
                hover_reversed = list(reversed(hover_texts))
                
                bar_trace = go.Bar(
                    x=pps_reversed,
                    y=names_reversed,
                    orientation='h',
                    marker=dict(color=color),
                    hovertext=hover_reversed,
                    hovertemplate='%{hovertext}<br>Max PPS: %{x:,.0f}<extra></extra>'
                )
                
                if show_values:
                    bar_trace.text = [f'{val:,.0f}' for val in pps_reversed]
                    bar_trace.textposition = 'outside'
                    bar_trace.textfont = dict(size=values_text_size)
                
                fig = go.Figure(data=[bar_trace])
                
                layout = self.base_layout.copy()
                layout.update({
                    'title': {
                        'text': f'Top {top_n} Attacks by Maximum PPS',
                        'font': {'size': 18, 'color': '#000000'},
                        'x': 0.5
                    },
                    'xaxis': {'title': 'Maximum PPS'},
                    'yaxis': {'title': 'Attack Name'},
                    'height': max(400, len(attack_labels) * 35),
                    'showlegend': False
                })
            else:
                # Vertical bar chart
                bar_trace = go.Bar(
                    x=attack_labels,
                    y=max_pps_values,
                    marker=dict(color=color),
                    hovertext=hover_texts,
                    hovertemplate='%{hovertext}<br>Max PPS: %{y:,.0f}<extra></extra>'
                )
                
                if show_values:
                    bar_trace.text = [f'{val:,.0f}' for val in max_pps_values]
                    bar_trace.textposition = 'outside'
                    bar_trace.textfont = dict(size=values_text_size)
                
                fig = go.Figure(data=[bar_trace])
                
                # Add margin if showing values outside
                if show_values:
                    self._add_bar_chart_margin(fig, max_pps_values, 'bar', True)
                
                layout = self.base_layout.copy()
                layout.update({
                    'title': {
                        'text': f'Top {top_n} Attacks by Maximum PPS',
                        'font': {'size': 18, 'color': '#000000'},
                        'x': 0.5
                    },
                    'xaxis': {'title': 'Attack Name'},
                    'yaxis': {'title': 'Maximum PPS'},
                    'height': 500,
                    'showlegend': False
                })
            
            fig.update_layout(layout)
            
            # Disable zoom on axes for bar charts
            fig.update_xaxes(fixedrange=True)
            fig.update_yaxes(fixedrange=True)
            
            # Bar chart config - disable all zoom
            bar_config = {
                'displayModeBar': False,
                'responsive': True,
                'scrollZoom': False,
                'doubleClick': False
            }
            
            return self._convert_to_html(fig, bar_config)
            
        except Exception as e:
            logger.error(f"Failed to create top attacks by max PPS bar chart: {e}")
            return self._create_error_chart("Top Attacks by Max PPS", str(e))
    
    def create_security_events_by_policy_pie(self, holistic_data: Dict[str, Any], top_n: int = 10) -> str:
        """
        Create a chart showing security events distribution by policy (pie, donut, bar, or horizontal bar).

        Args:
            holistic_data: Dictionary with holistic analysis data
            top_n: Number of top policies to show
            
        Returns:
            HTML string of the chart
        """
        try:
            policies = holistic_data.get('policies', {})
            
            if not policies:
                return self._create_no_data_chart("Security Events by Policy", "No policy data available")
            
            # Get chart type and style configuration first to check sort order
            chart_type = self._get_chart_type('policy_distribution')
            chart_style = self.get_chart_style('policy_distribution', chart_type)
            
            # Apply sort order from configuration
            sort_order = chart_style.get('sort_values', 'descending')
            reverse_sort = (sort_order == 'descending')
            
            # Get top policies by event count
            sorted_policies = sorted(policies.items(), key=lambda x: x[1], reverse=reverse_sort)
            top_policies = sorted_policies[:top_n]
            
            # Group remaining policies as "Others"
            if len(sorted_policies) > top_n:
                others_count = sum(count for _, count in sorted_policies[top_n:])
                top_policies.append(("Others", others_count))
            
            labels = [policy[0] for policy in top_policies]
            values = [policy[1] for policy in top_policies]
            colors = self._get_chart_colors_list('policy_distribution')[:len(labels)]
            # If we need more colors than provided, extend with palette colors
            if len(colors) < len(labels):
                colors.extend(self.active_palette[len(colors):len(labels)])
            
            # Handle bar charts
            if chart_type in ['bar', 'horizontal_bar']:
                orientation = chart_style.get('orientation', 'vertical')
                show_values = chart_style.get('show_values', True)
                values_text_size = chart_style.get('values_text_size', 11)
                
                if orientation == 'horizontal':
                    # Horizontal bar chart - reverse order so top value is at top
                    labels_reversed = list(reversed(labels))
                    values_reversed = list(reversed(values))
                    colors_reversed = list(reversed(colors))
                    
                    bar_trace = go.Bar(
                        x=values_reversed,
                        y=labels_reversed,
                        orientation='h',
                        marker=dict(color=colors_reversed),
                        hovertemplate='<b>%{y}</b><br>Events: %{x:,}<extra></extra>'
                    )
                    
                    if show_values:
                        bar_trace.text = [f'{val:,}' for val in values_reversed]
                        bar_trace.textposition = 'outside'
                        bar_trace.textfont = dict(size=values_text_size)
                    
                    fig = go.Figure(data=[bar_trace])
                    
                    layout = self.base_layout.copy()
                    layout.update({
                        'title': {
                            'text': f'Security Events by Policy (Top {top_n})',
                            'font': {'size': 18, 'color': '#000000'},
                            'x': 0.5
                        },
                        'xaxis': {'title': 'Number of Events'},
                        'yaxis': {'title': 'Policy'},
                        'showlegend': False,
                        'height': max(400, len(labels) * 40)  # Dynamic height based on number of items
                    })
                    
                    fig.update_layout(layout)
                    fig.update_xaxes(fixedrange=True)
                    fig.update_yaxes(fixedrange=True)
                    
                else:
                    # Vertical bar chart
                    bar_trace = go.Bar(
                        x=labels,
                        y=values,
                        marker=dict(color=colors),
                        hovertemplate='<b>%{x}</b><br>Events: %{y:,}<extra></extra>'
                    )
                    
                    if show_values:
                        bar_trace.text = [f'{val:,}' for val in values]
                        bar_trace.textposition = 'outside'
                        bar_trace.textfont = dict(size=values_text_size)
                    
                    fig = go.Figure(data=[bar_trace])
                    
                    # Add margin for bar charts with outside text
                    max_value = max(values) if values else 0
                    
                    layout = self.base_layout.copy()
                    layout.update({
                        'title': {
                            'text': f'Security Events by Policy (Top {top_n})',
                            'font': {'size': 18, 'color': '#000000'},
                            'x': 0.5
                        },
                        'xaxis': {'title': 'Policy'},
                        'yaxis': {
                            'title': 'Number of Events',
                            'range': [0, max_value * 1.15] if show_values and max_value > 0 else None
                        },
                        'showlegend': False,
                        'height': 500
                    })
                    
                    fig.update_layout(layout)
                    fig.update_xaxes(fixedrange=True)
                    fig.update_yaxes(fixedrange=True)
                
                bar_config = {
                    'displayModeBar': False,
                    'responsive': True,
                    'scrollZoom': False,
                    'doubleClick': False
                }
                
                return self._convert_to_html(fig, bar_config)
            
            # Handle pie/donut charts
            else:
                hole_size = chart_style.get('hole', 0.4)
                textinfo = chart_style.get('textinfo', 'label+percent')
                textposition = chart_style.get('textposition', 'outside')
                
                # Build texttemplate based on textinfo configuration
                if textinfo == 'label+percent':
                    texttemplate = '%{label}, %{percent}'
                elif textinfo == 'percent':
                    texttemplate = '%{percent}'
                elif textinfo == 'label':
                    texttemplate = '%{label}'
                elif textinfo == 'value':
                    texttemplate = '%{value}'
                elif textinfo == 'label+value':
                    texttemplate = '%{label}, %{value}'
                else:
                    # Default to label+percent for any other value
                    texttemplate = '%{label}, %{percent}'
                
                fig = go.Figure(data=[go.Pie(
                    labels=labels,
                    values=values,
                    hole=hole_size,  # Use configured hole size
                    marker=dict(colors=colors),
                    textposition=textposition,  # Use configured text position
                    texttemplate=texttemplate,  # Dynamic based on textinfo config
                    textfont=dict(size=11),  # Smaller text to fit better
                    hovertemplate='<b>%{label}</b><br>Events: %{value:,}<br>Percentage: %{percent}<extra></extra>',
                    # Prevent text overlap by using pull for small slices
                    pull=[0.1 if value / sum(values) < 0.05 else 0 for value in values],
                    # Move the pie chart further left to avoid title overlap
                    domain={'x': [0.0, 0.55], 'y': [0.1, 0.9]}  # Move pie chart further left
                )])
                
                layout = self.base_layout.copy()
                layout.update({
                    'title': {
                        'text': f'Security Events by Policy (Top {top_n})',
                        'font': {'size': 18, 'color': '#000000'},
                        'x': 0.5,
                        'y': 0.95  # Keep title high
                    },
                    'showlegend': True,
                    'legend': {
                        'orientation': 'v',
                        'yanchor': 'middle',
                        'y': 0.5,
                        'xanchor': 'left',
                        'x': 0.65  # Adjust legend position for moved pie chart
                    },
                    'height': 600,
                    'margin': {'t': 80, 'b': 40, 'l': 10, 'r': 120}  # Adjusted margins - less left margin, more right for legend
                })
                
                fig.update_layout(layout)
                
                return self._convert_to_html(fig)
            
        except Exception as e:
            logger.error(f"Failed to create security events by policy pie chart: {e}")
            return self._create_error_chart("Security Events by Policy", str(e))

    def get_available_chart_types(self, chart_name: str = None) -> Dict[str, List[str]]:
        """
        Get available chart types for a specific chart or all charts.
        
        Args:
            chart_name: Name of chart (None for all charts)
            
        Returns:
            Dictionary with available chart types
        """
        # Get available types based on CHART_PREFERENCES configuration
        available_types = {}
        for name, config in self.chart_preferences.items():
            if isinstance(config, dict):
                # Get all type keys except 'default_type'
                types = [key for key in config.keys() if key != 'default_type']
                available_types[name] = types
        
        if chart_name:
            return {chart_name: available_types.get(chart_name, [])}
        return available_types.copy()
    
    def reset_chart_preferences(self, chart_name: str = None) -> bool:
        """
        Reset chart preferences to defaults.
        
        Args:
            chart_name: Name of chart to reset (None for all charts)
            
        Returns:
            True if reset successful, False otherwise
        """
        try:
            if chart_name:
                if chart_name in self.chart_preferences and 'default_type' in self.chart_preferences[chart_name]:
                    # Reset to default chart type for this chart
                    default_type = self.chart_preferences[chart_name]['default_type']
                    self.chart_preferences[chart_name] = {'type': default_type}
                    logger.info(f"Reset chart preferences for {chart_name} to type: {default_type}")
                else:
                    logger.warning(f"No chart configuration found for {chart_name}")
                    return False
            else:
                # Reset all preferences to default types
                original_prefs = self.chart_preferences.copy()
                self.chart_preferences = {}
                for name, config in original_prefs.items():
                    if 'default_type' in config:
                        self.chart_preferences[name] = {'type': config['default_type']}
                logger.info("Reset all chart preferences to default types")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to reset chart preferences: {e}")
            return False
