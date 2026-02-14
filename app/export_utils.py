"""Export utilities for CSV, JSON, and Excel formats."""
from __future__ import annotations

import csv
import io
import json
from typing import List

from flask import make_response


class ExportHelper:
    """Helper class for exporting data in various formats."""
    
    @staticmethod
    def to_csv_response(data: List[dict], filename: str, fieldnames: List[str]) -> object:
        """
        Export data to CSV format.
        
        Args:
            data: List of dictionaries to export
            filename: Name of the CSV file
            fieldnames: List of field names for CSV header
            
        Returns:
            Flask response object with CSV data
        """
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(data)
        
        response = make_response(output.getvalue())
        response.headers['Content-Type'] = 'text/csv'
        response.headers['Content-Disposition'] = f'attachment; filename={filename}'
        return response
    
    @staticmethod
    def to_json_response(data: List[dict], filename: str) -> object:
        """
        Export data to JSON format.
        
        Args:
            data: List of dictionaries to export
            filename: Name of the JSON file
            
        Returns:
            Flask response object with JSON data
        """
        json_data = json.dumps(data, indent=2, default=str)
        
        response = make_response(json_data)
        response.headers['Content-Type'] = 'application/json'
        response.headers['Content-Disposition'] = f'attachment; filename={filename}'
        return response
    
    @staticmethod
    def to_excel_response(data: List[dict], filename: str, sheet_name: str = 'Sheet1') -> object:
        """
        Export data to Excel format.
        
        Args:
            data: List of dictionaries to export
            filename: Name of the Excel file
            sheet_name: Name of the sheet
            
        Returns:
            Flask response object with Excel data
        """
        try:
            import pandas as pd
            from io import BytesIO
            
            # Create DataFrame
            df = pd.DataFrame(data)
            
            # Create Excel file in memory
            output = BytesIO()
            with pd.ExcelWriter(output, engine='openpyxl') as writer:
                df.to_excel(writer, sheet_name=sheet_name, index=False)
            
            output.seek(0)
            
            response = make_response(output.read())
            response.headers['Content-Type'] = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            response.headers['Content-Disposition'] = f'attachment; filename={filename}'
            return response
            
        except ImportError:
            # Fallback to CSV if pandas/openpyxl not available
            return ExportHelper.to_csv_response(data, filename.replace('.xlsx', '.csv'), list(data[0].keys()) if data else [])
