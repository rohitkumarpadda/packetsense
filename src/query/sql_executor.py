"""
sql_executor.py - Execute SQL queries on Parquet files with DuckDB
"""

import duckdb
import pandas as pd
from pathlib import Path
from typing import Optional, Dict, Any


class SQLExecutor:
    """Execute SQL queries against Parquet packet data."""

    def __init__(self, parquet_path: str):
        """
        Initialize executor with a Parquet file.

        Args:
            parquet_path: Path to .parquet file
        """
        self.parquet_path = Path(parquet_path)
        if not self.parquet_path.exists():
            raise FileNotFoundError(f"Parquet file not found: {parquet_path}")

        # Create in-memory DuckDB connection
        self.conn = duckdb.connect(":memory:")

        # Register the parquet file as a table named 'packets'
        self.conn.execute(
            f"CREATE TABLE packets AS SELECT * FROM read_parquet('{self.parquet_path}')"
        )

    def get_schema(self) -> Dict[str, str]:
        """
        Get the schema of the packets table.

        Returns:
            Dictionary mapping column names to types
        """
        result = self.conn.execute("DESCRIBE packets").fetchall()
        return {row[0]: row[1] for row in result}

    def get_schema_str(self) -> str:
        """
        Get schema as a formatted string for LLM prompts.

        Returns:
            Formatted schema description
        """
        schema = self.get_schema()
        lines = ["Table: packets"]
        lines.append("Columns:")
        for col, dtype in schema.items():
            lines.append(f"  - {col}: {dtype}")
        return "\n".join(lines)

    def execute(self, sql: str) -> pd.DataFrame:
        """
        Execute SQL query and return results as DataFrame.

        Args:
            sql: SQL query string

        Returns:
            Query results as pandas DataFrame
        """
        try:
            result = self.conn.execute(sql).fetchdf()
            return result
        except Exception as e:
            raise RuntimeError(f"Query execution failed: {e}")

    def get_sample_queries(self) -> list:
        """
        Generate sample queries based on available columns.

        Returns:
            List of example SQL queries
        """
        schema = self.get_schema()
        queries = [
            "SELECT COUNT(*) as total_packets FROM packets",
        ]

        # Add protocol-specific queries if columns exist
        if any("src_ip" in col for col in schema):
            queries.append(
                'SELECT DISTINCT "src_ip" as source_ip FROM packets WHERE "src_ip" IS NOT NULL LIMIT 10'
            )

        if any("timestamp" in col for col in schema):
            queries.append('SELECT "timestamp" as timestamp FROM packets LIMIT 10')

        if any("ngap" in col.lower() for col in schema):
            queries.append('SELECT * FROM packets WHERE "proto.ngap" = true LIMIT 5')

        return queries

    def close(self):
        """Close the database connection."""
        self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
