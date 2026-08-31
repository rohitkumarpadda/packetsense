"""
llm_client.py - LLM integration for natural language to SQL translation
Supports: Anthropic Claude, OpenAI, Google Gemini, OpenRouter, Ollama (local)
"""

import os
from typing import Optional


class LLMClient:
    """Client for translating natural language queries to SQL."""

    def __init__(self, api_key: Optional[str] = None, provider: str = "anthropic"):
        """
        Initialize LLM client.

        Args:
            api_key: API key (or set via environment variable). Not required for ollama.
            provider: One of 'anthropic', 'openai', 'gemini', 'openrouter', 'ollama'
        """
        self.provider = provider.lower()

        # Ollama doesn't need API key
        if self.provider == "ollama":
            self.api_key = None
        elif api_key:
            self.api_key = api_key
        elif self.provider == "anthropic":
            self.api_key = os.getenv("ANTHROPIC_API_KEY")
        elif self.provider == "openai":
            self.api_key = os.getenv("OPENAI_API_KEY")
        elif self.provider == "gemini":
            self.api_key = os.getenv("GEMINI_API_KEY")
        elif self.provider == "openrouter":
            self.api_key = os.getenv("OPENROUTER_API_KEY")
        else:
            raise ValueError(f"Unknown provider: {provider}")

        if not self.api_key and self.provider != "ollama":
            raise ValueError(
                f"API key not found for {provider}. Set {provider.upper()}_API_KEY environment variable."
            )

        self._init_client()

    def _init_client(self):
        """Initialize the provider-specific client."""
        if self.provider == "anthropic":
            try:
                import anthropic

                self.client = anthropic.Anthropic(api_key=self.api_key)
                self.model = "claude-sonnet-4-20250514"
            except ImportError:
                raise ImportError("Install anthropic: pip install anthropic")

        elif self.provider == "openai":
            try:
                import openai

                self.client = openai.OpenAI(api_key=self.api_key)
                self.model = "gpt-4o"
            except ImportError:
                raise ImportError("Install openai: pip install openai")

        elif self.provider == "gemini":
            try:
                import google.generativeai as genai

                genai.configure(api_key=self.api_key)
                self.client = genai.GenerativeModel("gemini-1.5-flash")
                self.model = "gemini-1.5-flash"
            except ImportError:
                raise ImportError(
                    "Install google-generativeai: pip install google-generativeai"
                )

        elif self.provider == "openrouter":
            try:
                import openai

                self.client = openai.OpenAI(
                    api_key=self.api_key, base_url="https://openrouter.ai/api/v1"
                )
                # Use model from env var or your OpenRouter default routing configuration
                self.model = os.getenv("OPENROUTER_MODEL", "")
            except ImportError:
                raise ImportError("Install openai: pip install openai")

        elif self.provider == "ollama":
            try:
                import openai

                # Ollama uses OpenAI-compatible API
                ollama_url = os.getenv("OLLAMA_URL", "http://localhost:11434/v1")
                self.client = openai.OpenAI(
                    api_key="ollama", base_url=ollama_url  # dummy key, not used
                )
                # Get model from env or use default
                self.model = os.getenv("OLLAMA_MODEL", "llama3.2")
                print(f"[INFO] Using Ollama at {ollama_url} with model {self.model}")
            except ImportError:
                raise ImportError("Install openai: pip install openai")

    def nl_to_sql(
        self, nl_query: str, schema: str, custom_instructions: str = ""
    ) -> str:
        """
        Translate natural language query to SQL.

        Args:
            nl_query: Natural language query from user
            schema: Database schema description
            custom_instructions: Optional instructions (e.g., column mappings)

        Returns:
            SQL query string
        """
        prompt = self._build_prompt(nl_query, schema, custom_instructions)

        try:
            if self.provider == "anthropic":
                response = self.client.messages.create(
                    model=self.model,
                    max_tokens=1024,
                    messages=[{"role": "user", "content": prompt}],
                )
                sql = response.content[0].text

            elif self.provider in ["openai", "openrouter", "ollama"]:
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=1024,
                )
                sql = response.choices[0].message.content

            elif self.provider == "gemini":
                response = self.client.generate_content(prompt)
                sql = response.text

            sql = self._clean_sql(sql)
            return sql

        except Exception as e:
            raise RuntimeError(f"LLM query failed: {e}")

    def explain_results(self, nl_query: str, results: list) -> str:
        """
        Generate a natural language answer based on the query and results.
        """
        # Truncate results if too large to avoid token limits
        data_preview = str(results[:10])
        count = len(results)

        prompt = f"""
        User Question: "{nl_query}"
        Data Results ({count} rows total): {data_preview}
        
        Task: Answer the user's question in natural language based on the data.
        - Be concise.
        - If the result is a number, just state it (e.g., "There are 500 TCP packets").
        - If it's a list, summarize the top items.
        - Do not mention "SQL" or "database".
        
        Answer:"""

        try:
            if self.provider == "anthropic":
                response = self.client.messages.create(
                    model=self.model,
                    max_tokens=200,
                    messages=[{"role": "user", "content": prompt}],
                )
                return response.content[0].text

            elif self.provider == "openai" or self.provider == "openrouter":
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=200,
                )
                return response.choices[0].message.content

            elif self.provider == "gemini":
                response = self.client.generate_content(prompt)
                return response.text

            return "Here are the results."
        except:
            return "I found some data, but couldn't generate a summary."

    def _build_prompt(
        self, nl_query: str, schema: str, custom_instructions: str = ""
    ) -> str:
        """Build the prompt for SQL translation."""
        return f"""You are a SQL query generator for 5G packet capture data stored in DuckDB.

Database Schema:
{schema}

CRITICAL RULES:
- The schema provided above is the GROUND TRUTH. If columns are "ip.src" use that. If "ip.ip.src" use that.
- ALL columns with dots (e.g., "frame.time") MUST be wrapped in double quotes
- ALL columns are stored as VARCHAR/STRING. You MUST CAST for numeric comparisons.
- Example: CAST("frame.len" AS INTEGER) > 100
- Protocol matching MUST use LIKE.
- Example: "frame.protocols" LIKE '%tcp%' (NOT = 'tcp')
- Boolean columns use true/false (lowercase)
- The table name is 'packets' (no quotes needed for table name)
- Use DuckDB SQL syntax
- Generate ONLY the SQL query, no explanations or markdown

Common Logic:
- You MUST use the column names exactly as they appear in the "CURRENT COLUMN MAPPING" below.
- Do NOT guess column names.
- Protocol matching MUST use LIKE (e.g. LIKE '%tcp%').

{custom_instructions}

QUERY BEST PRACTICES:
- For "show me" or "find" queries, SELECT specific columns, NOT *
- Example good query: SELECT "frame.number", "ip.src", "ip.dst" FROM packets
- Example bad query: SELECT * FROM packets (includes huge payload columns)

User Question: {nl_query}

Generate ONLY the SQL query:"""

    def _clean_sql(self, sql: str) -> str:
        """Remove markdown code blocks, backticks, and extra whitespace."""
        sql = sql.strip()
        if sql.startswith("```sql"):
            sql = sql[6:]
        elif sql.startswith("```"):
            sql = sql[3:]
        if sql.endswith("```"):
            sql = sql[:-3]
        return sql.replace("`", "").strip()
