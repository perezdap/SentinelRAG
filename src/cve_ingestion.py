"""
SentinelRAG - CVE Ingestion Script

Fetches CVEs from the NVD API 2.0 and stores them in the Postgres database
with vector embeddings for semantic search.

Usage:
    uv run python src/cve_ingestion.py --full          # Initial full load
    uv run python src/cve_ingestion.py --recent        # Last 7 days (default)
    uv run python src/cve_ingestion.py --recent --days 30  # Custom window
"""

import argparse
import sys
import time
from datetime import datetime, timedelta, timezone
from typing import Generator

import psycopg2
from psycopg2.extras import execute_values
import requests

from src.config import config


# ============================================================================
# NVD API Client
# ============================================================================

class NVDClient:
    """Client for the NVD API 2.0 with rate limiting and pagination."""
    
    def __init__(self):
        self.base_url = config.NVD_BASE_URL
        self.api_key = config.NVD_API_KEY
        self.rate_limit = config.NVD_RATE_LIMIT
        self.results_per_page = 2000
        self._request_times: list[float] = []
    
    def _wait_for_rate_limit(self):
        """Enforce rate limiting (N requests per 30 seconds)."""
        now = time.time()
        # Remove requests older than 30 seconds
        self._request_times = [t for t in self._request_times if now - t < 30]
        
        if len(self._request_times) >= self.rate_limit:
            sleep_time = 30 - (now - self._request_times[0]) + 0.5
            if sleep_time > 0:
                print(f"   ⏳ Rate limit reached, waiting {sleep_time:.1f}s...")
                time.sleep(sleep_time)
        
        self._request_times.append(time.time())
    
    def _make_request(self, params: dict) -> dict:
        """Make a rate-limited request to the NVD API."""
        self._wait_for_rate_limit()
        
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key
        
        response = requests.get(self.base_url, params=params, headers=headers, timeout=60)
        response.raise_for_status()
        return response.json()
    
    def fetch_cves(
        self,
        start_date: datetime | None = None,
        end_date: datetime | None = None
    ) -> Generator[dict, None, None]:
        """
        Fetch CVEs with pagination. Yields individual CVE records.
        
        Args:
            start_date: Filter by lastModStartDate (optional)
            end_date: Filter by lastModEndDate (optional)
        """
        start_index = 0
        total_results = None
        
        while True:
            params = {
                "startIndex": start_index,
                "resultsPerPage": self.results_per_page,
            }
            
            if start_date and end_date:
                params["lastModStartDate"] = start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
                params["lastModEndDate"] = end_date.strftime("%Y-%m-%dT%H:%M:%S.000")
            
            print(f"   📥 Fetching CVEs {start_index} - {start_index + self.results_per_page}...")
            data = self._make_request(params)
            
            if total_results is None:
                total_results = data.get("totalResults", 0)
                print(f"   📊 Total CVEs to fetch: {total_results:,}")
            
            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                break
            
            for vuln in vulnerabilities:
                yield vuln.get("cve", {})
            
            start_index += len(vulnerabilities)
            if start_index >= total_results:
                break


# ============================================================================
# CVE Processing
# ============================================================================

def parse_cve(cve: dict) -> dict:
    """Parse a CVE record into our database schema."""
    cve_id = cve.get("id", "")
    
    # Get English description
    descriptions = cve.get("descriptions", [])
    description = next(
        (d.get("value", "") for d in descriptions if d.get("lang") == "en"),
        ""
    )
    
    # Get CVSS score (prefer v3.1, fallback to v3.0, then v2)
    metrics = cve.get("metrics", {})
    cvss_score = None
    severity = None
    
    for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if version in metrics and metrics[version]:
            metric = metrics[version][0]
            cvss_data = metric.get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            severity = cvss_data.get("baseSeverity") or metric.get("baseSeverity")
            break
    
    # Parse dates
    published = cve.get("published")
    modified = cve.get("lastModified")
    
    # Get affected products (CPE names)
    affected_products = []
    for config_node in cve.get("configurations", []):
        for node in config_node.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable"):
                    affected_products.append(match.get("criteria", ""))
    
    # Get references
    references = [ref.get("url", "") for ref in cve.get("references", [])]
    
    # Create title from CVE ID and truncated description
    title = f"{cve_id}: {description[:200]}..." if len(description) > 200 else f"{cve_id}: {description}"
    
    return {
        "cve_id": cve_id,
        "title": title[:500],
        "description": description,
        "severity": severity,
        "cvss_score": cvss_score,
        "published_date": published,
        "modified_date": modified,
        "affected_products": affected_products[:50],  # Limit array size
        "references": references[:20],
    }


# ============================================================================
# Embedding Generation
# ============================================================================

import openai


def create_embeddings_client() -> openai.OpenAI:
    """Create an OpenAI-compatible embeddings client."""
    return openai.OpenAI(
        api_key=config.OPENAI_API_KEY,
        base_url=config.OPENAI_BASE_URL,
    )


def generate_embedding(client: openai.OpenAI, text: str) -> list[float]:
    """Generate embedding for a single text."""
    if not text:
        return [0.0] * config.EMBEDDING_DIMENSIONS
    
    # Truncate very long texts
    max_chars = 8000
    if len(text) > max_chars:
        text = text[:max_chars]
    
    response = client.embeddings.create(
        model=config.EMBEDDING_MODEL,
        input=text
    )
    return response.data[0].embedding


# ============================================================================
# Database Operations
# ============================================================================

def get_connection():
    """Get database connection."""
    if not config.NEON_DATABASE_URL:
        print("❌ Error: NEON_DATABASE_URL not configured.")
        sys.exit(1)
    
    return psycopg2.connect(config.NEON_DATABASE_URL)


def upsert_cves(conn, cves: list[dict]):
    """Upsert CVEs into the database."""
    if not cves:
        return
    
    cursor = conn.cursor()
    
    # Prepare data for batch insert
    values = [
        (
            cve["cve_id"],
            cve["title"],
            cve["description"],
            cve["severity"],
            cve["cvss_score"],
            cve["published_date"],
            cve["modified_date"],
            cve["affected_products"],
            cve["references"],
            cve["embedding"],
        )
        for cve in cves
    ]
    
    query = """
        INSERT INTO vulnerabilities (
            cve_id, title, description, severity, cvss_score,
            published_date, modified_date, affected_products, "references", embedding
        ) VALUES %s
        ON CONFLICT (cve_id) DO UPDATE SET
            title = EXCLUDED.title,
            description = EXCLUDED.description,
            severity = EXCLUDED.severity,
            cvss_score = EXCLUDED.cvss_score,
            modified_date = EXCLUDED.modified_date,
            affected_products = EXCLUDED.affected_products,
            "references" = EXCLUDED."references",
            embedding = EXCLUDED.embedding
    """
    
    execute_values(cursor, query, values)
    conn.commit()
    cursor.close()


# ============================================================================
# Main Ingestion Logic
# ============================================================================

def ingest_cves(full: bool = False, days: int = 7, batch_size: int = 50):
    """
    Main ingestion function.
    
    Args:
        full: If True, fetch all CVEs. If False, fetch recent only.
        days: Number of days to look back for recent mode.
        batch_size: Number of CVEs to process before database commit.
    """
    print("🚀 SentinelRAG CVE Ingestion")
    print("=" * 50)
    
    # Validate configuration
    missing = config.validate()
    if missing:
        print(f"❌ Missing configuration: {', '.join(missing)}")
        sys.exit(1)
    
    # Show rate limit status
    if config.NVD_API_KEY:
        print(f"✅ NVD API key configured (50 req/30s)")
    else:
        print(f"⚠️  No NVD API key - using slower rate limit (5 req/30s)")
    
    # Initialize clients
    nvd = NVDClient()
    embeddings = create_embeddings_client()
    conn = get_connection()
    
    # Determine date range
    if full:
        print("\n📦 Mode: FULL (all CVEs)")
        start_date = None
        end_date = None
    else:
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=days)
        print(f"\n📦 Mode: RECENT (last {days} days)")
        print(f"   From: {start_date.strftime('%Y-%m-%d')}")
        print(f"   To:   {end_date.strftime('%Y-%m-%d')}")
    
    # Process CVEs
    print("\n🔄 Processing CVEs...")
    batch = []
    total_processed = 0
    total_errors = 0
    
    try:
        for cve_raw in nvd.fetch_cves(start_date, end_date):
            try:
                # Parse CVE
                cve = parse_cve(cve_raw)
                
                # Generate embedding from description
                text_for_embedding = f"{cve['title']}\n\n{cve['description']}"
                cve["embedding"] = generate_embedding(embeddings, text_for_embedding)
                
                batch.append(cve)
                
                # Commit batch
                if len(batch) >= batch_size:
                    upsert_cves(conn, batch)
                    total_processed += len(batch)
                    print(f"   ✅ Processed {total_processed:,} CVEs")
                    batch = []
                    
            except Exception as e:
                total_errors += 1
                print(f"   ⚠️  Error processing {cve_raw.get('id', 'unknown')}: {e}")
        
        # Final batch
        if batch:
            upsert_cves(conn, batch)
            total_processed += len(batch)
    
    finally:
        conn.close()
    
    # Summary
    print("\n" + "=" * 50)
    print("📊 Ingestion Complete!")
    print(f"   ✅ CVEs processed: {total_processed:,}")
    print(f"   ⚠️  Errors: {total_errors}")


# ============================================================================
# CLI Entry Point
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Ingest CVEs from NVD into SentinelRAG database"
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="Fetch all CVEs (initial load, ~30 min with API key)"
    )
    parser.add_argument(
        "--recent",
        action="store_true",
        help="Fetch recently modified CVEs (default)"
    )
    parser.add_argument(
        "--days",
        type=int,
        default=7,
        help="Days to look back for --recent mode (default: 7)"
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=50,
        help="CVEs per database commit (default: 50)"
    )
    
    args = parser.parse_args()
    
    # Default to recent if neither specified
    if not args.full and not args.recent:
        args.recent = True
    
    ingest_cves(
        full=args.full,
        days=args.days,
        batch_size=args.batch_size
    )


if __name__ == "__main__":
    main()
