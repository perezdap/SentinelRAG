"""
SentinelRAG - Database Setup Script

Initializes the Neon Postgres database with pgvector extension
and creates the vulnerabilities table for storing embeddings.

Usage:
    python src/db_setup.py
"""

import os
import sys
from dotenv import load_dotenv
import psycopg2
from psycopg2 import sql

from src.config import config


# Load environment variables
load_dotenv()


def get_connection():
    """Create a connection to the Neon Postgres database."""
    database_url = os.getenv("NEON_DATABASE_URL")
    
    if not database_url:
        print("❌ Error: NEON_DATABASE_URL environment variable not set.")
        print("   Copy .env.example to .env and configure your database URL.")
        sys.exit(1)
    
    try:
        conn = psycopg2.connect(database_url)
        print("✅ Connected to Neon Postgres database.")
        return conn
    except psycopg2.Error as e:
        print(f"❌ Database connection failed: {e}")
        sys.exit(1)


def setup_database(conn):
    """Initialize pgvector extension and create vulnerabilities table."""
    cursor = conn.cursor()
    
    try:
        # Enable pgvector extension
        print("📦 Enabling pgvector extension...")
        cursor.execute("CREATE EXTENSION IF NOT EXISTS vector;")
        
        # Create vulnerabilities table with vector column
        print("📊 Creating vulnerabilities table...")
        cursor.execute(f"""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id SERIAL PRIMARY KEY,
                cve_id VARCHAR(20) UNIQUE,
                title VARCHAR(500) NOT NULL,
                description TEXT,
                severity VARCHAR(20),
                cvss_score NUMERIC(3, 1),
                published_date TIMESTAMP,
                modified_date TIMESTAMP,
                affected_products TEXT[],
                "references" TEXT[],
                embedding vector({config.EMBEDDING_DIMENSIONS}),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        
        # Create index for vector similarity search
        print("🔍 Creating vector similarity index...")
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS vulnerabilities_embedding_idx 
            ON vulnerabilities 
            USING ivfflat (embedding vector_cosine_ops)
            WITH (lists = 100);
        """)
        
        conn.commit()
        print("✅ Database setup complete!")
        
        # Show table info
        cursor.execute("""
            SELECT column_name, data_type 
            FROM information_schema.columns 
            WHERE table_name = 'vulnerabilities'
            ORDER BY ordinal_position;
        """)
        
        print("\n📋 Table schema:")
        for row in cursor.fetchall():
            print(f"   - {row[0]}: {row[1]}")
            
    except psycopg2.Error as e:
        conn.rollback()
        print(f"❌ Database setup failed: {e}")
        sys.exit(1)
    finally:
        cursor.close()


def main():
    """Main entry point for database setup."""
    print("🚀 SentinelRAG Database Setup")
    print("=" * 40)
    
    conn = get_connection()
    
    try:
        setup_database(conn)
    finally:
        conn.close()
        print("\n🔒 Connection closed.")


if __name__ == "__main__":
    main()
