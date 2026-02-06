# SentinelRAG 🛡️

A production-ready security intelligence engine. Query CVE vulnerabilities using natural language, powered by RAG with LangChain and pgvector.

## Features

- **Semantic Search**: Query 330,000+ CVEs using natural language
- **Real-time Ingestion**: Automated CVE fetching from NVD API
- **LangSmith Tracing**: Full observability for debugging and evaluation
- **Flexible LLM**: Works with Ollama, OpenAI, or any compatible endpoint

## Tech Stack

| Component | Technology |
|-----------|------------|
| Frontend | Streamlit |
| Orchestration | LangChain |
| Database | Neon Postgres + pgvector |
| Embeddings | nomic-embed-text-v1.5 |
| Observability | LangSmith |

---

## Quick Start

### Prerequisites

- [uv](https://docs.astral.sh/uv/) (Python package manager)
- [Neon](https://neon.tech/) account (free Postgres with pgvector)
- [LangSmith](https://smith.langchain.com/) account (free tracing)
- [NVD API Key](https://nvd.nist.gov/developers/request-an-api-key) (free, optional but recommended)

### 1. Clone & Configure

```bash
git clone https://github.com/yourusername/SentinelRAG.git
cd SentinelRAG

# Copy environment template
cp .env.example .env
```

Edit `.env` with your credentials:

```env
# LLM (OpenAI-compatible endpoint)
OPENAI_API_KEY=your-api-key
OPENAI_BASE_URL=https://api.synthetic.new/v1
LLM_MODEL=llama3.2
EMBEDDING_MODEL=hf:nomic-ai/nomic-embed-text-v1.5

# Database (from Neon dashboard)
NEON_DATABASE_URL=postgresql://user:pass@host.neon.tech/db?sslmode=require

# LangSmith (Settings → Access Tokens)
LANGSMITH_API_KEY=lsv2_pt_xxxxx
LANGSMITH_PROJECT=SentinelRAG-dev
LANGCHAIN_TRACING_V2=true

# NVD API (optional - 10x faster ingestion)
NVD_API_KEY=your-nvd-key
```

### 2. Install Dependencies

```bash
uv sync
```

### 3. Initialize Database

```bash
uv run python src/db_setup.py
```

You should see:
```
✅ Connected to Neon Postgres database.
📦 Enabling pgvector extension...
📊 Creating vulnerabilities table...
✅ Database setup complete!
```

### 4. Ingest CVE Data

**Quick test (last 7 days, ~750 CVEs):**
```bash
uv run python src/cve_ingestion.py --recent --days 7
```

**Full database (all 330k CVEs, ~30 min with API key):**
```bash
uv run python src/cve_ingestion.py --full
```

### 5. Run the App

```bash
uv run streamlit run app.py
```

Open http://localhost:8501 and start querying!

---

## Example Queries

- "What are the most critical vulnerabilities in Apache Log4j?"
- "Show me recent CVEs affecting Windows with remote code execution"
- "Find SQL injection vulnerabilities in web frameworks"

---

## Project Structure

```
SentinelRAG/
├── app.py                 # Streamlit UI
├── src/
│   ├── config.py          # Environment configuration
│   ├── db_setup.py        # Database initialization
│   ├── cve_ingestion.py   # NVD CVE fetcher
│   └── rag_chain.py       # LangChain RAG pipeline
├── .env.example           # Environment template
├── pyproject.toml         # Dependencies (uv)
└── GEMINI.md              # Project memory & architecture
```

---

## Deployment

For Railway or Streamlit Cloud, set the same environment variables as secrets. Use `LANGSMITH_PROJECT=SentinelRAG-prod` for production traces.

---

## License

MIT
