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

### Streamlit Community Cloud (Free)

1. **Push to GitHub:**
   ```bash
   git add .
   git commit -m "Prepare for deployment"
   git push origin main
   ```

2. **Deploy on Streamlit Cloud:**
   - Go to [share.streamlit.io](https://share.streamlit.io)
   - Sign in with GitHub
   - Click **"New app"** → Select your repo
   - Set main file: `app.py`
   - Click **"Deploy"**

3. **Configure Secrets:**
   
   In Streamlit Cloud dashboard → **Settings** → **Secrets**, add:
   ```toml
   OPENAI_API_KEY = "your-api-key"
   OPENAI_BASE_URL = "https://api.synthetic.new/openai/v1"
   LLM_MODEL = "hf:zai-org/GLM-4.7"
   EMBEDDING_MODEL = "hf:nomic-ai/nomic-embed-text-v1.5"
   NEON_DATABASE_URL = "postgresql://user:pass@host.neon.tech/db?sslmode=require"
   LANGSMITH_API_KEY = "lsv2_pt_xxxxx"
   LANGSMITH_PROJECT = "SentinelRAG-prod"
   APP_PASSWORD = "your-secret-password"
   ```

4. **Reboot the app** after adding secrets.

> **Note:** Your Neon database persists across deployments. CVE data only needs to be ingested once.

### Password Protection

Set `APP_PASSWORD` in your secrets to require authentication. Leave empty for open access.

## License

MIT
