"""
SentinelRAG - RAG Chain Implementation

LangChain-based RAG pipeline with pgvector retriever for semantic search
over security vulnerabilities.
"""

import os
import re
import openai
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.runnables import RunnablePassthrough, RunnableLambda
from langchain_core.output_parsers import StrOutputParser
from langchain_core.embeddings import Embeddings

from src.config import config


# Enable LangSmith tracing
os.environ["LANGCHAIN_TRACING_V2"] = "true"
os.environ["LANGCHAIN_API_KEY"] = config.LANGSMITH_API_KEY
os.environ["LANGCHAIN_PROJECT"] = config.LANGSMITH_PROJECT


# ============================================================================
# Custom Embeddings for Synthetic.new Compatibility
# ============================================================================

class SyntheticEmbeddings(Embeddings):
    """Custom embeddings wrapper using raw OpenAI client for synthetic.new."""
    
    def __init__(self):
        self.client = openai.OpenAI(
            api_key=config.OPENAI_API_KEY,
            base_url=config.OPENAI_BASE_URL,
        )
        self.model = config.EMBEDDING_MODEL
    
    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        """Embed a list of documents."""
        embeddings = []
        for text in texts:
            if not text:
                embeddings.append([0.0] * config.EMBEDDING_DIMENSIONS)
            else:
                # Truncate long texts
                if len(text) > 8000:
                    text = text[:8000]
                response = self.client.embeddings.create(
                    model=self.model,
                    input=text
                )
                embeddings.append(response.data[0].embedding)
        return embeddings
    
    def embed_query(self, text: str) -> list[float]:
        """Embed a single query."""
        if not text:
            return [0.0] * config.EMBEDDING_DIMENSIONS
        if len(text) > 8000:
            text = text[:8000]
        response = self.client.embeddings.create(
            model=self.model,
            input=text
        )
        return response.data[0].embedding


# ============================================================================
# Component Factories
# ============================================================================

def create_embeddings() -> SyntheticEmbeddings:
    """Create embeddings client for vector similarity search."""
    return SyntheticEmbeddings()


def create_llm() -> ChatOpenAI:
    """Create LLM client for response generation."""
    return ChatOpenAI(
        model=config.LLM_MODEL,
        openai_api_key=config.OPENAI_API_KEY,
        openai_api_base=config.OPENAI_BASE_URL,
        temperature=0.1,  # Low temperature for factual responses
    )


def create_retriever(embeddings: SyntheticEmbeddings, k: int = 5):
    """
    Create a custom retriever for our vulnerabilities table.
    
    Args:
        embeddings: Embeddings client for query vectorization
        k: Number of documents to retrieve
    """
    import psycopg2
    from langchain_core.documents import Document
    from langchain_core.retrievers import BaseRetriever
    from typing import List
    from pydantic import PrivateAttr
    
    class VulnerabilityRetriever(BaseRetriever):
        """Custom retriever that queries the vulnerabilities table directly."""
        
        k: int = 5
        _embeddings: SyntheticEmbeddings = PrivateAttr()
        _connection_string: str = PrivateAttr()
        
        def __init__(self, embeddings: SyntheticEmbeddings, connection_string: str, k: int = 5):
            super().__init__(k=k)
            self._embeddings = embeddings
            self._connection_string = connection_string
        
        @staticmethod
        def _is_recent_query(query: str) -> bool:
            """Detect whether user asked for recency-based results."""
            return bool(re.search(r"\b(recent|latest|newest|most recent|newly published)\b", query.lower()))
        
        @staticmethod
        def _is_generic_recent_query(query: str) -> bool:
            """
            Detect broad recency requests (e.g., "list most recent CVEs")
            where date ordering should be global, not semantic.
            """
            words = re.findall(r"[a-z0-9]+", query.lower())
            if not words:
                return False
            
            stopwords = {
                "do", "you", "have", "a", "an", "the", "of", "for", "to", "in", "on",
                "and", "or", "with", "me", "show", "list", "give", "what", "are", "is",
                "please", "can",
            }
            generic_terms = {
                "cve", "cves", "vulnerability", "vulnerabilities",
                "recent", "latest", "newest", "most", "new", "published",
            }
            
            meaningful = [w for w in words if w not in stopwords]
            if not meaningful:
                return False
            
            return all(w in generic_terms for w in meaningful)
        
        def _get_relevant_documents(self, query: str) -> List[Document]:
            """Retrieve documents similar to the query."""
            is_recent_query = self._is_recent_query(query)
            is_generic_recent_query = self._is_generic_recent_query(query)
            query_embedding = None if is_generic_recent_query else self._embeddings.embed_query(query)
            
            conn = psycopg2.connect(self._connection_string)
            try:
                with conn.cursor() as cur:
                    if is_generic_recent_query:
                        cur.execute("""
                            SELECT
                                cve_id,
                                title,
                                description,
                                severity,
                                cvss_score,
                                published_date,
                                NULL::float as similarity
                            FROM vulnerabilities
                            WHERE cve_id IS NOT NULL
                            ORDER BY published_date DESC NULLS LAST
                            LIMIT %s
                        """, (self.k,))
                    elif is_recent_query:
                        candidate_pool = max(self.k * 40, 200)
                        cur.execute("""
                            WITH semantic_candidates AS (
                                SELECT
                                    cve_id,
                                    title,
                                    description,
                                    severity,
                                    cvss_score,
                                    published_date,
                                    1 - (embedding <=> %s::vector) AS similarity
                                FROM vulnerabilities
                                WHERE embedding IS NOT NULL
                                ORDER BY embedding <=> %s::vector
                                LIMIT %s
                            )
                            SELECT
                                cve_id,
                                title,
                                description,
                                severity,
                                cvss_score,
                                published_date,
                                similarity
                            FROM semantic_candidates
                            ORDER BY published_date DESC NULLS LAST, similarity DESC
                            LIMIT %s
                        """, (str(query_embedding), str(query_embedding), candidate_pool, self.k))
                    else:
                        cur.execute("""
                            SELECT
                                cve_id,
                                title,
                                description,
                                severity,
                                cvss_score,
                                published_date,
                                1 - (embedding <=> %s::vector) as similarity
                            FROM vulnerabilities
                            WHERE embedding IS NOT NULL
                            ORDER BY embedding <=> %s::vector
                            LIMIT %s
                        """, (str(query_embedding), str(query_embedding), self.k))
                    
                    rows = cur.fetchall()
            finally:
                conn.close()
            
            # Convert to LangChain Documents
            documents = []
            for row in rows:
                cve_id, title, description, severity, cvss_score, published_date, similarity = row
                
                # Build document content
                content = f"{title}\n\n{description or 'No description available.'}"
                
                # Build metadata
                metadata = {
                    "cve_id": cve_id,
                    "title": title,
                    "severity": severity,
                    "cvss_score": float(cvss_score) if cvss_score else None,
                    "published_date": str(published_date) if published_date else None,
                    "similarity": float(similarity) if similarity else None,
                }
                
                documents.append(Document(page_content=content, metadata=metadata))
            
            return documents
    
    return VulnerabilityRetriever(
        embeddings=embeddings,
        connection_string=config.NEON_DATABASE_URL,
        k=k
    )


# ============================================================================
# RAG Chain
# ============================================================================

SYSTEM_PROMPT = """You are a security intelligence assistant specializing in CVE analysis.
Your role is to help security professionals understand vulnerabilities, assess risks, 
and recommend mitigations.

When answering questions:
1. Be precise and technical - security professionals need accurate information
2. Always cite CVE IDs when referencing specific vulnerabilities
3. Include CVSS scores and severity ratings when available
4. Suggest practical remediation steps when relevant
5. If information is not in the context, say so clearly
6. For "recent/latest" requests, determine recency using published_date only
7. Never infer recency from CVE ID numbering

Context from vulnerability database:
{context}
"""

USER_PROMPT = """Question: {question}

Based on the vulnerability data provided, give a comprehensive answer. Include specific 
CVE IDs, severity levels, and any relevant technical details."""


def format_docs(docs) -> str:
    """Format retrieved documents for the prompt context."""
    formatted = []
    for i, doc in enumerate(docs, 1):
        content = doc.page_content
        metadata = doc.metadata
        
        # Build context entry
        entry = f"[{i}] {content}"
        
        if metadata.get("cve_id"):
            entry = f"[{i}] CVE: {metadata['cve_id']}\n{content}"
        if metadata.get("severity"):
            entry += f"\nSeverity: {metadata['severity']}"
        if metadata.get("cvss_score"):
            entry += f" (CVSS: {metadata['cvss_score']})"
        if metadata.get("published_date"):
            entry += f"\nPublished: {metadata['published_date']}"
            
        formatted.append(entry)
    
    return "\n\n---\n\n".join(formatted)


def create_rag_chain(k: int = 5):
    """
    Create the complete RAG chain.
    
    Args:
        k: Number of documents to retrieve for context
        
    Returns:
        A runnable chain that takes a question and returns an answer
    """
    # Initialize components
    embeddings = create_embeddings()
    llm = create_llm()
    retriever = create_retriever(embeddings, k=k)
    
    # Build prompt template
    prompt = ChatPromptTemplate.from_messages([
        ("system", SYSTEM_PROMPT),
        ("human", USER_PROMPT),
    ])
    
    # Build chain with LCEL
    chain = (
        {
            "context": retriever | format_docs,
            "question": RunnablePassthrough(),
        }
        | prompt
        | llm
        | StrOutputParser()
    )
    
    return chain


def create_rag_chain_with_sources(k: int = 5):
    """
    Create RAG chain that returns both answer and source documents.
    
    Returns:
        A chain that returns {"answer": str, "sources": list[Document]}
    """
    embeddings = create_embeddings()
    llm = create_llm()
    retriever = create_retriever(embeddings, k=k)
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", SYSTEM_PROMPT),
        ("human", USER_PROMPT),
    ])
    
    def get_answer_with_sources(inputs: dict) -> dict:
        """Run chain and return answer with sources."""
        docs = inputs["docs"]
        question = inputs["question"]
        
        # Format context and generate answer
        context = format_docs(docs)
        messages = prompt.format_messages(context=context, question=question)
        response = llm.invoke(messages)
        
        return {
            "answer": response.content,
            "sources": docs,
        }
    
    chain = (
        {
            "docs": retriever,
            "question": RunnablePassthrough(),
        }
        | RunnableLambda(get_answer_with_sources)
    )
    
    return chain


# ============================================================================
# Convenience Functions
# ============================================================================

def query(question: str, k: int = 5) -> str:
    """
    Simple query interface for the RAG system.
    
    Args:
        question: Natural language question about vulnerabilities
        k: Number of documents to retrieve
        
    Returns:
        Generated answer string
    """
    chain = create_rag_chain(k=k)
    return chain.invoke(question)


def query_with_sources(question: str, k: int = 5) -> dict:
    """
    Query with source documents returned.
    
    Args:
        question: Natural language question about vulnerabilities
        k: Number of documents to retrieve
        
    Returns:
        Dict with "answer" and "sources" keys
    """
    chain = create_rag_chain_with_sources(k=k)
    return chain.invoke(question)
