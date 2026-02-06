"""
SentinelRAG - RAG Chain Implementation

LangChain-based RAG pipeline with pgvector retriever for semantic search
over security vulnerabilities.
"""

import os
import openai
from langchain_openai import ChatOpenAI
from langchain_community.vectorstores import PGVector
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
    Create a pgvector retriever for semantic search.
    
    Args:
        embeddings: Embeddings client for query vectorization
        k: Number of documents to retrieve
    """
    connection_string = config.NEON_DATABASE_URL
    
    vectorstore = PGVector(
        connection_string=connection_string,
        embedding_function=embeddings,
        collection_name="vulnerabilities",
        distance_strategy="cosine",
    )
    
    return vectorstore.as_retriever(
        search_type="similarity",
        search_kwargs={"k": k}
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
