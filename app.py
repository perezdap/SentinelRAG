"""
SentinelRAG - Streamlit Application

Interactive web UI for querying security vulnerabilities using RAG.
"""

import streamlit as st
from src.rag_chain import query_with_sources
from src.config import config


# ============================================================================
# Page Configuration
# ============================================================================

st.set_page_config(
    page_title="SentinelRAG",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: 700;
        color: #1a1a2e;
        margin-bottom: 0.5rem;
    }
    .sub-header {
        font-size: 1.1rem;
        color: #4a4a6a;
        margin-bottom: 2rem;
    }
    .source-card {
        background-color: #f8f9fa;
        border-left: 4px solid #0066cc;
        padding: 1rem;
        margin: 0.5rem 0;
        border-radius: 0 8px 8px 0;
    }
    .severity-critical { color: #dc3545; font-weight: bold; }
    .severity-high { color: #fd7e14; font-weight: bold; }
    .severity-medium { color: #ffc107; font-weight: bold; }
    .severity-low { color: #28a745; font-weight: bold; }
    .cve-id { 
        font-family: monospace; 
        background-color: #e9ecef;
        padding: 2px 6px;
        border-radius: 4px;
    }
</style>
""", unsafe_allow_html=True)


# ============================================================================
# Sidebar
# ============================================================================

with st.sidebar:
    st.image("https://raw.githubusercontent.com/simple-icons/simple-icons/develop/icons/gnuprivacyguard.svg", width=60)
    st.title("SentinelRAG")
    st.markdown("---")
    
    st.subheader("⚙️ Settings")
    
    num_results = st.slider(
        "Number of sources to retrieve",
        min_value=3,
        max_value=10,
        value=5,
        help="More sources provide broader context but may slow responses"
    )
    
    st.markdown("---")
    
    st.subheader("📊 Status")
    
    # Check configuration
    missing = config.validate()
    if missing:
        st.error(f"⚠️ Missing config: {', '.join(missing)}")
    else:
        st.success("✅ Configuration valid")
        st.caption(f"Model: `{config.LLM_MODEL}`")
        st.caption(f"Embeddings: `{config.EMBEDDING_MODEL}`")
    
    st.markdown("---")
    
    st.subheader("📚 Example Queries")
    example_queries = [
        "What are the most critical vulnerabilities in Apache Log4j?",
        "Show me recent CVEs affecting Windows with remote code execution",
        "What vulnerabilities exist in OpenSSL from 2024?",
        "Find SQL injection vulnerabilities in web frameworks",
    ]
    
    for eq in example_queries:
        if st.button(eq, key=eq, use_container_width=True):
            st.session_state.query_input = eq


# ============================================================================
# Main Content
# ============================================================================

st.markdown('<p class="main-header">🛡️ SentinelRAG</p>', unsafe_allow_html=True)
st.markdown('<p class="sub-header">AI-powered security vulnerability intelligence</p>', unsafe_allow_html=True)

# Query input
query_input = st.text_area(
    "Ask about security vulnerabilities:",
    value=st.session_state.get("query_input", ""),
    height=100,
    placeholder="e.g., What are the most critical vulnerabilities affecting Kubernetes?",
    key="query_text"
)

col1, col2 = st.columns([1, 5])
with col1:
    search_button = st.button("🔍 Search", type="primary", use_container_width=True)
with col2:
    if st.button("🗑️ Clear", use_container_width=False):
        st.session_state.query_input = ""
        st.rerun()


# ============================================================================
# Query Processing
# ============================================================================

if search_button and query_input:
    # Validate configuration
    missing = config.validate()
    if missing:
        st.error(f"❌ Cannot query: Missing configuration ({', '.join(missing)})")
        st.info("Please configure your `.env` file with the required variables.")
    else:
        with st.spinner("🔄 Searching vulnerability database..."):
            try:
                # Execute RAG query
                result = query_with_sources(query_input, k=num_results)
                
                # Display answer
                st.markdown("### 💡 Analysis")
                st.markdown(result["answer"])
                
                # Display sources
                st.markdown("---")
                st.markdown("### 📄 Sources")
                
                sources = result.get("sources", [])
                if sources:
                    for i, doc in enumerate(sources, 1):
                        metadata = doc.metadata
                        cve_id = metadata.get("cve_id", "Unknown")
                        severity = metadata.get("severity", "Unknown")
                        cvss = metadata.get("cvss_score", "N/A")
                        
                        # Severity color coding
                        severity_class = f"severity-{severity.lower()}" if severity else ""
                        
                        with st.expander(f"[{i}] {cve_id} - Severity: {severity} (CVSS: {cvss})"):
                            st.markdown(doc.page_content)
                            
                            if metadata.get("published_date"):
                                st.caption(f"Published: {metadata['published_date']}")
                            if metadata.get("references"):
                                refs = metadata["references"][:3]  # Show first 3
                                st.markdown("**References:**")
                                for ref in refs:
                                    st.markdown(f"- [{ref}]({ref})")
                else:
                    st.info("No matching vulnerabilities found in the database.")
                    
            except Exception as e:
                st.error(f"❌ Query failed: {str(e)}")
                st.exception(e)

elif search_button:
    st.warning("Please enter a query to search.")


# ============================================================================
# Footer
# ============================================================================

st.markdown("---")
st.markdown(
    """
    <div style="text-align: center; color: #888; font-size: 0.85rem;">
        <p>SentinelRAG • Powered by LangChain & pgvector • 
        <a href="https://nvd.nist.gov/" target="_blank">Data from NVD</a></p>
    </div>
    """,
    unsafe_allow_html=True
)
