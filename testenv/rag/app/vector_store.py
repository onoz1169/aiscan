"""
In-memory vector store using TF-IDF keyword scoring.
No embedding model required — keeps the demo self-contained and fast.

The vulnerability being demonstrated (RAG poisoning) does not depend on
retrieval quality; it depends on the LLM trusting retrieved content.
"""

import uuid
import re
from collections import Counter


def _tokenize(text: str) -> list[str]:
    return re.findall(r"[a-z0-9]+", text.lower())


def _tfidf_score(query_tokens: list[str], doc_tokens: list[str]) -> float:
    """Simple TF-IDF-inspired overlap score."""
    if not query_tokens or not doc_tokens:
        return 0.0
    doc_freq = Counter(doc_tokens)
    doc_len = len(doc_tokens)
    score = 0.0
    for token in query_tokens:
        tf = doc_freq.get(token, 0) / doc_len
        score += tf
    return score


class VectorStore:
    def __init__(self, **kwargs):  # accepts but ignores ollama_url / embed_model
        self.documents: list[dict] = []

    async def add(self, title: str, content: str) -> str:
        doc_id = str(uuid.uuid4())[:8]
        self.documents.append({
            "id": doc_id,
            "title": title,
            "content": content,
            "tokens": _tokenize(title + " " + content),
        })
        return doc_id

    async def search(self, query: str, n_results: int = 3) -> list[dict]:
        if not self.documents:
            return []
        query_tokens = _tokenize(query)
        scored = [
            (_tfidf_score(query_tokens, d["tokens"]), d)
            for d in self.documents
        ]
        scored.sort(key=lambda x: x[0], reverse=True)
        return [
            {"id": d["id"], "title": d["title"], "content": d["content"]}
            for _, d in scored[:n_results]
        ]

    def list_all(self) -> list[dict]:
        return [{"id": d["id"], "title": d["title"]} for d in self.documents]

    def delete(self, doc_id: str) -> None:
        self.documents = [d for d in self.documents if d["id"] != doc_id]
