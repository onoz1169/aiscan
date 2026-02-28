"""
In-memory vector store using Ollama embeddings + cosine similarity.
No external vector DB required — keeps the demo self-contained.
"""

import uuid
import httpx
import numpy as np


class VectorStore:
    def __init__(self, ollama_url: str, embed_model: str = "nomic-embed-text"):
        self.ollama_url = ollama_url
        self.embed_model = embed_model
        self.documents: list[dict] = []

    async def add(self, title: str, content: str) -> str:
        embedding = await self._embed(content)
        doc_id = str(uuid.uuid4())[:8]
        self.documents.append({
            "id": doc_id,
            "title": title,
            "content": content,
            "embedding": embedding,
        })
        return doc_id

    async def search(self, query: str, n_results: int = 3) -> list[dict]:
        if not self.documents:
            return []
        query_vec = np.array(await self._embed(query))
        scored = []
        for doc in self.documents:
            doc_vec = np.array(doc["embedding"])
            norm = np.linalg.norm(query_vec) * np.linalg.norm(doc_vec)
            score = float(np.dot(query_vec, doc_vec) / norm) if norm > 0 else 0.0
            scored.append((score, doc))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [
            {"id": d["id"], "title": d["title"], "content": d["content"]}
            for _, d in scored[:n_results]
        ]

    def list_all(self) -> list[dict]:
        return [{"id": d["id"], "title": d["title"]} for d in self.documents]

    def delete(self, doc_id: str) -> None:
        self.documents = [d for d in self.documents if d["id"] != doc_id]

    async def _embed(self, text: str) -> list[float]:
        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.post(
                f"{self.ollama_url}/api/embeddings",
                json={"model": self.embed_model, "prompt": text},
            )
            resp.raise_for_status()
            return resp.json()["embedding"]
