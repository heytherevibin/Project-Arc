"""
Vector Store - Qdrant Integration

Provides vector similarity search for semantic memory retrieval.
Embeds text observations using OpenAI/Anthropic embeddings and
stores them in Qdrant for nearest-neighbor lookup.
"""

from __future__ import annotations

import hashlib
import uuid
from typing import Any

from core.config import get_settings
from core.logging import get_logger

logger = get_logger(__name__)

# Embedding dimension for OpenAI text-embedding-3-small
EMBEDDING_DIM = 1536
COLLECTION_NAME = "arc_semantic_memory"


class VectorStore:
    """
    Qdrant-backed vector store for semantic similarity search.

    Stores text chunks with embeddings for fast nearest-neighbor
    retrieval, augmenting the Neo4j knowledge graph with fuzzy
    semantic matching.
    """

    def __init__(
        self,
        qdrant_url: str | None = None,
        qdrant_api_key: str | None = None,
        collection_name: str = COLLECTION_NAME,
    ) -> None:
        settings = get_settings()
        self._qdrant_url = qdrant_url or getattr(settings, "QDRANT_URL", "http://localhost:6333")
        self._api_key = qdrant_api_key or getattr(settings, "QDRANT_API_KEY", "")
        self._collection = collection_name
        self._client: Any = None
        self._embedder: Any = None

    async def initialize(self) -> None:
        """Connect to Qdrant and ensure the collection exists."""
        try:
            from qdrant_client import AsyncQdrantClient
            from qdrant_client.models import Distance, VectorParams

            self._client = AsyncQdrantClient(
                url=self._qdrant_url,
                api_key=self._api_key or None,
            )

            # Ensure collection exists
            collections = await self._client.get_collections()
            existing = {c.name for c in collections.collections}

            if self._collection not in existing:
                await self._client.create_collection(
                    collection_name=self._collection,
                    vectors_config=VectorParams(
                        size=EMBEDDING_DIM,
                        distance=Distance.COSINE,
                    ),
                )
                logger.info("Created Qdrant collection", collection=self._collection)

            logger.info("VectorStore initialized", url=self._qdrant_url)
        except ImportError:
            logger.warning("qdrant-client not installed, vector store disabled")
        except Exception as e:
            logger.warning("Failed to initialize vector store", error=str(e))

    async def _embed(self, text: str) -> list[float]:
        """Generate an embedding vector for the given text."""
        settings = get_settings()

        if self._embedder is None:
            try:
                import openai
                self._embedder = openai.AsyncOpenAI(
                    api_key=settings.OPENAI_API_KEY or "",
                )
            except Exception:
                # Fallback: deterministic hash-based pseudo-embedding for testing
                return self._hash_embed(text)

        try:
            response = await self._embedder.embeddings.create(
                model="text-embedding-3-small",
                input=text[:8000],
            )
            return response.data[0].embedding
        except Exception as e:
            logger.warning("Embedding API failed, using hash fallback", error=str(e))
            return self._hash_embed(text)

    @staticmethod
    def _hash_embed(text: str) -> list[float]:
        """Deterministic pseudo-embedding for when the API is unavailable."""
        digest = hashlib.sha512(text.encode()).digest()
        # Expand to EMBEDDING_DIM floats in [-1, 1]
        import struct
        values: list[float] = []
        while len(values) < EMBEDDING_DIM:
            digest = hashlib.sha512(digest).digest()
            chunk_floats = [
                (b / 127.5) - 1.0 for b in digest
            ]
            values.extend(chunk_floats)
        return values[:EMBEDDING_DIM]

    async def store(
        self,
        text: str,
        metadata: dict[str, Any] | None = None,
        point_id: str | None = None,
    ) -> str:
        """Embed and store a text chunk with optional metadata."""
        if not self._client:
            logger.debug("VectorStore not initialized, skipping store")
            return ""

        from qdrant_client.models import PointStruct

        pid = point_id or uuid.uuid4().hex
        embedding = await self._embed(text)

        payload = {
            "text": text[:5000],
            **(metadata or {}),
        }

        await self._client.upsert(
            collection_name=self._collection,
            points=[PointStruct(id=pid, vector=embedding, payload=payload)],
        )

        logger.debug("Stored vector", point_id=pid)
        return pid

    async def search(
        self,
        query: str,
        limit: int = 10,
        filter_payload: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Search for similar text chunks using vector similarity."""
        if not self._client:
            return []

        embedding = await self._embed(query)

        # Build optional filter
        query_filter = None
        if filter_payload:
            from qdrant_client.models import Filter, FieldCondition, MatchValue
            conditions = [
                FieldCondition(key=k, match=MatchValue(value=v))
                for k, v in filter_payload.items()
            ]
            query_filter = Filter(must=conditions)

        results = await self._client.search(
            collection_name=self._collection,
            query_vector=embedding,
            limit=limit,
            query_filter=query_filter,
        )

        return [
            {
                "id": str(hit.id),
                "score": hit.score,
                **hit.payload,
            }
            for hit in results
        ]

    async def delete(self, point_ids: list[str]) -> None:
        """Delete vectors by their IDs."""
        if not self._client or not point_ids:
            return

        from qdrant_client.models import PointIdsList
        await self._client.delete(
            collection_name=self._collection,
            points_selector=PointIdsList(points=point_ids),
        )

    async def close(self) -> None:
        """Close the Qdrant client."""
        if self._client:
            await self._client.close()
            self._client = None
