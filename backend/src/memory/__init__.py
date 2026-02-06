"""
Arc Cognitive Memory Architecture

Three-tier memory system inspired by human cognition:
- Episodic: Event logging with temporal retrieval (what happened)
- Semantic: Structured knowledge and entity relationships (what we know)
- Procedural: Attack techniques and learned playbooks (how to do things)
- Working: Active context window with attention management (current focus)
"""

from memory.cognitive import CognitiveMemory

__all__ = ["CognitiveMemory"]
