# Graph Report - Major-Project  (2026-10-21)

## Corpus Check
- 44 files · ~25,275 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 9 file(s) not represented in the graph (top: (none) 4, .example 2, .css 2)

## Summary
- 371 nodes · 781 edges · 22 communities (11 shown, 11 thin omitted)
- Extraction: 92% EXTRACTED · 8% INFERRED · 0% AMBIGUOUS · INFERRED: 61 edges (avg confidence: 0.94)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `f535fe7f`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- db_models.py
- chat_routes.py
- App.jsx
- sop_routes.py
- SOPManager
- VectorStore
- package.json
- rag_engine.py
- Implementation Plan: Chat Interface with RAG Tool for Smart Threat Response Assistant
- EmbeddingService
- auth_service.py
- .oxlintrc.json
- frontend/README.md
- SOC Assistant backend
- backend
- Settings
- SOC Chatbot — RAG-powered Incident Response Assistant
- Role

## God Nodes (most connected - your core abstractions)
1. `User` - 31 edges
2. `request()` - 18 edges
3. `SOCAgent` - 17 edges
4. `SOPManager` - 16 edges
5. `App()` - 15 edges
6. `VectorStore` - 12 edges
7. `SOC Chatbot — RAG-powered Incident Response Assistant` - 12 edges
8. `EmbeddingService` - 11 edges
9. `upload_sop()` - 10 edges
10. `Base` - 10 edges

## Surprising Connections (you probably didn't know these)
- `login()` --uses--> `Token`  [INFERRED]
  backend/app/api/auth_routes.py → backend/app/models/schemas.py
- `login()` --uses--> `UserLogin`  [INFERRED]
  backend/app/api/auth_routes.py → backend/app/models/schemas.py
- `_ensure_session()` --uses--> `ChatSession`  [INFERRED]
  backend/app/api/chat_routes.py → backend/app/models/db_models.py
- `_save_message()` --uses--> `ChatSession`  [INFERRED]
  backend/app/api/chat_routes.py → backend/app/models/db_models.py
- `new_chat()` --uses--> `ChatSession`  [INFERRED]
  backend/app/api/chat_routes.py → backend/app/models/db_models.py

## Import Cycles
- None detected.

## Communities (22 total, 11 thin omitted)

### Community 0 - "db_models.py"
Cohesion: 0.14
Nodes (9): init_db(), _migrate_ticket_status_nullable(), Base, ChatMessage, ChatSession, Ticket, utcnow(), TicketService (+1 more)

### Community 1 - "chat_routes.py"
Cohesion: 0.09
Nodes (33): read_current_user(), archive_session(), delete_session(), _ensure_session(), get_messages(), list_sessions(), new_chat(), _save_message() (+25 more)

### Community 2 - "App.jsx"
Cohesion: 0.11
Nodes (35): archiveChat(), AUTH_EXPIRED_EVENT, AuthError, clearToken(), deleteChat(), fetchMe(), getChatMessages(), getSOPChunks() (+27 more)

### Community 3 - "sop_routes.py"
Cohesion: 0.10
Nodes (13): delete_sop(), get_sop_chunks(), list_sops(), upload_sop(), health(), lifespan(), _seed(), SOPChunkOut (+5 more)

### Community 4 - "SOPManager"
Cohesion: 0.22
Nodes (3): SOPChunk, SOPDocument, SOPManager

### Community 6 - "package.json"
Cohesion: 0.07
Nodes (29): dependencies, lucide-react, react, react-dom, react-markdown, remark-gfm, devDependencies, oxlint (+21 more)

### Community 7 - "rag_engine.py"
Cohesion: 0.14
Nodes (10): _build_citations(), _build_context(), _is_social_message(), _local_synthesis(), _message_text(), SOCAgent, _text_chunks(), _text_tool_query() (+2 more)

### Community 8 - "Implementation Plan: Chat Interface with RAG Tool for Smart Threat Response Assistant"
Cohesion: 0.09
Nodes (18): 1.1 Configuration, 1.2 Pydantic Schemas, 1.3 Chat Engine Service, 1.4 Chat Router, 1.5 Dependencies, 1. Backend Changes, 2.1 API Client Extension, 2.2 Chat Component (+10 more)

### Community 10 - "auth_service.py"
Cohesion: 0.24
Nodes (7): login(), authenticate(), create_access_token(), decode_token(), get_user_by_username(), _hash_password(), _verify_password()

### Community 11 - ".oxlintrc.json"
Cohesion: 0.33
Nodes (5): plugins, rules, react/only-export-components, react/rules-of-hooks, $schema

### Community 20 - "SOC Chatbot — RAG-powered Incident Response Assistant"
Cohesion: 0.07
Nodes (27): 1. Clone / open the project, 2. Backend, 3. Frontend, 4. Use the app, API Reference, Auth, Authentication, Backend Architecture (+19 more)

## Knowledge Gaps
- **4 isolated node(s):** `backend`, `@types/react`, `@types/react-dom`, `oxlint`
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 136 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **11 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `VectorStore` connect `VectorStore` to `Implementation Plan: Chat Interface with RAG Tool for Smart Threat Response Assistant`, `sop_routes.py`?**
  _High betweenness centrality (0.076) - this node is a cross-community bridge._
- **Are the 22 inferred relationships involving `User` (e.g. with `read_current_user()` and `archive_session()`) actually correct?**
  _`User` has 22 INFERRED edges - model-reasoned connections that need verification._
- **What connects `backend`, `@types/react`, `@types/react-dom` to the rest of the system?**
  _4 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `db_models.py` be split into smaller, more focused modules?**
  _Cohesion score 0.13675213675213677 - nodes in this community are weakly interconnected._
- **Why does `User` connect `chat_routes.py` to `db_models.py`, `auth_service.py`, `sop_routes.py`?**
  _High betweenness centrality (0.045) - this node is a cross-community bridge._
- **Are the 2 inferred relationships involving `SOCAgent` (e.g. with `ChatResponse` and `SOCAgentTest`) actually correct?**
  _`SOCAgent` has 2 INFERRED edges - model-reasoned connections that need verification._
- **Should `chat_routes.py` be split into smaller, more focused modules?**
  _Cohesion score 0.08892921960072596 - nodes in this community are weakly interconnected._