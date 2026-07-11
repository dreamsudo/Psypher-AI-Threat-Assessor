# Psypher AI Threat Assessor — Probe Roadmap

*Full-stack AI/ML security — MITRE ATLAS–grounded penetration testing of the model and the infrastructure it runs on. Powered by Claude · Designed by PsypherLabs.*

The consolidated, authoritative list of every planned observation probe, sorted by attack-surface **category**. Each category is a probe pack. This file is the single source of truth for the probe backlog — add here, don't re-brainstorm.

## Legend

- **Status:** `designed` (spec complete, ready to drop in) · `planned` (spec here, not yet built) · `backlog` (idea captured, spec thin)
- **Tier:** `passive` · `active_safe` · `intrusive` (intrusive is off by default, approval-gated)
- **Type:** `shell` (runs on target via SSH) · `http` (endpoint request) · `script` (stdlib module, runs in engine venv — local/colocated file access)
- **Grounding:** ATLAS technique that anchors the finding · CVE (rides in evidence) · CVE (concrete real-world anchor, matches via the CVE-graph/promotion path)
- **[confirm]** = the ATLAS/CVE/CVE id must be verified in `build/graph/nodes.json` before build (`grep -c '"<id>"' build/graph/nodes.json`)

## Grounding already confirmed in-graph

`AML.T0010` + subs `.000` Hardware / `.001` AI Software / `.002` Data / `.003` Model / `.004` Container Registry / `.005` AI Agent Tool · `AML.T0029` Denial of ML Service · `AML.T0040` AI Model Inference API Access · `AML.T0051` Prompt Injection · `AML.T0051.001` Indirect · `AML.T0057` LLM Data Leakage · CVE-250/306/353/693/502.

## Current state (what already ships)

19 probes across three surfaces (`packs/probes/probes.yaml`):
- **host-isolation:** `docker_socket`, `process_capabilities`, `syscall_filtering`, `mac_confinement`, `container_runtime`, `host_hypervisor_dmi`, `cred_env_names`, `world_readable_secrets`
- **model-endpoint / serving:** `api_banner`, `endpoint_banner`, `listening_sockets`, `mgmt_exposed`, `model_digest`, `unauth_inference`, `detect_virt`, `pip_freeze`, `os_packages`
- **embeddings:** `embedding_probe`
- **behavioral:** the `rt_*` corpus capture probes

Coverage today: host isolation + endpoint exposure + serving-stack CVE inventory. Everything below is net-new surface.

---

# Category 1 — Model-Artifact Safety
*The model file/format itself. Pack: `packs/probes/model-artifact/`. Grounds mostly to `AML.T0010.*` (supply chain).*

### model_artifact_scan  — `designed`
- **Tier/Type:** active_safe · script
- **Observes:** `model_serialization_format`, `model_serialization_verdict`, `model_serialization_unsafe`, `model_serialization_path`, `model_serialization_scanned`
- **Method:** magic-byte format triage (not extension); for pickle-derived formats disassemble the opcode stream with stdlib `pickletools.genops` (never loads) against a dangerous-globals denylist (PickleScan's set + post-bypass additions: asyncio/pty/pkgutil/importlib). Malformed stream = signal, not skip (CVE-2025-1945).
- **Grounding:** `AML.T0010.003` Model · CVE-502 Deserialization of Untrusted Data
- **Posture rule:** verdict `dangerous` → critical finding. `executable_format` (clean pickle) stays a grain.
- **Depends:** ships first; scanner + descriptor + posture rule written.

### keras_lambda_layer  — `planned`
- **Tier/Type:** active_safe · script
- **Observes:** `keras_lambda_present`, `keras_lambda_count`
- **Method:** parse HDF5/Keras model config JSON for `Lambda` layers, which embed arbitrary Python in the model graph — a real RCE path a pickle scan misses entirely.
- **Grounding:** `AML.T0010.001` AI Software · CVE-94 Code Injection
- **Posture rule:** any Lambda layer present → high finding.

### gguf_template_ssti  — `planned`
- **Tier/Type:** active_safe · script
- **Observes:** `gguf_chat_template_risk`, `gguf_template_sink`
- **Method:** parse the GGUF metadata KV block, extract the embedded `chat_template` (Jinja2, executed by the serving runtime), static-analyze for server-side template-injection sinks.
- **Grounding:** `AML.T0051` Prompt Injection · CVE-1336 SSTI
- **Posture rule:** dangerous template construct → high finding.

### onnx_custom_ops  — `planned`
- **Tier/Type:** active_safe · script
- **Observes:** `onnx_custom_op_domains`, `onnx_external_ops`
- **Method:** inspect the ONNX graph for non-standard operator domains / external custom ops that load native code at inference.
- **Grounding:** `AML.T0010.001` AI Software · CVE-829 Inclusion of Untrusted Functionality
- **Posture rule:** non-standard op domain present → medium finding.

### trust_remote_code  — `planned`
- **Tier/Type:** active_safe · script
- **Observes:** `hf_trust_remote_code`, `hf_auto_map_present`
- **Method:** parse HF `config.json` / tokenizer config for `trust_remote_code: true` or a custom `auto_map` — code-on-load without any pickle.
- **Grounding:** `AML.T0010.001` AI Software · CVE-494 Download of Code Without Integrity Check
- **Posture rule:** `trust_remote_code: true` or `auto_map` present → high finding.

### adapter_provenance  — `planned`
- **Tier/Type:** passive · script
- **Observes:** `adapter_files_present`, `adapter_unsigned`
- **Method:** detect LoRA/adapter/`.safetensors` adapter files with no signature or pinned digest; extends the `model_digest` provenance signal to fine-tune artifacts.
- **Grounding:** `AML.T0010.003` Model · CVE-353 Missing Integrity Check
- **Posture rule:** unsigned adapter present → low finding.

### model_lineage_drift  — `planned`
- **Tier/Type:** passive · http+correlation
- **Observes:** `served_digest_vs_declared`
- **Method:** reconcile the *running* model digest (`/api/tags`) against the declared/pinned provenance (intake); flag when served ≠ declared (tampering-in-place / swapped weights).
- **Grounding:** `AML.T0018` Backdoor ML Model **[confirm]** · CVE-353
- **Posture rule:** mismatch → high finding.

---

# Category 2 — Serving-Stack Exposure
*The infrastructure serving the model. Pack: `packs/probes/serving-stack/`. CVE-heavy; grounds to `AML.T0040` + CVEs.*

### ray_cluster_exposure  — `planned`
- **Tier/Type:** active_safe · http
- **Observes:** `ray_dashboard_reachable`, `ray_job_api_unauth`, `ray_version`
- **Method:** detect an exposed Ray head/dashboard/Serve endpoint; ShadowRay (CVE-2023-48022) is unauthenticated job submission = RCE, actively exploited. Correlate reachability + version.
- **Grounding:** `AML.T0040` · CVE-2023-48022 · CVE-306 Missing Authentication
- **Posture rule:** unauth job API reachable → critical finding.

### triton_model_control  — `planned`
- **Tier/Type:** active_safe · http
- **Observes:** `triton_control_api_reachable`, `triton_model_load_allowed`
- **Method:** NVIDIA Triton's model-control API can load arbitrary models from a path = RCE; detect the exposed control endpoint and whether explicit-control mode is on.
- **Grounding:** `AML.T0010.003` Model · CVE **[confirm current Triton CVE]** · CVE-306
- **Posture rule:** control API reachable → critical finding.

### ml_notebook_exposure  — `planned`
- **Tier/Type:** active_safe · http
- **Observes:** `jupyter_reachable`, `jupyter_token_required`, `tensorboard_reachable`
- **Method:** detect exposed/token-less Jupyter or TensorBoard on the serving host — ubiquitous on ML boxes, direct RCE / training-data leak.
- **Grounding:** `AML.T0040` · CVE **[confirm]** · CVE-306
- **Posture rule:** notebook reachable without token → high finding.

### model_registry_exposure  — `planned`
- **Tier/Type:** active_safe · http
- **Observes:** `mlflow_reachable`, `registry_unauth`
- **Method:** unauthenticated MLflow / model registry reachable (a real, common exposure — MLflow ships with no auth by default).
- **Grounding:** `AML.T0010.004` Container Registry · CVE-306
- **Posture rule:** unauth registry reachable → high finding.

### gpu_accelerator  — `backlog`
- **Tier/Type:** passive · shell
- **Observes:** `cuda_version`, `driver_version`, `weights_world_readable`
- **Method:** CUDA/driver/runtime versions (CVE surface the host-isolation probes miss) + whether model weights are readable on disk (model-theft precondition).
- **Grounding:** driver CVEs via the matcher · `AML.T0044` Full ML Model Access **[confirm]**
- **Posture rule:** known-vuln driver → CVE finding; weights world-readable → medium.

---

# Category 3 — Agent / Tool Surface
*The agentic layer. Pack: `packs/probes/agent-surface/`. Grounds to `AML.T0053` / `AML.T0010.005`.*

### mcp_server_exposure  — `planned`
- **Tier/Type:** active_safe · http
- **Observes:** `mcp_server_reachable`, `mcp_inspector_unauth`, `mcp_tool_count`
- **Method:** detect exposed MCP servers and the unauthenticated MCP Inspector (CVE-2025-49596, CVSS 9.4 RCE); enumerate exposed tools/resources (observation only — never invoke).
- **Grounding:** `AML.T0053` LLM Plugin Compromise **[confirm]** · CVE-2025-49596 · CVE-306
- **Posture rule:** unauth MCP Inspector reachable → critical; MCP server reachable → medium.

### tool_permission_audit  — `planned`
- **Tier/Type:** active_safe · script+correlation
- **Observes:** `agent_tools`, `tool_capability_tier`, `untrusted_input_reaches_tools`
- **Method:** enumerate the agent's wired tools and correlate each tool's capability (shell/file/network/db) against whether untrusted input reaches the model — quantifies a jailbreak's blast radius.
- **Grounding:** `AML.T0010.005` AI Agent Tool · `AML.T0053` **[confirm]** · CVE-250 Excessive Privilege
- **Posture rule:** high-capability tool reachable from untrusted input → high finding.

### mcp_tool_metadata_scan  — `planned`
- **Tier/Type:** active_safe · script
- **Observes:** `mcp_tool_poisoning_signatures`, `mcp_cross_server_collisions`
- **Method:** fetch each MCP tool's full description/schema and static-analyze for embedded instructions (tool-poisoning signatures) and cross-server name collisions (shadowing / rug-pull).
- **Grounding:** `AML.T0051.001` Indirect Prompt Injection · CVE-77
- **Posture rule:** poisoning signature or name collision → high finding.

---

# Category 4 — RAG / Retrieval / Data
*The data layer. Pack: `packs/probes/retrieval/`. Grounds to `AML.T0051.001` / `AML.T0057`.*

### vector_store_exposure  — `planned`
- **Tier/Type:** active_safe · http
- **Observes:** `vector_db_kind`, `vector_db_unauth`, `vector_db_version`, `collection_count`
- **Method:** fingerprint the vector DB (Weaviate `/v1/schema`, Milvus collections API, ChromaDB `/api/v1/collections`, Qdrant) and check unauthenticated reachability. ChromaToast (CVE-2026-45829, CVSS 10.0) is a pre-auth RCE.
- **Grounding:** `AML.T0051.001` (indirect-injection precondition) · CVE-2026-45829 · CVE-306
- **Posture rule:** unauth vector store reachable → high; vuln version → CVE finding.

### rag_injection_surface  — `planned`
- **Tier/Type:** active_safe · correlation
- **Observes:** `untrusted_content_ingested`, `shared_collection_with_model`
- **Method:** map the retrieval ingestion path — does untrusted content (web scrapes, uploads) land in the same collection the model reads? That's the indirect-injection precondition.
- **Grounding:** `AML.T0051.001` · CVE-1426 Improper Validation of Generative AI Output **[confirm]**
- **Posture rule:** untrusted ingestion → model-read collection → high finding.

### vector_tenant_isolation  — `planned`
- **Tier/Type:** active_safe · correlation
- **Observes:** `tenant_metadata_filtering`, `cross_tenant_retrieval`
- **Method:** test whether the vector store enforces per-tenant metadata filtering *before* similarity ranking (cross-tenant retrieval leak — the most common production RAG bug).
- **Grounding:** `AML.T0057` LLM Data Leakage · CVE-284 Improper Access Control
- **Posture rule:** no pre-ranking tenant filter → high finding.

### embedding_inversion_exposure  — `planned`
- **Tier/Type:** active_safe · correlation
- **Observes:** `sensitive_embeddings_reachable`, `embedding_access_control`
- **Method:** a reachable vector store holding sensitive embeddings without access control (embeddings invert to source text — "embeddings = PII").
- **Grounding:** `AML.T0024` Exfiltration via ML Inference API **[confirm]** · CVE-284
- **Posture rule:** sensitive embeddings reachable unauth → high finding.

### training_data_exposure  — `planned`
- **Tier/Type:** passive · shell
- **Observes:** `dataset_dirs_world_readable`, `rag_source_store_readable`
- **Method:** reachable dataset dirs / RAG source stores world-readable on the serving host; mirrors `world_readable_secrets` for training/RAG data.
- **Grounding:** `AML.T0010.002` Data · CVE-732 Incorrect Permission Assignment
- **Posture rule:** world-readable dataset store → medium finding.

---

# Category 5 — Inference Behavior
*The model's runtime behavior — extraction, DoS, side-channels. Pack: `packs/probes/inference-behavior/`. Grounds to `AML.T0024` / `AML.T0029`.*

### resource_limits  — `planned`
- **Tier/Type:** active_safe · http
- **Observes:** `rate_limit_present`, `token_cap_present`, `concurrency_bound`
- **Method:** probe whether the endpoint enforces rate limits / token caps / concurrency bounds (OWASP LLM10 Unbounded Consumption).
- **Grounding:** `AML.T0029` Denial of ML Service · CVE-770 Allocation Without Limits
- **Posture rule:** no rate limit / no token cap → medium finding.

### model_extraction_rate  — `planned`
- **Tier/Type:** active_safe · correlation
- **Observes:** `extraction_feasible`, `queries_per_min_allowed`
- **Method:** reason about whether rate limits permit distillation-scale querying (stealing the model through its own API).
- **Grounding:** `AML.T0024` Exfiltration **[confirm]** · `AML.T0044` Full ML Model Access **[confirm]**
- **Posture rule:** unbounded query rate on a proprietary model → medium finding.

### context_window_dos  — `planned`
- **Tier/Type:** active_safe · http (bounded)
- **Observes:** `max_context_bound`, `unbounded_input_accepted`
- **Method:** probe max-token/context bounds and whether unbounded input is accepted (resource exhaustion) — bounded, never an actual flood.
- **Grounding:** `AML.T0029` · CVE-770
- **Posture rule:** unbounded input accepted → medium finding.

### inference_timing_leak  — `backlog`
- **Tier/Type:** active_safe · side-channel
- **Observes:** `timing_variance`, `cache_leak_signal`
- **Method:** measure response-timing variance to infer whether prompt caching / speculative decoding leaks token-level or membership information.
- **Grounding:** side channel · CVE-208 Observable Timing Discrepancy
- **Posture rule:** significant timing variance correlated to input → low finding.

---

# Category 6 — Guardrail / Defense Posture
*Whether defenses exist and hold. Pack: `packs/probes/guardrail-posture/`. Grounds to defense gaps / CVE.*

### guardrail_bypass_surface  — `planned`
- **Tier/Type:** active_safe · correlation
- **Observes:** `guardrailed_path`, `raw_model_port_reachable`
- **Method:** the sharp one — a moderation layer fronts the *app*, but is the raw model port reachable directly, bypassing it? Correlate the guardrailed path vs. raw-endpoint reachability.
- **Grounding:** defense gap · `AML.T0040` · CVE-693 Protection Mechanism Failure
- **Posture rule:** raw model port reachable alongside a guardrailed path → high finding.

### safety_filter_fail_mode  — `planned`
- **Tier/Type:** active_safe · side-channel
- **Observes:** `guardrail_fail_open`
- **Method:** does the safety/guardrail layer fail *open* (allow) or *closed* (deny) when it errors or times out?
- **Grounding:** `AML.T0040` · CVE-636 Not Failing Securely
- **Posture rule:** fails open → high finding.

### output_guardrail_presence  — `planned`
- **Tier/Type:** passive · http+intake
- **Observes:** `guardrail_layer_present`
- **Method:** whether a moderation/guardrail layer (Llama Guard / NeMo Guardrails / a moderation endpoint) fronts the model — defense-in-depth posture.
- **Grounding:** posture signal · CVE-693
- **Posture rule:** no guardrail layer detected → low finding (informational).

### tls_transport  — `planned`
- **Tier/Type:** active_safe · http
- **Observes:** `endpoint_plaintext`, `weak_tls`
- **Method:** inference endpoint served plaintext / weak TLS (subject to the relevance layer — only in scope where crypto/network is in the profile).
- **Grounding:** transport weakness · CVE-319 Cleartext Transmission
- **Posture rule:** plaintext inference endpoint → medium finding (scope-gated).

---

# Backlog (captured, spec thin)

- **gpu_mig_isolation** — GPU MIG/time-slice tenant isolation on shared accelerators.
- **cloud_iam_scope** — the serving host's cloud IAM role scope (over-privileged inference node).
- **weights_at_rest_encryption** — model weights encrypted at rest vs. plaintext on disk.
- **function_schema_leakage** — the model's own tool/function schemas leaking via error messages or `/v1/models` metadata.

---

# Recommended build order

1. **model_artifact_scan** *(designed — ship first)*
2. **vector_store_exposure** + **mcp_server_exposure** — concrete CVE anchors (ChromaToast, MCP Inspector), reuse the http pattern, high impact.
3. **ray_cluster_exposure** / **ml_notebook_exposure** — actively-exploited serving-stack RCE, hard CVE anchors.
4. **guardrail_bypass_surface** + **tool_permission_audit** — the highest-signal correlation probes; where "assess the whole system, not one box" shows.
5. **trust_remote_code** + **keras_lambda_layer** + **gguf_template_ssti** — complete the model-artifact family (they catch RCE paths the pickle scan misses).
6. Everything else by category as capacity allows.

Each probe still follows the editing protocol (read in full → back up → anchored edit → verify → log) and grows through packs + data, never the sealed core. Confirm every **[confirm]** id in-graph before building the probe that anchors on it.
