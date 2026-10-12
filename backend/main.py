import os
import re
import json
import asyncio
import threading

from datetime import datetime, timedelta, timezone
from contextlib import asynccontextmanager

import httpx

from openai import AsyncOpenAI
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Response
from fastapi.middleware.cors import CORSMiddleware

import io
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer

# Import The Stable Processor And Metric Extractor Helper
from processor import process_cves, extract_cvss_metrics


SHUTDOWN_MSG = "\n[ThreatMesh 3D] Shutting Down. Stay Safe."
ai_client = AsyncOpenAI(
    base_url="https://generativelanguage.googleapis.com/v1beta/openai/",
    api_key=os.environ["GEMINI_API_KEY"]
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global cached_attack_techniques
    cached_attack_techniques = await fetch_attack()
    print(
        f"Att&ck Techniques Loaded: {len(cached_attack_techniques)}", flush=True)

    # Start The Centralized Threat Polling Engine
    polling_task = asyncio.create_task(centralized_threat_polling())

    yield

    polling_task.cancel()
    print(SHUTDOWN_MSG, flush=True)


async def centralized_threat_polling():
    global cached_kev, cached_cves
    cycle_count = 0

    while True:
        try:
            if cycle_count % KEV_REFRESH_CYCLES == 0:
                cached_kev = await fetch_kev()
                print(
                    f"Kev Loaded: {len(cached_kev)} Actively Exploited Cves", flush=True)

            cves = await fetch_cves(cached_kev)

            # Broadcast Data To All Connected Users Simultaneously
            if cves and active_connections:
                payload = json.dumps({"status": "ok", "data": cves})

                for connection in list(active_connections):
                    try:
                        await connection.send_text(payload)
                    except Exception:
                        active_connections.remove(connection)

            cycle_count += 1
        except Exception as e:
            print(f"Error In Centralized Background Polling: {e}", flush=True)

        await asyncio.sleep(60)


app = FastAPI(lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"]
)

# NVD API Configuration.
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_HEADERS = {}
nvd_api_key = os.environ.get("NVD_API_KEY")

# AI Prompt Limits And Sampling.
MAX_TECHNIQUES_FOR_PROMPT = 1000
AI_SAMPLE_SIZE = 40

# Graph Size Limits.
MAX_NODES = 500
MIN_NON_KEV_NODES = 100

# Verification And Analysis Thresholds.
VERIFICATION_CHUNK_SIZE = 4
MAX_DELTA_WINDOW = timedelta(hours=2)
LOW_CONFIDENCE_VALUES = {"Low", "Medium"}
WEAK_EVIDENCE_VALUES = {"Inferred", "Insufficient"}

# Runtime Caches And Connection State.
cached_kev = set()
cached_attack_techniques = []
cached_ai_analysis = {}
active_connections = set()


cached_cves = {"nodes": [], "edges": []}
KEV_REFRESH_CYCLES = 30 * 60 // 60

last_fetched_timestamp = (datetime.now(timezone.utc) - timedelta(hours=24))

if nvd_api_key:
    NVD_HEADERS = {"apiKey": nvd_api_key}


def sanitize_json_string(raw: str) -> str:
    raw = re.sub(r'(?<!\\)\\(?![/"\\bfnrtu]|u[0-9a-fA-F]{4})', r'\\\\', raw)
    raw = re.sub(r',\s*([}\]])', r'\1', raw)
    # Fix Single-Quoted Property Names (Model Occasionally Emits Python-Style Keys)
    raw = re.sub(r"'([A-Za-z_][A-Za-z0-9_]*)'\s*:", r'"\1":', raw)
    return raw


def normalize_technique_mapping(cve: dict, techniques: list[dict]) -> dict:
    tech_list = cve.get("techniques", [])
    if not tech_list:
        cve["techniques"] = []
        return cve

    technique_map = {
        t["id"]: t["name"]
        for t in techniques
        if t.get("id") and t.get("name")
    }

    valid_techniques = []
    for t in tech_list:
        t_id = t.get("technique_id")
        if not t_id or str(t_id).lower() == "null" or t_id == "Unverified" or t_id not in technique_map:
            continue

        # Backend Is Authoritative For The Technique Name
        t["technique_name"] = technique_map[t_id]
        valid_techniques.append(t)

    cve["techniques"] = valid_techniques
    return cve


@app.get("/report/pdf")
async def generate_pdf_report():
    # Automated Compliance-Style Export Of The Current Live Threat Snapshot
    nodes = cached_cves.get("nodes", [])
    kev_nodes = [n for n in nodes if n.get("is_kev")]

    severity_counts = {"CRITICAL": 0, "HIGH": 0,
                       "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for n in nodes:
        key = n.get("severity", "UNKNOWN")
        severity_counts[key] = severity_counts.get(key, 0) + 1

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter,
                            title="Threatmesh 3D Threat Intelligence Report")
    styles = getSampleStyleSheet()
    elements = []

    elements.append(
        Paragraph("Threatmesh 3D — Threat Intelligence Report", styles["Title"]))
    elements.append(Paragraph(
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}", styles["Normal"]))
    elements.append(Spacer(1, 12))

    summary = (
        f"Total Threats Monitored: {len(nodes)} &nbsp;|&nbsp; Actively Exploited (Kev): {len(kev_nodes)} "
        f"&nbsp;|&nbsp; Critical: {severity_counts['CRITICAL']} &nbsp; High: {severity_counts['HIGH']} "
        f"&nbsp; Medium: {severity_counts['MEDIUM']} &nbsp; Low: {severity_counts['LOW']}"
    )
    elements.append(Paragraph(summary, styles["Normal"]))
    elements.append(Spacer(1, 16))
    elements.append(
        Paragraph("Actively Exploited Threats (Kev-Confirmed)", styles["Heading2"]))

    table_data = [["Cve Id", "Severity", "Score",
                   "Vendor / Product", "Att&ck", "Confidence", "Verified"]]
    sorted_kev = sorted(kev_nodes, key=lambda n: -(n.get("score") or 0))[:30]

    for n in sorted_kev:
        table_data.append([
            n.get("id", "-"),
            n.get("severity", "-"),
            str(n.get("score", "-")),
            f"{n.get('vendor', '-')}/{n.get('product', '-')}",
            n.get("technique_id") or "-",
            n.get("confidence") or "-",
            "Yes" if n.get("verified") else "No",
        ])

    report_table = Table(table_data, repeatRows=1)
    report_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.white, colors.HexColor("#f3f4f6")]),
    ]))
    elements.append(report_table)

    doc.build(elements)
    buffer.seek(0)

    return Response(
        content=buffer.read(),
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=threatmesh_report.pdf"}
    )


def get_cve_description(cve: dict) -> str:
    descriptions = cve.get("descriptions", [])
    for item in descriptions:
        if item.get("lang") == "en":
            return item.get("value", "")
    return descriptions[0].get("value", "") if descriptions else ""


async def fetch_cves(kev_cves: set) -> dict:
    global cached_cves, last_fetched_timestamp

    now = datetime.now(timezone.utc)
    window_start = last_fetched_timestamp
    if window_start < now - MAX_DELTA_WINDOW:
        window_start = now - MAX_DELTA_WINDOW
        print(
            f"Delta Window Exceeded {MAX_DELTA_WINDOW}, Capping Lookback To Prevent Runaway Growth.", flush=True)

    start_str = window_start.strftime("%Y-%m-%dT%H:%M:%S.000")
    end_str = now.strftime("%Y-%m-%dT%H:%M:%S.000")

    data = {"vulnerabilities": []}

    async with httpx.AsyncClient() as client:
        # Block One: Isolate The Fragile Delta Fetch With A Hard Wall Clock Kill Switch
        try:
            print(
                f"Polling Nvd For Rolling Delta Updates Since: {start_str}", flush=True)

            response = await asyncio.wait_for(
                client.get(
                    NVD_URL,
                    params={"lastModStartDate": start_str,
                            "lastModEndDate": end_str},
                    headers=NVD_HEADERS,
                    timeout=15.0
                ),
                timeout=15.0
            )
            response.raise_for_status()
            delta_data = response.json()

            delta_count = len(delta_data.get("vulnerabilities", []))
            print(
                f"Nvd Delta Fetch Returned {delta_count} Modified Vulnerabilities This Cycle.", flush=True)

            if "vulnerabilities" in delta_data:
                data["vulnerabilities"].extend(delta_data["vulnerabilities"])

            # Only Update Timestamp If The Request Fully Succeeds
            last_fetched_timestamp = now

        except asyncio.TimeoutError:
            print(
                "Nvd Delta Application Programming Interface Hard Timed Out. Skipping Delta.", flush=True)
        except Exception as e:
            print(
                f"Nvd Delta Application Programming Interface Degraded. Skipping. Error: {e}", flush=True)

        # Block Two: The Core Processing Engine Runs Even If The Delta Fails
        try:
            kev_details = await fetch_kev_details(kev_cves)
            raw_kev_list = kev_details.get("vulnerabilities", [])
            data["vulnerabilities"].extend(raw_kev_list)

            unique_vulnerabilities = {}
            for item in data["vulnerabilities"]:
                cve_id = item.get("cve", {}).get("id")
                if cve_id:
                    unique_vulnerabilities[cve_id] = item

            data["vulnerabilities"] = list(unique_vulnerabilities.values())

            unanalyzed_cves = []
            for item in data["vulnerabilities"]:
                cve_inner = item.get("cve", {})
                cve_id = cve_inner.get("id")

                if cve_id and (cve_id in kev_cves) and (cve_id not in cached_ai_analysis):
                    source_description = get_cve_description(cve_inner)
                    severity, score = extract_cvss_metrics(cve_inner)

                    unanalyzed_cves.append({
                        "id": cve_id,
                        "description": source_description[:200],
                        "source_description": source_description,
                        "severity": severity,
                        "score": score,
                        "is_kev": True
                    })

            unanalyzed_cves.sort(key=lambda x: -x["score"])

            if unanalyzed_cves:
                print(
                    f"Processing Rolling AI Security Evaluation For {len(unanalyzed_cves[:AI_SAMPLE_SIZE])} Active Threats.", flush=True)
                new_analysis = await analyze_with_ai(
                    unanalyzed_cves[:AI_SAMPLE_SIZE],
                    cached_attack_techniques
                )
                if isinstance(new_analysis, list):
                    for item in new_analysis:
                        cve_id = item.get("id")
                        if cve_id:
                            item["attack_vector"] = item.get(
                                "facts", "Unknown Facts")
                            techs = item.get("techniques", [])
                            if techs and len(techs) > 0:
                                primary = techs[0]
                                item["technique_id"] = primary.get(
                                    "technique_id")
                                item["technique_name"] = primary.get(
                                    "technique_name")
                                item["confidence"] = primary.get("confidence")
                                item["evidence_type"] = primary.get(
                                    "evidence_type")
                                item["evidence"] = primary.get("evidence")
                                item["all_techniques"] = techs
                            else:
                                item["technique_id"] = None
                                item["technique_name"] = None
                                item["confidence"] = "Low"
                                item["evidence_type"] = "Insufficient"
                                item["evidence"] = "Insufficient Data To Confidently Map Att&ck Behavior"
                                item["all_techniques"] = []

                            item["verified"] = False
                            item["verification_verdict"] = None
                            cached_ai_analysis[cve_id] = item

                    # --- Month 4: Verifier Agents, Dispatched Only For What The Classifier Was Unsure About ---
                    desc_by_id = {cve["id"]: cve for cve in unanalyzed_cves}
                    flagged_for_verification = [
                        {**item, "source_description": desc_by_id.get(
                            item["id"], {}).get("source_description", "")}
                        for item in new_analysis
                        if needs_verification(item)
                    ]
                    verification_results = await run_verification_agents(flagged_for_verification, cached_attack_techniques)

                    for cve_id, verdict in verification_results.items():
                        item = cached_ai_analysis.get(cve_id)
                        if not item:
                            continue
                        item["verified"] = True
                        item["verification_verdict"] = verdict.get("verdict")
                        if verdict.get("verifier_note"):
                            item["verifier_note"] = verdict["verifier_note"]

                        if verdict.get("verdict") == "revise" and verdict.get("techniques"):
                            item["techniques"] = verdict["techniques"]
                            normalize_technique_mapping(
                                item, cached_attack_techniques)
                            item["all_techniques"] = item["techniques"]

                            if item["all_techniques"]:
                                primary = item["all_techniques"][0]
                                item["technique_id"] = primary.get(
                                    "technique_id")
                                item["technique_name"] = primary.get(
                                    "technique_name")
                                item["confidence"] = primary.get("confidence")
                                item["evidence_type"] = primary.get(
                                    "evidence_type")
                                item["evidence"] = primary.get("evidence")
                            else:
                                # Verifier's Suggestion Was Entirely Invalid/Hallucinated — Fall Back
                                item["confidence"] = "Low"
                                item["evidence_type"] = "Insufficient"
                                item["evidence"] = "Verifier's Revision Contained No Valid Att&ck Technique Ids"
                                item["technique_id"] = None
                                item["technique_name"] = None
                        elif verdict.get("verdict") == "insufficient":
                            item["confidence"] = "Low"
                            item["evidence_type"] = "Insufficient"
                            item["evidence"] = "Verifier Agent Found Insufficient Evidence For A Confident Mapping"
                            item["all_techniques"] = []
                            item["technique_id"] = None
                            item["technique_name"] = None

                elif isinstance(new_analysis, dict):
                    cached_ai_analysis.update(new_analysis)

            result = process_cves(
                data, kev_ids=kev_cves, ai_analysis=cached_ai_analysis, cached_nodes=cached_cves.get("nodes", []))

            if result and isinstance(result, dict):
                for cve in result.get("nodes", []):
                    cve_id = cve.get("id")
                    cve["is_kev"] = cve_id in kev_cves

                    if cve_id not in cached_ai_analysis:
                        if cve["is_kev"]:
                            cve["technique_id"] = "Pending"
                            cve["technique_name"] = "Awaiting AI Processing In Queue..."
                            cve["confidence"] = "Pending"
                            cve["evidence_type"] = "Insufficient"
                            cve["attack_vector"] = "Active KEV Threat In Queue"
                            cve["mitigation"] = "Prioritize Immediate Vendor Patch"
                            cve["evidence"] = "In Queue"
                            cve["all_techniques"] = []
                        else:
                            cve["technique_id"] = "Standard"
                            cve["technique_name"] = "Standard Vulnerability Record"
                            cve["confidence"] = "Baseline"
                            cve["evidence_type"] = "Insufficient"
                            cve["attack_vector"] = "Standard Security Advisory"
                            cve["mitigation"] = "Standard Lifecycle Patching"
                            cve["evidence"] = "Unexploited Record"
                            cve["all_techniques"] = []

                existing_node_ids = {n["id"]
                                     for n in cached_cves.get("nodes", [])}
                combined_nodes = list(cached_cves.get("nodes", []))

                for new_node in result.get("nodes", []):
                    if new_node["id"] not in existing_node_ids:
                        combined_nodes.append(new_node)
                        existing_node_ids.add(new_node["id"])

                if len(combined_nodes) > MAX_NODES:
                    kev_nodes = [n for n in combined_nodes if n.get("is_kev")]
                    non_kev_nodes = [
                        n for n in combined_nodes if not n.get("is_kev")]

                    kept_non_kev = non_kev_nodes[-MIN_NON_KEV_NODES:]
                    remaining_budget = MAX_NODES - len(kept_non_kev)
                    kept_kev = kev_nodes[-remaining_budget:]

                    combined_nodes = kept_kev + kept_non_kev

                from processor import build_attack_path_edges
                cached_cves = {
                    "nodes": combined_nodes,
                    "edges": build_attack_path_edges(combined_nodes)
                }

                kev_count = sum(1 for n in combined_nodes if n.get("is_kev"))
                non_kev_count = len(combined_nodes) - kev_count
                print(
                    f"Node Population — Total: {len(combined_nodes)}, Kev: {kev_count}, Non-Kev: {non_kev_count}", flush=True)

            return cached_cves

        except Exception as e:
            print(f"Error Inside Core Threat Processing Loop: {e}", flush=True)
            return cached_cves


async def fetch_attack() -> list[dict]:
    ATTACK_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(ATTACK_URL, timeout=30.0)
            response.raise_for_status()
            data = response.json()

            techniques = []
            for obj in data.get("objects", []):
                if obj.get("type") != "attack-pattern":
                    continue
                if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                    continue

                attack_id = None
                for ref in obj.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack":
                        attack_id = ref.get("external_id")
                        break

                if not attack_id:
                    continue

                techniques.append({
                    "id": attack_id,
                    "name": obj.get("name", "")
                })

            return techniques

        except Exception as e:
            print(f"Error Fetching Att&ck Data: {e}", flush=True)
            return []


async def fetch_kev_details(kev_ids: set) -> dict:
    if not kev_ids:
        return {"vulnerabilities": []}

    unprocessed_ids = [
        cve_id
        for cve_id in kev_ids
        if cve_id not in cached_ai_analysis
    ]

    sample = unprocessed_ids[:AI_SAMPLE_SIZE]

    if not sample:
        return {"vulnerabilities": []}

    print(
        f"Firing Fast Concurrent Network Requests For {len(sample)} Threats...", flush=True)

    async with httpx.AsyncClient() as client:
        # Wrap Every Single Task In A Hard Wall Clock Kill Switch
        tasks = [
            asyncio.wait_for(
                client.get(
                    NVD_URL,
                    params={"cveId": cve_id},
                    headers=NVD_HEADERS,
                    timeout=15.0
                ),
                timeout=15.0
            )
            for cve_id in sample
        ]

        responses = await asyncio.gather(
            *tasks,
            return_exceptions=True
        )

        combined = []
        for r in responses:
            if isinstance(r, asyncio.TimeoutError):
                print(
                    "A Threat Request Hard Timed Out Due To Server Tarpitting.", flush=True)
                continue
            if isinstance(r, Exception):
                print(f"Error Fetching Cve Details: {r}", flush=True)
                continue
            try:
                r.raise_for_status()
                combined.extend(r.json().get("vulnerabilities", []))
            except (httpx.HTTPStatusError, ValueError) as e:
                print(f"Error Processing Response: {e}", flush=True)

        return {"vulnerabilities": combined}


async def fetch_kev() -> set:
    KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(KEV_URL, timeout=30.0)
            response.raise_for_status()
            data = response.json()
            return {cve.get("cveID") for cve in data.get("vulnerabilities", [])}
        except Exception as e:
            print(f"Error Fetching Kev: {e}", flush=True)
            return set()


def needs_verification(item: dict) -> bool:
    return (
        item.get("confidence") in LOW_CONFIDENCE_VALUES
        or item.get("evidence_type") in WEAK_EVIDENCE_VALUES
    )


async def verify_cve_chunk(chunk: list[dict], techniques: list[dict]) -> list[dict]:
    # Verifier Agent — Audits A Small Chunk Of Already-Classified Cves
    technique_list_items = [
        f"{t['id']}: {t['name']}"
        for t in techniques
        if t.get("id") and t.get("name")
    ][:MAX_TECHNIQUES_FOR_PROMPT]
    technique_list = "\n".join(technique_list_items)

    system_prompt = (
        "You Are A Skeptical Senior Threat Analyst Auditing A Junior Analyst's Mitre Att&ck Classifications. "
        "Do Not Re-Derive From Scratch — Find Mistakes In What's Already Proposed.\n"
        "\nDecide Per Cve:\n"
        "- 'confirm': The Mapping Is Reasonable As-Is.\n"
        "- 'revise': The Mapping Is Wrong Or Too Weak — Provide Corrected Technique(s) From The List Below.\n"
        "- 'insufficient': The Description Doesn't Support Any Confident Mapping.\n"
        "\nWrap Output In A Dictionary With A 'verifications' Key, Exactly Like This:\n"
        '{"verifications": [{"id": "CVE-Identifier", "verdict": "confirm Or revise Or insufficient", '
        '"techniques": [{"technique_id": "Txxxx", "technique_name": "Name", "confidence": "High Or Medium Or Low", '
        '"evidence_type": "Direct Or Inferred Or Insufficient", "evidence": "Short Extracted Proof"}], '
        '"verifier_note": "One Short Sentence Explaining The Verdict"}]}\n'
        "For 'confirm' Or 'insufficient', Repeat The Original Techniques Unchanged (Empty Array For Insufficient)."
        f"\n\nFramework Categories Available:\n{technique_list}"
    )

    user_message = "\n\n".join(
        f"Identifier: {cve['id']}\n"
        f"Original Description: {cve.get('source_description', '')[:1000]}\n"
        f"Junior Analyst Proposed: {cve.get('all_techniques', [])}\n"
        f"Stated Confidence: {cve.get('confidence')}, Evidence Type: {cve.get('evidence_type')}"
        for cve in chunk
    )

    raw_content = None

    try:
        response = await ai_client.chat.completions.create(
            model="gemini-3.5-flash-lite",
            temperature=0.0,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message}
            ]
        )
        usage = response.usage
        print(f"[Verifier Agent] Prompt Tokens: {usage.prompt_tokens}, "
              f"Completion Tokens: {usage.completion_tokens}", flush=True)

        raw_content = response.choices[0].message.content.strip()
        json_match = re.search(r'(\{.*\}|\[.*\])', raw_content, re.DOTALL)
        if not json_match:
            return []

        clean_json_string = json_match.group(1)
        try:
            parsed = json.loads(clean_json_string, strict=False)
        except json.JSONDecodeError:
            parsed = json.loads(sanitize_json_string(
                clean_json_string), strict=False)

        return parsed.get("verifications", []) if isinstance(parsed, dict) else []

    except Exception as e:
        print(f"Error In Verifier Agent: {e}", flush=True)
        if raw_content:
            print(
                f"Raw Verifier Output That Failed To Parse: {raw_content}", flush=True)
        return []


async def run_verification_agents(flagged: list[dict], techniques: list[dict]) -> dict:
    # Orchestrator — Splits Flagged Cves Into Chunks, Runs Verifier Agents Concurrently
    if not flagged:
        return {}

    chunks = [
        flagged[i:i + VERIFICATION_CHUNK_SIZE]
        for i in range(0, len(flagged), VERIFICATION_CHUNK_SIZE)
    ]
    print(
        f"Dispatching {len(chunks)} Concurrent Verifier Agents For {len(flagged)} Flagged Cves.", flush=True)

    results = await asyncio.gather(
        *[verify_cve_chunk(chunk, techniques) for chunk in chunks],
        return_exceptions=True
    )

    verified_map = {}
    for r in results:
        if isinstance(r, Exception):
            print(f"Verifier Chunk Failed: {r}", flush=True)
            continue
        for v in r:
            if v.get("id"):
                verified_map[v["id"]] = v
    return verified_map


async def analyze_with_ai(kev_cves: list[dict], techniques: list[dict]) -> list[dict]:
    if not kev_cves:
        return []

    cve_summary = [
        {
            "id": cve.get("id"),
            "description": cve.get("description", "")[:200],
            "source_description": cve.get(
                "source_description",
                cve.get("description", "")
            ),
            "severity": cve.get("severity"),
            "score": cve.get("score")
        }
        for cve in kev_cves
    ]

    technique_list_items = [
        f"{t['id']}: {t['name']}"
        for t in techniques
        if t.get("id") and t.get("name")
    ][:MAX_TECHNIQUES_FOR_PROMPT]

    print(
        f"Mitre Framework Categories Available To The Model: {len(technique_list_items)} / {len(techniques)}", flush=True)

    technique_list = "\n".join(technique_list_items)

    # V5 Attack Chain Prompt Enforcing Absolute Fact Integrity And Multi-Technique Arrays
    system_prompt = (
        "You Are A Fast, Expert Cyber Threat Analyst. Evaluate Vulnerabilities And Map Them To Up To TWO Specific Mitre Att&ck Techniques to represent the attack chain (e.g., Initial Access + Execution).\n"
        "\nStrict Architectural Mapping Rules:\n"
        "1. Fact Extraction Accuracy: Be meticulously accurate. If the exploit is network-based, Reachability is 'Remote'. If it explicitly says 'unauthenticated', Auth MUST be 'None'. If it requires a victim to process a payload or open a link, UI MUST be 'True'.\n"
        "2. T1210 Remote Services: If the vulnerability targets internal/SMB/RPC services (e.g., SMBv1/EternalBlue) rather than a public-facing web app, map to T1210 (Exploitation of Remote Services) instead of T1190.\n"
        "3. T1059 vs ACE: Do Not Map Generic 'Arbitrary Code Execution' To T1059. T1059 Strictly Requires Explicit Evidence Of A Shell, CLI, Exec() Function, Or Command Injection. If present, pair it with the initial access technique (e.g., T1190 + T1059.004).\n"
        "4. T1190 Public-Facing: RCE or Auth Bypass targeting Web Services/APIs without user interaction is T1190.\n"
        "5. T1203 Client Execution: UI 'True' (Opening Malicious Files/Webpages) maps to T1203.\n"
        "6. T1068 Privilege Escalation: 'Local' reachability granting Root/SYSTEM privileges is T1068.\n"
        "\nJson Construction Directive:\n"
        "Generate Minimal Json. Keep 'Mitigation' And 'Evidence' Strings Under Fifteen Words. "
        "You Must Wrap The Output In A Dictionary With A 'cves' Key. The Output Must Look Exactly Like This:\n"
        '{"cves": [{"id": "CVE-Identifier", '
        '"facts": "Reachability: Remote Or Local Or Adjacent Or Physical, Auth: None Or Required, UI: True Or False", '
        '"mitigation": "Short Specific Patch Instruction", '
        '"techniques": [{"technique_id": "Txxxx", "technique_name": "Name", "confidence": "High Or Medium Or Low", "evidence_type": "Direct Or Inferred Or Insufficient", "evidence": "Short Extracted Proof"}]}]}'
        f"\n\nFramework Categories Available:\n{technique_list}"
    )

    try:
        user_message = f"You Must Process Exactly {len(cve_summary)} Vulnerabilities. Do Not Miss Any. Your Output Array Must Contain Exactly {len(cve_summary)} Elements.\n\n" + "\n".join(
            f"Identifier: {cve['id']}\n"
            f"Original Vulnerability Description: {cve['source_description'][:1000]}\n"
            f"Severity Level: {cve['severity']}\n"
            f"Vulnerability Score: {cve['score']}"
            for cve in cve_summary
        )

        response = await ai_client.chat.completions.create(
            model="gemini-3.5-flash-lite",
            temperature=0.0,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message}
            ]
        )

        usage = response.usage
        print(
            f"Model Resource Consumption — Prompt Tokens: {usage.prompt_tokens}, Completion Tokens: {usage.completion_tokens}, Total Tokens: {usage.total_tokens}", flush=True)

        raw_content = response.choices[0].message.content.strip()

        json_match = re.search(r'(\{.*\}|\[.*\])', raw_content, re.DOTALL)

        if json_match:
            clean_json_string = json_match.group(1)

            try:
                parsed_data = json.loads(clean_json_string, strict=False)
                if isinstance(parsed_data, list):
                    analysis = parsed_data
                else:
                    analysis = parsed_data.get("cves", [])
            except json.JSONDecodeError:
                clean_json_string = sanitize_json_string(clean_json_string)
                try:
                    parsed_data = json.loads(clean_json_string, strict=False)
                    if isinstance(parsed_data, list):
                        analysis = parsed_data
                    else:
                        analysis = parsed_data.get("cves", [])
                except json.JSONDecodeError as e:
                    print(
                        f"Error Decoding Extracted Json After Sanitization: {e}", flush=True)
                    return []
        else:
            print("Error: Could Not Locate Json Payload In The Output", flush=True)
            return []

        if not isinstance(analysis, list):
            print("Error Encountered In Model Analysis: Expected Json Array", flush=True)
            return []

        expected_ids = {
            cve["id"]
            for cve in kev_cves
            if cve.get("id")
        }

        analysis = [
            cve
            for cve in analysis
            if isinstance(cve, dict)
            and cve.get("id") in expected_ids
        ]

        for cve in analysis:
            normalize_technique_mapping(cve, techniques)

        return analysis

    except Exception as e:
        print(f"Error Encountered In Model Analysis: {e}", flush=True)
        return []


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_connections.add(websocket)

    try:
        if cached_cves.get("nodes"):
            await websocket.send_text(json.dumps({"status": "ok", "data": cached_cves}))

        while True:
            await websocket.receive_text()

    except WebSocketDisconnect:
        if websocket in active_connections:
            active_connections.remove(websocket)
        print("Frontend Client Disconnected.", flush=True)


def listen_for_quit():
    while True:
        try:
            if input().strip().lower() == 'q':
                print(SHUTDOWN_MSG, flush=True)
                os._exit(0)
        except EOFError:
            break


if __name__ == "__main__":
    import uvicorn
    threading.Thread(target=listen_for_quit, daemon=True).start()
    uvicorn.run(app, host="127.0.0.1", port=8000)
