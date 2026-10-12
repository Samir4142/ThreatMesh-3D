import random
import hashlib


MAX_HISTORIC_NODES = 200


def extract_vendor_product(cve_data: dict) -> tuple[str, str]:
    configurations = cve_data.get("cve", {}).get("configurations", [])
    for config in configurations:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable") is True:
                    criteria = match.get("criteria", "")
                    parts = criteria.split(":")
                    if len(parts) >= 5:
                        return parts[3], parts[4]
    return "Unknown", "Unknown"


def build_attack_path_edges(clean_cves: list[dict]) -> list[dict]:
    cluster_map = {}
    for cve in clean_cves:
        vendor = cve.get("vendor", "Unknown")
        product = cve.get("product", "Unknown")
        if vendor != "Unknown" and product != "Unknown":
            key = (vendor, product)
            if key not in cluster_map:
                cluster_map[key] = []
            cluster_map[key].append(cve.get("id"))

    edges = []
    MAX_EDGES_PER_CLUSTER = 500

    for key, members in cluster_map.items():
        if len(members) >= 2:
            edge_count = 0
            for i in range(len(members)):
                for j in range(i + 1, len(members)):
                    if edge_count >= MAX_EDGES_PER_CLUSTER:
                        break
                    edges.append({
                        "source": members[i],
                        "target": members[j],
                        "label": f"{key[0]}:{key[1]}"
                    })
                    edge_count += 1
    return edges


def extract_cvss_metrics(cve_inner: dict) -> tuple[str, float]:
    metrics = cve_inner.get("metrics", {})

    v40 = metrics.get("cvssMetricV40", [])
    if v40:
        data = v40[0].get("cvssData", {})
        return data.get("baseSeverity", "UNKNOWN").upper(), data.get("baseScore", 0.0)

    v31 = metrics.get("cvssMetricV31", [])
    if v31:
        data = v31[0].get("cvssData", {})
        return data.get("baseSeverity", "UNKNOWN").upper(), data.get("baseScore", 0.0)

    v30 = metrics.get("cvssMetricV30", [])
    if v30:
        data = v30[0].get("cvssData", {})
        return data.get("baseSeverity", "UNKNOWN").upper(), data.get("baseScore", 0.0)

    v2 = metrics.get("cvssMetricV2", [])
    if v2:
        severity = v2[0].get("baseSeverity", "UNKNOWN").upper()
        score = v2[0].get("cvssData", {}).get("baseScore", 0.0)
        return severity, score

    return "UNKNOWN", 0.0


def get_stable_coordinates(cve_id: str) -> tuple[float, float, float]:
    hasher = hashlib.md5(cve_id.encode())
    seed = int(hasher.hexdigest(), 16)
    r = random.Random(seed)
    return r.uniform(-100, 100), r.uniform(-100, 100), r.uniform(-100, 100)


def process_cves(raw_data: dict, kev_ids: set, ai_analysis: dict, cached_nodes: list = None) -> dict:
    if cached_nodes is None:
        cached_nodes = []

    historic_added = 0
    cve_list = raw_data.get("vulnerabilities", [])
    clean_cves = []
    current_ids = set()

    for cve in cve_list:
        cve_inner = cve.get("cve", {})
        cve_id = cve_inner.get("id")

        if not cve_id:
            continue

        description = (
            cve_inner.get("descriptions", [{}])[0]
            .get("value", "No Description Available")
            .replace("\xa0", " ")
            .replace("\u202f", " ")
            .strip()
        )

        severity, score = extract_cvss_metrics(cve_inner)
        published = cve_inner.get("published", "Unknown")
        x, y, z = get_stable_coordinates(cve_id)
        vendor, product = extract_vendor_product(cve)

        node_dict = {
            "id": cve_id,
            "description": description,
            "severity": severity,
            "score": score,
            "published": published,
            "position": {
                "x": x,
                "y": y,
                "z": z
            },
            "is_kev": cve_id in kev_ids,
            "vendor": vendor,
            "product": product,
            "attack_vector": ai_analysis.get(cve_id, {}).get("attack_vector", "Unknown"),
            "mitigation": ai_analysis.get(cve_id, {}).get("mitigation", "Unknown"),
            "technique_id": ai_analysis.get(cve_id, {}).get("technique_id", "Unknown"),
            "technique_name": ai_analysis.get(cve_id, {}).get("technique_name", "Unknown"),
            "confidence": ai_analysis.get(cve_id, {}).get("confidence", "Unknown"),
            "evidence": ai_analysis.get(cve_id, {}).get("evidence", "Unknown"),
            "evidence_type": ai_analysis.get(cve_id, {}).get("evidence_type", "Unknown"),
            "all_techniques": ai_analysis.get(cve_id, {}).get("all_techniques", []),
            "verified": ai_analysis.get(cve_id, {}).get("verified", False),
            "verification_verdict": ai_analysis.get(cve_id, {}).get("verification_verdict"),
        }

        clean_cves.append(node_dict)
        current_ids.add(cve_id)

    for cached_node in cached_nodes:
        if historic_added >= MAX_HISTORIC_NODES:
            break

        if cached_node.get("id") not in current_ids and cached_node.get("is_kev"):
            clean_cves.append(cached_node)
            current_ids.add(cached_node.get("id"))
            historic_added += 1

    edges = build_attack_path_edges(clean_cves)

    return {
        "nodes": clean_cves,
        "edges": edges
    }
