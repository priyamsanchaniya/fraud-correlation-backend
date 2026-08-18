"""
Correlation logic for the backend.
-------------------------------------
This is the SAME tested logic from correlation_engine.py (fraud rings,
mule cluster detection, MO text similarity), adapted to work on rows
fetched from the database instead of a CSV file.
"""

import re
from collections import defaultdict

MATCH_WEIGHTS = {
    "phone_used_by_fraudster": 0.9,
    "upi_id": 0.9,
    "bank_account": 0.95,
    # ifsc_code intentionally excluded - a bank branch code alone is
    # shared by thousands of unrelated customers, so it should never
    # independently form a "confirmed ring".
}


def build_fraud_rings(complaints: list) -> list:
    """Groups complaints into fraud rings based on shared phone/UPI/account."""
    index = {field: defaultdict(list) for field in MATCH_WEIGHTS}
    for c in complaints:
        for field in MATCH_WEIGHTS:
            val = (c.get(field) or "").strip()
            if val:
                index[field][val].append(c["complaint_id"])

    edge_reasons = defaultdict(list)
    for field, value_map in index.items():
        for value, ids in value_map.items():
            if len(ids) < 2:
                continue
            for i in range(len(ids)):
                for j in range(i + 1, len(ids)):
                    key = tuple(sorted([ids[i], ids[j]]))
                    edge_reasons[key].append((field, value))

    adjacency = defaultdict(set)
    edge_confidence = {}
    for (a, b), reasons in edge_reasons.items():
        combined = 1.0
        for field, _ in reasons:
            combined *= (1 - MATCH_WEIGHTS[field])
        confidence = round(1 - combined, 3)
        adjacency[a].add(b)
        adjacency[b].add(a)
        edge_confidence[(a, b)] = confidence

    by_id = {c["complaint_id"]: c for c in complaints}
    visited = set()
    clusters = []

    for c in complaints:
        cid = c["complaint_id"]
        if cid in visited:
            continue
        stack, component = [cid], []
        visited.add(cid)
        while stack:
            cur = stack.pop()
            component.append(cur)
            for n in adjacency[cur]:
                if n not in visited:
                    visited.add(n)
                    stack.append(n)
        if len(component) < 2:
            continue

        component.sort()
        states = sorted(set(by_id[i]["state"] for i in component))
        total_loss = sum(float(by_id[i].get("amount_lost_inr") or 0) for i in component)

        confs = []
        for i in range(len(component)):
            for j in range(i + 1, len(component)):
                key = tuple(sorted([component[i], component[j]]))
                if key in edge_confidence:
                    confs.append(edge_confidence[key])

        clusters.append({
            "member_ids": component,
            "size": len(component),
            "states": states,
            "cross_state": len(states) > 1,
            "avg_confidence": round(sum(confs) / len(confs), 3) if confs else 0,
            "total_loss": total_loss,
        })

    clusters.sort(key=lambda c: (c["cross_state"], c["size"], c["total_loss"]), reverse=True)
    for i, c in enumerate(clusters, start=1):
        c["cluster_id"] = f"CLUSTER-{i:03d}"
    return clusters


def build_mule_clusters(complaints: list, min_distinct_accounts: int = 3) -> list:
    """Flags bank branches (IFSC) showing 3+ distinct account numbers
    across different complaints - a proxy signal for mule recruitment,
    with supporting evidence (not a bare confidence score)."""
    by_ifsc = defaultdict(lambda: defaultdict(list))
    for c in complaints:
        ifsc = (c.get("ifsc_code") or "").strip()
        account = (c.get("bank_account") or "").strip()
        if ifsc and account:
            by_ifsc[ifsc][account].append(c)

    clusters = []
    for ifsc, acc_map in by_ifsc.items():
        if len(acc_map) < min_distinct_accounts:
            continue

        all_complaints = [c for lst in acc_map.values() for c in lst]
        states = sorted(set(c["state"] for c in all_complaints))
        total_loss = sum(float(c.get("amount_lost_inr") or 0) for c in all_complaints)

        evidence = [
            f"{len(acc_map)} different account numbers at the same branch ({ifsc}) "
            f"across {len(all_complaints)} separate complaints."
        ]

        dates = sorted(c["date_filed"] for c in all_complaints if c.get("date_filed"))
        tight_window = False
        if len(dates) >= 2:
            from datetime import datetime
            try:
                spread = (datetime.fromisoformat(dates[-1]) - datetime.fromisoformat(dates[0])).days
                if spread <= 30:
                    tight_window = True
                    evidence.append(f"All complaints filed within a {spread}-day window - consistent with bulk mule recruitment.")
            except ValueError:
                pass

        numeric_accounts = sorted(int(a) for a in acc_map if a.isdigit())
        sequential = False
        if len(numeric_accounts) >= 3:
            gaps = [numeric_accounts[i] - numeric_accounts[i - 1] for i in range(1, len(numeric_accounts))]
            avg_gap = sum(gaps) / len(gaps)
            if 0 < avg_gap < 500:
                sequential = True
                evidence.append(f"Account numbers are numerically close together (avg. gap {round(avg_gap)}) - a sign of bulk account opening.")

        if len(states) > 1:
            evidence.append(f"Victims span {len(states)} different states ({', '.join(states)}).")

        signal_count = 1 + tight_window + sequential + (len(states) > 1)
        flag = ("SUSPECTED MULE NETWORK" if signal_count >= 3
                else "POSSIBLE MULE NETWORK" if signal_count == 2
                else "WORTH REVIEWING")

        clusters.append({
            "ifsc": ifsc,
            "bank_code": ifsc[:4],
            "distinct_accounts": len(acc_map),
            "complaint_count": len(all_complaints),
            "states": states,
            "total_loss": total_loss,
            "flag": flag,
            "signal_count": signal_count,
            "evidence": evidence,
            "complaint_ids": [c["complaint_id"] for c in all_complaints],
        })

    clusters.sort(key=lambda c: (c["signal_count"], c["distinct_accounts"]), reverse=True)
    return clusters


STOPWORDS = {
    "the", "a", "an", "and", "or", "to", "of", "in", "on", "for", "was", "were",
    "is", "are", "he", "she", "they", "victim", "fraudster", "then", "after",
    "with", "from", "that", "this", "his", "her", "their", "had", "have",
    "has", "it", "as", "by", "at", "be", "been",
}


def _tokenize(text: str) -> set:
    words = re.sub(r"[^a-z0-9\s]", " ", (text or "").lower()).split()
    return {w for w in words if len(w) > 2 and w not in STOPWORDS}


def _jaccard(a: set, b: set) -> float:
    if not a or not b:
        return 0
    inter = len(a & b)
    union = len(a | b)
    return inter / union if union else 0


def build_mo_pattern_clusters(complaints: list, threshold: float = 0.45) -> list:
    """Flags complaints with near-identical MO (modus operandi) text even
    when phone/UPI/account/IFSC are all completely different - catches a
    gang reusing the same script with fresh identifiers each time."""
    tokenized = [(c, _tokenize(c.get("mo_description"))) for c in complaints]
    tokenized = [(c, t) for c, t in tokenized if len(t) >= 4]

    adjacency = defaultdict(set)
    pair_sim = {}
    for i in range(len(tokenized)):
        for j in range(i + 1, len(tokenized)):
            ci, ti = tokenized[i]
            cj, tj = tokenized[j]
            sim = _jaccard(ti, tj)
            if sim >= threshold:
                adjacency[ci["complaint_id"]].add(cj["complaint_id"])
                adjacency[cj["complaint_id"]].add(ci["complaint_id"])
                pair_sim[tuple(sorted([ci["complaint_id"], cj["complaint_id"]]))] = sim

    by_id = {c["complaint_id"]: c for c, _ in tokenized}
    visited = set()
    clusters = []
    for c, _ in tokenized:
        cid = c["complaint_id"]
        if cid in visited:
            continue
        stack, component = [cid], []
        visited.add(cid)
        while stack:
            cur = stack.pop()
            component.append(cur)
            for n in adjacency[cur]:
                if n not in visited:
                    visited.add(n)
                    stack.append(n)
        if len(component) < 2:
            continue
        members = [by_id[i] for i in component]

        sims = []
        for i in range(len(component)):
            for j in range(i + 1, len(component)):
                key = tuple(sorted([component[i], component[j]]))
                if key in pair_sim:
                    sims.append(pair_sim[key])

        clusters.append({
            "member_ids": component,
            "size": len(component),
            "states": sorted(set(m["state"] for m in members)),
            "total_loss": sum(float(m.get("amount_lost_inr") or 0) for m in members),
            "avg_similarity": round(sum(sims) / len(sims), 3) if sims else 0,
        })

    clusters.sort(key=lambda c: c["size"], reverse=True)
    for i, c in enumerate(clusters, start=1):
        c["pattern_id"] = f"PATTERN-{i:03d}"
    return clusters
