"""
Cross-State Fraud Correlation Engine
--------------------------------------
Reads complaint records and builds a graph where:
  - Nodes = individual complaints
  - Edges = complaints that share an identifier (phone / UPI / account / IFSC)

Then finds connected components (clusters) = suspected fraud rings.

Built with robustness in mind:
  1. Input validation      -> bad rows are rejected, not silently ignored
  2. Confidence scoring     -> not all matches are equally trustworthy
  3. Audit logging          -> every decision is traceable
  4. Error handling         -> partial failures don't crash the whole run
  5. Self-tests             -> run this file directly to execute test suite
"""

import csv
import json
import re
import logging
from dataclasses import dataclass, field
from collections import defaultdict
import networkx as nx

# ---------------------------------------------------------------------
# 1. LOGGING SETUP (audit trail)
# ---------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    handlers=[
        logging.FileHandler("correlation_engine_audit.log"),
        logging.StreamHandler()
    ]
)
log = logging.getLogger("correlation_engine")


# ---------------------------------------------------------------------
# 2. VALIDATION
# ---------------------------------------------------------------------

PHONE_RE = re.compile(r"^\+91\d{10}$")
UPI_RE = re.compile(r"^[\w.\-]{2,256}@[a-zA-Z]{2,64}$")
ACCOUNT_RE = re.compile(r"^\d{9,18}$")
IFSC_RE = re.compile(r"^[A-Z]{4}0[A-Z0-9]{6}$")


class ValidationError(Exception):
    pass


def validate_row(row: dict, row_num: int) -> dict:
    """
    Validates a single complaint row. Raises ValidationError with a
    clear reason if the row is unusable. Returns a cleaned copy of
    the row if valid. Identifier fields that are present but malformed
    are dropped individually (with a warning) rather than rejecting
    the whole complaint, since a complaint can still be valid evidence
    even if e.g. the IFSC field was left blank.
    """
    required = ["complaint_id", "state", "city"]
    for field_name in required:
        if not row.get(field_name, "").strip():
            raise ValidationError(
                f"Row {row_num}: missing required field '{field_name}'"
            )

    cleaned = dict(row)

    # Phone: validate if present
    phone = row.get("phone_used_by_fraudster", "").strip()
    if phone and not PHONE_RE.match(phone):
        log.warning(f"Row {row_num} ({row['complaint_id']}): invalid phone format '{phone}' -> dropped from matching")
        cleaned["phone_used_by_fraudster"] = ""

    # UPI: validate if present
    upi = row.get("upi_id", "").strip()
    if upi and not UPI_RE.match(upi):
        log.warning(f"Row {row_num} ({row['complaint_id']}): invalid UPI format '{upi}' -> dropped from matching")
        cleaned["upi_id"] = ""

    # Account: validate if present
    acc = row.get("bank_account", "").strip()
    if acc and not ACCOUNT_RE.match(acc):
        log.warning(f"Row {row_num} ({row['complaint_id']}): invalid account format '{acc}' -> dropped from matching")
        cleaned["bank_account"] = ""

    # IFSC: validate if present
    ifsc = row.get("ifsc_code", "").strip()
    if ifsc and not IFSC_RE.match(ifsc):
        log.warning(f"Row {row_num} ({row['complaint_id']}): invalid IFSC format '{ifsc}' -> dropped from matching")
        cleaned["ifsc_code"] = ""

    # A complaint with ZERO usable identifiers can't be correlated -
    # still valid as a standalone complaint, just flagged.
    if not any([cleaned.get("phone_used_by_fraudster"),
                cleaned.get("upi_id"),
                cleaned.get("bank_account"),
                cleaned.get("ifsc_code")]):
        log.warning(f"Row {row_num} ({row['complaint_id']}): no usable identifiers, will appear as isolated node")

    return cleaned


def load_complaints(csv_path: str) -> list:
    """
    Loads and validates complaints from CSV. Rows that fail hard
    validation (missing required fields) are skipped and logged,
    NOT silently dropped - every skip is auditable.
    """
    complaints = []
    skipped = 0
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader, start=1):
            try:
                complaints.append(validate_row(row, i))
            except ValidationError as e:
                log.error(str(e))
                skipped += 1

    log.info(f"Loaded {len(complaints)} valid complaints, skipped {skipped} invalid rows from {csv_path}")
    return complaints


# ---------------------------------------------------------------------
# 3. CONFIDENCE SCORING for each identifier type
# ---------------------------------------------------------------------
# Not all matches deserve equal trust. Exact phone/UPI/account reuse is
# strong, individually-attributable signal. IFSC (bank branch code) is
# deliberately EXCLUDED from this dict - a branch code is shared by
# thousands of unrelated customers, so two complaints matching only on
# IFSC are not real evidence of a shared fraud ring. That specific
# "same branch, different accounts" pattern is handled separately and
# more carefully as a distinct "mule cluster" signal, which requires
# 3+ distinct account numbers before flagging anything - see the
# dashboard's buildMuleClusters() for the JS equivalent of that logic.

MATCH_WEIGHTS = {
    "phone_used_by_fraudster": 0.9,
    "upi_id": 0.9,
    "bank_account": 0.95,
}


# ---------------------------------------------------------------------
# 4. GRAPH BUILDING
# ---------------------------------------------------------------------

@dataclass
class CorrelationResult:
    graph: nx.Graph
    clusters: list = field(default_factory=list)
    stats: dict = field(default_factory=dict)


def build_correlation_graph(complaints: list) -> CorrelationResult:
    """
    Builds a graph where each complaint is a node, and an edge is
    added between two complaints for every identifier they share.
    Edge weight = confidence that the shared identifier is a real link.
    """
    G = nx.Graph()
    identifier_fields = list(MATCH_WEIGHTS.keys())

    # Add all complaints as nodes first (so isolated complaints with
    # no shared identifiers still show up in the graph)
    for c in complaints:
        G.add_node(c["complaint_id"], **c)

    # Index: identifier_value -> list of complaint_ids that used it
    index = {field_name: defaultdict(list) for field_name in identifier_fields}
    for c in complaints:
        for field_name in identifier_fields:
            val = c.get(field_name, "").strip()
            if val:
                index[field_name][val].append(c["complaint_id"])

    edge_reasons = defaultdict(list)  # (id1,id2) -> list of (field, value)

    for field_name, value_map in index.items():
        for value, complaint_ids in value_map.items():
            if len(complaint_ids) < 2:
                continue  # unique to one complaint, no correlation
            # connect every pair that shares this identifier value
            for i in range(len(complaint_ids)):
                for j in range(i + 1, len(complaint_ids)):
                    a, b = complaint_ids[i], complaint_ids[j]
                    key = tuple(sorted([a, b]))
                    edge_reasons[key].append((field_name, value))

    for (a, b), reasons in edge_reasons.items():
        # combined confidence: 1 - product(1 - weight) across all shared identifiers
        # (multiple independent shared identifiers compound confidence)
        combined = 1.0
        for field_name, _ in reasons:
            combined *= (1 - MATCH_WEIGHTS[field_name])
        confidence = round(1 - combined, 3)
        G.add_edge(a, b, weight=confidence, reasons=reasons)
        log.info(f"LINK: {a} <-> {b} | confidence={confidence} | shared={[r[0]+':'+r[1] for r in reasons]}")

    result = CorrelationResult(graph=G)
    result.clusters = find_clusters(G)
    result.stats = {
        "total_complaints": len(complaints),
        "total_links": G.number_of_edges(),
        "clusters_found": len([c for c in result.clusters if len(c["complaint_ids"]) > 1]),
        "isolated_complaints": len([c for c in result.clusters if len(c["complaint_ids"]) == 1]),
    }
    log.info(f"Correlation complete: {result.stats}")
    return result


def find_clusters(G: nx.Graph) -> list:
    """
    Finds connected components = suspected fraud rings.
    Each cluster gets a risk score based on size and avg edge confidence.
    """
    clusters = []
    for i, component in enumerate(nx.connected_components(G), start=1):
        complaint_ids = sorted(component)
        subgraph = G.subgraph(component)
        edges = subgraph.edges(data=True)
        avg_confidence = (
            round(sum(d["weight"] for _, _, d in edges) / len(edges), 3)
            if edges else 0.0
        )
        states = sorted(set(G.nodes[cid].get("state", "?") for cid in complaint_ids))
        total_loss = sum(
            int(G.nodes[cid].get("amount_lost_inr", 0) or 0) for cid in complaint_ids
        )
        clusters.append({
            "cluster_id": f"CLUSTER-{i:03d}",
            "complaint_ids": complaint_ids,
            "size": len(complaint_ids),
            "states_involved": states,
            "cross_state": len(states) > 1,
            "avg_confidence": avg_confidence,
            "total_amount_lost_inr": total_loss,
        })
    # Sort biggest / highest-value rings first - most actionable for investigators
    clusters.sort(key=lambda c: (c["cross_state"], c["size"], c["total_amount_lost_inr"]), reverse=True)
    return clusters


def export_results(result: CorrelationResult, out_path: str = "correlation_results.json"):
    exportable = {
        "stats": result.stats,
        "clusters": result.clusters,
    }
    with open(out_path, "w") as f:
        json.dump(exportable, f, indent=2)
    log.info(f"Results exported to {out_path}")


# ---------------------------------------------------------------------
# 5. SELF-TESTS (run this file directly to execute)
# ---------------------------------------------------------------------

def _run_tests():
    print("\n=== Running self-tests ===")
    passed = 0
    failed = 0

    def check(name, condition):
        nonlocal passed, failed
        if condition:
            print(f"  PASS: {name}")
            passed += 1
        else:
            print(f"  FAIL: {name}")
            failed += 1

    # Test 1: valid row passes
    try:
        row = {"complaint_id": "CMP-1", "state": "Gujarat", "city": "Surat",
               "phone_used_by_fraudster": "+919876543210", "upi_id": "abc@ybl",
               "bank_account": "123456789012", "ifsc_code": "SBIN0001234"}
        validate_row(row, 1)
        check("valid row passes validation", True)
    except ValidationError:
        check("valid row passes validation", False)

    # Test 2: missing required field raises
    try:
        validate_row({"complaint_id": "CMP-2", "state": "", "city": "Surat"}, 2)
        check("missing required field raises ValidationError", False)
    except ValidationError:
        check("missing required field raises ValidationError", True)

    # Test 3: malformed phone is dropped, not fatal
    row = {"complaint_id": "CMP-3", "state": "Gujarat", "city": "Surat",
           "phone_used_by_fraudster": "12345"}
    cleaned = validate_row(row, 3)
    check("malformed phone is dropped not fatal", cleaned["phone_used_by_fraudster"] == "")

    # Test 4: two complaints sharing a phone number get linked
    complaints = [
        {"complaint_id": "A", "state": "Gujarat", "city": "Surat",
         "phone_used_by_fraudster": "+919876543210", "upi_id": "", "bank_account": "", "ifsc_code": "",
         "amount_lost_inr": "1000"},
        {"complaint_id": "B", "state": "Bihar", "city": "Patna",
         "phone_used_by_fraudster": "+919876543210", "upi_id": "", "bank_account": "", "ifsc_code": "",
         "amount_lost_inr": "2000"},
        {"complaint_id": "C", "state": "Delhi", "city": "Rohini",
         "phone_used_by_fraudster": "+911111111111", "upi_id": "", "bank_account": "", "ifsc_code": "",
         "amount_lost_inr": "500"},
    ]
    result = build_correlation_graph(complaints)
    check("shared phone creates an edge A-B", result.graph.has_edge("A", "B"))
    check("unrelated complaint C stays isolated", not result.graph.has_edge("A", "C") and not result.graph.has_edge("B", "C"))
    ring_cluster = next(c for c in result.clusters if "A" in c["complaint_ids"])
    check("A and B end up in same cluster", set(ring_cluster["complaint_ids"]) == {"A", "B"})
    check("cross-state flag true for A-B (Gujarat + Bihar)", ring_cluster["cross_state"] is True)
    check("cluster total loss = 3000", ring_cluster["total_amount_lost_inr"] == 3000)

    # Test 5: empty complaint list doesn't crash
    try:
        empty_result = build_correlation_graph([])
        check("empty input doesn't crash", empty_result.stats["total_complaints"] == 0)
    except Exception:
        check("empty input doesn't crash", False)

    print(f"\n=== {passed} passed, {failed} failed ===\n")
    return failed == 0


# ---------------------------------------------------------------------
# 6. MAIN
# ---------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    if "--test" in sys.argv:
        ok = _run_tests()
        sys.exit(0 if ok else 1)

    # Normal run: process the synthetic dataset
    try:
        complaints = load_complaints("synthetic_complaints_clean.csv")
        result = build_correlation_graph(complaints)
        export_results(result)

        print(f"\n=== SUMMARY ===")
        print(f"Total complaints processed: {result.stats['total_complaints']}")
        print(f"Total links found: {result.stats['total_links']}")
        print(f"Suspected fraud rings (clusters size > 1): {result.stats['clusters_found']}")
        print(f"\nTop 5 rings by size / cross-state spread / loss amount:")
        for c in result.clusters[:5]:
            if c["size"] > 1:
                print(f"  {c['cluster_id']}: {c['size']} complaints across {c['states_involved']} "
                      f"| confidence={c['avg_confidence']} | total loss=Rs.{c['total_amount_lost_inr']:,}")
    except FileNotFoundError as e:
        log.error(f"Input file not found: {e}")
        print("ERROR: synthetic_complaints_clean.csv not found in current directory.")
    except Exception as e:
        log.error(f"Unexpected error during run: {e}")
        raise
