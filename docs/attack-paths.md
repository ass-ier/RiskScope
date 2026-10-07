# Potential attack paths

RiskScope paths are **evidence-backed prioritization hypotheses**, never confirmation that a host can be exploited or that lateral movement succeeds.

## Inputs and semantics

* Source: an active vulnerability risk (`OPEN`, `ASSIGNED`, `IN_PROGRESS`, or `REMEDIATED`) on an active asset with an effective confirmed/potential match.
* Internet reachability: explicitly `INTERNET_FACING` in the latest asset exposure observation, otherwise asset inventory, with supporting evidence. An analyst exposure override is respected, but does not remove the evidence requirement.
* An explicit asset-specific `BLOCKED` exploitability/reachability observation suppresses the source. The global vulnerability known-exploitation flag is never rewritten.
* Target: another active asset explicitly classified `CRITICAL`.
* Edges: existing, directed, evidence-backed asset relationships of types `CONNECTS_TO`, `DEPENDS_ON`, `AUTHENTICATES_TO`, `MANAGES`, or `ROUTES_TO`.

`MEMBER_OF`, `HOSTS`, and `BACKS_UP` are not automatically interpreted as network progression. Shared zones, address ranges, IPs, packages, or vulnerabilities do not imply edges. SBOM dependencies are a separate component graph; they do not claim network exploitability.

Every persisted path has the source risk, source/target assets, ordered asset IDs, ordered relationship IDs, evidence IDs, `confidence="POTENTIAL"` and an explanation of the limits. The UI may decorate these records with Internet, software, service or vulnerability nodes; that decoration is not additional observed connectivity.

## Algorithm and bounds

`discover_paths(db)` deletes and rebuilds current `AttackPath` rows in the caller's transaction. Deleting a relationship then rediscovering/correlating removes paths that depended on it. Historical assessments retain their original factor/evidence snapshots.

Discovery runs deterministic breadth-first traversal, ordered by database relationship/risk ID. The current path's visited assets prevent cycles. Source/target direction is never reversed.

Default limits:

| Setting | Default | Allowed |
|---|---:|---:|
| `max_path_depth` | 4 relationship edges | 1–6 |
| `max_paths` | 200 results | 1–500 |
| `max_graph_edges` | 500 relationships | 10–1000 |

A separate **global** expansion budget is `min(20,000, max_graph_edges × max_path_depth × 2)`, shared across all risks and paths. It bounds attempted adjacency traversals, including cycle edges. Graph loading requests only the configured limit plus one to detect truncation. Queue growth is bounded by attempted expansions rather than all possible paths in a dense graph.

The result exposes:

```json
{
  "paths": 2,
  "truncated": false,
  "truncation_reasons": [],
  "expansions": 4,
  "expansion_limit": 4000,
  "edges_considered": 3,
  "max_path_depth": 4
}
```

Possible truncation reasons are `graph-edge-limit`, `path-depth-limit`, `path-count-limit`, and `expansion-limit`. A truncated analysis is incomplete; zero discovered paths is not evidence of absence. Hitting the result cap is reported conservatively even if the last available result happened to exactly fill it.

The risk engine adds the path weight once per source risk, regardless of the number of paths. Changing/deleting relationships and rerunning correlation updates that contribution.

## Synthetic scenario

The explicit ExampleCorp relationships are:

```text
Internet exposure observation
  → WEB-01 (affected installation)
  → APP-01 (CONNECTS_TO with evidence)
  → DB-01 (CONNECTS_TO with evidence; critical target)
```

Both relevant WEB-01 vulnerability risks can reference this same asset progression. WEB-02's identical global nginx vulnerability metadata does not imply an internet entry point or a path.

These hosts, relationships, vulnerability metadata and business roles are **fictional demo observations**. Their path is potential, not a demonstrated exploit chain. Unit tests cover deletion, evidence requirements, excluded relationship types, cycles, active-status filtering and dense-graph truncation.
