# V1C — Closure evidence

**Tranche:** V1C — Technician/auditor UX walk  
**Status:** ACCEPT / CLOSED  
**V1A:** ACCEPT / CLOSED (`a06e455` on audited baseline `3f702b8`)  
**V1B acceptance checkpoint:** `39f463c0f34289f4dc0e5eb74886471dc6e256e2` (merge of [PR #2](https://github.com/JustinTDCT/nuclei-dashboard/pull/2); parents `bb63c6b` and `68cc342`)  
**Implementation/ops baseline:** `bb63c6b7bc91e9098f2edc035fe3828aec831618` (merge of [PR #1](https://github.com/JustinTDCT/nuclei-dashboard/pull/1))  
**Walked live HEAD:** `39f463c0` on secdock (`https://scanner.thedubes.net:8118`)  
**V1C acceptance checkpoint:** the GitHub merge commit of this docs-only PR. That merge SHA is the immutable V1C acceptance reference. Checking out `39f463c0` still shows V1C as READY TO START; that is expected.  
**Schema:** `0017_security_h6_h8` · **`0018` not created**  
**Agent pin:** `3cdb52c42a87552db98e609e9ec7c1c01e86b23b` (unchanged)  
**Verdict:** **V1C — ACCEPT / CLOSED.** **V1D — READY TO START.**

This file records the walk. V1D soak procedure is `docs/V1D_OPERATIONS.md`. V1A product PARTIALs stay backlog. No schema, no Agent pin bump, no product fixes in this checkpoint.

---

## Verdict

The operator walked the live product at V1B acceptance `39f463c0` on 2026-09-01 and declared **V1C — ACCEPT / CLOSED**.

| Question | Answer |
|---|---|
| V1C blockers (product unusable)? | **None found.** |
| Known V1A PARTIAL/MISSING items fixed? | **No.** They remain the V1A backlog. The walk did not show any of them making the product unusable. |
| Schema / Agent pin changed? | **No.** Head stays `0017_security_h6_h8`. Pin stays `3cdb52c`. |
| V1 release tag? | **No.** Next gate is V1D operational soak. |

---

## What was walked

This was an operator UX walk of the live dashboard, not an automated browser script and not a click-by-click lab transcript. Roles below are the product roles (`User.role`). “Technician” is staff `admin` / `user`. “Auditor” is `viewer` (Phase 3C grants and expiry).

| Role | Product role | Workflows in scope |
|---|---|---|
| Technician / MSP staff | `admin`, `user` | V1A MSP script and README technician path: tenant → site → network → Agent create / deploy / approve / authorize → WAN targets → scan definition → run or schedule → assets → findings triage → treatments → control mapping → reports → alerts → history |
| Auditor | `viewer` | Read-only tenant-scoped dashboard, assets, findings, reports, alerts, and history. Cannot mutate, start scans, approve Agents, or fetch enrollment/deploy material |

Live context at the walk: secdock at `39f463c0`, `--scale api=2`, schema `0017`, both LAN Agents (Nuclei-Pi4 on NUCLEI-AGENT, TAB1 on docker01) heartbeating, WAN scanner present. That topology is the V1B operating model, not a V1C code change.

---

## Blockers

**None.** Known V1A gaps were visible as already-documented PARTIALs (single-CIDR Networks, site-timezone lists, scan cancel/dry-run UI, exclusions UI tenant-only, ID-typed merge/split, no manual finding resolve, no treatment-review policy category, missing event families). They stay backlog. They are not V1C reopen items.

---

## Preserved V1A backlog

Do not treat these as V1C failures. Implement only in a later named UX/product tranche after V1D and the V1 release decision, unless a later soak shows one of them makes the product unusable.

| Item | V1A status | Notes |
|---|---|---|
| Single CIDR per Network | PARTIAL | Workaround: multiple Networks |
| Site timezone on job/finding lists | PARTIAL | Persist/schedule COMPLETE; display often uses global TZ |
| Scan cancel UI | PARTIAL | Deadline/H7 path exists; no staff cancel button |
| Dry-run UI | PARTIAL | Backend exists; no intensity-step control |
| Exclusions UI | PARTIAL | Enforced all scopes; UI creates tenant exclusions only |
| Guided merge/split | PARTIAL | Backend COMPLETE; UI is ID-typed confirm, not a wizard |
| Manual finding resolve/reopen | MISSING | Auto path only; no `/resolve` |
| Treatment-review policy category | PARTIAL | Four policy categories exist; no risk/treatment-review |
| Missing event families | PARTIAL | Service appear/disappear, distinct critical finding, agent online/offline, concurrent identity anomaly |
| Other §8 UX polish | backlog | Cron on common schedule step, `window.prompt` revoke, thin empty states, Home “New devices” copy |

Canonical matrices: `docs/V1A_CLOSURE_AUDIT.md` §2–§8.

---

## What V1C is not

- Not a reopen of S1–S3 or H1–H9.
- Not permission to add `0018` or bump the Agent pin.
- Not a fix for V1A product gaps.
- Not a V1 release tag.
- Not a soak. V1D is the soak.
- Not a claim that §26 ease-of-use is now COMPLETE. The happy path was walked and is usable; PARTIALs remain.

---

## Next

**V1D — Operational soak** is READY TO START. Runbook: `docs/V1D_OPERATIONS.md`. After V1D: V1 Release Decision, then a V1 tag, then a V1.1/V2 roadmap. There is still no Phase 4.
