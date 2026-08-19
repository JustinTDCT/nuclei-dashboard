"""Scale S2 harness.

S2A is measurement and semantic freeze only. Production ingest paths are
not imported for replacement here; later tranches compare against this
package.
"""

from tests.scale_s2.constants import S1_BASELINE_SHA, WORKLOADS

__all__ = ["S1_BASELINE_SHA", "WORKLOADS"]
