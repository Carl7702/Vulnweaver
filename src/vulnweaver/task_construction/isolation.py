"""Construction-side views that exclude all verifier-only information."""

from __future__ import annotations

from vulnweaver.common.schema import CaseSpec


def construction_view(case: CaseSpec) -> CaseSpec:
    """Return the only case view that construction agents may receive."""

    return case.model_copy(
        update={
            "neutralized_environment": None,
            "patched_environment": None,
            "reference_poc": None,
        }
    )
