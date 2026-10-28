"""Scan modules. Each module file defines:

    NAME: str
    def run(ctx: adint_scan.context.ScanContext) -> adint_scan.result.ModuleResult

and records every sub-check with result.ModuleResult.ran() / .could_not_run()
so that CLEAN is never reported for something that did not actually execute (D3).
"""
