# -*- coding: utf-8 -*-
import re
from pathlib import Path

MAIN = Path(__file__).parent / "main.py"
src = MAIN.read_text(encoding="utf-8")

NEW = r'''async def run_global_search(task_id: str, query: str, forced_type: Optional[str] = None) -> None:
    started = time.perf_counter()
    target_type = (forced_type or detect_target_type(query)).lower()

    async def progress(p, msg):
        try:
            await _set_global_task(task_id, progress=p, message=msg, status="running")
        except Exception:
            pass

    try:
        await progress(5, "Search initialized")
        await progress(15, f"Type detected: {target_type.upper()}")

        ctx = SearchContext(
            search_id=task_id,
            query=query,
            normalized_query=normalize_query(query, target_type),
            target_type=target_type,
            started_at=now_iso(),
        )

        await progress(30, f"{target_type.upper()} started")

        try:
            result = await asyncio.wait_for(dispatch_search(ctx), timeout=90)
        except asyncio.TimeoutError:
            result = {"summary": {"query": query, "error": "TIMEOUT"}, "sources": []}
        except Exception as exc:
            result = {"summary": {"query": query, "error": clamp_text(exc)}, "sources": []}

        await progress(80, "Processing result")

        result["search_id"] = task_id
        result["timeline"] = ctx.timeline
        result["logs"] = ctx.logs
        duration_ms = (time.perf_counter() - started) * 1000

        await _set_global_task(
            task_id, status="completed", progress=100, message="Completed",
            result=result.get("summary", result),
            sources=result.get("sources", []),
            completed_at=now_iso(),
            duration_ms=round(duration_ms, 2),
        )
    except Exception as exc:
        await _set_global_task(
            task_id, status="error", progress=100,
            message=clamp_text(exc), error=clamp_text(exc),
            completed_at=now_iso(),
        )
    finally:
        try:
            t = GLOBAL_TASKS.get(task_id)
            if t and t.get("status") == "running":
                await _set_global_task(
                    task_id, status="error", progress=100,
                    message="Force-completed", error="Force-completed",
                    completed_at=now_iso(),
                )
        except Exception:
            pass'''

pattern = re.compile(
    r'async def run_global_search\(.*?\n(?=\n@app\.post\("/api/global_search"\))',
    re.DOTALL,
)
new_src, n = pattern.subn(lambda m: NEW + "\n", src)
MAIN.write_text(new_src, encoding="utf-8")
print(f"[OK] run_global_search patched: {n}")