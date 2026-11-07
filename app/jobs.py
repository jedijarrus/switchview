"""The scheduler of SwitchView and its jobs: poll, names, nightly backup, PacketFence sync, session pruning and the expiry of
four-eyes requests (Phase 4a, Task 6). One scheduler in the process (the single-worker invariant in main.py): main.lifespan schedules
the jobs and starts it, PUT /api/settings (api_settings.put_settings) schedules them anew with the poll interval it stored. Split from
main.py (Phase 3, Task 11), the code as it was."""
from apscheduler.schedulers.asyncio import AsyncIOScheduler

import approvals
import auth
import names as names_mod
import pf
import poller
import sshcli
from db import get_setting

scheduler = AsyncIOScheduler(timezone="Europe/Berlin")


async def _schedule():
    minutes = int(await get_setting("poll_minutes", "15") or 15)
    scheduler.add_job(poller.poll_all, "interval", minutes=max(5, minutes), id="poll", replace_existing=True, max_instances=1, coalesce=True)
    scheduler.add_job(names_mod.refresh_names, "interval", minutes=15, id="names", replace_existing=True, max_instances=1, coalesce=True)
    scheduler.add_job(sshcli.backup_all, "cron", hour=2, minute=30, id="backup", replace_existing=True, max_instances=1, coalesce=True)
    scheduler.add_job(pf.expire_and_sync, "cron", hour=3, minute=15, id="pf_sync", replace_existing=True, max_instances=1, coalesce=True)
    scheduler.add_job(auth.prune_sessions, "interval", minutes=60, id="sessions", replace_existing=True, max_instances=1, coalesce=True)
    scheduler.add_job(approvals.expire_due, "interval", minutes=10, id="approvals", replace_existing=True, max_instances=1, coalesce=True)
