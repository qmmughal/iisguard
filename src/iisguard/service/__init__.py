"""Run `iisguard watch` as a service: systemd unit (Linux) or Task Scheduler task (Windows, no extra dependency).

Everything here is generated text plus a command list. Nothing is executed unless the caller passes apply=True, and
the commands written here have NOT been run against a real Windows Task Scheduler or systemd by the author's CI
(they are unit-tested as generated text). Review them first.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from xml.sax.saxutils import escape

from iisguard.firewall.base import Cmd

NAME = "iisguard"
UNIT_PATH = "/etc/systemd/system/iisguard.service"


@dataclass
class ServicePlan:
    files: dict[str, str] = field(default_factory=dict)  # path -> content
    commands: list[Cmd] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def watch_args(logs: list[str], backend: str, live: bool, config: str | None) -> list[str]:
    args = ["watch", *logs, "--backend", backend]
    if config:
        args += ["--config", config]
    if live:
        args.append("--live")
    return args


def systemd_unit(python: str, args: list[str]) -> str:
    exec_line = " ".join([python, "-m", "iisguard", *args])
    return (
        "[Unit]\nDescription=iisguard log watcher and blocker\nAfter=network.target\n\n[Service]\nType=simple\n"
        f"ExecStart={exec_line}\nRestart=on-failure\nRestartSec=10\nNoNewPrivileges=false\n"
        "ProtectHome=true\nPrivateTmp=true\n\n[Install]\nWantedBy=multi-user.target\n"
    )


def task_xml(python: str, args: list[str]) -> str:
    arg_text = escape(" ".join(["-m", "iisguard", *args]))
    return f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>iisguard log watcher and blocker</Description></RegistrationInfo>
  <Triggers><BootTrigger><Enabled>true</Enabled></BootTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <RestartOnFailure><Interval>PT1M</Interval><Count>999</Count></RestartOnFailure>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author"><Exec><Command>{escape(python)}</Command><Arguments>{arg_text}</Arguments></Exec></Actions>
</Task>
"""


def plan(action: str, logs: list[str], backend: str, live: bool, config: str | None, platform: str | None = None,
         python: str | None = None, xml_path: str = "iisguard-task.xml") -> ServicePlan:  # fmt: skip
    plat = platform or sys.platform
    py = python or sys.executable
    sp = ServicePlan()
    win = plat.startswith("win")
    if action == "install":
        args = watch_args(logs, backend, live, config)
        if win:
            sp.files[xml_path] = task_xml(py, args)
            sp.commands = [
                Cmd(["schtasks", "/Create", "/TN", NAME, "/XML", xml_path, "/F"], purpose="register the scheduled task")
            ]
        else:
            sp.files[UNIT_PATH] = systemd_unit(py, args)
            sp.commands = [
                Cmd(["systemctl", "daemon-reload"]),
                Cmd(["systemctl", "enable", NAME], purpose="start at boot"),
            ]
        if not live:
            sp.notes.append(
                "The service will run in DRY-RUN mode (it logs what it would block). Reinstall with --live to enforce."
            )
    elif action == "uninstall":
        sp.commands = (
            [Cmd(["schtasks", "/Delete", "/TN", NAME, "/F"])] if win
            else [Cmd(["systemctl", "disable", "--now", NAME]), Cmd(["systemctl", "daemon-reload"])]
        )  # fmt: skip
        if not win:
            sp.notes.append(f"Then delete {UNIT_PATH}.")
    elif action in ("start", "stop"):
        sp.commands = (
            [Cmd(["schtasks", "/Run" if action == "start" else "/End", "/TN", NAME])] if win
            else [Cmd(["systemctl", action, NAME])]
        )  # fmt: skip
    else:
        raise ValueError(f"unknown service action {action!r}")
    return sp


def apply(sp: ServicePlan, run: Callable[[Cmd], tuple[int, str]]) -> list[str]:
    msgs: list[str] = []
    for path, content in sp.files.items():
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        enc = "utf-16" if content.startswith("<?xml") and "UTF-16" in content[:60] else "utf-8"
        p.write_text(content, encoding=enc)
        msgs.append(f"wrote {p}")
    for c in sp.commands:
        rc, out = run(c)
        msgs.append(f"{c.display()} -> rc={rc} {out[:200]}")
        if rc != 0:
            break
    return msgs
