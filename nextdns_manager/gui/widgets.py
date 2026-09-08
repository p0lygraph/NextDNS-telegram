"""Reusable Tk widgets."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Any, Callable


class MultiSelectMenu(ttk.Frame):
    def __init__(self, master: tk.Widget, text: str, on_change: Callable[[], None]):
        super().__init__(master)
        self.on_change = on_change
        self.button = ttk.Menubutton(self, text=text)
        self.menu = tk.Menu(self.button, tearoff=0)
        self.button["menu"] = self.menu
        self.button.pack(fill="x", expand=True)
        self.vars: dict[str, tk.BooleanVar] = {}

    def set_options(self, options: list[Any], selected: set[str] | None = None) -> None:
        selected = selected or set()
        self.menu.delete(0, "end")
        self.vars.clear()

        self.menu.add_command(label="Select all", command=self.select_all)
        self.menu.add_command(label="Deselect all", command=self.deselect_all)
        self.menu.add_separator()

        for opt in options:
            if isinstance(opt, tuple):
                value, label = str(opt[0]), str(opt[1])
            else:
                value, label = str(opt), str(opt)
            var = tk.BooleanVar(value=value in selected)
            self.vars[value] = var
            self.menu.add_checkbutton(label=label, variable=var, command=self.on_change)

    def select_all(self) -> None:
        for var in self.vars.values():
            var.set(True)
        self.on_change()

    def deselect_all(self) -> None:
        for var in self.vars.values():
            var.set(False)
        self.on_change()

    def values(self) -> set[str]:
        return {k for k, v in self.vars.items() if v.get()}


class ProfilePickerDialog(tk.Toplevel):
    def __init__(self, master: Any, profiles: list[dict[str, Any]], title: str):
        super().__init__(master)
        self.title(title)
        self.resizable(False, False)
        self.grab_set()
        self.result: list[dict[str, Any]] | None = None

        container = ttk.Frame(self, padding=12)
        container.pack(fill="both", expand=True)

        self.vars: dict[str, tuple[tk.BooleanVar, dict[str, Any]]] = {}
        for p in profiles:
            label = f"{p.get('name', p.get('id'))} ({p.get('id')})"
            var = tk.BooleanVar(value=False)
            ttk.Checkbutton(container, text=label, variable=var).pack(anchor="w", pady=1)
            self.vars[p["id"]] = (var, p)

        actions = ttk.Frame(container)
        actions.pack(fill="x", pady=(10, 0))

        ttk.Button(actions, text="Select all", command=self._select_all).pack(side="left")
        ttk.Button(actions, text="Deselect all", command=self._deselect_all).pack(side="left", padx=6)
        ttk.Button(actions, text="Cancel", command=self._cancel).pack(side="right")
        ttk.Button(actions, text="Apply", command=self._apply).pack(side="right", padx=6)

    def _select_all(self) -> None:
        for var, _ in self.vars.values():
            var.set(True)

    def _deselect_all(self) -> None:
        for var, _ in self.vars.values():
            var.set(False)

    def _cancel(self) -> None:
        self.result = None
        self.destroy()

    def _apply(self) -> None:
        self.result = [p for _, (var, p) in self.vars.items() if var.get()]
        self.destroy()
