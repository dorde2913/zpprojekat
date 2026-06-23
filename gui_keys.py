"""
GUI za upravljanje ključevima.

Sadrži:
  KeyRingFrame  — glavni Frame koji se ubacuje u app notebook
  _GenerateDialog  — dijalog za generisanje novog para
  _ImportDialog    — dijalog za uvoz (javnog ili para)
  _ExportDialog    — dijalog za izvoz (javnog ili para)
  _PasswordDialog  — jednostavan dijalog za unos lozinke

Upotreba u main.py:
    from gui_keys import KeyRingFrame
    frame = KeyRingFrame(notebook)
    notebook.add(frame, text="Ključevi")
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

import key_ops
from exceptions import (
    PGPError, WrongPasswordError, KeyNotFoundError,
    KeyAlreadyExistsError, InvalidKeyError, KeyHasNoPrivatePartError,
)


# ── pomoćni dijalozi ──────────────────────────────────────────────────────────

class _PasswordDialog(tk.Toplevel):
    """Modalni dijalog za unos jedne lozinke. Vraća lozinku ili None."""

    def __init__(self, parent, title="Unesite lozinku", prompt="Lozinka:"):
        super().__init__(parent)
        self.title(title)
        self.resizable(False, False)
        self.grab_set()
        self.result = None

        ttk.Label(self, text=prompt, padding=(12, 12, 12, 4)).pack(anchor="w")
        self._var = tk.StringVar()
        entry = ttk.Entry(self, textvariable=self._var, show="*", width=30)
        entry.pack(padx=12, pady=4)
        entry.focus_set()
        entry.bind("<Return>", lambda e: self._ok())

        btn_frame = ttk.Frame(self)
        btn_frame.pack(pady=(4, 12), padx=12, fill="x")
        ttk.Button(btn_frame, text="Potvrdi", command=self._ok).pack(side="right", padx=(4, 0))
        ttk.Button(btn_frame, text="Otkaži", command=self.destroy).pack(side="right")

        self._center(parent)
        self.wait_window()

    def _ok(self):
        self.result = self._var.get()
        self.destroy()

    def _center(self, parent):
        self.update_idletasks()
        x = parent.winfo_rootx() + (parent.winfo_width()  - self.winfo_width())  // 2
        y = parent.winfo_rooty() + (parent.winfo_height() - self.winfo_height()) // 2
        self.geometry(f"+{x}+{y}")


# ── dijalog: generisanje ──────────────────────────────────────────────────────

class _GenerateDialog(tk.Toplevel):
    """Dijalog za generisanje novog RSA para ključeva."""

    def __init__(self, parent, on_success):
        super().__init__(parent)
        self.title("Generisanje novog para ključeva")
        self.resizable(False, False)
        self.grab_set()
        self._on_success = on_success

        pad = {"padx": 12, "pady": 4}

        ttk.Label(self, text="Ime i prezime:").grid(row=0, column=0, sticky="w", **pad)
        self._name_var = tk.StringVar()
        ttk.Entry(self, textvariable=self._name_var, width=32).grid(row=0, column=1, **pad)

        ttk.Label(self, text="E-mail adresa:").grid(row=1, column=0, sticky="w", **pad)
        self._email = tk.StringVar()
        ttk.Entry(self, textvariable=self._email, width=32).grid(row=1, column=1, **pad)

        ttk.Label(self, text="Veličina ključa:").grid(row=2, column=0, sticky="w", **pad)
        self._size = tk.IntVar(value=2048)
        size_frame = ttk.Frame(self)
        size_frame.grid(row=2, column=1, sticky="w", **pad)
        ttk.Radiobutton(size_frame, text="1024 bit", variable=self._size, value=1024).pack(side="left")
        ttk.Radiobutton(size_frame, text="2048 bit", variable=self._size, value=2048).pack(side="left", padx=(12, 0))

        ttk.Separator(self, orient="horizontal").grid(row=3, column=0, columnspan=2, sticky="ew", pady=8, padx=12)

        ttk.Label(self, text="Lozinka:").grid(row=4, column=0, sticky="w", **pad)
        self._pw = tk.StringVar()
        ttk.Entry(self, textvariable=self._pw, show="*", width=32).grid(row=4, column=1, **pad)

        ttk.Label(self, text="Potvrda lozinke:").grid(row=5, column=0, sticky="w", **pad)
        self._pw2 = tk.StringVar()
        ttk.Entry(self, textvariable=self._pw2, show="*", width=32).grid(row=5, column=1, **pad)

        btn_frame = ttk.Frame(self)
        btn_frame.grid(row=6, column=0, columnspan=2, pady=(8, 12), padx=12, sticky="e")
        ttk.Button(btn_frame, text="Generiši", command=self._submit).pack(side="right", padx=(4, 0))
        ttk.Button(btn_frame, text="Otkaži", command=self.destroy).pack(side="right")

        self._center(parent)

    def _submit(self):
        if self._pw.get() != self._pw2.get():
            messagebox.showerror("Greška", "Lozinke se ne poklapaju.", parent=self)
            return
        try:
            key_id = key_ops.generate_key(
                self._name_var.get(),
                self._email.get(),
                self._size.get(),
                self._pw.get(),
            )
            self.destroy()
            self._on_success(key_id)
        except InvalidKeyError as e:
            messagebox.showerror("Greška pri generisanju", str(e), parent=self)

    def _center(self, parent):
        self.update_idletasks()
        x = parent.winfo_rootx() + (parent.winfo_width()  - self.winfo_width())  // 2
        y = parent.winfo_rooty() + (parent.winfo_height() - self.winfo_height()) // 2
        self.geometry(f"+{x}+{y}")


# ── dijalog: uvoz ─────────────────────────────────────────────────────────────

class _ImportDialog(tk.Toplevel):
    """Dijalog za uvoz javnog ključa ili celog para."""

    def __init__(self, parent, on_success):
        super().__init__(parent)
        self.title("Uvoz ključa")
        self.resizable(False, False)
        self.grab_set()
        self._on_success = on_success

        pad = {"padx": 12, "pady": 4}

        # tip uvoza
        ttk.Label(self, text="Šta uvozite:").grid(row=0, column=0, sticky="w", **pad)
        self._mode = tk.StringVar(value="public")
        mode_frame = ttk.Frame(self)
        mode_frame.grid(row=0, column=1, sticky="w", **pad)
        ttk.Radiobutton(mode_frame, text="Samo javni ključ",
                        variable=self._mode, value="public",
                        command=self._toggle).pack(side="left")
        ttk.Radiobutton(mode_frame, text="Ceo par ključeva",
                        variable=self._mode, value="pair",
                        command=self._toggle).pack(side="left", padx=(12, 0))

        # fajl
        ttk.Label(self, text="PEM fajl:").grid(row=1, column=0, sticky="w", **pad)
        self._path = tk.StringVar()
        path_frame = ttk.Frame(self)
        path_frame.grid(row=1, column=1, sticky="w", **pad)
        ttk.Entry(path_frame, textvariable=self._path, width=26).pack(side="left")
        ttk.Button(path_frame, text="...", width=3,
                   command=self._browse).pack(side="left", padx=(4, 0))

        # ime i email (samo za javni ključ)
        self._lbl_name  = ttk.Label(self, text="Ime i prezime:")
        self._lbl_email = ttk.Label(self, text="E-mail adresa:")
        self._name_var  = tk.StringVar()
        self._email = tk.StringVar()
        self._ent_name  = ttk.Entry(self, textvariable=self._name_var,  width=32)
        self._ent_email = ttk.Entry(self, textvariable=self._email, width=32)
        self._lbl_name.grid( row=2, column=0, sticky="w", **pad)
        self._ent_name.grid( row=2, column=1, **pad)
        self._lbl_email.grid(row=3, column=0, sticky="w", **pad)
        self._ent_email.grid(row=3, column=1, **pad)

        ttk.Separator(self, orient="horizontal").grid(
            row=4, column=0, columnspan=2, sticky="ew", pady=8, padx=12)

        # lozinka fajla
        self._lbl_pw = ttk.Label(self, text="Lozinka fajla:")
        self._pw     = tk.StringVar()
        self._ent_pw = ttk.Entry(self, textvariable=self._pw, show="*", width=32)

        # nova lozinka
        self._lbl_pw2  = ttk.Label(self, text="Nova lozinka:")
        self._pw2      = tk.StringVar()
        self._ent_pw2  = ttk.Entry(self, textvariable=self._pw2, show="*", width=32)
        self._lbl_pw3  = ttk.Label(self, text="Potvrda lozinke:")
        self._pw3      = tk.StringVar()
        self._ent_pw3  = ttk.Entry(self, textvariable=self._pw3, show="*", width=32)

        # lozinka je uvek vidljiva (i za par)
        self._lbl_pw.grid( row=5, column=0, sticky="w", **pad)
        self._ent_pw.grid( row=5, column=1, **pad)
        self._lbl_pw2.grid(row=6, column=0, sticky="w", **pad)
        self._ent_pw2.grid(row=6, column=1, **pad)
        self._lbl_pw3.grid(row=7, column=0, sticky="w", **pad)
        self._ent_pw3.grid(row=7, column=1, **pad)

        btn_frame = ttk.Frame(self)
        btn_frame.grid(row=8, column=0, columnspan=2, pady=(8, 12), padx=12, sticky="e")
        ttk.Button(btn_frame, text="Uvezi", command=self._submit).pack(side="right", padx=(4, 0))
        ttk.Button(btn_frame, text="Otkaži", command=self.destroy).pack(side="right")

        self._toggle()  # postavi početno stanje
        self._center(parent)

    def _toggle(self):
        is_pair = self._mode.get() == "pair"
        # za javni ključ: skrivamo lozinku fajla i novu lozinku
        # za par: skrivamo name/email polja (preuzimaju se iz PEM-a)
        state_pair   = "normal" if is_pair  else "disabled"
        state_public = "normal" if not is_pair else "disabled"

        self._ent_name.config(state=state_public)
        self._ent_email.config(state=state_public)
        self._ent_pw.config(state=state_pair)
        self._ent_pw2.config(state=state_pair)
        self._ent_pw3.config(state=state_pair)

    def _browse(self):
        path = filedialog.askopenfilename(
            parent=self,
            title="Izaberi PEM fajl",
            filetypes=[("PEM fajlovi", "*.pem"), ("Svi fajlovi", "*.*")],
        )
        if path:
            self._path.set(path)

    def _submit(self):
        path = self._path.get().strip()
        if not path:
            messagebox.showerror("Greška", "Izaberite PEM fajl.", parent=self)
            return

        try:
            if self._mode.get() == "public":
                key_id = key_ops.import_public_key(
                    path, self._name_var.get(), self._email.get()
                )
            else:
                if self._pw2.get() != self._pw3.get():
                    messagebox.showerror("Greška", "Lozinke se ne poklapaju.", parent=self)
                    return
                key_id = key_ops.import_key_pair(
                    path, self._pw.get(), self._pw2.get()
                )
            self.destroy()
            self._on_success(key_id)

        except WrongPasswordError:
            messagebox.showerror("Pogrešna lozinka",
                                 "Lozinka fajla nije ispravna.", parent=self)
        except KeyAlreadyExistsError as e:
            messagebox.showerror("Duplikat", str(e), parent=self)
        except InvalidKeyError as e:
            messagebox.showerror("Neispravan ključ", str(e), parent=self)
        except PGPError as e:
            messagebox.showerror("Greška pri uvozu", str(e), parent=self)

    def _center(self, parent):
        self.update_idletasks()
        x = parent.winfo_rootx() + (parent.winfo_width()  - self.winfo_width())  // 2
        y = parent.winfo_rooty() + (parent.winfo_height() - self.winfo_height()) // 2
        self.geometry(f"+{x}+{y}")


# ── dijalog: izvoz ────────────────────────────────────────────────────────────

class _ExportDialog(tk.Toplevel):
    """Dijalog za izvoz javnog ključa ili celog para."""

    def __init__(self, parent, key_id: str, has_private: bool):
        super().__init__(parent)
        self.title(f"Izvoz ključa  [{key_id}]")
        self.resizable(False, False)
        self.grab_set()
        self._key_id = key_id

        pad = {"padx": 12, "pady": 4}

        self._mode = tk.StringVar(value="public")
        mode_frame = ttk.LabelFrame(self, text="Šta izvoziti", padding=8)
        mode_frame.grid(row=0, column=0, columnspan=2, sticky="ew", **pad)

        ttk.Radiobutton(mode_frame, text="Samo javni ključ",
                        variable=self._mode, value="public",
                        command=self._toggle).pack(side="left")
        if has_private:
            ttk.Radiobutton(mode_frame, text="Ceo par ključeva",
                            variable=self._mode, value="pair",
                            command=self._toggle).pack(side="left", padx=(12, 0))

        ttk.Label(self, text="Destinacija:").grid(row=1, column=0, sticky="w", **pad)
        self._path = tk.StringVar()
        path_frame = ttk.Frame(self)
        path_frame.grid(row=1, column=1, sticky="w", **pad)
        ttk.Entry(path_frame, textvariable=self._path, width=26).pack(side="left")
        ttk.Button(path_frame, text="...", width=3,
                   command=self._browse).pack(side="left", padx=(4, 0))

        self._lbl_pw = ttk.Label(self, text="Lozinka privatnog ključa:")
        self._pw     = tk.StringVar()
        self._ent_pw = ttk.Entry(self, textvariable=self._pw, show="*", width=32)
        self._lbl_pw.grid(row=2, column=0, sticky="w", **pad)
        self._ent_pw.grid(row=2, column=1, **pad)

        btn_frame = ttk.Frame(self)
        btn_frame.grid(row=3, column=0, columnspan=2, pady=(8, 12), padx=12, sticky="e")
        ttk.Button(btn_frame, text="Izvezi", command=self._submit).pack(side="right", padx=(4, 0))
        ttk.Button(btn_frame, text="Otkaži", command=self.destroy).pack(side="right")

        self._toggle()
        self._center(parent)

    def _toggle(self):
        is_pair = self._mode.get() == "pair"
        self._ent_pw.config(state="normal" if is_pair else "disabled")

    def _browse(self):
        path = filedialog.asksaveasfilename(
            parent=self,
            title="Sačuvaj PEM fajl",
            defaultextension=".pem",
            filetypes=[("PEM fajlovi", "*.pem"), ("Svi fajlovi", "*.*")],
        )
        if path:
            self._path.set(path)

    def _submit(self):
        path = self._path.get().strip()
        if not path:
            messagebox.showerror("Greška", "Izaberite destinaciju.", parent=self)
            return
        try:
            if self._mode.get() == "public":
                key_ops.export_public_key(self._key_id, path)
            else:
                key_ops.export_key_pair(self._key_id, self._pw.get(), path)
            self.destroy()
            messagebox.showinfo("Izvoz uspešan", f"Ključ je sačuvan u:\n{path}")
        except WrongPasswordError:
            messagebox.showerror("Pogrešna lozinka",
                                 "Lozinka privatnog ključa nije ispravna.", parent=self)
        except KeyHasNoPrivatePartError as e:
            messagebox.showerror("Nema privatnog dela", str(e), parent=self)
        except PGPError as e:
            messagebox.showerror("Greška pri izvozu", str(e), parent=self)

    def _center(self, parent):
        self.update_idletasks()
        x = parent.winfo_rootx() + (parent.winfo_width()  - self.winfo_width())  // 2
        y = parent.winfo_rooty() + (parent.winfo_height() - self.winfo_height()) // 2
        self.geometry(f"+{x}+{y}")


# ── glavni Frame ──────────────────────────────────────────────────────────────

class KeyRingFrame(ttk.Frame):
    """
    Glavni Frame za upravljanje ključevima.
    Ubaci u ttk.Notebook u main.py:

        nb = ttk.Notebook(root)
        nb.add(KeyRingFrame(nb), text="Ključevi")
    """

    # kolone tabele i njihove širine
    _COLUMNS = [
        ("key_id",      "Key ID",      80),
        ("name",        "Ime",         160),
        ("email",       "E-mail",      180),
        ("key_size",    "Veličina",    80),
        ("tip",         "Tip",         100),
        ("created_at",  "Datum",       150),
    ]

    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)
        self._build_toolbar()
        self._build_table()
        self._build_detail()
        self.refresh()

    # ── izgradnja UI ─────────────────────────────────────────────────────────

    def _build_toolbar(self):
        bar = ttk.Frame(self)
        bar.pack(fill="x", padx=8, pady=(8, 4))

        ttk.Button(bar, text="＋ Generiši par",
                   command=self._on_generate).pack(side="left", padx=(0, 4))
        ttk.Button(bar, text="⬆ Uvezi",
                   command=self._on_import).pack(side="left", padx=(0, 4))

        ttk.Separator(bar, orient="vertical").pack(side="left", fill="y", padx=6)

        self._btn_export = ttk.Button(bar, text="⬇ Izvezi",
                                      command=self._on_export, state="disabled")
        self._btn_export.pack(side="left", padx=(0, 4))

        self._btn_delete = ttk.Button(bar, text="✕ Obriši",
                                      command=self._on_delete, state="disabled")
        self._btn_delete.pack(side="left")

        ttk.Button(bar, text="↻ Osveži",
                   command=self.refresh).pack(side="right")

    def _build_table(self):
        frame = ttk.LabelFrame(self, text="Prsten ključeva")
        frame.pack(fill="both", expand=True, padx=8, pady=4)

        cols = [c[0] for c in self._COLUMNS]
        self._tree = ttk.Treeview(frame, columns=cols, show="headings",
                                  selectmode="browse")

        for col_id, col_label, col_width in self._COLUMNS:
            self._tree.heading(col_id, text=col_label,
                               command=lambda c=col_id: self._sort_by(c))
            self._tree.column(col_id, width=col_width, minwidth=40, anchor="w")

        vsb = ttk.Scrollbar(frame, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)

        self._tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        # boje za tip
        self._tree.tag_configure("pair",   foreground="#1a5f1a")
        self._tree.tag_configure("public", foreground="#1a3f6f")

        self._tree.bind("<<TreeviewSelect>>", self._on_select)
        self._tree.bind("<Double-1>",         self._on_double_click)

    def _build_detail(self):
        self._detail_var = tk.StringVar(value="Izaberite ključ za detalje.")
        detail = ttk.LabelFrame(self, text="Detalji")
        detail.pack(fill="x", padx=8, pady=(4, 8))
        ttk.Label(detail, textvariable=self._detail_var,
                  font=("Courier", 9), anchor="w",
                  justify="left").pack(fill="x", padx=8, pady=6)

    # ── osvežavanje tabele ───────────────────────────────────────────────────

    def refresh(self):
        """Ponovo učitava sve ključeve iz key_ops i puni tabelu."""
        selected = self._selected_key_id()

        for row in self._tree.get_children():
            self._tree.delete(row)

        for entry in key_ops.list_keys():
            tip  = "Par (pub+priv)" if entry["has_private"] else "Javni"
            tag  = "pair"           if entry["has_private"] else "public"
            date = entry["created_at"].replace("T", "  ").replace("Z", "")

            self._tree.insert("", "end", iid=entry["key_id"], tags=(tag,), values=(
                entry["key_id"],
                entry["name"],
                entry["email"],
                f"{entry['key_size']} bit",
                tip,
                date,
            ))

        # vrati selekciju ako ključ još postoji
        if selected and self._tree.exists(selected):
            self._tree.selection_set(selected)
        else:
            self._update_buttons(selected=False)
            self._detail_var.set("Izaberite ključ za detalje.")

    def _sort_by(self, col):
        """Sortira tabelu po kliknutoj koloni."""
        items = [(self._tree.set(k, col), k) for k in self._tree.get_children("")]
        items.sort()
        for i, (_, k) in enumerate(items):
            self._tree.move(k, "", i)

    # ── selekcija ─────────────────────────────────────────────────────────────

    def _selected_key_id(self) -> str | None:
        sel = self._tree.selection()
        return sel[0] if sel else None

    def _on_select(self, _event=None):
        key_id = self._selected_key_id()
        if not key_id:
            return
        self._update_buttons(selected=True)
        try:
            e = key_ops.get_entry(key_id)
            tip = "Par (javni + privatni)" if e["has_private"] else "Samo javni ključ"
            self._detail_var.set(
                f"Key ID:      {e['key_id']}\n"
                f"Fingerprint: {e['fingerprint']}\n"
                f"Ime:         {e['name']}\n"
                f"E-mail:      {e['email']}\n"
                f"Veličina:    {e['key_size']} bita\n"
                f"Tip:         {tip}\n"
                f"Kreiran:     {e['created_at']}"
            )
        except KeyNotFoundError:
            pass

    def _on_double_click(self, _event=None):
        if self._selected_key_id():
            self._on_export()

    def _update_buttons(self, selected: bool):
        state = "normal" if selected else "disabled"
        self._btn_export.config(state=state)
        self._btn_delete.config(state=state)

    # ── akcije dugmadi ────────────────────────────────────────────────────────

    def _on_generate(self):
        _GenerateDialog(
            self,
            on_success=lambda kid: (
                self.refresh(),
                self._tree.selection_set(kid),
                self._on_select(),
            ),
        )

    def _on_import(self):
        _ImportDialog(
            self,
            on_success=lambda kid: (
                self.refresh(),
                self._tree.selection_set(kid),
                self._on_select(),
            ),
        )

    def _on_export(self):
        key_id = self._selected_key_id()
        if not key_id:
            return
        try:
            entry = key_ops.get_entry(key_id)
        except KeyNotFoundError:
            return
        _ExportDialog(self, key_id=key_id, has_private=entry["has_private"])

    def _on_delete(self):
        key_id = self._selected_key_id()
        if not key_id:
            return
        try:
            entry = key_ops.get_entry(key_id)
        except KeyNotFoundError:
            self.refresh()
            return

        tip = "par ključeva" if entry["has_private"] else "javni ključ"
        confirm = messagebox.askyesno(
            "Potvrda brisanja",
            f"Da li sigurno želite da obrišete {tip}?\n\n"
            f"  {entry['name']}  <{entry['email']}>\n"
            f"  Key ID: {key_id}\n\n"
            f"{'Privatni ključ će biti trajno obrisan!' if entry['has_private'] else ''}",
            icon="warning",
        )
        if not confirm:
            return

        try:
            key_ops.delete_key(key_id)
        except KeyNotFoundError:
            pass

        self.refresh()