import os
import shlex
import subprocess
import platform
from datetime import datetime

from kivy.properties import (
    StringProperty, ListProperty, BooleanProperty,
    NumericProperty, ObjectProperty
)
from kivy.uix.boxlayout import BoxLayout
from kivy.clock import Clock, mainthread
from kivy.uix.popup import Popup
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button

from services import (
    NmapRunner,
    PrivilegeManager, PrivState,
    ProgressTracker,
    parse_nmap_xml,
)


class MainUI(BoxLayout):
    # stato visivo / dati
    status_text = StringProperty("idle")
    last_xml = StringProperty("")
    parsed_hosts = ListProperty([])
    defaults_use_syn = BooleanProperty(True)
    last_target = StringProperty("192.168.1.0/24")

    # progresso
    progress = NumericProperty(0.0)        # 0..100
    phase_text = StringProperty("")        # fase corrente
    eta_text = StringProperty("")          # ETC / remaining
    progress_log_text = StringProperty("")  # tail stderr
    result_grid = ObjectProperty(None)     # bound da KV (id: result_grid)

    # privilegi
    syn_capable = BooleanProperty(False)
    is_root = BooleanProperty(False)
    is_sudoer = BooleanProperty(False)
    sudo_cached = BooleanProperty(False)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.runner = None
        self.scans_dir = os.path.join(os.getcwd(), "scans")
        os.makedirs(self.scans_dir, exist_ok=True)

        # servizi
        self.priv = PrivilegeManager(status_cb=self.set_status)
        self.progress_tracker = ProgressTracker(
            log_tail_lines=120, stall_after_sec=20)

        # scheduler
        Clock.schedule_once(self._detect_privileges, 0.1)
        Clock.schedule_interval(self._check_stall, 1.0)

    # ---------------------- Utility ----------------------
    def _norm_timing(self, t: str) -> str:
        t = (t or "").strip()
        if not t:
            return ""
        return t if t.startswith("-T") else f"-{t}"

    def _as_int(self, s, default=None):
        try:
            return int(str(s).strip())
        except Exception:
            return default

    def _wants_udp_from_ports(self, ports_str: str) -> bool:
        if not ports_str:
            return False
        return "u:" in ports_str.lower()

    def _needs_privileges(self, use_syn: bool, use_udp: bool, use_os: bool) -> bool:
        return bool(use_syn or use_udp)

    def _maybe_add_stats_every(self, args: list):
        # inietta '--stats-every Xs' se assente
        try:
            if "--stats-every" in args:
                return
            val = "5s"
            if hasattr(self, "ids") and "stats_every" in self.ids:
                v = (self.ids.stats_every.text or "").strip()
                if v:
                    val = v
            args.insert(0, val)
            args.insert(0, "--stats-every")
        except Exception:
            args[:0] = ["--stats-every", "5s"]

    # ---------------------- Privileges ----------------------
    def _detect_privileges(self, dt=None):
        st: PrivState = self.priv.detect()
        self.is_root = st.is_root
        self.is_sudoer = st.is_sudoer
        self.sudo_cached = st.sudo_cached
        self.syn_capable = st.syn_capable

        # riflesso in UI
        try:
            self.ids.use_syn.disabled = not self.syn_capable
            if not self.syn_capable:
                self.ids.use_syn.active = False
                self.set_status(
                    "SYN disabilitato: utente non root e non sudoer.")
            else:
                if self.is_root:
                    self.set_status("SYN abilitato (sei root).")
                elif self.sudo_cached:
                    self.set_status(
                        "SYN abilitato (sudo già valido, nessuna password richiesta).")
                else:
                    self.set_status(
                        "SYN abilitato (sudoer, potrebbe essere richiesta la password).")
        except Exception:
            pass

    def _sudo_cached_now(self) -> bool:
        return self.priv.sudo_cached_now()

    # ---------------------- Command builders ----------------------
    def build_nmap_cmd(self, base_args):
        return ["nmap"] + base_args

    def build_custom_args(self):
        target = self.ids.target.text.strip()
        if not target:
            raise ValueError("Target mancante")

        ports = self.ids.ports.text.strip()
        timing = self._norm_timing(self.ids.timing.text)

        use_tcp_connect = bool(self.ids.adv_tcp_connect.active)
        use_syn = bool(self.ids.adv_syn.active)
        use_udp = bool(
            self.ids.adv_udp.active or self._wants_udp_from_ports(ports))
        use_sV = bool(self.ids.adv_sV.active)
        version_intensity = (self.ids.adv_version_intensity.text or "").strip()
        use_os = bool(self.ids.adv_os.active)
        verbose = (self.ids.adv_verbose.text or "").strip()

        use_Pn = bool(self.ids.adv_Pn.active)
        no_dns = bool(self.ids.adv_no_dns.active)
        resolve_all = bool(self.ids.adv_resolve_all.active)

        top_ports = self._as_int(self.ids.adv_topports.text, None)
        min_rate = self._as_int(self.ids.adv_min_rate.text, None)
        max_rate = self._as_int(self.ids.adv_max_rate.text, None)
        max_retries = self._as_int(self.ids.adv_max_retries.text, None)
        host_timeout = (self.ids.adv_host_timeout.text or "").strip()

        nse_scripts = (self.ids.adv_scripts.text or "").strip()
        nse_args = (self.ids.adv_script_args.text or "").strip()

        oA_prefix = (self.ids.adv_oA.text or "").strip()

        args = []
        if timing:
            args.append(timing)

        if use_Pn:
            args.append("-Pn")
        if no_dns and resolve_all:
            args.append("-n")
        elif no_dns:
            args.append("-n")
        elif resolve_all:
            args.append("-R")

        if ports:
            args += ["-p", ports]
        elif top_ports:
            args += ["--top-ports", str(top_ports)]

        scan_selected = False
        if use_tcp_connect:
            args.append("-sT")
            scan_selected = True
        if use_syn:
            args.append("-sS")
            scan_selected = True
        if use_udp:
            args.append("-sU")
            scan_selected = True
        if not scan_selected:
            args.append("-sT")

        if use_sV:
            args.append("-sV")
            if version_intensity.isdigit():
                vi = max(0, min(9, int(version_intensity)))
                args += ["--version-intensity", str(vi)]
        if use_os:
            args.append("-O")

        if (min_rate or 0) > 0:
            args += ["--min-rate", str(min_rate)]
        if (max_rate or 0) > 0:
            args += ["--max-rate", str(max_rate)]
        if max_retries is not None:
            args += ["--max-retries", str(max_retries)]
        if host_timeout:
            args += ["--host-timeout", host_timeout]

        if nse_scripts:
            args += ["--script", nse_scripts]
        if nse_args:
            args += ["--script-args", nse_args]

        if verbose:
            args.append(verbose)

        if oA_prefix:
            oA_dir = os.path.dirname(oA_prefix)
            if oA_dir:
                os.makedirs(oA_dir, exist_ok=True)
            args += ["-oA", oA_prefix]

        args.append(target)

        requires_priv = self._needs_privileges(
            use_syn=use_syn, use_udp=use_udp, use_os=use_os)
        return args, requires_priv

    # ---------------------- Exec (sudo / runner) ----------------------
    def run_nmap_with_sudo(self, args):
        self._maybe_add_stats_every(args)
        if self._sudo_cached_now():
            cmd = ["sudo", "nmap"] + args
            self.start_nmap_thread(cmd, label="sudo_scan")
            return True

        # popup password
        box = BoxLayout(orientation="vertical", spacing=6, padding=6)
        box.add_widget(
            Label(text="Inserisci password sudo per questa scansione:"))
        pwd_input = TextInput(password=True, multiline=False)
        box.add_widget(pwd_input)
        btn_box = BoxLayout(size_hint_y=None, height="40dp", spacing=6)
        ok_btn = Button(text="OK")
        cancel_btn = Button(text="Annulla")
        btn_box.add_widget(ok_btn)
        btn_box.add_widget(cancel_btn)
        box.add_widget(btn_box)

        popup = Popup(title="Password richiesta", content=box,
                      size_hint=(0.7, 0.4), auto_dismiss=False)

        def start_scan_with_password(password: str):
            popup.dismiss()
            cmd = ["sudo", "-S", "nmap"] + args
            self.start_nmap_thread(
                cmd, label="sudo_scan", stdin_input=password)

        def on_ok(_btn):
            password = pwd_input.text
            if not password:
                self.set_status(
                    "Password non inserita, scan annullato", error=True)
                popup.dismiss()
                return
            pwd_input.text = ""
            start_scan_with_password(password)

        def on_cancel(_btn):
            self.set_status(
                "Scan privilegiato annullato dall'utente", error=True)
            popup.dismiss()

        ok_btn.bind(on_release=on_ok)
        cancel_btn.bind(on_release=on_cancel)
        popup.open()
        return True

    def start_nmap_thread(self, cmd, label="scan", timeout=None, stdin_input: str = None):
        if self.runner is not None:
            self.set_status("Scan già in esecuzione", error=True)
            return

        # reset progress UI
        self.progress_tracker.progress = 0.0
        self.progress_tracker.phase_text = ""
        self.progress_tracker.eta_text = ""
        self.progress_log_text = ""
        self.progress = 0.0
        self.phase_text = ""
        self.eta_text = ""

        self.set_status(f"lanciando {label}...")
        if isinstance(cmd, str):
            cmd = shlex.split(cmd)

        self.runner = NmapRunner(
            cmd_args=cmd,
            on_done=self._on_scan_done,
            on_progress=self._on_progress_line,
            timeout=timeout,
            stdin_input=stdin_input,
        )
        self.runner.start()

    def abort_scan(self):
        if self.runner:
            self.runner.abort()
            self.set_status("abort richiesto")

    # ---------------------- Preset / Custom ----------------------
    def start_preset(self, preset_name):
        target = self.ids.target.text.strip()
        if not target:
            self.set_status("Inserisci un target valido", error=True)
            return

        timing = self._norm_timing(self.ids.timing.text)
        user_wants_syn = self.ids.use_syn.active
        base = []

        if preset_name == "discovery":
            base = ["-sn", "-n", target]

        elif preset_name == "fast_syn":
            base = [("-sS" if user_wants_syn else "-sT"),
                    "-T4", "-F", "--open", target]
            if user_wants_syn and self.syn_capable and not self.is_root:
                self.set_status("SYN con privilegi: verifica sudo...")
                self._maybe_add_stats_every(base)
                self.run_nmap_with_sudo(base)
                return

        elif preset_name == "top_version":
            base = [("-sS" if user_wants_syn else "-sT"),
                    "-T4", "--top-ports", "200", "-sV", target]
            if user_wants_syn and self.syn_capable and not self.is_root:
                self.set_status("SYN con privilegi: verifica sudo...")
                self._maybe_add_stats_every(base)
                self.run_nmap_with_sudo(base)
                return

        elif preset_name == "udp_quick":
            base = ["-sU", "--top-ports", "100", "-T3", target]
            if not self.is_root:
                if self.syn_capable:
                    self.set_status(
                        "UDP scan richiede privilegi: verifica sudo...")
                    self._maybe_add_stats_every(base)
                    self.run_nmap_with_sudo(base)
                    return
                else:
                    self.set_status(
                        "UDP scan richiede privilegi: utente non sudoer.", error=True)
                    return

        elif preset_name == "vuln":
            base = [("-sS" if user_wants_syn else "-sT"),
                    "-T4", "--script", "vuln", target]
            if user_wants_syn and self.syn_capable and not self.is_root:
                self.set_status("SYN con privilegi: verifica sudo...")
                self._maybe_add_stats_every(base)
                self.run_nmap_with_sudo(base)
                return

        else:
            self.set_status("Preset non riconosciuto", error=True)
            return

        if timing and not any(a.startswith("-T") for a in base):
            base.insert(0, timing)
        self._maybe_add_stats_every(base)

        cmd = self.build_nmap_cmd(base)
        self.start_nmap_thread(cmd, label=f"preset:{preset_name}")

    def start_custom_scan(self):
        try:
            args, requires_priv = self.build_custom_args()
        except ValueError as e:
            self.set_status(str(e), error=True)
            return

        self._maybe_add_stats_every(args)

        if requires_priv and not self.is_root:
            if self.syn_capable:
                self.set_status(
                    "Custom: sono richiesti privilegi, verifica sudo...")
                self.run_nmap_with_sudo(args)
                return
            else:
                self.set_status(
                    "Custom: privilegi richiesti ma utente non sudoer.", error=True)
                return

        cmd = self.build_nmap_cmd(args)
        self.start_nmap_thread(cmd, label="custom")

    # ---------------------- UI helpers ----------------------
    def set_status(self, text, error=False):
        # In futuro puoi fare colorazione o log di sistema qui
        self.status_text = text

    def _populate_results(self, hosts):
        grid = self.result_grid
        if not grid:
            self.set_status(
                "UI non inizializzata (result_grid mancante)", error=True)
            return
        grid.clear_widgets()
        from kivy.uix.label import Label
        for h in hosts:
            line = f"{h['addr']}\t{h['hostname']}\t{h['state']}\t{h['ports']}"
            grid.add_widget(Label(text=line, size_hint_y=None, height="28dp"))
        self.parsed_hosts = hosts

    def parse_and_display(self, xml_text: str):
        hosts = parse_nmap_xml(xml_text)
        if not self.result_grid:
            Clock.schedule_once(lambda dt: self._populate_results(hosts), 0)
        else:
            self._populate_results(hosts)

    def save_last_xml(self):
        if not self.last_xml:
            self.set_status("Nessun xml disponibile", error=True)
            return
        ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        path = os.path.join(self.scans_dir, f"manual_saved_{ts}.xml")
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.last_xml)
        self.set_status(f"XML salvato in {path}")

    def export_csv(self):
        if not self.parsed_hosts:
            self.set_status("Nessun host da esportare", error=True)
            return
        ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        path = os.path.join(self.scans_dir, f"ports_export_{ts}.csv")
        import csv
        with open(path, "w", newline="", encoding="utf-8") as csvf:
            w = csv.writer(csvf)
            w.writerow(["ip", "hostname", "state", "ports"])
            for h in self.parsed_hosts:
                w.writerow([h["addr"], h["hostname"], h["state"], h["ports"]])
        self.set_status(f"CSV esportato: {path}")

    def open_scans_folder(self):
        try:
            sysname = platform.system()
            if sysname == "Windows":
                os.startfile(self.scans_dir)  # type: ignore[attr-defined]
            elif sysname == "Darwin":
                subprocess.run(["open", self.scans_dir])
            else:
                subprocess.run(["xdg-open", self.scans_dir])
            self.set_status("Aperta cartella scans")
        except Exception as e:
            self.set_status(f"Impossibile aprire: {e}", error=True)

    # ---------------------- Progress / stall ----------------------
    def _check_stall(self, dt):
        if self.runner is None:
            return
        stale = self.progress_tracker.stall_tick()
        if stale:
            self.eta_text = stale

    @mainthread
    def _on_progress_line(self, line: str):
        s = (line or "").strip()
        if not s:
            return
        self.progress_tracker.handle_line(s)
        # riflette in UI
        self.progress = self.progress_tracker.progress
        self.phase_text = self.progress_tracker.phase_text
        self.eta_text = self.progress_tracker.eta_text
        self.progress_log_text = self.progress_tracker.log_tail_text
        # status sintetico SOLO per stderr (non XML)
        if not s.startswith("<"):
            self.set_status(f"[stderr] {s[:200]}")

    @mainthread
    def _on_scan_done(self, error, xml_output):
        if error:
            self.set_status(f"Errore: {error}", error=True)
            self.progress = 0.0
            self.phase_text = "Errore"
        else:
            ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
            fname = os.path.join(self.scans_dir, f"scan_{ts}.xml")
            with open(fname, "w", encoding="utf-8") as f:
                f.write(xml_output)
            self.last_xml = xml_output
            self.parse_and_display(xml_output)
            self.set_status(f"Scan completato, salvato {fname}")
            self.progress = 100.0
            self.phase_text = "Completed"
            self.eta_text = ""
        self.runner = None
