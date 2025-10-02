import os
import shlex
import subprocess
import threading
import xml.etree.ElementTree as ET
import csv
import time
from datetime import datetime

from kivy.app import App
from kivy.lang import Builder
from kivy.properties import StringProperty, ListProperty, BooleanProperty
from kivy.uix.boxlayout import BoxLayout
from kivy.clock import Clock, mainthread
from kivy.uix.popup import Popup
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
import pwd
import grp

# (fallback KV: se carichi gui.kv da main.py non viene usato)
KV = r'''
<MainUI>:
    orientation: 'vertical'
    padding: 8
    spacing: 8

    BoxLayout:
        size_hint_y: None
        height: '40dp'
        Label:
            text: 'Nmap GUI — Preset scans'
            bold: True

    BoxLayout:
        size_hint_y: None
        height: '120dp'
        spacing: 8

        BoxLayout:
            orientation: 'vertical'
            size_hint_x: .6
            spacing: 6

            BoxLayout:
                size_hint_y: None
                height: '36dp'
                Label:
                    text: 'Target (IP / CIDR / host):'
                TextInput:
                    id: target
                    text: root.last_target
                    multiline: False

            BoxLayout:
                size_hint_y: None
                height: '36dp'
                Label:
                    text: 'Porte (es. 22,80 o leave blank):'
                TextInput:
                    id: ports
                    multiline: False

            BoxLayout:
                size_hint_y: None
                height: '36dp'
                Label:
                    text: 'Timing (T0..T5):'
                Spinner:
                    id: timing
                    text: 'T4'
                    values: ['T0','T1','T2','T3','T4','T5']
            BoxLayout:
                size_hint_y: None
                height: '36dp'
                CheckBox:
                    id: use_syn
                    active: root.defaults_use_syn
                Label:
                    text: 'Usa SYN scan (richiede sudo / capability)'

        BoxLayout:
            orientation: 'vertical'
            spacing: 6

            Label:
                text: 'Presets'
                size_hint_y: None
                height: '24dp'

            GridLayout:
                cols: 1
                spacing: 6
                Button:
                    text: 'Host discovery (ping) -sn'
                    on_release: root.start_preset('discovery')
                Button:
                    text: 'Fast SYN scan (top ports) -sS -F'
                    on_release: root.start_preset('fast_syn')
                Button:
                    text: 'Top ports + version -sS --top-ports -sV'
                    on_release: root.start_preset('top_version')
                Button:
                    text: 'UDP quick (top ports) -sU --top-ports'
                    on_release: root.start_preset('udp_quick')
                Button:
                    text: 'Vulnerability scan (NSE --script=vuln)'
                    on_release: root.start_preset('vuln')

    BoxLayout:
        size_hint_y: None
        height: '40dp'
        spacing: 8
        Button:
            text: 'Start custom scan'
            on_release: root.start_custom_scan()
        Button:
            text: 'Abort scan'
            on_release: root.abort_scan()
        Button:
            text: 'Save last XML'
            on_release: root.save_last_xml()

    Label:
        text: 'Status: ' + root.status_text
        size_hint_y: None
        height: '24dp'

    BoxLayout:
        size_hint_y: None
        height: '24dp'
        Label:
            text: 'Results (hosts)'
    ScrollView:
        GridLayout:
            id: result_grid
            cols: 1
            size_hint_y: None
            height: self.minimum_height
            row_default_height: '28dp'
            row_force_default: True

    BoxLayout:
        size_hint_y: None
        height: '28dp'
        spacing: 8
        Button:
            text: 'Export CSV (ports)'
            on_release: root.export_csv()
        Button:
            text: 'Open scans folder'
            on_release: root.open_scans_folder()
'''

# ---------------- Runner ----------------


class NmapRunner(threading.Thread):
    """
    Esegue nmap (o sudo nmap) e:
      - raccoglie SOLO l'XML da stdout (con -oX -)
      - inoltra stderr (prompt/progress/errori) a on_output_line in parallelo
    Se stdin_input è valorizzato, viene scritto su stdin (es. password per sudo -S).
    """

    def __init__(self, cmd_args, on_done, on_output_line=None, timeout=None, stdin_input: str = None):
        super().__init__(daemon=True)
        self.cmd_args = cmd_args
        self.on_done = on_done
        self.on_output_line = on_output_line
        self.proc = None
        self._aborted = False
        self.timeout = timeout
        self.stdin_input = stdin_input

    def run(self):
        try:
            # Assicura '-oX -' se non già presente (per ricevere XML su stdout)
            cmd = list(self.cmd_args)
            if "-oX" not in cmd:
                cmd += ['-oX', '-']

            # stdout e stderr SEPARATI
            self.proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
                text=True,
                bufsize=1  # line-buffered
            )
        except Exception as e:
            self.on_done(error=str(e), xml_output=None)
            return

        out_lines = []
        start = time.time()

        # Thread drain per stderr → inoltra progress/prompt a on_output_line
        def _drain_stderr():
            try:
                for line in self.proc.stderr:
                    if self.on_output_line and line:
                        self.on_output_line(line.rstrip("\n"))
                    if self._aborted:
                        break
            except Exception:
                pass  # ignora problemi di lettura stderr

        t_err = threading.Thread(target=_drain_stderr, daemon=True)
        t_err.start()

        try:
            # Inietta password (se necessario) e chiudi stdin
            if self.stdin_input is not None:
                try:
                    self.proc.stdin.write(self.stdin_input + "\n")
                    self.proc.stdin.flush()
                finally:
                    try:
                        self.proc.stdin.close()
                    except Exception:
                        pass

            # Legge SOLO stdout (XML) riga per riga
            for line in self.proc.stdout:
                out_lines.append(line)
                if self._aborted:
                    try:
                        self.proc.kill()
                    except Exception:
                        pass
                    break

                if self.timeout and (time.time() - start) > self.timeout:
                    try:
                        self.proc.kill()
                    except Exception:
                        pass
                    break

            rc = self.proc.wait()
        except Exception as e:
            self.on_done(error=str(e), xml_output=None)
            return
        finally:
            # assicura la chiusura dei pipe
            try:
                if self.proc.stdout:
                    self.proc.stdout.close()
            except Exception:
                pass
            try:
                if self.proc.stderr:
                    self.proc.stderr.close()
            except Exception:
                pass
            # attendi il drain di stderr
            try:
                t_err.join(timeout=1.0)
            except Exception:
                pass

        xml_output = ''.join(out_lines)

        if self._aborted:
            self.on_done(error='aborted', xml_output=None)
            return

        # Validazione minima dell'XML
        if '<nmaprun' in xml_output:
            self.on_done(error=None, xml_output=xml_output)
        else:
            # Se XML mancante, inoltra un estratto utile di stdout/stderr già mostrato come status
            err_preview = (xml_output.strip()[
                           :400]) if xml_output else 'empty stdout'
            self.on_done(error=f'no xml output; raw stdout: {
                         err_preview}', xml_output=None)

    def abort(self):
        self._aborted = True
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.kill()
            except Exception:
                pass

# ---------------- Main UI ----------------


class MainUI(BoxLayout):
    status_text = StringProperty('idle')
    last_xml = StringProperty('')
    parsed_hosts = ListProperty([])
    defaults_use_syn = BooleanProperty(True)
    last_target = StringProperty('192.168.1.0/24')

    # stato privilegi
    syn_capable = BooleanProperty(False)        # root o sudoer -> True
    is_root = BooleanProperty(False)            # euid==0
    # in sudoers (anche se richiede password)
    is_sudoer = BooleanProperty(False)
    # sudo -n -v restituisce 0 (no password necessaria)
    sudo_cached = BooleanProperty(False)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # fallback KV se non caricato da main.py
        try:
            Builder.load_string(KV)
        except Exception:
            pass

        self.runner = None
        self.scans_dir = os.path.join(os.getcwd(), 'scans')
        os.makedirs(self.scans_dir, exist_ok=True)

        # rilevamento privilegi post-build per avere self.ids pronti
        Clock.schedule_once(self._detect_privileges, 0.1)

    # --------- Rilevamento privilegi (EN/IT) ----------
    def _detect_privileges(self, dt=None):
        # 1) root?
        try:
            self.is_root = (os.geteuid() == 0)
        except Exception:
            self.is_root = False

        # 2) sudo non-interattivo
        self.is_sudoer, self.sudo_cached = self._probe_sudo_noninteractive()

        # 3) fallback gruppi 'sudo' / 'wheel' / 'admin' se sudo non disponibile
        if not self.is_sudoer and not self.is_root:
            try:
                user = pwd.getpwuid(os.getuid()).pw_name
                gids = os.getgroups()
                groups = {grp.getgrgid(g).gr_name for g in gids}
                # euristica comune su distro
                if groups.intersection({"sudo", "wheel", "admin"}):
                    self.is_sudoer = True
            except Exception:
                pass

        self.syn_capable = bool(self.is_root or self.is_sudoer)

        # rifletti in UI
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

    def _probe_sudo_noninteractive(self):
        """
        Ritorna (is_sudoer, sudo_cached).
        Usa 'sudo -n -v' forzando lingua EN; gestisce anche messaggi IT se l'override non riuscisse.
        """
        try:
            env = os.environ.copy()
            env.update({"LANG": "C", "LC_ALL": "C"})
            res = subprocess.run(
                ["sudo", "-n", "-v"], capture_output=True, text=True, env=env, timeout=3)
            out = (res.stdout + res.stderr).strip()
            low = out.lower()

            if res.returncode == 0:
                # sudo non chiede password (NOPASSWD o cache attiva)
                return True, True

            # pattern EN
            if "password is required" in low:
                return True, False
            if "may not run sudo" in low or "not in the sudoers" in low:
                return False, False

            # pattern IT (se l'override di lingua non è riuscito)
            it_pw = ("password è richiesta" in low) or ("è richiesta una password" in low) \
                or ("password richiesta" in low) or ("password necessaria" in low)
            if it_pw:
                return True, False
            it_no = ("non è nel file sudoers" in low) or ("non puo" in low and "eseguire sudo" in low) \
                or ("non può eseguire sudo" in low)
            if it_no:
                return False, False

            # casi ambigui → non trattare come sudoer
            return False, False

        except FileNotFoundError:
            # sudo non installato
            self.set_status(
                "sudo non trovato nel PATH: impossibile usare SYN come utente normale.", error=True)
            return False, False
        except subprocess.TimeoutExpired:
            self.set_status(
                "Timeout controllo sudo -v; stato privilegi non determinato.", error=True)
            return False, False
        except Exception as e:
            self.set_status(f"Errore controllo sudo: {e}", error=True)
            return False, False

    def _sudo_cached_now(self):
        """Ritorna True se ora sudo è utilizzabile senza password."""
        try:
            env = os.environ.copy()
            env.update({"LANG": "C", "LC_ALL": "C"})
            res = subprocess.run(
                ["sudo", "-n", "-v"], capture_output=True, text=True, env=env, timeout=3)
            return res.returncode == 0
        except Exception:
            return False

    # -------------- Costruzione comandi --------------
    def build_nmap_cmd(self, base_args):
        return ['nmap'] + base_args

    # -------------- Popup / sudo --------------
    def run_nmap_with_sudo(self, args):
        """
        Esegue nmap privilegiato:
        - se sudo cached → esegue direttamente con 'sudo nmap'
        - altrimenti chiede password e usa 'sudo -S nmap'
        """
        if self._sudo_cached_now():
            cmd = ["sudo", "nmap"] + args
            self.start_nmap_thread(cmd, label='sudo_scan')
            return True

        # Popup password
        def start_scan_with_password(password):
            popup.dismiss()
            cmd = ["sudo", "-S", "nmap"] + args
            self.start_nmap_thread(
                cmd, label='sudo_scan', stdin_input=password)

        box = BoxLayout(orientation='vertical', spacing=6, padding=6)
        box.add_widget(Label(text="Inserisci password sudo per SYN scan:"))
        pwd_input = TextInput(password=True, multiline=False)
        box.add_widget(pwd_input)
        btn_box = BoxLayout(size_hint_y=None, height='40dp', spacing=6)
        ok_btn = Button(text="OK")
        cancel_btn = Button(text="Annulla")
        btn_box.add_widget(ok_btn)
        btn_box.add_widget(cancel_btn)
        box.add_widget(btn_box)

        popup = Popup(title="Password richiesta", content=box,
                      size_hint=(0.7, 0.4), auto_dismiss=False)

        def on_ok(_):
            password = pwd_input.text
            if not password:
                self.set_status(
                    "Password non inserita, scan annullato", error=True)
                popup.dismiss()
                return
            pwd_input.text = ""
            start_scan_with_password(password)

        def on_cancel(_):
            self.set_status("Scan SYN annullato dall'utente", error=True)
            popup.dismiss()

        ok_btn.bind(on_release=on_ok)
        cancel_btn.bind(on_release=on_cancel)
        popup.open()
        return True

    # -------------- Preset / Custom --------------
    def start_preset(self, preset_name):
        target = self.ids.target.text.strip()
        if not target:
            self.set_status('Inserisci un target valido', error=True)
            return
        timing = self.ids.timing.text
        user_wants_syn = self.ids.use_syn.active
        base = []

        if preset_name == 'discovery':
            base = ['-sn', '-n', target]

        elif preset_name == 'fast_syn':
            if user_wants_syn and self.syn_capable and not self.is_root:
                self.set_status("SYN con privilegi: verifica sudo...")
                base = ['-sS', '-T4', '-F', '--open', target]
                self.run_nmap_with_sudo(base)
                return
            base = [('-sS' if user_wants_syn else '-sT'),
                    '-T4', '-F', '--open', target]

        elif preset_name == 'top_version':
            if user_wants_syn and self.syn_capable and not self.is_root:
                self.set_status("SYN con privilegi: verifica sudo...")
                base = ['-sS', '-T4', '--top-ports', '200', '-sV', target]
                self.run_nmap_with_sudo(base)
                return
            base = [('-sS' if user_wants_syn else '-sT'),
                    '-T4', '--top-ports', '200', '-sV', target]

        elif preset_name == 'udp_quick':
            # UDP richiede privilegi (raw sockets) su Unix
            base = ['-sU', '--top-ports', '100', '-T3', target]

            # Se non sei root ma sei sudoer → usa lo stesso percorso con sudo del SYN
            if not self.is_root:
                if self.syn_capable:  # nel nostro codice: root OR sudoer; qui siamo nel ramo not root -> sudoer
                    self.set_status(
                        "UDP scan richiede privilegi: verifica sudo...")
                    # gestisce cache sudo o popup password
                    self.run_nmap_with_sudo(base)
                    return
                else:
                    self.set_status(
                        "UDP scan richiede privilegi: utente non sudoer.", error=True)
                    return
            # Sei root -> esegui direttamente
            # (inietteremo il timing se non presente, come per gli altri preset)

        elif preset_name == 'vuln':
            if user_wants_syn and self.syn_capable and not self.is_root:
                self.set_status("SYN con privilegi: verifica sudo...")
                base = ['-sS', '-T4', '--script', 'vuln', target]
                self.run_nmap_with_sudo(base)
                return
            base = [('-sS' if user_wants_syn else '-sT'),
                    '-T4', '--script', 'vuln', target]

        else:
            self.set_status('Preset non riconosciuto', error=True)
            return

        if not any(a.startswith('-T') for a in base):
            base.insert(0, timing)

        cmd = self.build_nmap_cmd(base)
        self.start_nmap_thread(cmd, label=f'preset:{preset_name}')

    def start_custom_scan(self):
        target = self.ids.target.text.strip()
        if not target:
            self.set_status('Inserisci target prima di partire', error=True)
            return
        ports = self.ids.ports.text.strip()
        timing = self.ids.timing.text
        user_wants_syn = self.ids.use_syn.active

        args = [timing]
        if ports:
            args += ['-p', ports]

        if user_wants_syn and self.syn_capable and not self.is_root:
            base = args + ['-sS']
            if not ports:
                base += ['--top-ports', '200']
            base += ['-sV', target]
            self.set_status("SYN con privilegi: verifica sudo...")
            self.run_nmap_with_sudo(base)
            return

        args += ['-sS' if (user_wants_syn and self.syn_capable) else '-sT']
        if not ports:
            args += ['--top-ports', '200']
        args += ['-sV', target]

        cmd = self.build_nmap_cmd(args)
        self.start_nmap_thread(cmd, label='custom')

    # -------------- Thread orchestration --------------
    def start_nmap_thread(self, cmd, label='scan', timeout=None, stdin_input: str = None):
        if self.runner is not None:
            self.set_status('Scan già in esecuzione', error=True)
            return
        self.set_status(f'lanciando {label}...')
        if isinstance(cmd, str):
            cmd = shlex.split(cmd)
        self.runner = NmapRunner(cmd, on_done=self._on_scan_done,
                                 on_output_line=self._on_output_line,
                                 timeout=timeout, stdin_input=stdin_input)
        self.runner.start()

    def abort_scan(self):
        if self.runner:
            self.runner.abort()
            self.set_status('abort richiesto')

    @mainthread
    def _on_output_line(self, line):
        if line.strip():
            self.set_status(line.strip()[:200])

    @mainthread
    def _on_scan_done(self, error, xml_output):
        if error:
            self.set_status(f'Errore: {error}', error=True)
        else:
            ts = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
            fname = os.path.join(self.scans_dir, f'scan_{ts}.xml')
            with open(fname, 'w', encoding='utf-8') as f:
                f.write(xml_output)
            self.last_xml = xml_output
            self.parse_and_display(xml_output)
            self.set_status(f'Scan completato, salvato {fname}')
        self.runner = None

    # -------------- UI helpers / XML / CSV --------------
    def set_status(self, text, error=False):
        self.status_text = text

    def parse_and_display(self, xml_text):
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError as e:
            self.set_status(f'XML parse error: {e}', error=True)
            return
        hosts = []
        for host in root.findall('host'):
            haddr = host.find('address').get('addr') if host.find(
                'address') is not None else ''
            status = host.find('status').get('state') if host.find(
                'status') is not None else 'unknown'
            hostname = host.find('./hostnames/hostname').get('name',
                                                             '') if host.find('./hostnames/hostname') is not None else ''
            ports = []
            for p in host.findall('./ports/port'):
                portid = p.get('portid')
                proto = p.get('protocol')
                state = p.find('state').get('state') if p.find(
                    'state') is not None else ''
                service = p.find('service')
                sname = service.get('name') if service is not None else ''
                sversion = service.get(
                    'version') if service is not None and service.get('version') else ''
                ports.append(
                    f'{portid}/{proto} {state} {sname} {sversion}'.strip())
            hosts.append({'addr': haddr, 'hostname': hostname,
                         'state': status, 'ports': '; '.join(ports)})
        grid = self.ids.result_grid
        grid.clear_widgets()
        from kivy.uix.label import Label
        for h in hosts:
            grid.add_widget(Label(text=f"{h['addr']}\t{h['hostname']}\t{h['state']}\t{h['ports']}",
                                  size_hint_y=None, height='28dp'))
        self.parsed_hosts = hosts

    def save_last_xml(self):
        if not self.last_xml:
            self.set_status('Nessun xml disponibile', error=True)
            return
        ts = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
        path = os.path.join(self.scans_dir, f'manual_saved_{ts}.xml')
        with open(path, 'w', encoding='utf-8') as f:
            f.write(self.last_xml)
        self.set_status(f'XML salvato in {path}')

    def export_csv(self):
        if not self.parsed_hosts:
            self.set_status('Nessun host da esportare', error=True)
            return
        path = os.path.join(self.scans_dir, f'ports_export_{
                            datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")}.csv')
        with open(path, 'w', newline='', encoding='utf-8') as csvf:
            w = csv.writer(csvf)
            w.writerow(['ip', 'hostname', 'state', 'ports'])
            for h in self.parsed_hosts:
                w.writerow([h['addr'], h['hostname'], h['state'], h['ports']])
        self.set_status(f'CSV esportato: {path}')

    def open_scans_folder(self):
        try:
            if os.name == 'nt':
                os.startfile(self.scans_dir)
            elif os.uname().sysname == 'Darwin':
                subprocess.run(['open', self.scans_dir])
            else:
                subprocess.run(['xdg-open', self.scans_dir])
            self.set_status('Aperta cartella scans')
        except Exception as e:
            self.set_status(f'Impossibile aprire: {e}', error=True)


# Fallback single-file run
class NmapKivyApp(App):
    def build(self):
        try:
            Builder.load_string(KV)
        except Exception:
            pass
        return MainUI()


if __name__ == '__main__':
    NmapKivyApp().run()
