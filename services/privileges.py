import os
import subprocess
import grp
import pwd
from dataclasses import dataclass
from typing import Tuple


@dataclass
class PrivState:
    is_root: bool
    is_sudoer: bool
    sudo_cached: bool

    @property
    def syn_capable(self) -> bool:
        # in app: usato per -sS/-sU (raw sockets)
        return bool(self.is_root or self.is_sudoer)


class PrivilegeManager:
    """
    Rilevazione privilegi:
      - root tramite os.geteuid()
      - sudo non-interattivo con 'sudo -n -v' (forza LANG=C; fallback EN/IT)
      - euristica gruppi: sudo / wheel / admin
    """

    def __init__(self, status_cb=None):
        self.status_cb = status_cb or (lambda *_: None)

    def _probe_sudo_noninteractive(self) -> Tuple[bool, bool]:
        """
        Ritorna (is_sudoer, sudo_cached).
        sudo_cached=True significa che *ora* sudo non richiede password (NOPASSWD o cache attiva).
        """
        try:
            env = dict(os.environ)
            env.update({"LANG": "C", "LC_ALL": "C"})
            res = subprocess.run(
                ["sudo", "-n", "-v"], capture_output=True, text=True, env=env, timeout=3)
            out = (res.stdout + res.stderr).strip().lower()
            if res.returncode == 0:
                return True, True  # sudo ok senza password
            # pattern EN
            if "password is required" in out:
                return True, False
            if "may not run sudo" in out or "not in the sudoers" in out:
                return False, False
            # pattern IT
            it_pw = ("password è richiesta" in out) or ("è richiesta una password" in out) \
                or ("password richiesta" in out) or ("password necessaria" in out)
            if it_pw:
                return True, False
            it_no = ("non è nel file sudoers" in out) or ("non puo" in out and "eseguire sudo" in out) \
                or ("non può eseguire sudo" in out)
            if it_no:
                return False, False
            return False, False
        except FileNotFoundError:
            self.status_cb(
                "sudo non trovato nel PATH: scansioni SYN/UDP richiederanno root/capabilities.", True)
            return False, False
        except subprocess.TimeoutExpired:
            self.status_cb(
                "Timeout controllo sudo -v; stato privilegi non determinato.", True)
            return False, False
        except Exception as e:
            self.status_cb(f"Errore controllo sudo: {e}", True)
            return False, False

    def sudo_cached_now(self) -> bool:
        try:
            env = dict(os.environ)
            env.update({"LANG": "C", "LC_ALL": "C"})
            res = subprocess.run(
                ["sudo", "-n", "-v"], capture_output=True, text=True, env=env, timeout=3)
            return res.returncode == 0
        except Exception:
            return False

    def detect(self) -> PrivState:
        try:
            is_root = (os.geteuid() == 0)
        except Exception:
            is_root = False

        is_sudoer, sudo_cached = self._probe_sudo_noninteractive()

        if not is_sudoer and not is_root:
            # euristica gruppi “amministrativi”
            try:
                user = pwd.getpwuid(os.getuid()).pw_name
                groups_ids = os.getgroups()
                groups = {grp.getgrgid(g).gr_name for g in groups_ids}
                if groups.intersection({"sudo", "wheel", "admin"}):
                    is_sudoer = True
            except Exception:
                pass

        return PrivState(is_root=is_root, is_sudoer=is_sudoer, sudo_cached=sudo_cached)
