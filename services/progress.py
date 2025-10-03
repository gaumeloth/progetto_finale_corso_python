import time
import re
from collections import deque
from typing import Optional


class ProgressTracker:
    """
    Converte righe di output (stderr testuale o XML <taskprogress/> da stdout)
    in stato UI: progress (0..100), phase_text, eta_text e un tail di log.
    """

    def __init__(self, log_tail_lines: int = 120, stall_after_sec: int = 20):
        self.progress: float = 0.0
        self.phase_text: str = ""
        self.eta_text: str = ""
        self._stderr_ring = deque(maxlen=log_tail_lines)
        self._last_update_ts = time.time()
        self._stall_after = stall_after_sec

        # pattern classici(stderr)
        self._re_about = re.compile(
            r"About\s+([\d.]+)%\s+done;.*?ETC:\s*([^\r\n]+)")
        self._re_initiating = re.compile(r"Initiating\s+(.+?)\s+at")
        self._re_completed = re.compile(r"Completed\s+(.+?)\s+at")
        self._re_hosts = re.compile(
            r"(\d+)\s+hosts?\s+completed\s+\((\d+)\s+up\)")

        # pattern XML (stdout “filtrato” dal runner)
        self._re_taskprogress = re.compile(
            r'<taskprogress[^>]*percent="([\d.]+)"(?:[^>]*remaining="(\d+)")?(?:[^>]*etc="(\d+)")?'
        )
        self._re_finished = re.compile(
            r'<finished[^>]*time="(\d+)"[^>]*summary="([^"]+)"')

    @property
    def log_tail_text(self) -> str:
        return "\n".join(list(self._stderr_ring)[-8:])

    @property
    def last_update_age(self) -> int:
        return int(time.time() - self._last_update_ts)

    def handle_line(self, line: str):
        if not line:
            return
        self._last_update_ts = time.time()
        s = line.strip()

        # --- XML progress da stdout (NmapRunner inoltra solo i marker rilevanti) ---
        if s.startswith("<taskprogress"):
            m = self._re_taskprogress.search(s)
            if m:
                try:
                    self.progress = float(m.group(1))
                except Exception:
                    pass
                if m.group(2):  # remaining (secondi)
                    self.eta_text = f"remaining ~{m.group(2)}s"
                elif m.group(3):  # etc (epoch)
                    try:
                        etc_ts = int(m.group(3))
                        self.eta_text = "ETC: " + \
                            time.strftime("%H:%M:%S", time.localtime(etc_ts))
                    except Exception:
                        pass
            return  # NON sporcare il log con XML

        if s.startswith("<finished"):
            self.progress = 100.0
            self.phase_text = "Completed"
            self.eta_text = ""
            return

        # --- stderr testuale ---
        m = self._re_about.search(s)
        if m:
            try:
                self.progress = float(m.group(1))
            except Exception:
                pass
            self.eta_text = f"ETC: {m.group(2)}"

        m = self._re_initiating.search(s)
        if m:
            self.phase_text = f"Initiating {m.group(1)}"

        m = self._re_completed.search(s)
        if m:
            self.phase_text = f"Completed {m.group(1)}"

        m = self._re_hosts.search(s)
        if m:
            self.phase_text = f"Hosts: {m.group(1)} done, {m.group(2)} up"

        # Accumula tail solo per stderr testuale
        self._stderr_ring.append(s)

    def stall_tick(self) -> Optional[str]:
        """
        Se non arrivano update da troppo tempo, restituisce una ETA sintetica
        ('no update for Ns') che puoi impostare in UI; altrimenti None.
        """
        delta = self.last_update_age
        if delta >= self._stall_after:
            return f"no update for {delta}s"
        return None
