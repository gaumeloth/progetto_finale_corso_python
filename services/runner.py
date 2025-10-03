import subprocess
import threading
import time
from collections import deque
from typing import Callable, Optional, List


class NmapRunner(threading.Thread):
    """
    Esegue nmap (o sudo nmap) e:
      - forza '-oX -' su stdout (XML su stdout)
      - inoltra TUTTO stderr (progress testuale) al callback on_progress
      - inoltra SOLO da stdout le righe XML di progresso: <taskprogress/>, <finished/>, <runstats>
      - opzionalmente scrive su stdin (es. password per 'sudo -S')
    Al termine: on_done(error:str|None, xml_output:str|None).
    """

    def __init__(
        self,
        cmd_args: List[str],
        on_done: Callable[[Optional[str], Optional[str]], None],
        on_progress: Optional[Callable[[str], None]] = None,
        timeout: Optional[float] = None,
        stdin_input: Optional[str] = None,
    ):
        super().__init__(daemon=True)
        self.cmd_args = cmd_args
        self.on_done = on_done
        self.on_progress = on_progress
        self.timeout = timeout
        self.stdin_input = stdin_input
        self.proc: Optional[subprocess.Popen] = None
        self._aborted = False
        self._stderr_tail = deque(maxlen=80)

    def _ensure_xml_stdout(self, argv: List[str]) -> List[str]:
        fixed, skip = [], False
        for i, a in enumerate(argv):
            if skip:
                skip = False
                continue
            if a == "-oX":
                if i + 1 < len(argv):
                    skip = True  # salta il path
                continue
            if a.startswith("-oX"):
                continue
            fixed.append(a)
        fixed += ["-oX", "-"]
        return fixed

    def run(self):
        try:
            cmd = self._ensure_xml_stdout(list(self.cmd_args))
            self.proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
                text=True,
                bufsize=1,  # line-buffered
            )
        except Exception as e:
            self.on_done(error=str(e), xml_output=None)
            return

        out_lines = []
        start = time.time()

        # --- Drain stderr su thread dedicato ---
        def _drain_stderr():
            try:
                assert self.proc and self.proc.stderr
                for line in self.proc.stderr:
                    if not line:
                        continue
                    s = line.rstrip("\n")
                    self._stderr_tail.append(s)
                    if self.on_progress:
                        self.on_progress(s)  # progress testuale (stderr)
                    if self._aborted:
                        break
            except Exception:
                pass

        t_err = threading.Thread(target=_drain_stderr, daemon=True)
        t_err.start()

        # --- Stdout (XML completo) + inoltro progress XML ---
        try:
            if self.stdin_input is not None and self.proc and self.proc.stdin:
                try:
                    self.proc.stdin.write(self.stdin_input + "\n")
                    self.proc.stdin.flush()
                finally:
                    try:
                        self.proc.stdin.close()
                    except Exception:
                        pass

            assert self.proc and self.proc.stdout
            for line in self.proc.stdout:
                if not line:
                    continue
                out_lines.append(line)

                # inoltra SOLO marker XML di progress
                s = line.strip()
                if s.startswith("<taskprogress") or s.startswith("<finished") or s.startswith("<runstats"):
                    if self.on_progress:
                        self.on_progress(s)

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
            try:
                if self.proc and self.proc.stdout:
                    self.proc.stdout.close()
            except Exception:
                pass
            try:
                if self.proc and self.proc.stderr:
                    self.proc.stderr.close()
            except Exception:
                pass
            try:
                t_err.join(timeout=1.0)
            except Exception:
                pass

        xml_output = "".join(out_lines)

        if self._aborted:
            self.on_done(error="aborted", xml_output=None)
            return

        if "<nmaprun" in xml_output:
            self.on_done(error=None, xml_output=xml_output)
        else:
            err_preview = (xml_output.strip()[
                           :400]) if xml_output else "empty stdout"
            stderr_preview = "\n".join(
                list(self._stderr_tail)[-12:]) or "empty stderr"
            err_msg = f"no xml output; raw stdout: {
                err_preview}; stderr tail:\n{stderr_preview}"
            self.on_done(error=err_msg, xml_output=None)

    def abort(self):
        self._aborted = True
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.kill()
            except Exception:
                pass
