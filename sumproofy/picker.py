"""File-picker dialog that runs on the main thread.

tkinter is only safe on the thread that owns the Tk root. The web server
handles /api/browse on a worker thread, so the worker asks the main thread
(via a queue) to open the dialog and waits for the answer. If the main
thread is not running the dialog loop (no tkinter, or --no-picker), pick()
is never called: the server hands out None and the page falls back to the
manual path box.
"""
import queue
import threading

DIALOG_TITLE = "Choose the downloaded file"


class MainThreadPicker:
    def __init__(self, timeout=300):
        self._requests = queue.Queue()
        self.timeout = timeout

    def pick(self):
        """Called from any worker thread. Returns the chosen path or None."""
        reply = queue.Queue()
        self._requests.put(reply)
        try:
            return reply.get(timeout=self.timeout)
        except queue.Empty:
            return None

    def service_one(self, open_dialog):
        """Answer one pending request, if any. Testable without tkinter."""
        try:
            reply = self._requests.get_nowait()
        except queue.Empty:
            return False
        try:
            chosen = open_dialog()
        except Exception:
            chosen = None
        reply.put(chosen or None)
        return True

    def run(self):
        """Own the Tk root and service dialog requests. Main thread only."""
        import tkinter as tk
        from tkinter import filedialog
        root = tk.Tk()
        root.withdraw()

        def open_dialog():
            root.deiconify()
            root.attributes("-topmost", True)
            try:
                return filedialog.askopenfilename(parent=root, title=DIALOG_TITLE)
            finally:
                root.withdraw()

        def poll():
            while self.service_one(open_dialog):
                pass
            root.after(100, poll)

        root.after(100, poll)
        root.mainloop()


def make_picker(disabled=False):
    """(picker_or_None, run_fn). run_fn blocks on the main thread."""
    if disabled:
        return None, _wait_forever
    try:
        import tkinter  # noqa: F401
    except Exception:
        return None, _wait_forever
    picker = MainThreadPicker()
    return picker, picker.run


def _wait_forever():
    """Main-thread wait when there is no dialog loop (Ctrl+C to stop)."""
    threading.Event().wait()
