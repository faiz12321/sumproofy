"""Read-only SHA-256 hashing of one file."""
import hashlib
import os

CHUNK = 1024 * 1024  # 1 MiB


class HashError(Exception):
    """The file could not be read."""


def sha256_file(path, progress=None):
    """Return the SHA-256 hex digest of the file at path.

    Read-only. Raises HashError on any problem (missing file, directory,
    permission error, file changing or disappearing while reading).
    progress(bytes_done, total) is called after each chunk when given.
    """
    if not isinstance(path, str) or not path.strip():
        raise HashError("No file was chosen.")
    path = path.strip().strip('"')
    if not os.path.exists(path):
        raise HashError("That file does not exist.")
    if not os.path.isfile(path):
        raise HashError("That is a folder, not a file. Pick a single file.")
    try:
        total = os.path.getsize(path)
    except OSError as exc:
        raise HashError(f"Could not read the file's size: {exc}")
    h = hashlib.sha256()
    done = 0
    try:
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(CHUNK)
                if not chunk:
                    break
                h.update(chunk)
                done += len(chunk)
                if progress:
                    progress(done, total)
    except OSError as exc:
        raise HashError(f"Could not read the file: {exc}")
    if done != total:
        raise HashError("The file changed while it was being read. Try again.")
    return h.hexdigest()
