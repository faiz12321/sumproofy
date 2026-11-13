# SumProofy

Make sure a file you downloaded is the real one.

You pick a file you downloaded. SumProofy works out the file's
fingerprint (SHA-256) and automatically looks for the official fingerprint
from the maker, then tells you clearly if they match.

## What you see

One of three clear answers:

- **MATCHES** - the file is exactly what the maker published.
- **DOES NOT MATCH** - do not run or open it. Delete it and download it again
  from the maker's real site.
- **NOT SURE** - no official fingerprint could be found. The app shows the
  file's fingerprint so you can compare it by eye.

## How it finds the official fingerprint

- If you paste the page you downloaded from, it looks on that page for the
  official fingerprint, including the small `.sha256` files many makers
  publish next to their downloads.
- If the file came from GitHub, it asks GitHub directly. For many release
  files GitHub can return a stored SHA-256 fingerprint (when one was
  recorded at upload); when there is none, it looks for a checksum file
  attached to the release instead.
- On Windows, for app files (.exe, .msi and friends), it also shows who
  digitally signed the file, using Windows' own signature check.

## Honest limits

- A matching fingerprint from the same site you downloaded from only proves
  the download was not corrupted. It cannot prove the website itself is
  honest. Only download from places you trust.
- If the maker does not publish a fingerprint, the app cannot invent one.
  It says "NOT SURE" instead of guessing.
- The Windows signature check adds the publisher's name when present. It is
  extra information, not the verdict by itself.

## What it never does

- It only reads the file you pick. Nothing is uploaded, changed or deleted.
- The only internet it uses is the page you give it (or GitHub) to find the
  official fingerprint. Links that point at local or private network
  addresses are refused.
- It runs only on your own computer (a small local page at 127.0.0.1,
  protected so other websites cannot talk to it).

## Download and run it (Windows)

1. Open the latest release on this repository's Releases page and download
   `sumproofy.exe`. The exe is built from this exact code by the repo's CI.
2. Windows may show a blue "Windows protected your PC" message, because the
   app is not signed with a paid certificate. Click "More info", then
   "Run anyway".
3. Double-click `sumproofy.exe`; your browser opens the checker page. Pick
   the file (or type its path), optionally paste the download page link,
   and press "Check it".

## Build it from source

Needs Python 3.10+.

```
python -m sumproofy            # run the app
python -m unittest discover -s tests  # run the tests
pyinstaller --onefile --name sumproofy --add-data "sumproofy/ui.html;sumproofy" run.py
```

## License

MIT. See LICENSE.
