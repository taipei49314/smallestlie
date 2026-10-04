"""Prepare sealed W3 installation inputs; never run cases or import product code."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import stat
import subprocess
import sys
import time
import tomllib
import urllib.parse
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[2]
NAME = "m12-w3-freeze-prepare"
HOST = "LAPTOP-50KP71KA"
MIB = 1024 * 1024
PYTHON = {
    "version": "3.12.10",
    "url": "https://api.nuget.org/v3-flatcontainer/python/3.12.10/python.3.12.10.nupkg",
    "sha256": "0eb85c2dfccccf1b17352de4c397f69194035b7d37149eacc16f1147d93de3b8",
}
NODE = {
    "version": "24.19.0",
    "url": "https://nodejs.org/dist/v24.19.0/node-v24.19.0-win-x64.zip",
    "sha256": "57f71ab3652e797d84acddc79c81cc9ff1c6ddb2a1974cdb83f00fee9bff4c73",
    "executable_sha256": "3602f2bb1a10f2cbab4c36886218a33c1ab3db87290e73b033c46c77147d0237",
}
PY_DEPS = {"pytest", "pytest-timeout", "pyyaml", "colorama", "iniconfig",
           "packaging", "pluggy", "pygments"}
JS_DEPS = {"mocha": "12.0.3", "chai": "5.3.3", "vitest": "3.2.7"}
DOWNLOAD_HOSTS = {"api.nuget.org", "globalcdn.nuget.org", "nodejs.org",
                  "files.pythonhosted.org"}
CHUNK_BYTES = 8 * MIB
MAX_FILES = 50000
MAX_FILE_BYTES = 256 * MIB


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":"), allow_nan=False).encode("ascii")


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(json.dumps(value, indent=2, sort_keys=True,
                                allow_nan=False).encode("utf-8") + b"\n")


def plain(path: Path) -> None:
    for item in (path, *path.parents):
        if not item.exists():
            continue
        info = item.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("reparse or linked path refused")


def relative(name: str) -> str:
    parts = name.split("/")
    if (PurePosixPath(name).is_absolute() or "\\" in name or ":" in name
            or any(p in {"", ".", "..", ".git"} or p.endswith((" ", ".")) for p in parts)):
        raise ValueError("unsafe archive/member path")
    return name


def inventory(root: Path, *, limit: int, file_limit: int = MAX_FILE_BYTES,
              file_count: int = MAX_FILES) -> dict[str, str]:
    plain(root)
    found: dict[str, str] = {}
    aliases: set[str] = set()
    total = 0
    def unreadable(error: OSError) -> None:
        raise error
    for parent, directories, files in os.walk(root, followlinks=False, onerror=unreadable):
        for name in [*directories, *files]:
            plain(Path(parent) / name)
        for name in sorted(files):
            path = Path(parent) / name
            key = relative(path.relative_to(root).as_posix())
            if key.casefold() in aliases or not path.is_file():
                raise ValueError("nonregular or aliased installation input")
            size = path.stat().st_size
            total += size
            if size > file_limit or total > limit or len(found) >= file_count:
                raise ValueError("complete installation exceeds declared byte/file bound")
            aliases.add(key.casefold())
            found[key] = digest(path.read_bytes())
    if not found:
        raise ValueError("empty installation")
    return dict(sorted(found.items()))


class FixedRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urllib.parse.urlsplit(newurl)
        if (target.scheme != "https" or target.hostname not in DOWNLOAD_HOSTS
                or target.username or target.password):
            raise ValueError("download redirect outside approved hosts")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(url: str, sha256: str, path: Path, records: list[dict]) -> None:
    target = urllib.parse.urlsplit(url)
    if (target.scheme != "https" or target.hostname not in DOWNLOAD_HOSTS
            or target.username or target.password or not re.fullmatch("[0-9a-f]{64}", sha256)):
        raise ValueError("unapproved download identity")
    started = time.monotonic()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), FixedRedirects())
    with opener.open(url, timeout=45) as response, path.open("xb") as stream:
        received = 0
        while block := response.read(MIB):
            received += len(block)
            if received > 64 * MIB or time.monotonic() - started > 180:
                raise ValueError("download exceeds bound")
            stream.write(block)
    actual = digest(path.read_bytes())
    records.append({"url": url, "path": path.name, "sha256": actual, "bytes": received})
    if actual != sha256:
        raise ValueError("download raw hash differs")


def unpack(archive: Path, root: Path, *, prefix: str = "", wheel: bool = False) -> None:
    root.mkdir(parents=True, exist_ok=True)
    seen: set[str] = set()
    total = 0
    with zipfile.ZipFile(archive) as package:
        if len(package.infolist()) > MAX_FILES:
            raise ValueError("archive has too many entries")
        for member in package.infolist():
            if member.is_dir():
                continue
            full = relative(member.filename)
            if prefix:
                if not full.startswith(prefix):
                    continue
                full = relative(full[len(prefix):])
            if wheel and any(part.endswith(".data") for part in full.split("/")):
                raise ValueError("wheel needs an unsupported installation scheme")
            mode = member.external_attr >> 16
            if stat.S_ISLNK(mode) or (stat.S_IFMT(mode) not in {0, stat.S_IFREG}):
                raise ValueError("nonregular archive member")
            total += member.file_size
            if (member.file_size > MAX_FILE_BYTES or total > 512 * MIB
                    or full.casefold() in seen):
                raise ValueError("archive bound or alias")
            seen.add(full.casefold())
            target = root / full
            target.parent.mkdir(parents=True, exist_ok=True)
            plain(target.parent)
            with package.open(member) as source, target.open("xb") as dest:
                remaining = member.file_size
                while block := source.read(MIB):
                    remaining -= len(block)
                    if remaining < 0:
                        raise ValueError("archive size differs")
                    dest.write(block)
                if remaining:
                    raise ValueError("incomplete archive member")


def preserve_parts(archive: Path, name: str, out: Path) -> dict:
    chunks = []
    whole = hashlib.sha256()
    with archive.open("rb") as stream:
        index = 0
        while block := stream.read(CHUNK_BYTES):
            filename = f"{name}-{index:04d}.zip.part"
            with (out / filename).open("xb") as dest:
                dest.write(block)
            whole.update(block)
            chunks.append({"path": filename, "bytes": len(block), "sha256": digest(block)})
            index += 1
    return {"archive_sha256": whole.hexdigest(),
              "chunks": chunks, "raw_zip_bytes": archive.stat().st_size,
              "reassembly": "ordered byte concatenation; do not decode"}


def seal(root: Path, name: str, work: Path, out: Path, *, limit: int,
         file_limit: int = MAX_FILE_BYTES, file_count: int = MAX_FILES) -> dict:
    before = inventory(root, limit=limit, file_limit=file_limit, file_count=file_count)
    write_json(out / (name + "-files.json"), before)
    archive = work / (name + ".zip")
    with zipfile.ZipFile(archive, "x", compression=zipfile.ZIP_DEFLATED,
                         compresslevel=6) as package:
        for ref in before:
            info = zipfile.ZipInfo(ref, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            package.writestr(info, (root / ref).read_bytes())
    restored = work / ("restore-" + name)
    unpack(archive, restored)
    if (inventory(restored, limit=limit, file_limit=file_limit, file_count=file_count) != before
            or inventory(root, limit=limit, file_limit=file_limit, file_count=file_count) != before):
        raise ValueError("restored or source installation differs from full snapshot")
    result = {"files_sha256": digest(canonical(before)), **preserve_parts(archive, name, out),
              "restore_equals_full_source": True}
    write_json(out / (name + "-archive.json"), result)
    return result


def main() -> int:
    keys = ("EC_WORKLOAD_SOURCE", "EC_WORKLOAD_OUT", "EC_WORKLOAD_WORK", "EC_WORKLOAD_SHA")
    if any(not os.environ.get(key) for key in keys):
        raise RuntimeError("approved EC dispatch required")
    if (os.environ.get("EC_WORKLOAD_REPOSITORY") != "taipei49314/smallestlie"
            or os.environ.get("EC_WORKLOAD_NAME") != NAME
            or Path(os.environ["EC_WORKLOAD_SOURCE"]).resolve() != ROOT
            or platform.node().upper() != HOST or os.environ.get("COMPUTERNAME", "").upper() != HOST
            or sys.platform != "win32" or sys.version_info[:3] != (3, 12, 10)
            or platform.machine().lower() not in {"amd64", "x86_64"}
            or os.environ.get("EC_WORKLOAD_MODE") != "single"
            or not re.fullmatch("[0-9a-f]{40}", os.environ["EC_WORKLOAD_SHA"])):
        raise RuntimeError("unexpected source, host, runtime or workload")
    work = Path(os.environ["EC_WORKLOAD_WORK"]).resolve() / "w3-freeze"
    out = Path(os.environ["EC_WORKLOAD_OUT"]).resolve() / "w3-freeze"
    for path in (ROOT, work.parent, out.parent):
        plain(path)
    if any(a.is_relative_to(b) or b.is_relative_to(a) for a, b in
           ((ROOT, work), (ROOT, out), (work, out))):
        raise RuntimeError("overlapping roots")
    work.mkdir(exist_ok=False)
    out.mkdir(exist_ok=False)
    downloads: list[dict] = []
    original_archives: dict = {}
    steps: list[dict] = []
    images: dict = {}
    problems: list[str] = []
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("GIT_", "NPM_", "npm_", "NODE_", "PYTHON", "PYTEST", "EC_WORKLOAD_"))}
    env.update(PYTHONUTF8="1", PYTHONDONTWRITEBYTECODE="1",
               HOME=str(work), USERPROFILE=str(work), APPDATA=str(work / "appdata"),
               LOCALAPPDATA=str(work / "localappdata"), TEMP=str(work / "tmp"), TMP=str(work / "tmp"))
    for name in ("appdata", "localappdata", "tmp"):
        (work / name).mkdir()

    def run(name: str, argv: list[str], cwd: Path, timeout: int) -> bytes:
        started = time.monotonic()
        process = subprocess.Popen(argv, cwd=cwd, env=env, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, creationflags=subprocess.CREATE_NO_WINDOW)
        timed_out = False
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            stdout, stderr = exc.stdout or b"", exc.stderr or b""
            taskkill = Path(os.environ["SystemRoot"]) / "System32" / "taskkill.exe"
            try:
                killed = subprocess.run([str(taskkill), "/PID", str(process.pid), "/T", "/F"],
                                        capture_output=True, timeout=15, check=False,
                                        creationflags=subprocess.CREATE_NO_WINDOW)
                (out / (name + "-taskkill.stdout")).write_bytes(killed.stdout)
                (out / (name + "-taskkill.stderr")).write_bytes(killed.stderr)
                stdout, stderr = process.communicate(timeout=10)
            except (OSError, subprocess.TimeoutExpired):
                if process.poll() is None:
                    process.kill()
        (out / (name + ".stdout")).write_bytes(stdout)
        (out / (name + ".stderr")).write_bytes(stderr)
        steps.append({"name": name, "argv": argv, "cwd": str(cwd), "exit_code": process.returncode,
                      "timed_out": timed_out,
                      "elapsed_seconds": round(time.monotonic() - started, 3),
                      "stdout_sha256": digest(stdout), "stderr_sha256": digest(stderr)})
        if timed_out or process.returncode or len(stdout) + len(stderr) > 4 * MIB:
            raise RuntimeError("preparation child failed or log bound exceeded")
        return stdout

    def source_check(label: str) -> None:
        head = run(label + "-head", ["git", "-c", "core.hooksPath=NUL", "rev-parse", "HEAD"], ROOT, 30)
        status = run(label + "-status", ["git", "-c", "core.hooksPath=NUL",
                                      "status", "--porcelain", "-z"], ROOT, 30)
        if head.decode("ascii").strip() != os.environ["EC_WORKLOAD_SHA"] or status:
            raise RuntimeError("source changed or dirty")

    try:
        source_check("initial")
        lock = (ROOT / "uv.lock").read_bytes()
        (out / "python-input-uv.lock").write_bytes(lock)
        packages = tomllib.loads(lock.decode("utf-8"))["package"]
        selected = [p for p in packages if p["name"] in PY_DEPS]
        if len(selected) != len(PY_DEPS) or {p["name"] for p in selected} != PY_DEPS:
            raise ValueError("Python input lock lacks exact package set")
        archives = work / "archives"
        archives.mkdir()
        py_archive, node_archive = archives / "python.nupkg", archives / "node.zip"
        download(PYTHON["url"], PYTHON["sha256"], py_archive, downloads)
        download(NODE["url"], NODE["sha256"], node_archive, downloads)
        original_archives["python-download"] = preserve_parts(py_archive, "python-download", out)
        original_archives["node-download"] = preserve_parts(node_archive, "node-download", out)
        pyroot, noderoot, jsroot = work / "python", work / "node", work / "js"
        unpack(py_archive, pyroot, prefix="tools/")
        unpack(node_archive, noderoot, prefix="node-v24.19.0-win-x64/")
        wheels = []
        for p in sorted(selected, key=lambda p: p["name"]):
            suffix = "-cp312-cp312-win_amd64.whl" if p["name"] == "pyyaml" else "-none-any.whl"
            compatible = [w for w in p["wheels"] if w["url"].endswith(suffix)]
            if len(compatible) != 1:
                raise ValueError("ambiguous compatible locked wheel")
            w = compatible[0]
            wheel = archives / (p["name"] + ".whl")
            download(w["url"], w["hash"].removeprefix("sha256:"), wheel, downloads)
            original_archives[p["name"] + "-wheel"] = preserve_parts(wheel, p["name"] + "-wheel", out)
            unpack(wheel, pyroot / "Lib" / "site-packages", wheel=True)
            wheels.append({"name": p["name"], "version": p["version"], **w})
        write_json(out / "python-wheels.json", wheels)
        node = noderoot / "node.exe"
        if digest(node.read_bytes()) != NODE["executable_sha256"]:
            raise ValueError("actual Node executable differs from published identity")
        if run("node-version", [str(node), "--version"], work, 30).decode("ascii").strip() != "v24.19.0":
            raise ValueError("actual Node version differs")
        jsroot.mkdir()
        write_json(jsroot / "package.json", {"name": "smallestlie-w3-runners", "version": "1.0.0",
                                           "private": True, "dependencies": JS_DEPS})
        user_config, global_config = work / "user.npmrc", work / "global.npmrc"
        user_config.write_bytes(b"")
        global_config.write_bytes(b"")
        npm = [str(node), str(noderoot / "node_modules/npm/bin/npm-cli.js")]
        flags = ["--ignore-scripts", "--no-audit", "--no-fund", "--fetch-retries=0",
                 "--registry=https://registry.npmjs.org", "--cache=" + str(work / "npm-cache"),
                 "--userconfig=" + str(user_config), "--globalconfig=" + str(global_config)]
        run("npm-lock", [*npm, "install", "--package-lock-only", *flags], jsroot, 240)
        jslock = json.loads((jsroot / "package-lock.json").read_bytes())
        for ref, item in jslock["packages"].items():
            if ref and ("integrity" not in item or not item.get("resolved", "").startswith(
                    "https://registry.npmjs.org/")):
                raise ValueError("npm lock has an unbound or external package")
        run("npm-ci", [*npm, "ci", *flags], jsroot, 360)
        for name, version in JS_DEPS.items():
            item = json.loads((jsroot / "node_modules" / name / "package.json").read_bytes())
            if item["name"] != name or item["version"] != version:
                raise ValueError("installed JS runner version differs")
        (out / "js-package.json").write_bytes((jsroot / "package.json").read_bytes())
        (out / "js-package-lock.json").write_bytes((jsroot / "package-lock.json").read_bytes())
        probe = work / "python-identity.py"
        probe.write_text(
            "import importlib.metadata,json,platform,sys\n"
            "print(json.dumps({'executable':sys.executable,'prefix':sys.prefix,"
            "'base_prefix':sys.base_prefix,'version':list(sys.version_info[:3]),"
            "'machine':platform.machine(),'pytest':importlib.metadata.version('pytest')},sort_keys=True))\n",
            encoding="utf-8", newline="\n")
        py_identity = json.loads(run("python-identity", [str(pyroot / "python.exe"), "-I", "-B",
                                    str(probe)], work, 30))
        if (py_identity["version"] != [3, 12, 10] or py_identity["pytest"] != "9.1.1"
                or Path(py_identity["prefix"]).resolve() != pyroot):
            raise ValueError("actual Python installation or distribution differs")
        write_json(out / "python-identity.json", py_identity)
        images["python"] = seal(pyroot, "python", work, out, limit=100_000_000,
                                file_limit=10_000_000, file_count=20_000)
        images["node"] = seal(noderoot, "node", work, out, limit=256 * MIB)
        images["js"] = seal(jsroot, "js", work, out, limit=512 * MIB)
        pymaps = {p: inventory(pyroot / "Lib/site-packages" / p, limit=100_000_000,
                              file_limit=10_000_000, file_count=20_000)
                  for p in ("pytest", "_pytest")}
        write_json(out / "pytest-package-files.json", pymaps)
        js_runner_maps = {p: inventory(jsroot / "node_modules" / p, limit=512 * MIB)
                          for p in ("mocha", "vitest")}
        write_json(out / "js-runner-package-files.json", js_runner_maps)
        full_python = json.loads((out / "python-files.json").read_bytes())
        full_js = json.loads((out / "js-files.json").read_bytes())
        for name, measured in pymaps.items():
            prefix = "Lib/site-packages/" + name + "/"
            if measured != {p.removeprefix(prefix): h for p, h in full_python.items() if p.startswith(prefix)}:
                raise ValueError("pytest package snapshot differs from sealed full prefix")
        for name, measured in js_runner_maps.items():
            prefix = "node_modules/" + name + "/"
            if measured != {p.removeprefix(prefix): h for p, h in full_js.items() if p.startswith(prefix)}:
                raise ValueError("JS runner snapshot differs from sealed full installation")
        for name, root, limit, file_limit, file_count in (
                ("python", pyroot, 100_000_000, 10_000_000, 20_000),
                ("node", noderoot, 256 * MIB, MAX_FILE_BYTES, MAX_FILES),
                ("js", jsroot, 512 * MIB, MAX_FILE_BYTES, MAX_FILES)):
            if digest(canonical(inventory(root, limit=limit, file_limit=file_limit,
                                         file_count=file_count))) != images[name]["files_sha256"]:
                raise ValueError("final installation closure changed")
        images["profile_inputs"] = {
            "python_runtime_sha256": digest((pyroot / "python.exe").read_bytes()),
            "pytest_runner_sha256": digest(canonical(pymaps)),
            "python_installed_sha256": images["python"]["files_sha256"],
            "node_runtime_sha256": digest(node.read_bytes()),
            "mocha_runner_sha256": digest(canonical(js_runner_maps["mocha"])),
            "vitest_runner_sha256": digest(canonical(js_runner_maps["vitest"])),
            "js_installed_sha256": images["js"]["files_sha256"],
        }
    except Exception as exc:
        problems.append(type(exc).__name__ + ": " + str(exc))
    try:
        source_check("final")
    except Exception as exc:
        problems.append("final-source: " + type(exc).__name__ + ": " + str(exc))
    result = {"schema_version": 1, "workload": NAME, "source_commit": os.environ["EC_WORKLOAD_SHA"],
              "host": HOST, "downloads": downloads, "steps": steps, "images": images,
              "original_archives": original_archives,
              "complete": not problems, "problems": problems, "case_execution": "NOT_RUN",
              "formal_phase1_approval": False, "collector_or_runner_adoption": False}
    write_json(out / "preparation.json", result)
    (out.parent / "SUMMARY.md").write_text(
        "# W3 installation preparation\n\n"
        + ("COMPLETE" if not problems else "INCOMPLETE") + ": sealed preparation inputs only.\n\n"
        + "Case/verifier execution: NOT_RUN. No Phase1 approval or external adoption.\n"
        + "\n".join("- " + p for p in problems) + "\n",
        encoding="utf-8", newline="\n")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
