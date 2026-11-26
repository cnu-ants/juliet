#!/usr/bin/env python3
"""Analyze six Juliet CWEs and automatically export compact, validated results.

Put this SINGLE file beside testcases/ and testcasesupport/:
    python3 analyze_juliet.py --jobs 4
Edit VERSION and IKOS below. Only the CWE checker(s) are selected; other IKOS
analysis options stay at defaults. Each program's entry is its original main.
Each goodG2B/goodB2G/good1/bad driver is one testcase, excluding good dispatchers.

Successful output in JULIET_ROOT/results/VERSION/: summary.csv + details.json.gz.
The script stays beside testcases/; --root selects that Juliet root.
Archive: original commands/settings, source hashes, testcase functions/statuses,
target FP/TP messages and exact sites, FN expected manifest sites and functions.
Counts are verified against summary.csv before temporary SQLite/CSVs are removed.
Unfinished/failed runs retain the cache in results/VERSION/ for resuming the same command.
Do not commit an unfinished results/VERSION folder. Completed VERSIONs are not rerun;
choose a new VERSION for new code/tool/settings. Raw temporary bitcode is removed.

--list: inventory only, no analysis or source changes.
--summary-only results/VERSION/: print a readable table and optionally save summary.html.
--compact-only OLD_VERSION/: compact existing results without reanalysis;
    default output is JULIET_ROOT/results/OLD_VERSION/; originals are preserved.
    --output PATH changes this export destination.

FP/FN are Juliet-label candidates for the target subtype, not independent proofs.
Failed analyses are separate from FN; no-check/unreachable FN subsets are explicit.
Safe locations were not retained individually: per-testcase check counts are kept.
Native implementation definitions alone do not establish checker reachability.
FN locations refer to Juliet expected flaws, not emitted analyzer diagnostics.
Source Warning/Error comments use /* ikos: warning: ... */ with no version tag.
An unchanged diagnostic leaves its existing canonical comment byte-identical.
A disappearing diagnostic removes the managed comment after successful analysis.
File ownership/mode are preserved. VERSION names result folders only.
"""

import os

# ======================== EDIT THESE SETTINGS ========================
VERSION = os.environ.get("IKOS_VERSION", "v3.5.3")                 # Result directory only; source comments never include VERSION.
IKOS = "ikos"                      # Or an absolute path, e.g. /opt/ikos/bin/ikos.
JOBS = 1                           # Independent processes; not IKOS's -j option.
TIMEOUT_SECONDS = None             # External wall timeout; None leaves it unlimited.
# ====================================================================

import argparse
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
import csv
import hashlib
import gzip
import importlib
import json
from pathlib import Path
import re
import shlex
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import xml.etree.ElementTree as ET

CHECKERS = {
    126: ("CWE126_Buffer_Overread", "boa"),
    190: ("CWE190_Integer_Overflow", "sio,uio"),
    369: ("CWE369_Divide_by_Zero", "dbz"),
    415: ("CWE415_Double_Free", "dfa"),
    457: ("CWE457_Use_of_Uninitialized_Variable", "uva"),
    476: ("CWE476_NULL_Pointer_Dereference", "nullity"),
}
CODE_EXT = {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp"}
SOURCE_EXT = {".c", ".cpp", ".cc", ".cxx"}
MANAGED = re.compile(r"/\*\s*ikos(?:\[[^\]\r\n]*\])?\s*:[\s\S]*?\*/", re.I)
LEX = re.compile(
    r'/\*.*?\*/|//[^\n]*|'
    r'(?:u8|u|U|L)?R"(?P<ikos_raw_delim>[^\s()\\]{0,16})\(.*?\)(?P=ikos_raw_delim)"|'
    r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', re.S)
STOP = threading.Event()
ACTIVE = set()
ACTIVE_LOCK = threading.Lock()
RUNTIME = None


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_text(path):
    return path.read_bytes().decode("utf-8", errors="surrogateescape")


def clean_annotations(text):
    # Preserve physical line numbers, including any old multiline managed comment.
    return LEX.sub(lambda m: "".join(re.findall(r"\r\n|\r|\n", m[0]))
                   if m[0].startswith("/*") and MANAGED.fullmatch(m[0])
                   else MANAGED.sub("", m[0]) if m[0].startswith("//") else m[0], text)


def semantic_bytes(path):
    return clean_annotations(read_text(path)).encode("utf-8", errors="surrogateescape")


def save_json(path, value):
    temp = path.with_name(path.name + ".tmp")
    temp.write_text(json.dumps(value, ensure_ascii=True, indent=2) + "\n")
    output_owner(temp,path.parent)
    temp.replace(path)


def write_csv(path, fields, rows):
    temp = path.with_name(path.name + ".tmp")
    with temp.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({k: json.dumps(v, ensure_ascii=False) if isinstance(v, (list, dict)) else v
                             for k, v in row.items() if k in fields})
    output_owner(temp,path.parent)
    temp.replace(path)


def cwe_number(name):
    match = re.match(r"CWE(\d+)_", Path(name).name)
    return int(match[1]) if match else None


def case_key(name):
    stem = Path(name).stem
    match = re.match(r"^(CWE\d+_.*_\d\d)(?:[a-z]|_(?:bad|good)[A-Za-z0-9]*)?$", stem)
    return match[1] if match else stem


def masked(text):
    return LEX.sub(lambda m: re.sub(r"[^\r\n]", " ", m[0]), text)


def source_functions(text):
    """Lexical definition inventory; compiled/native names are added from each run."""
    import bisect
    code = masked(text)
    offsets = [0] + [m.end() for m in re.finditer("\n", code)]
    code = re.sub(r"^[ \t]*#[^\n]*", lambda m: " " * len(m[0]), code, flags=re.M)
    brackets, stack = {}, []
    for m in re.finditer(r"[{}]", code):
        if m[0] == "{":
            stack.append(m.start())
        elif stack:
            brackets[stack.pop()] = m.start()
    definitions = []
    sig = re.compile(r"([~\w:]+)\s*\([^;{}]*\)\s*(?:const\s*)?(?:noexcept\s*)?(?::[^;{}]*)?\{")
    for m in sig.finditer(code):
        if m[1] in {"if", "for", "while", "switch", "catch", "sizeof", "alignof"}:
            continue
        start = m.end() - 1
        if start not in brackets:
            continue
        definitions.append(dict(name=m[1], line=bisect.bisect_right(offsets, m.start()),
                                end_line=bisect.bisect_right(offsets, brackets[start])))
    return definitions


def scan_inventory(root):
    """Use manifest AND filesystem. Deleted nonselected CWEs do not cause failures."""
    inventory, by_name = {}, defaultdict(list)
    for n, (directory, _) in CHECKERS.items():
        folder = root / "testcases" / directory
        if not folder.is_dir():
            raise ValueError("Required CWE directory is missing: " + str(folder))
        for path in sorted(folder.rglob("*")):
            if path.is_file() and path.suffix.lower() in CODE_EXT:
                rel = str(path.relative_to(root))
                content = semantic_bytes(path)
                inventory[rel] = dict(path=rel, cwe=n, sha256=digest(content),
                    kind="test_source" if path.suffix.lower() in SOURCE_EXT and path.name.startswith("CWE")
                         else "header" if path.suffix.lower() not in SOURCE_EXT else "aggregate_driver",
                    functions=source_functions(content.decode("utf-8", errors="surrogateescape")))
                by_name[path.name].append(rel)
    units = []
    manifest = root / "manifest.xml"
    used = Counter()
    if manifest.is_file():
        for index, (_, tc) in enumerate(ET.iterparse(manifest, events=("end",)), 1):
            if tc.tag != "testcase":
                continue
            refs = tc.findall("file")
            ns = {cwe_number(f.attrib.get("path", "")) for f in refs} & set(CHECKERS)
            if not ns:
                tc.clear()
                continue
            if len(ns) != 1:
                raise ValueError("Mixed selected CWEs in one manifest testcase")
            n = ns.pop()
            files, missing, flaws = [], [], []
            for f in refs:
                ref = f.attrib["path"]
                hits = by_name.get(Path(ref).name, [])
                if len(hits) > 1:
                    raise ValueError("Ambiguous manifest source: " + ref)
                path = hits[0] if hits else "testcases/" + CHECKERS[n][0] + "/" + Path(ref).name
                if not hits:
                    missing.append(path)
                else:
                    files.append(path)
                    used[path] += 1
                for flaw in f.findall("flaw"):
                    flaws.append(dict(path=path, line=int(flaw.attrib["line"]), name=flaw.attrib.get("name", "")))
            sources = [p for p in files if Path(p).suffix.lower() in SOURCE_EXT]
            # A missing-only testcase is still scheduled and reported as unavailable.
            if not sources and not any(Path(p).suffix.lower() in SOURCE_EXT for p in missing):
                tc.clear()
                continue
            key = case_key(next((f.attrib["path"] for f in refs if cwe_number(f.attrib["path"]) == n), refs[0].attrib["path"]))
            units.append(dict(id="manifest:" + key, name=key, cwe=n, files=files, sources=sources,
                              missing=missing, flaws=flaws, inventory_method="manifest"))
            tc.clear()
    # New source files absent from a stale manifest are not silently dropped.
    orphan = [r for r in inventory.values() if r["kind"] == "test_source" and not used[r["path"]]]
    fallback = defaultdict(list)
    for r in orphan:
        fallback[(r["cwe"], str(Path(r["path"]).parent), case_key(r["path"]))].append(r["path"])
    for (n, parent, key), sources in sorted(fallback.items()):
        files = sorted(sources + [r["path"] for r in inventory.values()
                                 if r["kind"] == "header" and str(Path(r["path"]).parent) == parent
                                 and case_key(r["path"]) == key and not used[r["path"]]])
        units.append(dict(id="filesystem:" + parent + "/" + key, name=key, cwe=n, files=files,
                          sources=sorted(sources), missing=[], flaws=[], inventory_method="filesystem"))
        used.update(files)
    duplicates = [p for p, count in used.items() if count != 1 and inventory[p]["kind"] == "test_source"]
    if duplicates:
        raise ValueError("Test sources assigned more than once: " + repr(duplicates))
    expected = {p for p, r in inventory.items() if r["kind"] == "test_source"}
    assigned = [p for u in units for p in u["sources"]]
    if set(assigned) != expected or len(assigned) != len(expected):
        raise ValueError("Test source coverage mismatch")
    if len({u["id"] for u in units}) != len(units):
        raise ValueError("Duplicate testcase names in manifest")
    for u in units:
        mains = [s for s in u["sources"] if re.search(r"\bint\s+main\s*\(", masked(clean_annotations(read_text(root / s))))]
        u["variant_sources"] = {}
        for role in ("good", "bad"):
            sources = u["sources"]
            if len(mains) > 1:
                sources = [s for s in sources if re.search(r"_" + role + r"\d*\.(?:c|cpp|cc|cxx)$", s)]
                if len(sources) != 1:
                    raise ValueError("Cannot separate standalone good/bad pair: " + u["name"])
            u["variant_sources"][role] = sources
        if set(sum(u["variant_sources"].values(), [])) != set(u["sources"]):
            raise ValueError("Variant source coverage mismatch: " + u["name"])
    if not units:
        raise ValueError("No Juliet testcases found")
    return sorted(units, key=lambda u: (u["cwe"], u["name"])), inventory


def find_ikos(value):
    result = shutil.which(value) if not Path(value).is_file() else str(Path(value).resolve())
    if not result:
        raise ValueError("IKOS not found. Set IKOS at the top of this script, or use --ikos PATH")
    return Path(result).resolve()


def import_runtime(ikos):
    """Use the selected installation's Python/modules, not an unrelated system IKOS."""
    global RUNTIME
    candidates = [ikos.parent.parent / "libexec" / "bin" / "python"]
    try:
        head = ikos.open("rb").readline(4096).decode().strip()
        if head.startswith("#!"):
            words = shlex.split(head[2:])
            if words and Path(words[0]).name == "env" and len(words) > 1:
                executable = shutil.which(words[1])
                if executable:
                    candidates.insert(0, Path(executable))
            elif words:
                candidates.insert(0, Path(words[0]))
    except (UnicodeError, OSError):
        pass
    guard = os.environ.get("JULIET_IKOS_REEXEC")
    for py in candidates:
        if py.is_file() and "python" in py.name:
            if os.path.abspath(sys.executable) != os.path.abspath(str(py)) and not guard:
                env = os.environ.copy()
                env["JULIET_IKOS_REEXEC"] = str(ikos)
                os.execve(str(py), [str(py), str(Path(__file__).resolve()), *sys.argv[1:]], env)
            break
    try:
        from ikos import analyzer, report, colors
        from ikos.output_db import OutputDatabase
        colors.setup("no")
        RUNTIME = (analyzer, report, OutputDatabase)
    except ImportError as error:
        raise ValueError("Cannot import this IKOS installation's Python modules. Run with its Python interpreter: " + str(error))


def capture(command):
    return subprocess.check_output([str(x) for x in command], text=True, stderr=subprocess.STDOUT).strip()


def tools_config(ikos):
    config = ikos.parent / "ikos-config"
    if not config.is_file():
        raise ValueError("ikos-config must be next to the selected ikos executable")
    tools = {key: capture([config, "--" + key]) for key in ("clang", "llvm-bindir", "includedir")}
    tools.update(ikos=str(ikos), version=capture([ikos, "--version"]).splitlines()[0])
    for tool in [Path(tools["clang"]), Path(tools["llvm-bindir"]) / "llvm-link", Path(tools["llvm-bindir"]) / "llvm-nm"]:
        if not tool.is_file():
            raise ValueError("IKOS-config tool is unavailable: " + str(tool))
    tools["binary_hashes"] = {str(p): digest(p.read_bytes()) for p in
                              [ikos, ikos.parent / "ikos-analyzer", ikos.parent / "ikos-pp", Path(tools["clang"])] if p.is_file()}
    analyzer = RUNTIME[0]
    tools["compile_flags"] = [*analyzer.clang_emit_llvm_flags(), *analyzer.clang_ikos_flags()]
    return tools


def invoke(command, folder, timeout):
    command = [str(x) for x in command]
    if STOP.is_set():
        return dict(status="interrupted", command=command, output="", returncode=None)
    proc = subprocess.Popen(command, cwd=folder, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            start_new_session=(os.name == "posix"))
    with ACTIVE_LOCK:
        ACTIVE.add(proc)
    try:
        output, _ = proc.communicate(timeout=timeout)
        status = "ok" if proc.returncode == 0 else "failed"
    except subprocess.TimeoutExpired:
        if os.name == "posix":
            os.killpg(proc.pid, signal.SIGKILL)
        else:
            proc.kill()
        output, _ = proc.communicate()
        status = "timeout"
    finally:
        with ACTIVE_LOCK:
            ACTIVE.discard(proc)
    if STOP.is_set():
        status = "interrupted"
    return dict(status=status, command=command, output=output.decode("utf-8", errors="replace"), returncode=proc.returncode)


def compile_cmd(source, target, role, tools, snapshot, include_main=True):
    command = [tools["clang"], *tools["compile_flags"], str(source), "-o", str(target),
               "-isystem", tools["includedir"], "-I" + str(snapshot / "testcasesupport")]
    if include_main:
        command += ["-DINCLUDEMAIN", "-DOMITBAD" if role == "good" else "-DOMITGOOD"]
    # No optimization/procedural/domain/entry-point options are added to IKOS.
    # Do not force a C++ language standard: use the installation's compiler default.
    return command


def scenario_functions(unit, root):
    """A zero-argument goodG2B/goodB2G/good1/bad driver is one testcase.

    Sink/Source functions and constructors are implementation details. The outer
    good() dispatcher is counted only when it implements the scenario itself.
    """
    result = []
    for rel in unit['sources']:
        text = clean_annotations(read_text(root / rel))
        code = masked(text)
        lines = code.splitlines()
        for fn in source_functions(text):
            name = fn['name'].split('::')[-1]
            role = ('good' if re.fullmatch(r'(?:CWE\w+_)?good(?:G2B\d*|B2G\d*|\d*)', name)
                    else 'bad' if re.fullmatch(r'(?:CWE\w+_)?bad', name) else None)
            if not role:
                continue
            excerpt = '\n'.join(lines[fn['line']-1:fn['end_line']])
            sig = re.search(r'\b' + re.escape(name) + r'\s*\(([^)]*)\)', excerpt)
            if not sig or sig[1].strip() not in ('', 'void'):
                continue
            body = excerpt[excerpt.find('{') + 1:]
            dispatch = bool(re.search(r'\bgood(?:G2B\d*|B2G\d*|\d+)\s*\(', body))
            if role == 'good' and (name == 'good' or name.endswith('_good')) and dispatch:
                continue
            result.append(dict(id=unit['id'] + ':' + rel + ':' + str(fn['line']),
                               name=fn['name'], path=rel, line=fn['line'], end_line=fn['end_line'], role=role))
    roles = {s['role'] for s in result}
    if roles != {'good', 'bad'} and not unit['missing']:
        raise ValueError('Cannot enumerate both good and bad scenario functions: ' + unit['name'] + ' ' + repr(result))
    return result


def program_plan(units, root):
    programs = []
    for unit in units:
        scenarios = scenario_functions(unit, root)
        if unit['variant_sources']['good'] == unit['variant_sources']['bad']:
            programs.append(dict(unit, program_id=unit['id'], scenarios=scenarios))
        else:
            for role in ('good', 'bad'):
                sources = unit['variant_sources'][role]
                programs.append(dict(unit, program_id=unit['id'] + ':' + role, sources=sources,
                                     scenarios=[s for s in scenarios if s['role'] == role]))
    return programs


def short_message(message):
    text = ' '.join(message.split())
    quoted = False
    for i, ch in enumerate(text):
        if ch == "'":
            quoted = not quoted
        if (ch == ',' or text[i:i+2] == ' (') and not quoted:
            return text[:i].strip()
    return text


def relative_source(path, snapshot):
    if not path:
        return ''
    try:
        return str(Path(path).resolve().relative_to(snapshot.resolve()))
    except ValueError:
        return str(path)


def find_scenario(path, line, function, scenarios):
    exact = [s for s in scenarios if path == s['path'] and line and s['line'] <= line <= s['end_line']]
    if len(exact) == 1:
        return exact[0]['id']
    # Native C++ names include namespaces and argument lists.
    simple = function.split('(')[0].split('::')[-1]
    hits = [s for s in scenarios if s['name'].split('::')[-1] == simple and path == s['path']]
    return hits[0]['id'] if len(hits) == 1 else None


def context_frames(context, snapshot):
    frames = []
    while not context.empty():
        call = context.call()
        frames.append(dict(path=relative_source(call.file_path(), snapshot), line=call.line,
                           column=call.column, function=call.function().pretty_name()))
        context = context.parent()
    return frames


def attribution(path, line, function, frames, scenarios):
    direct = find_scenario(path, line, function, scenarios)
    if direct:
        return direct
    for frame in frames:   # innermost caller first
        hit = find_scenario(frame['path'], frame['line'], frame['function'], scenarios)
        if hit:
            return hit
    return None


def target_match(n, kind, status, message, path, line, column, snapshot, frames):
    """Filter defect subtype as well as checker. Preserve every rejection reason."""
    allowed = {126: {22}, 190: {7, 8, 9, 10}, 369: {4}, 415: {39}, 457: {2}, 476: {12}}
    if kind not in allowed[n]:
        return False, 'other_defect_kind'
    if not path.startswith(('testcases/', 'testcasesupport/')):
        return False, 'library_internal_not_tested_sink'
    sites = [dict(path=path, line=line, column=column)] + frames
    site = next((s for s in sites if s['path'].startswith('testcases/') and s['line']), None)
    if not site:
        return False, 'outside_testcase_sink'
    try:
        raw = read_text(snapshot / site['path']).splitlines()[site['line']-1]
    except (OSError, IndexError):
        return False, 'source_unavailable'
    code = masked(raw)
    if n == 415:
        if status in (1, 2) and 'double free' not in message:
            return False, 'deallocation_error_is_not_double_free'
        return bool(re.search(r'\bfree\s*\(|\bdelete\b', code)), 'double_free_sink'
    if n == 126:
        if status in (1, 2) and not re.match(r'^(?:possible )?buffer overflow(?:,|$)', message):
            return False, 'not_explicit_buffer_bounds'
        if re.search(r'\bmem(?:cpy|move)\s*\(\s*dest\s*,\s*data\b', code):
            if re.search(r"(?:pointer|variable) '[^']*\bdest\b[^']*'", message):
                return False, 'destination_write'
            return True, 'copy_source_read'
        if re.search(r'\bdest\s*\[[^]]+\]\s*=\s*data\s*\[', code):
            if site['column'] and site['column'] < code.index('=') + 1:
                return False, 'destination_write'
            if re.search(r"(?:pointer|variable) '[^']*\bdest\b[^']*'", message):
                return False, 'destination_write'
            return True, 'loop_source_read'
        if re.search(r'\b(?:printIntLine|printf)\s*\([^;]*buffer\s*\[', code):
            return True, 'indexed_read'
        if re.search(r'\b(?:print(?:W)?Line|puts|wprintf|printf)\s*\([^;]*\b(?:data|dest)\b', code):
            return True, 'string_read'
        return False, 'unrecognized_read_site_review_required'
    if n == 190:
        return bool(re.search(r'\bdata\w*\b', code) and not code.lstrip().startswith('for')), 'tested_integer_operation'
    if n == 369:
        return bool(re.search(r'\bdata\w*\b', code) and re.search(r'[/%%]', code)), 'tested_division'
    if n == 457:
        return bool(re.search(r'\b(?:data\w*|(?:bad|good)ClassObject\w*|intOne|intTwo)\b', code)
                    and not code.lstrip().startswith('for')), 'tested_initialization_read'
    if re.search(r'__(?:stdinp|stdoutp|stderrp)', message):
        return False, 'stdio_global_not_tested_pointer'
    return bool(re.search(r'\b(?:data\w*|intPointer|twoIntsStructPointer)\b', code)), 'tested_null_dereference'


def collect_result(db_path, program, snapshot):
    _, reporter, OutputDatabase = RUNTIME
    db = OutputDatabase(str(db_path))
    try:
        settings = db.load_settings()
        settings = json.loads(json.dumps(settings, default=lambda x: sorted(x) if isinstance(x, set) else str(x)))
        actual = set(settings.get('analyses', []))
        expected = set(CHECKERS[program['cwe']][1].split(','))
        if actual != expected:
            raise ValueError('Checker mismatch: expected %r, got %r' % (expected, actual))
        diagnostics, coverage, definitions = [], defaultdict(Counter), []
        for fn in db.functions:
            rel = relative_source(fn.file_path(), snapshot)
            if fn.definition and rel.startswith('testcases/'):
                definitions.append(dict(function=fn.pretty_name(), path=rel, line=fn.line))
        frame_cache, statement_cache = {}, {}
        def frames_for(context_id):
            if context_id not in frame_cache:
                frame_cache[context_id] = context_frames(db.call_contexts[context_id], snapshot)
            return frame_cache[context_id]
        for statement_id, context_id, status, count in db.con.execute(
                'SELECT statement_id,call_context_id,status,COUNT(*) FROM checks GROUP BY statement_id,call_context_id,status'):
            stmt = db.statements[statement_id]
            if statement_id not in statement_cache:
                statement_cache[statement_id] = (relative_source(stmt.file_path(), snapshot), stmt.line, stmt.function().pretty_name())
            sid = attribution(*statement_cache[statement_id], frames_for(context_id), program['scenarios'])
            if sid:
                coverage[sid][str(status)] += count
        for item in reporter.generate_report(db).statement_reports:
            if item.status not in (1, 2):
                continue
            stmt = item.statement()
            path, line, column = relative_source(stmt.file_path(), snapshot), stmt.line, stmt.column
            function = stmt.function().pretty_name()
            message = ' '.join(reporter.generate_message(item, 1).split())
            # One record per native report, attributed separately to each scenario.
            by_scenario = defaultdict(list)
            for ctx in item.call_contexts():
                frames = frames_for(ctx.id)
                sid = attribution(path, line, function, frames, program['scenarios'])
                by_scenario[sid].append(frames)
            for sid, stacks in by_scenario.items():
                matches = [target_match(program['cwe'], item.kind, item.status, message, path, line, column, snapshot, f) for f in stacks]
                keep, reason = next((m for m in matches if m[0]), matches[0])
                diagnostics.append(dict(scenario_id=sid or '', path=path, line=line, column=column, function=function,
                    kind=item.kind, status=item.status, severity='warning' if item.status == 1 else 'error',
                    message=message, short_message=short_message(message), target=bool(keep and sid),
                    target_reason=reason if sid else 'not_attributed_to_testcase', contexts=stacks))
        return dict(settings=settings, diagnostics=diagnostics, coverage={k: dict(v) for k,v in coverage.items()}, definitions=definitions)
    finally:
        db.con.close()


def run_program(program, snapshot, tools, support, timeout, work_root):
    start = time.monotonic()
    result = dict(program_id=program['program_id'], status='failed', stage='inputs', commands=[], log='',
                  diagnostics=[], coverage={}, definitions=[])
    def step(command, stage, folder):
        run = invoke(command, folder, timeout)
        result['commands'].append(run['command'])
        if run['status'] != 'ok':
            result.update(status=run['status'], stage=stage, log=run['output'], returncode=run['returncode'])
            return False
        return True
    try:
        if program['missing']:
            result['log'] = 'Missing selected input files: ' + repr(program['missing'])
            return result
        with tempfile.TemporaryDirectory(prefix='case-', dir=work_root) as folder:
            folder = Path(folder)
            objects = list(support)
            for i, rel in enumerate(program['sources']):
                target = folder / ('source%d.bc' % i)
                # main includes BOTH good and bad. Never define OMITGOOD/OMITBAD.
                command = compile_cmd(snapshot / rel, target, None, tools, snapshot, include_main=False) + ['-DINCLUDEMAIN']
                if not step(command, 'compile:' + rel, folder):
                    result['failed_source'] = rel
                    return result
                objects.append(target)
            linked = folder / 'program.bc'
            if not step([Path(tools['llvm-bindir']) / 'llvm-link', *objects, '-o', linked], 'link', folder):
                return result
            names = invoke([Path(tools['llvm-bindir']) / 'llvm-nm', '--defined-only', linked], folder, timeout)
            if names['status'] != 'ok' or not re.search(r'\b_?main\s*$', names['output'], re.M):
                result.update(stage='entry_main', log=names['output'] + '\nNo defined main found')
                return result
            database = folder / 'output.db'
            command = [tools['ikos'], linked, '-a=' + CHECKERS[program['cwe']][1], '-o', database,
                       '-f=no', '--color=no', '--progress=no']
            if not step(command, 'analysis', folder):
                return result
            result.update(collect_result(database, program, snapshot))
            result.update(status='ok', stage='complete')
    except Exception:
        result.update(stage='internal', log=traceback.format_exc())
    finally:
        result['seconds'] = round(time.monotonic() - start, 3)
    return result


def annotate_source(path, clean, messages):
    """Append block comments outside // and existing block comments; keep line count."""
    text = clean.decode('utf-8', errors='surrogateescape')
    lines = text.splitlines(keepends=True)
    # Token spans identify unsafe insertion points (e.g. a multi-line literal/comment).
    starts, offset = [], 0
    for line in lines:
        starts.append(offset)
        offset += len(line)
    spans = [(m.start(), m.end()) for m in LEX.finditer(text)]
    for number, entries in sorted(messages.items(), reverse=True):
        if not 1 <= number <= len(lines):
            raise ValueError('Diagnostic line outside source: ' + str(number))
        original = lines[number-1]
        ending = '\r\n' if original.endswith('\r\n') else '\n' if original.endswith('\n') else ''
        body = original[:-len(ending)] if ending else original
        # For a continued macro insert BEFORE the backslash.
        end = len(body.rstrip())
        if body[:end].endswith('\\'):
            end -= 1
        absolute = starts[number-1] + end
        for begin, finish in spans:
            if begin <= absolute < finish:
                token = text[begin:finish]
                if token.startswith('//') and begin >= starts[number-1]:
                    end = begin - starts[number-1]
                    break
                raise ValueError('Cannot annotate safely inside a multiline token at line ' + str(number))
        safe = [e.replace('*/', '* /').replace('\r', ' ').replace('\n', ' ') for e in sorted(set(entries))]
        comment = '/* ikos: ' + '; '.join(safe) + ' */'
        lines[number-1] = body[:end] + comment + body[end:] + ending
    updated = ''.join(lines).encode('utf-8', errors='surrogateescape')
    # A semantic comparison also catches accidental insertion within literals.
    if clean_annotations(updated.decode('utf-8', errors='surrogateescape')).strip() != text.strip():
        # Insertion adds whitespace only; compare token-masked non-whitespace text.
        if re.sub(r'\s+', '', clean_annotations(updated.decode('utf-8', errors='surrogateescape'))) != re.sub(r'\s+', '', text):
            raise ValueError('Annotation would change source tokens')
    if path.read_bytes() != updated:
        temp = path.with_name(path.name + '.ikos-tmp')
        original_stat=path.stat()
        try:
            temp.write_bytes(updated)
            current_stat=temp.stat()
            if hasattr(os,'chown') and (current_stat.st_uid,current_stat.st_gid)!=(original_stat.st_uid,original_stat.st_gid):
                os.chown(temp,original_stat.st_uid,original_stat.st_gid)
            shutil.copymode(path,temp)
            temp.replace(path)
        finally:
            if temp.exists(): temp.unlink()
    return 'updated' if updated != clean else 'clean_no_diagnostics'


def stop_children(signum=None, frame=None):
    STOP.set()
    with ACTIVE_LOCK:
        processes = list(ACTIVE)
    for process in processes:
        try:
            if os.name == 'posix':
                os.killpg(process.pid, signal.SIGTERM)
            else:
                process.terminate()
        except ProcessLookupError:
            pass


def refresh_annotations(root, snapshot, inventory, programs, results):
    required = defaultdict(set)
    messages = defaultdict(lambda: defaultdict(set))
    for p in programs:
        for rel in p['files']:
            if rel in inventory:
                required[rel].add(p['program_id'])
        for d in results.get(p['program_id'], {}).get('diagnostics', []):
            if d['path'] in inventory and d['line']:
                messages[d['path']][d['line']].add(d['severity'] + ': ' + d['short_message'])
    statuses, errors = {}, []
    for rel in inventory:
        if inventory[rel]['kind'] == 'aggregate_driver':
            statuses[rel] = 'aggregate_driver_not_edited'
            continue
        deps = required[rel]
        if not deps:
            # Unowned headers may be used by any testcase within the CWE.
            deps = {p['program_id'] for p in programs if p['cwe'] == inventory[rel]['cwe']}
        if not deps or any(results.get(pid, {}).get('status') != 'ok' for pid in deps):
            statuses[rel] = 'preserved_incomplete_or_failed_analysis'
            continue
        try:
            clean = (snapshot / rel).read_bytes()
            if semantic_bytes(root / rel) != clean:
                raise ValueError('Source changed during analysis; not overwritten')
            statuses[rel] = annotate_source(root / rel, clean, messages[rel])
        except Exception as e:
            statuses[rel] = 'annotation_failed'
            errors.append(rel + ': ' + str(e))
    return statuses, errors


def summary_view(rows):
    """Keep function counts separate from diagnostic counts; do not reclassify."""
    numeric = [k for k in rows[0] if k not in ('cwe', 'checker')]
    totals = {k: sum(int(r[k]) for r in rows) for k in numeric}
    total = dict(totals, cwe='합계', checker='')
    for r in rows:
        assert int(r['testcase_functions']) == int(r['good_functions']) + int(r['bad_functions'])
        assert int(r['testcase_functions']) == sum(int(r[k]) for k in ('analyzed_functions','failed_functions','pending_functions'))
        assert int(r['analyzed_functions']) == sum(int(r[k]) for k in ('fp_functions','fn_functions','tp_functions','tn_functions'))
    def number(r, key):
        return format(int(r[key]), ',')
    def rate(r, numerator, denominator):
        n, d = int(r[numerator]), int(r[denominator])
        return number(r, numerator) + (' (' + format(100*n/d, '.1f') + '%)' if d else ' (—)')
    def name(r):
        return '합계' if r['cwe']=='합계' else 'CWE-' + str(r['cwe'])
    core_headers = ['CWE','전체 testcase','Good','Bad','FP / Good','FN / Bad','TP','TN','실패','대기']
    core = [[name(r),number(r,'testcase_functions'),number(r,'good_functions'),number(r,'bad_functions'),
             rate(r,'fp_functions','good_functions'),rate(r,'fn_functions','bad_functions'),
             number(r,'tp_functions'),number(r,'tn_functions'),number(r,'failed_functions'),number(r,'pending_functions')]
            for r in [*rows,total]]
    diag_headers = ['CWE','Good Warning','Good Error','Bad Warning','Bad Error']
    diagnostics = [[name(r),*[number(r,k) for k in ('good_target_warnings','good_target_errors','bad_target_warnings','bad_target_errors')]]
                   for r in [*rows,total]]
    return totals, core_headers, core, diag_headers, diagnostics


def write_readable_summary(out, rows):
    import html
    import unicodedata
    totals, headers, core, diag_headers, diagnostics = summary_view(rows)
    def number(r, key):
        return format(int(r[key]), ",")
    def width(value):
        return sum(2 if unicodedata.east_asian_width(c) in ('W','F') else 1 for c in value)
    sizes = [max(width(str(r[i])) for r in [headers,*core]) for i in range(len(headers))]
    def terminal_row(row):
        return ' | '.join(str(v) + ' ' * (sizes[i]-width(str(v))) for i,v in enumerate(row))
    terminal = '\n'.join([terminal_row(headers),'-+-'.join('-'*n for n in sizes),*[terminal_row(r) for r in core]])
    def table(headings, contents):
        head = '<thead><tr>' + ''.join('<th>'+html.escape(h)+'</th>' for h in headings)+'</tr></thead>'
        body = '<tbody>' + ''.join('<tr'+(' class="total"' if r[0]=='합계' else '')+'>' +
            ''.join('<td'+(' class="fp"' if i==4 and headings==headers else ' class="fn"' if i==5 and headings==headers else '')+'>'+html.escape(str(v))+'</td>' for i,v in enumerate(r))+'</tr>' for r in contents)+'</tbody>'
        return '<div class="scroll"><table>'+head+body+'</table></div>'
    completion = number(totals,'analyzed_functions')+' / '+number(totals,'testcase_functions')
    document = '''<!doctype html><html lang="ko"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Juliet 분석 결과</title><style>
body{font-family:system-ui,sans-serif;max-width:1400px;margin:36px auto;padding:0 20px;color:#172334;background:#f7f9fc;line-height:1.65}
h1{font-size:28px;margin-bottom:8px}h2{font-size:20px;margin-top:30px}.muted{color:#526176}.scroll{overflow:auto;background:white;border:1px solid #dbe1e9;border-radius:10px}
table{border-collapse:collapse;width:100%;font-variant-numeric:tabular-nums;white-space:nowrap}th,td{padding:12px 14px;text-align:right;border-bottom:1px solid #e8edf3}th:first-child,td:first-child{text-align:left}th{background:#eaf0f7;color:#33445a}tr.total{font-weight:700;background:#edf3fc}.fp{background:#fff4e3}.fn{background:#fff0f0}code{background:#e8edf3;padding:2px 5px;border-radius:4px}
</style><h1>Juliet 분석 결과</h1>'''
    document += '<p class="muted">버전 폴더: '+html.escape(out.name)+' · 소스 '+number(totals,'source_files')+'개 · 분석 완료 testcase '+completion+'개 · 실패 '+number(totals,'failed_functions')+'개 · 대기 '+number(totals,'pending_functions')+'개</p>'
    document += '<h2>Testcase 함수별 집계</h2><p><code>goodG2B1()</code>, <code>goodG2B2()</code> 등을 각각 1개로 셉니다. 같은 testcase에 진단이 여러 개 있어도 FP 또는 TP는 1개입니다.</p>'
    document += table(headers, core)
    document += '<p><b>FP</b>: Good에서 목표 진단 발생 · <b>FN</b>: Bad에서 목표 진단 없음 · <b>TP</b>: Bad에서 목표 진단 발생 · <b>TN</b>: Good에서 목표 진단 없음.<br>비율의 분모는 FP의 경우 전체 Good, FN의 경우 전체 Bad입니다. 실패·대기 testcase는 FP/FN/TP/TN에 넣지 않습니다. 판정은 Juliet 레이블과 목표 진단 대응 기준입니다.</p>'
    document += '<h2>실제 Warning/Error 진단 건수</h2><p>위 표의 testcase 수와 다른 단위입니다. 한 testcase에 여러 진단이 생길 수 있습니다. 해당 CWE 목표 진단만 집계합니다.</p>'
    document += table(diag_headers,diagnostics)
    document += '<p class="muted">파일·라인·실제 함수·메시지: <a href="details.json.gz">details.json.gz</a></p>'
    document += '<p class="muted">FN 중 checker 기록 자체가 없는 testcase: '+number(totals,'fn_no_checker_records')+'개. 도달 불가 기록만 있는 testcase: '+number(totals,'fn_unreachable_only')+'개. 두 수치는 FN 총수에 이미 포함되어 있습니다.</p></html>'
    temp = out/'summary.html.tmp'
    temp.write_text(document,encoding='utf-8')
    output_owner(temp,out)
    temp.replace(out/'summary.html')
    return terminal


def summary_only(path):
    source = path/'summary.csv' if path.is_dir() else path
    with source.open(newline='',encoding='utf-8-sig') as stream:
        rows = list(csv.DictReader(stream))
    if not rows:
        raise ValueError('Empty summary: '+str(source))
    print(write_readable_summary(source.parent,rows))
    print('Report: '+str(source.parent/'summary.html'))
    return 0


def export_results(out, programs, inventory, results, annotation_status, metadata, annotation_errors):
    functions, diagnostics, file_rows, summaries, failures = [], [], [], [], []
    for p in programs:
        r = results.get(p['program_id'], {})
        status = r.get('status', 'pending')
        for s in p['scenarios']:
            records = [d for d in r.get('diagnostics', []) if d['scenario_id'] == s['id']]
            target = [d for d in records if d['target']]
            coverage = r.get('coverage', {}).get(s['id'], {})
            reachable = sum(coverage.get(str(k), 0) for k in (0, 1, 2))
            observation = ('reachable_checker_records' if reachable else 'unreachable_checker_records_only'
                           if coverage.get('3') else 'no_checker_records') if status == 'ok' else status
            outcome = ('FP_candidate' if target else 'TN_by_label') if s['role'] == 'good' else ('TP_by_label' if target else 'FN_candidate')
            if status != 'ok':
                outcome = 'analysis_failed' if status != 'pending' else 'pending'
            functions.append(dict(cwe=p['cwe'], program_id=p['program_id'], testcase_id=s['id'], row_type='testcase',
                role=s['role'], function=s['name'], path=s['path'], line=s['line'], end_line=s['end_line'],
                status=status, outcome=outcome, observation=observation, target_diagnostics=len(target),
                target_warnings=sum(d['status'] == 1 for d in target), target_errors=sum(d['status'] == 2 for d in target),
                all_warnings=sum(d['status'] == 1 for d in records), all_errors=sum(d['status'] == 2 for d in records),
                checker_safe_records=coverage.get('0', 0), checker_warning_records=coverage.get('1', 0),
                checker_error_records=coverage.get('2', 0), checker_unreachable_records=coverage.get('3', 0),
                manifest_flaws=p['flaws']))
        # Actual native definitions plus lexical functions that failed to compile.
        native = {(d['path'], d['line'], d['function']): d for d in r.get('definitions', []) if d['path'] in inventory}
        if status != 'ok':
            for rel in p['sources']:
                for fn in inventory[rel]['functions']:
                    native[(rel, fn['line'], fn['name'])] = dict(path=rel, line=fn['line'], function=fn['name'])
        for d in native.values():
            functions.append(dict(cwe=p['cwe'], program_id=p['program_id'], row_type='implementation', status=status,
                                  observation='compiled_definition' if status == 'ok' else 'analysis_not_completed', **d))
        for index, d in enumerate(r.get('diagnostics', [])):
            diagnostics.append(dict(cwe=p['cwe'], program_id=p['program_id'], record_id=p['program_id']+':'+str(index), **d))
        if status not in ('ok', 'pending'):
            failures.append(p['program_id'] + '\nStage: ' + r.get('stage', '') + '\n' + r.get('log', '') + '\n')
    owners_by_file = defaultdict(list)
    for p in programs:
        for rel in p['files']:
            owners_by_file[rel].append(p)
    for rel, info in sorted(inventory.items()):
        owners = owners_by_file[rel]
        states = Counter(results.get(p['program_id'], {}).get('status', 'pending') for p in owners)
        state = ('analyzed' if states and set(states) == {'ok'} else 'pending' if not states or 'pending' in states
                 else 'analysis_failed')
        if info['kind'] == 'aggregate_driver':
            state = 'aggregate_driver_covered_by_individual_testcase_mains'
        elif info['kind'] == 'header' and not owners:
            state = 'included_header_inventory'
        file_rows.append(dict(cwe=info['cwe'], path=rel, kind=info['kind'], status=state,
                              programs=[p['program_id'] for p in owners], statuses=dict(states),
                              annotation_status=annotation_status.get(rel, 'not_updated'), sha256=info['sha256']))
    for p in programs:
        for rel in p['missing']:
            if not any(r['path'] == rel for r in file_rows):
                file_rows.append(dict(cwe=p['cwe'], path=rel, kind='missing_input', status='missing',
                    programs=[x['program_id'] for x in programs if rel in x['missing']],
                    annotation_status='source_missing', sha256=''))
    for n in CHECKERS:
        fs = [f for f in functions if f['cwe'] == n and f['row_type'] == 'testcase']
        good, bad = ([f for f in fs if f['role'] == role] for role in ('good', 'bad'))
        row = dict(cwe=n, checker=CHECKERS[n][1], testcase_functions=len(fs), good_functions=len(good), bad_functions=len(bad),
                   analyzed_functions=sum(f['status'] == 'ok' for f in fs), failed_functions=sum(f['status'] not in ('ok','pending') for f in fs),
                   pending_functions=sum(f['status'] == 'pending' for f in fs),
                   fp_functions=sum(f['outcome'] == 'FP_candidate' for f in fs), fn_functions=sum(f['outcome'] == 'FN_candidate' for f in fs),
                   tp_functions=sum(f['outcome'] == 'TP_by_label' for f in fs), tn_functions=sum(f['outcome'] == 'TN_by_label' for f in fs),
                   fp_diagnostics=sum(f['target_diagnostics'] for f in good), tp_diagnostics=sum(f['target_diagnostics'] for f in bad),
                   good_target_warnings=sum(f['target_warnings'] for f in good), good_target_errors=sum(f['target_errors'] for f in good),
                   bad_target_warnings=sum(f['target_warnings'] for f in bad), bad_target_errors=sum(f['target_errors'] for f in bad),
                   fn_no_checker_records=sum(f['outcome']=='FN_candidate' and f['observation']=='no_checker_records' for f in fs),
                   fn_unreachable_only=sum(f['outcome']=='FN_candidate' and f['observation']=='unreachable_checker_records_only' for f in fs),
                   source_files=sum(i['cwe']==n and i['kind']=='test_source' for i in inventory.values()),
                   missing_input_files=len({rel for p in programs if p['cwe']==n for rel in p['missing']}),
                   programs=sum(p['cwe']==n for p in programs), analyzed_programs=sum(p['cwe']==n and results.get(p['program_id'],{}).get('status')=='ok' for p in programs))
        assert row['testcase_functions'] == row['analyzed_functions'] + row['failed_functions'] + row['pending_functions']
        assert row['analyzed_functions'] == row['fp_functions'] + row['fn_functions'] + row['tp_functions'] + row['tn_functions']
        summaries.append(row)
    write_csv(out/'summary.csv', list(summaries[0]), summaries)
    write_readable_summary(out, summaries)
    write_csv(out/'functions.csv', ['cwe','program_id','testcase_id','row_type','role','function','path','line','end_line','status','outcome','observation',
                                  'target_diagnostics','target_warnings','target_errors','all_warnings','all_errors',
                                  'checker_safe_records','checker_warning_records','checker_error_records','checker_unreachable_records','manifest_flaws'], functions)
    write_csv(out/'files.csv', ['cwe','path','kind','status','programs','statuses','annotation_status','sha256'], file_rows)
    write_csv(out/'diagnostics.csv', ['cwe','program_id','scenario_id','record_id','path','line','column','function','severity','kind','target','target_reason','short_message','message','contexts'], diagnostics)
    log = failures + ['Annotation: ' + e for e in annotation_errors]
    if log:
        (out/'failures.log').write_text('\n'.join(log), encoding='utf-8', errors='replace')
        output_owner(out/'failures.log',out)
    elif (out/'failures.log').exists():
        (out/'failures.log').unlink()
    metadata.update(completed_programs=len(results), successful_programs=sum(r['status']=='ok' for r in results.values()),
                    failed_programs=sum(r['status']!='ok' for r in results.values()), interrupted=STOP.is_set(),
                    annotation_failures=len(annotation_errors), updated_at=time.strftime('%Y-%m-%dT%H:%M:%S%z'))
    save_json(out/'run.json', metadata)
    return summaries


FIELDS = ('testcase_functions','good_functions','bad_functions','analyzed_functions','failed_functions','pending_functions',
          'fp_functions','fn_functions','tp_functions','tn_functions','fp_diagnostics','tp_diagnostics',
          'good_target_warnings','good_target_errors','bad_target_warnings','bad_target_errors',
          'fn_no_checker_records','fn_unreachable_only','programs','analyzed_programs')


def compact_clean(text):
    return LEX.sub(lambda m: ''.join(re.findall(r'\r\n|\r|\n',m[0]))
                   if m[0].startswith('/*') and MANAGED.fullmatch(m[0])
                   else MANAGED.sub('',m[0]) if m[0].startswith('//') else m[0],text)


def compact_definitions(text):
    import bisect
    code=LEX.sub(lambda m: re.sub(r'[^\r\n]',' ',m[0]),text)
    offsets=[0]+[m.end() for m in re.finditer('\n',code)]
    code=re.sub(r'^[ \t]*#[^\n]*',lambda m:' '*len(m[0]),code,flags=re.M)
    brackets,stack={},[]
    for m in re.finditer(r'[{}]',code):
        if m[0]=='{': stack.append(m.start())
        elif stack: brackets[stack.pop()]=m.start()
    found=[]
    for m in re.finditer(r'([~\w:]+)\s*\([^;{}]*\)\s*(?:const\s*)?(?:noexcept\s*)?(?::[^;{}]*)?\{',code):
        if m[1] in {'if','for','while','switch','catch','sizeof','alignof'}: continue
        start=m.end()-1
        if start in brackets:
            found.append(dict(function=m[1],line=bisect.bisect_right(offsets,m.start()),
                              end_line=bisect.bisect_right(offsets,brackets[start])))
    return found


def expected_sites(program,scenario,root,hashes,native):
    sites=[]
    for f in program.get('flaws',[]):
        if not re.match(r'^CWE-?0*'+str(program['cwe'])+r'\b',f.get('name',''),re.I): continue
        site=dict(path=f['path'],line=f['line'],function='',expected_weakness=f.get('name',''),
                  location_basis='juliet_manifest',source_verification='unavailable')
        path=root/f['path']
        if path.is_file():
            text=compact_clean(path.read_bytes().decode('utf-8',errors='surrogateescape'))
            wanted=hashes.get(f['path'])
            digest=hashlib.sha256(text.encode('utf-8',errors='surrogateescape')).hexdigest()
            site['source_verification']='matches_analyzed_source' if digest==wanted else 'changed_or_hash_unavailable'
            if digest==wanted:
                hits=[x for x in compact_definitions(text) if x['line']<=int(f['line'])<=x['end_line']]
                if hits:
                    best=min(hits,key=lambda x:x['end_line']-x['line'])
                    names=[x['function'] for x in native if x.get('path')==f['path'] and x.get('line')==best['line']]
                    site['function']=' | '.join(sorted(set(names))) if names else best['function']
        sites.append(site)
    return sites


def prepare_result_directory(out, root):
    """Create results/VERSION under the testcase root; preserve host ownership."""
    results = root / 'results'
    results.mkdir(exist_ok=True)
    output_owner(results, root)
    out.mkdir(exist_ok=True)
    output_owner(out, root)


def output_owner(path, reference):
    # Docker root must not leave root-owned 0600 archives on the bind mount.
    if hasattr(os, 'geteuid') and os.geteuid() == 0:
        owner = Path(reference).stat()
        os.chown(path, owner.st_uid, owner.st_gid)


def compact_export(source, output, root, replace=False):
    source=Path(source).resolve(); output=Path(output).resolve(); root=Path(root).resolve()
    db=source/'results.sqlite'; summary=source/'summary.csv'
    if source==output and not replace: raise ValueError('Same-folder export requires replace=True')
    if not db.is_file() or not summary.is_file(): raise ValueError('Input folder must contain results.sqlite and summary.csv')
    with summary.open(newline='',encoding='utf-8-sig') as stream: rows=list(csv.DictReader(stream))
    if not rows: raise ValueError('Empty summary.csv')
    expected={int(r['cwe']):r for r in rows}
    con=sqlite3.connect(db.as_uri()+'?mode=ro',uri=True)
    con.execute('BEGIN')
    config_row=con.execute("SELECT value FROM metadata WHERE key='configuration'").fetchone()
    if not config_row: raise ValueError('No saved configuration')
    cfg=json.loads(config_row[0]); programs=cfg['plan']; hashes=cfg.get('sources',{})
    ids={p['program_id'] for p in programs}
    saved={r[0] for r in con.execute('SELECT program_id FROM results')}
    if saved-ids: raise ValueError('Saved results not represented in the plan')
    missing_dirs=[]
    directory=output
    while not directory.exists():
        missing_dirs.append(directory);directory=directory.parent
    output.mkdir(parents=True,exist_ok=True)
    for directory in missing_dirs: output_owner(directory,root)
    if not replace and ((output/'details.json.gz').exists() or (output/'summary.csv').exists()):
        raise ValueError('Output already contains an export; choose a new output folder')
    totals={n:Counter() for n in expected}
    run_meta=json.loads((source/'run.json').read_text()) if (source/'run.json').is_file() else {}
    complete=not any(int(row['failed_functions']) or int(row['pending_functions']) or int(row.get('missing_input_files',0)) for row in rows) and not run_meta.get('failed_programs',0) and not run_meta.get('annotation_failures',0) and not run_meta.get('interrupted',False)
    header=dict(complete=complete,annotation_failures=run_meta.get('annotation_failures',0),schema_version=1,version=source.name,ikos_version=cfg['tools'].get('version'),
                tools=cfg['tools'],analysis_script_sha256=cfg.get('script'),
                format='programs -> testcases -> target_diagnostics / expected_flaw_sites',
                counting='Individual testcase functions; same testcase with multiple alarms counts once.',
                fn_locations='Juliet manifest expected flaw locations, not emitted warnings. Missing sites remain explicitly unresolved.',
                implementation_functions='Compiled definitions; actual checker reachability is not retained for every helper.',
                safe_checks='Counts only; no individual Safe locations were retained by the original runner.',
                omitted='Off-target warnings, verbose call-context stacks, temporary bitcode, and resume-cache signatures.',
                analyzed_source_hashes=hashes)
    encoder=json.JSONEncoder(ensure_ascii=True,separators=(',',':'))
    fd,temp=tempfile.mkstemp(prefix='.details-',suffix='.gz',dir=output);os.close(fd)
    temp=Path(temp)
    try:
        with gzip.open(temp,'wt',encoding='utf-8',compresslevel=9) as out:
            def emit(value):
                for chunk in encoder.iterencode(value): out.write(chunk)
            out.write('{"metadata":');emit(header);out.write(',"programs":[')
            for index,p in enumerate(programs):
                record=con.execute('SELECT payload FROM results WHERE program_id=?',(p['program_id'],)).fetchone()
                r=json.loads(record[0]) if record else dict(status='pending')
                n=p['cwe']; tally=totals[n];status=r['status'];tally['programs']+=1
                tally['analyzed_programs']+=status=='ok'
                targets=[d for d in r.get('diagnostics',[]) if d.get('target')]
                fn_rows=[]
                for s in p['scenarios']:
                    tally['testcase_functions']+=1;tally[s['role']+'_functions']+=1
                    cov=r.get('coverage',{}).get(s['id'],{})
                    reachable=sum(cov.get(str(k),0) for k in (0,1,2))
                    observation=('reachable_checker_records' if reachable else 'unreachable_checker_records_only' if cov.get('3') else 'no_checker_records') if status=='ok' else status
                    ds=[d for d in targets if d.get('scenario_id')==s['id']]
                    verdict=('FP' if ds else 'TN') if s['role']=='good' else ('TP' if ds else 'FN')
                    if status=='ok':
                        tally['analyzed_functions']+=1;tally[verdict.lower()+'_functions']+=1
                    else:
                        tally['pending_functions' if status=='pending' else 'failed_functions']+=1
                        verdict='pending' if status=='pending' else 'analysis_failed'
                    if verdict in ('FP','TP'): tally[verdict.lower()+'_diagnostics']+=len(ds)
                    if verdict=='FN':
                        tally['fn_no_checker_records']+=observation=='no_checker_records'
                        tally['fn_unreachable_only']+=observation=='unreachable_checker_records_only'
                    for d in ds: tally[s['role']+'_target_'+('warnings' if d['status']==1 else 'errors')]+=1
                    entry=dict(id=s['id'],function=s['name'],path=s['path'],line=s['line'],end_line=s['end_line'],role=s['role'],
                               status=status,outcome=verdict,observation=observation,checker_counts=cov,
                               target_diagnostics=[{k:d.get(k) for k in ('path','line','column','function','severity','short_message','message','target_reason')} for d in ds])
                    if verdict=='FN':
                        entry['expected_flaw_sites']=expected_sites(p,s,root,hashes,r.get('definitions',[]))
                        entry['fn_location_status']='manifest_sites_available' if entry['expected_flaw_sites'] else 'unresolved_no_manifest_site'
                    fn_rows.append(entry)
                compact=dict(id=p['program_id'],cwe=n,checker=expected[n]['checker'],sources=p['sources'],files=p['files'],
                             missing_inputs=p.get('missing',[]),status=status,
                             commands=r.get('commands',[]),settings=r.get('settings',{}),testcases=fn_rows,
                             implementation_functions=r.get('definitions',[]))
                if status not in ('ok','pending'): compact.update(failure_stage=r.get('stage'),failure_log=r.get('log',''))
                if index:out.write(',')
                emit(compact)
                if (index+1)%500==0:print('Exported %d/%d programs'%(index+1,len(programs)),flush=True)
            out.write(']}')
        for n,row in expected.items():
            for field in FIELDS:
                if field in row and int(row[field])!=totals[n][field]:
                    raise ValueError('Count mismatch CWE%d %s: CSV=%s export=%s'%(n,field,row[field],totals[n][field]))
        # Reopen and fully decode the compressed document before reporting success.
        with gzip.open(temp,'rt',encoding='utf-8') as check: document=json.load(check)
        if len(document['programs'])!=len(programs):raise ValueError('Archive program count mismatch')
        if sum(len(p['testcases']) for p in document['programs'])!=sum(c['testcase_functions'] for c in totals.values()):
            raise ValueError('Archive testcase count mismatch')
        output_owner(temp,root)
        temp.replace(output/'details.json.gz')
        if source != output:
            summary_temp=output/'summary.csv.tmp'
            shutil.copyfile(summary,summary_temp)
            output_owner(summary_temp,root)
            summary_temp.replace(output/'summary.csv')
        output_owner(output/'summary.csv',root)
        print('Verified: %d programs, %d testcases, FP=%d FN=%d'%(
            len(programs),sum(c['testcase_functions'] for c in totals.values()),sum(c['fp_functions'] for c in totals.values()),sum(c['fn_functions'] for c in totals.values())))
        print('Archive: %s (%.2f MiB)'%(output/'details.json.gz',(output/'details.json.gz').stat().st_size/1048576))
        return complete
    finally:
        if temp.exists():temp.unlink()
        con.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--compact-only', type=Path, metavar='OLD_RESULT_DIR',
                        help='Compact an existing legacy result folder without IKOS; preserve originals')
    parser.add_argument('--output', type=Path, help='Output folder for --compact-only; default: JULIET_ROOT/results/VERSION')
    parser.add_argument('--summary-only', type=Path, metavar='RESULT_DIR',
                        help='Render an existing summary.csv as summary.html and a terminal table; no analysis or source edits')
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument('--ikos', default=IKOS)
    parser.add_argument('--jobs', type=int, default=JOBS)
    parser.add_argument('--timeout', type=float, default=TIMEOUT_SECONDS, help='External timeout in seconds per tool; default unlimited')
    parser.add_argument('--list', action='store_true', help='Audit all source groups and testcase functions without running IKOS or editing files')
    args = parser.parse_args()
    if args.summary_only is not None:
        return summary_only(args.summary_only.resolve())
    if args.compact_only is not None:
        source=args.compact_only.resolve()
        target=(args.output or args.root.resolve()/'results'/source.name).resolve()
        compact_export(source,target,args.root)
        return 0
    if args.output is not None:
        parser.error('--output is only used with --compact-only')
    if not re.fullmatch(r'v[0-9]+(?:\.[0-9]+)*(?:[-+][A-Za-z0-9_.-]+)?', VERSION):
        parser.error('VERSION must be a single version name such as v3.5.1')
    if args.jobs < 1 or (args.timeout is not None and args.timeout <= 0):
        parser.error('--jobs and --timeout must be positive')
    root = args.root.resolve()
    out = root / 'results' / VERSION
    if not args.list and (out/'details.json.gz').is_file() and not (out/'results.sqlite').exists():
        with gzip.open(out/'details.json.gz','rt',encoding='utf-8') as saved:
            archive=json.load(saved)
        if not archive['metadata'].get('complete'):
            raise ValueError('Incomplete archive without resume cache; use a new VERSION')
        with (out/'summary.csv').open(newline='',encoding='utf-8-sig') as saved:
            rows=list(csv.DictReader(saved))
        _,headers,core,_,_=summary_view(rows)
        print('This VERSION is already complete; no analysis rerun. Set a new VERSION for a new analysis.')
        for row in [headers,*core]: print(' | '.join(row))
        print('Results: '+str(out))
        return 0
    if not args.list:
        ikos = find_ikos(args.ikos)
        import_runtime(ikos)
    print('Inventory: ' + str(root), flush=True)
    units, inventory = scan_inventory(root)
    programs = program_plan(units, root)
    for n in CHECKERS:
        group = [s for p in programs if p['cwe']==n for s in p['scenarios']]
        print('CWE%d: files=%d programs=%d good=%d bad=%d' % (n,
            sum(i['cwe']==n and i['kind']=='test_source' for i in inventory.values()),
            sum(p['cwe']==n for p in programs), sum(s['role']=='good' for s in group), sum(s['role']=='bad' for s in group)), flush=True)
    if args.list:
        print('Audit complete. No source files changed; no analysis performed.', flush=True)
        return 0
    tools = tools_config(ikos)
    out = root / 'results' / VERSION
    if (out/'summary.csv').exists() and not (out/'results.sqlite').exists() and not (out/'details.json.gz').exists():
        raise ValueError('Existing output without resume cache. Choose a new VERSION or use --compact-only.')
    prepare_result_directory(out,root)
    support_dir = root / 'testcasesupport'
    support_inputs = sorted(p for p in support_dir.rglob('*') if p.is_file() and p.suffix.lower() in CODE_EXT)
    if not support_inputs or not (support_dir/'io.c').is_file():
        raise ValueError('testcasesupport/io.c and headers are required')
    support_hashes = {str(p.relative_to(root)): digest(semantic_bytes(p)) for p in support_inputs}
    signature_data = dict(script=digest(Path(__file__).read_bytes()), tools=tools,
        sources={p:i['sha256'] for p,i in inventory.items()}, support=support_hashes,
        plan=programs, root=str(root), timeout=args.timeout)
    signature = digest(json.dumps(signature_data, sort_keys=True).encode())
    con = sqlite3.connect(out/'results.sqlite')
    output_owner(out/'results.sqlite',out)
    con.execute('CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)')
    con.execute('CREATE TABLE IF NOT EXISTS results (program_id TEXT PRIMARY KEY, payload TEXT NOT NULL)')
    previous = con.execute("SELECT value FROM metadata WHERE key='signature'").fetchone()
    if previous and previous[0] != signature:
        # Existing results are kept until a deliberate new version is selected.
        raise ValueError('Inputs, script, IKOS, root, or timeout changed for ' + VERSION + '. Set a new VERSION at the script top; existing results were preserved.')
    con.execute('INSERT OR REPLACE INTO metadata VALUES (?,?)', ('signature',signature))
    con.execute('INSERT OR REPLACE INTO metadata VALUES (?,?)', ('configuration',json.dumps(signature_data)))
    con.commit()
    results = {pid:json.loads(data) for pid,data in con.execute('SELECT program_id,payload FROM results')}
    # Failed programs are retried on resume; successful records are reused.
    pending = [p for p in programs if results.get(p['program_id'],{}).get('status')!='ok']
    metadata = dict(version_label=VERSION, ikos_version=tools['version'], root=str(root), tools=tools,
        signature=signature, programs=len(programs), test_source_files=sum(i['kind']=='test_source' for i in inventory.values()),
        testcase_functions=sum(len(p['scenarios']) for p in programs), reused_programs=len(programs)-len(pending),
        semantic_options='IKOS CLI defaults; only -a selects checker(s). main is the sole program entry point.',
        count_unit='Each zero-argument goodG2B*, goodB2G*, good1/good2/etc, or bad driver is one testcase. Outer good dispatcher, Sink/Source, constructors/destructors are not extra testcases.',
        fp_fn_definition='Juliet-label candidates, target CWE subtype only: good target alarm=FP; bad target alarm=TP; bad without target alarm=FN. Failed analyses are separate; unreachable/no-check FN subsets are explicit.',
        diagnostic_unit='One IKOS native report per attributed testcase; multiple calling contexts of that testcase deduplicated. The same sink shared by different testcases is attributed to each.',
        safe_definition='Raw checker safe records are not a proof of complete safety; no-check and unreachable are separate.',
        annotation_policy='All IKOS warning/error messages from selected checkers, including off-target subtypes, are annotated; only target=True contributes to FP/TP. Failed/incomplete files retain previous comments.',
        coverage=dict(unassigned_test_sources=[], duplicate_test_sources=[], missing_inputs=sorted({x for p in programs for x in p['missing']})))
    print('IKOS: ' + tools['version'] + '; output: ' + str(out), flush=True)
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, stop_children)
    with tempfile.TemporaryDirectory(prefix='juliet-ikos-') as temporary:
        workspace = Path(temporary)
        snapshot = workspace/'inputs'
        snapshot.mkdir()
        for rel in list(inventory) + list(support_hashes):
            target = snapshot/rel
            target.parent.mkdir(parents=True, exist_ok=True)
            data = semantic_bytes(root/rel)
            expected = inventory[rel]['sha256'] if rel in inventory else support_hashes[rel]
            if digest(data) != expected:
                raise ValueError('Source changed while creating snapshot: ' + rel)
            target.write_bytes(data)
        support_objects = []
        if pending:
            for name in ('io.c','std_thread.c'):
                source = snapshot/'testcasesupport'/name
                if not source.is_file():
                    continue
                target = workspace/(name+'.bc')
                run = invoke(compile_cmd(source,target,None,tools,snapshot,include_main=False), workspace,args.timeout)
                if run['status']!='ok':
                    raise ValueError('Could not compile shared support ' + name + ':\n' + run['output'])
                support_objects.append(target)
        export_results(out, programs, inventory, results, {}, metadata, [])
        executor = ThreadPoolExecutor(max_workers=args.jobs)
        queued = iter(pending)
        futures = {}
        def schedule():
            while len(futures) < args.jobs and not STOP.is_set():
                p = next(queued, None)
                if p is None:
                    break
                f = executor.submit(run_program,p,snapshot,tools,support_objects,args.timeout,workspace)
                futures[f] = p
        schedule()
        last_export = last_print = time.monotonic()
        try:
            while futures:
                done, _ = wait(futures, timeout=1, return_when=FIRST_COMPLETED)
                for future in done:
                    p = futures.pop(future)
                    r = future.result()
                    results[p['program_id']] = r
                    con.execute('INSERT OR REPLACE INTO results VALUES (?,?)',(p['program_id'],json.dumps(r,separators=(',',':'))))
                    con.commit()
                    print('[%d/%d] %s %s (%ss)' % (len(results),len(programs),r['status'],p['name'],r['seconds']),flush=True)
                    last_print = time.monotonic()
                if time.monotonic()-last_print > 30:
                    print('Progress: %d/%d saved; %d running' % (len(results),len(programs),len(futures)),flush=True)
                    last_print=time.monotonic()
                if time.monotonic()-last_export > 60:
                    export_results(out,programs,inventory,results,{},metadata,[])
                    last_export=time.monotonic()
                schedule()
        finally:
            executor.shutdown(wait=True)
        statuses, errors = refresh_annotations(root,snapshot,inventory,programs,results)
        summaries = export_results(out,programs,inventory,results,statuses,metadata,errors)
    con.close()
    print(write_readable_summary(out, summaries), flush=True)
    complete=compact_export(out,out,root,replace=True)
    if complete and not STOP.is_set() and not metadata['failed_programs'] and not errors:
        for filename in ('results.sqlite','results.sqlite-journal','functions.csv','files.csv','diagnostics.csv','run.json','summary.html','failures.log'):
            intermediate=out/filename
            if intermediate.is_file(): intermediate.unlink()
        print('Compact output verified. Intermediate results removed; summary.csv and details.json.gz retained.',flush=True)
    else:
        print('Incomplete/failed run: intermediate files retained for resume and diagnosis.',flush=True)
    print('Results: ' + str(out),flush=True)
    return 130 if STOP.is_set() else 1 if metadata['failed_programs'] or errors else 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        print('ERROR: ' + str(error),file=sys.stderr)
        sys.exit(1)


