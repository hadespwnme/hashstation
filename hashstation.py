#!/usr/bin/env python3
import argparse
import signal
import re
from pathlib import Path
from typing import Any, Tuple, List, Dict
from pycrackhash import crack, crack_file, analyze, analyze_file
from rich import print
from rich.table import Table
from rich import box
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

dictHash = {
    "0": ("MD5", "Hash MD5 biasa"),
    "100": ("SHA1", "SHA-1"),
    "1400": ("SHA256", "SHA-256"),
    "1700": ("SHA512", "SHA-512"),
    "500": ("md5crypt (Unix)", "MD5 crypt ($1$)"),
    "1800": ("sha512crypt (Unix)", "SHA-512 crypt ($6$)"),
    "3200": ("bcrypt", "bcrypt ($2a$, $2b$)"),
    "1600": ("Apache MD5", "Apache $apr1$ MD5"),
    "1722": ("SHA256crypt (Unix)", "SHA-256 crypt (Unix)"),
    "3910": ("SHA1crypt (Unix)", "SHA-1 crypt (Unix)"),
    "1000": ("NTLM", "Windows NTLM hash"),
    "1100": ("LAN Manager (LM)", "Windows LAN Manager hash"),
    "2100": ("DCC2", "Domain Cached Credentials v2"),
    "5500": ("NetNTLMv2", "Microsoft NetNTLMv2"),
    "5600": ("NetNTLMv1", "Microsoft NetNTLMv1"),
    "7300": ("IPB2+", "Invision Power Board 2+"),
    "7400": ("MyBB", "MyBB forum"),
    "7900": ("Drupal7", "Drupal 7 CMS"),
    "2811": ("phpass", "WordPress, phpBB3 (PHPass)"),
    "3711": ("MediaWiki B", "MediaWiki B hashing"),
    "5100": ("Half MD5", "MD5 setengah"),
    "2600": ("Double MD5", "md5(md5($pass))"),
    "3500": ("Triple MD5", "md5(md5(md5($pass)))"),
    "23": ("Skype", "Skype password hash"),
    "10": ("MD5 + salt", "md5($pass.$salt)")
}

nameCode = {v[0].lower(): k for k, v in dictHash.items()}

def normKey(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.lower())

def modeDisplay(mode: str) -> str:
    if mode in dictHash:
        return f"{dictHash[mode][0]} ({mode})"
    mk = nameCode.get(normKey(mode))
    if mk and mk in dictHash:
        return f"{dictHash[mk][0]} ({mk})"
    return mode

def styleTable(columns, title=None):
    table = Table(title=title, show_lines=False, box=box.SIMPLE_HEAVY, pad_edge=False, header_style="bold", padding=(0, 1))
    for col in columns:
        if isinstance(col, tuple):
            table.add_column(*col)
        else:
            table.add_column(col)
    return table

def listModes():
    table = styleTable([("Mode", "bold"), ("Algorithm",), ("Description",)], title="List Hash Modes")
    for mode, (name, description) in sorted(dictHash.items(), key=lambda x: int(x[0])):
        table.add_row(mode, name, description)
    Console().print(table)

def analyzeTable(inputHash: str, candidates: Any):
    console = Console()
    console.print(f"\n[bold]Analyze for hash:[/bold]\n{inputHash if inputHash else '-'}")
    table = styleTable([("Hash Type", "bold"), ("Hashcat",), ("John",)])
    def addRow(ht, hc, jn):
        hc = "-" if hc in (None, "", "None") else str(hc)
        jn = "-" if jn in (None, "", "None") else str(jn)
        table.add_row(str(ht), hc, jn)
    printed = False
    if isinstance(candidates, list) and all(isinstance(c, dict) for c in candidates):
        for c in candidates:
            addRow(c.get("hashName", "-"), c.get("hashcat"), c.get("john"))
        printed = True
    elif isinstance(candidates, dict):
        ht = str(candidates.get("hashName") or candidates.get("type") or candidates.get("description") or "-")
        key = normKey(ht)
        code = nameCode.get(key, candidates.get("hashcat"))
        addRow(ht, code if code else "-", candidates.get("john") or (key if code else "-"))
        printed = True
    if not printed:
        addRow("-", "-", "-")
    console.print(table)

def crackRow(hashValue: str, modeStr: str, result: str, ok: bool):
    table = styleTable([("Hash", "bold"), ("Mode",), ("Result",)])
    style = "on green" if ok else "on red"
    table.add_row(hashValue, modeStr, result if ok else "not found", style=style)
    Console().print(table)

def iterCrackFile(filePath: str, mode: str):
    for item in crack_file(filePath, mode):
        if isinstance(item, tuple):
            if len(item) == 3:
                h, ok, res = item
            elif len(item) == 2:
                h, res = item
                ok = (res not in (None, "", "not found"))
            else:
                h, ok, res = str(item), False, "not found"
        else:
            h, ok, res = str(item), False, "not found"
        yield str(h), bool(ok), str(res)

def crackSingle(modeArg: str, hashValue: str):
    ok, res = crack(modeArg, hashValue)
    crackRow(hashValue, modeDisplay(modeArg), str(res), bool(ok))

def crackAll(pathStr: str):
    path = Path(pathStr).expanduser()
    if not path.is_file():
        Console().print(f"[bold red][!] File not found: {pathStr}[/bold red]")
        return
    try:
        total = sum(1 for _ in path.open(encoding="utf-8", errors="ignore"))
    except Exception:
        total = None
    results: List[Tuple[str, str, bool]] = []
    console = Console()
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TextColumn("{task.completed}/{task.total}" if total else "{task.completed}"), TimeElapsedColumn(), console=console) as progress:
        task = progress.add_task("Cracking (all modes)...", total=total or 0)
        for h, ok, res in iterCrackFile(str(path), "all"):
            results.append((h, res if ok else "not found", ok))
            progress.advance(task)
    table = styleTable([("Hash", "bold"), ("Mode",), ("Result",)], title="Result Crack File (all)")
    for h, msg, ok in results:
        style = "on green" if ok else "on red"
        table.add_row(h, "all", msg, style=style)
    Console().print(table)

def crackSingleMode(modeArg: str, pathStr: str):
    path = Path(pathStr).expanduser()
    if not path.is_file():
        Console().print(f"[bold red][!] File not found: {pathStr}[/bold red]")
        return
    try:
        total = sum(1 for _ in path.open(encoding="utf-8", errors="ignore"))
    except Exception:
        total = None
    rows: List[Tuple[str, str, bool]] = []
    console = Console()
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TextColumn("{task.completed}/{task.total}" if total else "{task.completed}"), TimeElapsedColumn(), console=console) as progress:
        task = progress.add_task(f"Cracking with mode '{modeArg}'...", total=total or 0)
        with path.open(encoding="utf-8", errors="ignore") as f:
            for line in f:
                h = line.strip()
                if not h:
                    progress.advance(task); continue
                ok, res = crack(modeArg, h)
                rows.append((h, res if ok else "not found", bool(ok)))
                progress.advance(task)
    titleStr = f"Result crack-file mode {modeDisplay(modeArg)}"
    table = styleTable([("Hash", "bold"), ("Mode",), ("Result",)], title=titleStr)
    for h, msg, ok in rows:
        style = "on green" if ok else "on red"
        table.add_row(h, modeDisplay(modeArg), msg, style=style)
    Console().print(table)

def analyzeFileAction(pathStr: str):
    path = Path(pathStr).expanduser()
    if not path.is_file():
        Console().print(f"[bold red][!] File not found: {pathStr}[/bold red]")
        return
    try:
        out = analyze_file(str(path))
        if isinstance(out, dict):
            if not out:
                Console().print("[bold yellow][!] No hashes in file.[/bold yellow]")
                return
            for h, cand in out.items():
                analyzeTable(str(h), cand)
            return
        if hasattr(out, "__iter__") and not isinstance(out, (str, bytes)):
            any_item = False
            for item in out:
                any_item = True
                if isinstance(item, tuple) and len(item) >= 2:
                    h, cand = str(item[0]), item[1]
                elif isinstance(item, dict) and "hash" in item:
                    h = str(item["hash"])
                    cand = item.get("candidates", item.get("result"))
                else:
                    h = str(item)
                    cand = analyze(h)
                analyzeTable(h, cand)
            if not any_item:
                Console().print("[bold yellow][!] No hashes in file.[/bold yellow]")
            return
        raise TypeError("Unsupported analyze_file() return type")
    except Exception:
        with path.open(encoding="utf-8", errors="ignore") as f:
            any_line = False
            for line in f:
                h = line.strip()
                if not h:
                    continue
                any_line = True
                analyzeTable(h, analyze(h))
            if not any_line:
                Console().print("[bold yellow][!] No hashes in file.[/bold yellow]")

def parseArgs():
    parser = argparse.ArgumentParser(prog="hashstation.py", description="Hashstation is a simple analyze and hash cracker using indonesia popular wordlists and rockyou")
    subparsers = parser.add_subparsers(dest="command", required=True)
    p_an = subparsers.add_parser("analyze", help="Analyze hash or file")
    p_an.add_argument("hashValue", nargs="?", help="Single hash for analyze")
    p_an.add_argument("-f", "--file", dest="filePath", help="Hash file for analyze")
    p_cr = subparsers.add_parser("crack", help="Crack hash atau file")
    p_cr.add_argument("hashValue", nargs="?", help="Single hash for crack")
    p_cr.add_argument("-f", "--file", dest="filePath", help="Hash file for crack")
    p_cr.add_argument("-m", "--mode", dest="modeArg", help="mode/algorithm to crack (e.g: 0, 1700, md5, sha512)")
    p_cr.add_argument("-a", "--all", action="store_true", help="crack use all mode for file")
    subparsers.add_parser("list", help="List all mode / algorithm")
    return parser.parse_args()

def main():
    args = parseArgs()
    if args.command == "list":
        listModes(); return
    if args.command == "analyze":
        if args.filePath:
            analyzeFileAction(args.filePath)
        elif args.hashValue:
            analyzeTable(args.hashValue, analyze(args.hashValue))
        else:
            Console().print("[bold red][!] Please give <hash> or -f <file>.[/bold red]")
        return
    if args.command == "crack":
        if args.filePath:
            if args.all:
                crackAll(args.filePath)
            elif args.modeArg:
                crackSingleMode(args.modeArg, args.filePath)
            else:
                Console().print("[bold red][!] For crack from file, use -m <mode> or -a.[/bold red]")
        else:
            if args.hashValue and args.modeArg:
                crackSingle(args.modeArg, args.hashValue)
            else:
                Console().print("[bold red][!] For single crack, use: crack -m <mode> <hash>.[/bold red]")
        return

def onSigInt(signum, frame):
    Console().print("\n[bold yellow]Interrupted.[/bold yellow]")

if __name__ == "__main__":
    signal.signal(signal.SIGINT, onSigInt)
    try:
        signal.signal(signal.SIGTSTP, signal.SIG_IGN)
    except AttributeError:
        pass
    main()
