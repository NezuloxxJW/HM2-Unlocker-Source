"""
=======================================================
  HM2 Démo - Runtime Unlocker - Nezuloxx / T @Kertopia  
  Appartient à SystemA et TMS - Systèmes sons suisses  
=======================================================

Patches D3D11 :
  P1 : tier licence -> Pro+   (sig disp32 -> qword_144648500 -> MainWindow -> LicStruct)
  P2 : watermarkEnabled -> 0  (sig -> patch bytes)
  P3 : WatermarkNode_updateBBoxAndUV -> retn  (sig -> patch bytes)

Traduit de C++ en Python
"""
__sp__ = 23


import ctypes
import ctypes.wintypes as wt
import struct
import sys
import time
from dataclasses import dataclass, field
from typing import Optional, Tuple

PROCESS_ALL_ACCESS     = 0x1F0FFF
TH32CS_SNAPPROCESS     = 0x00000002
TH32CS_SNAPMODULE      = 0x00000008
TH32CS_SNAPMODULE32    = 0x00000010
PAGE_EXECUTE_READWRITE = 0x40
PRO_PLUS_TIER          = 0x622117CB

kernel32 = ctypes.windll.kernel32


# ── Win32 structs ─────────────────────────────────────────────────────────────

class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize",              wt.DWORD),
        ("cntUsage",            wt.DWORD),
        ("th32ProcessID",       wt.DWORD),
        ("th32DefaultHeapID",   ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID",        wt.DWORD),
        ("cntThreads",          wt.DWORD),
        ("th32ParentProcessID", wt.DWORD),
        ("pcPriClassBase",      ctypes.c_long),
        ("dwFlags",             wt.DWORD),
        ("szExeFile",           ctypes.c_char * 260),
    ]


class MODULEENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize",        wt.DWORD),
        ("th32ModuleID",  wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("GlblcntUsage",  wt.DWORD),
        ("ProccntUsage",  wt.DWORD),
        ("modBaseAddr",   ctypes.POINTER(wt.BYTE)),
        ("modBaseSize",   wt.DWORD),
        ("hModule",       wt.HMODULE),
        ("szModule",      ctypes.c_char * 256),
        ("szExePath",     ctypes.c_char * 260),
    ]


# ── Memory I/O ────────────────────────────────────────────────────────────────

def read(hproc, addr: int, fmt: str):
    size = struct.calcsize(fmt)
    buf  = ctypes.create_string_buffer(size)
    n    = ctypes.c_size_t(0)
    kernel32.ReadProcessMemory(hproc, ctypes.c_void_p(addr), buf, size, ctypes.byref(n))
    return struct.unpack_from(fmt, buf)[0] if n.value == size else None


def read_bytes(hproc, addr: int, size: int) -> bytes:
    buf = ctypes.create_string_buffer(size)
    n   = ctypes.c_size_t(0)
    kernel32.ReadProcessMemory(hproc, ctypes.c_void_p(addr), buf, size, ctypes.byref(n))
    return bytes(buf[:n.value])


def write_bytes(hproc, addr: int, data: bytes) -> bool:
    old = wt.DWORD(0)
    kernel32.VirtualProtectEx(hproc, ctypes.c_void_p(addr), len(data), PAGE_EXECUTE_READWRITE, ctypes.byref(old))
    n  = ctypes.c_size_t(0)
    ok = kernel32.WriteProcessMemory(hproc, ctypes.c_void_p(addr), data, len(data), ctypes.byref(n))
    kernel32.VirtualProtectEx(hproc, ctypes.c_void_p(addr), len(data), old, ctypes.byref(old))
    return bool(ok) and n.value == len(data)


# ── Process helpers ───────────────────────────────────────────────────────────

def find_pid(exe: str) -> Optional[int]:
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    e = PROCESSENTRY32(); e.dwSize = ctypes.sizeof(PROCESSENTRY32)
    if not kernel32.Process32First(snap, ctypes.byref(e)):
        kernel32.CloseHandle(snap); return None
    while True:
        if e.szExeFile.decode(errors="replace").lower() == exe.lower():
            kernel32.CloseHandle(snap); return e.th32ProcessID
        if not kernel32.Process32Next(snap, ctypes.byref(e)): break
    kernel32.CloseHandle(snap); return None


def get_module_info(pid: int, mod: str) -> Tuple[int, int]:
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    e = MODULEENTRY32(); e.dwSize = ctypes.sizeof(MODULEENTRY32)
    if not kernel32.Module32First(snap, ctypes.byref(e)):
        kernel32.CloseHandle(snap); return 0, 0
    while True:
        if mod.lower() in e.szModule.decode(errors="replace").lower():
            base = ctypes.cast(e.modBaseAddr, ctypes.c_void_p).value
            kernel32.CloseHandle(snap); return base, e.modBaseSize
        if not kernel32.Module32Next(snap, ctypes.byref(e)): break
    kernel32.CloseHandle(snap); return 0, 0


# ── Patch descriptors ─────────────────────────────────────────────────────────

@dataclass
class Patch:
    name:      str
    sig:       list          
    patch_off: int           
    orig:      Optional[bytes]        
    patched:   Optional[bytes]        
    desc:      str
    tier_chain: Tuple[int, ...] = field(default_factory=tuple)  # (mw_lic_off, lic_tier_off)
    # set par scan()
    hit_va:    int  = 0
    is_patched: bool = False
    found:     bool = False

    @property
    def patch_va(self) -> int:
        return self.hit_va + self.patch_off

    def patched_sig(self) -> Optional[list]:
        if not self.patched:
            return None
        s = list(self.sig)
        for i, b in enumerate(self.patched):
            s[self.patch_off + i] = b
        return s


PATCHES = [
    # P1 - sub_14063DF30 : bool { return qword_144648500 != 0; }
    #   48 8B 05 [disp32:4B] 90  48 85 C0  0F 95 C0  C3
    #   patch_off=3 -> patch_va = disp32
    #   addr_global = patch_va + 4 + disp32
    #   mainwindow  = *(addr_global)
    #   lic_struct  = *(mainwindow + 0x1C0)
    #   tier        =  lic_struct + 0x10  -> PRO_PLUS_TIER
    Patch(
        name="tier licence -> Pro+",
        sig=[
            0x48, 0x8B, 0x05, None, None, None, None,  
            0x90,         
            0x48, 0x85, 0xC0,      
            0x0F, 0x95, 0xC0,      
            0xC3,         
        ],
        patch_off=3,
        orig=None, patched=None, # actiavte tier_chain
        desc="sig -> MainWindow -> LicStruct -> tier",
        tier_chain=(0x1C0, 0x10),
    ),

    # P2 - watermark init (WatermarkNode ctor ou équivalent)
    #   4C 89 75 F0  40 88 75 E0  33 F6  48 89 75 C0  48 89 75 D0
    #   [rbp-0x20] = al (watermarkEnabled)
    #   mov [rbp-0x20], sil -> mov byte [rbp-0x20], 0
    Patch(
        name="watermarkEnabled 1->0",
        sig=[
            0x4C, 0x89, 0x75, 0xF0,
            0x40, 0x88, 0x75, 0xE0,
            0x33, 0xF6,
            0x48, 0x89, 0x75, 0xC0,
            0x48, 0x89, 0x75, 0xD0,
        ],
        patch_off=4,
        orig=bytes([0x40, 0x88, 0x75, 0xE0]),
        patched=bytes([0xC6, 0x45, 0xE0, 0x00]),
        desc="Force watermarkEnabled with 0",
    ),

    # P3 - WatermarkNode::updateBBoxAndUV
    #   Force retn as first instruction to skip it
    Patch(
        name="WatermarkNode_updateBBoxAndUV early return",
        sig=[
            0x48, 0x89, 0x5c, 0x24, 0x10,
            0x48, 0x89, 0x74, 0x24, 0x18,
            0x55, 0x57, 0x41, 0x56,
            0x48, 0x8d, 0x6c, 0x24, 0xb9,
            0x48, 0x81, 0xec, 0x90, 0x00, 0x00, 0x00,
        ],
        patch_off=0,
        orig=bytes([0x48]),
        patched=bytes([0xC3]),
        desc="WatermarkNode_updateBBoxAndUV early retn",
    ),
]


# ── Scan ──────────────────────────────────────────────────────────────────────

def sig_match(data: bytes, off: int, sig: list) -> bool:
    if off + len(sig) > len(data): return False
    return all(b is None or data[off + i] == b for i, b in enumerate(sig))


def scan(hproc, base: int, mod_size: int, patches: list) -> None:
    CHUNK   = 0x100000
    max_sig = max(len(p.sig) for p in patches)
    psigs   = [(p, p.patched_sig()) for p in patches]
    pending = list(psigs)
    for chunk_off in range(0, mod_size, CHUNK):
        if not pending: break
        data  = read_bytes(hproc, base + chunk_off, min(CHUNK + max_sig, mod_size - chunk_off))
        if not data: continue
        still = []
        for p, psig in pending:
            va  = base + chunk_off
            hit = next((i for i in range(len(data) - len(p.sig) + 1)
                        if sig_match(data, i, p.sig)), -1)
            if hit >= 0:
                p.hit_va = va + hit; p.is_patched = False; p.found = True; continue
            if psig:
                hit2 = next((i for i in range(len(data) - len(psig) + 1)
                             if sig_match(data, i, psig)), -1)
                if hit2 >= 0:
                    p.hit_va = va + hit2; p.is_patched = True; p.found = True; continue
            still.append((p, psig))
        pending = still


# ── Apply ─────────────────────────────────────────────────────────────────────

def apply_tier_chain(hproc, p: Patch, dry_run: bool) -> int:
    mw_off, tier_off = p.tier_chain

    disp32 = read(hproc, p.patch_va, '<i')
    if disp32 is None:
        print(f"    [!] lecture disp32 échouée"); return -1

    addr_global = p.patch_va + 4 + disp32

    mainwindow = 0
    for _ in range(30):
        mainwindow = read(hproc, addr_global, '<Q') or 0
        if mainwindow: break
        time.sleep(0.5)
    if not mainwindow:
        print(f"    [!] MainWindow non initialisé après 15s"); return -1

    lic_struct = read(hproc, mainwindow + mw_off, '<Q') or 0
    if not lic_struct:
        print(f"    [!] LicStruct introuvable"); return -1

    tier_va  = lic_struct + tier_off
    cur_tier = read(hproc, tier_va, '<I')
    if cur_tier is None:
        print(f"    [!] lecture tier échouée"); return -1

    if cur_tier == PRO_PLUS_TIER:
        print(f"    [+] déjà Pro+ (0x{PRO_PLUS_TIER:08X})"); return 0

    if dry_run:
        print(f"    [~] 0x{cur_tier:08X} -> 0x{PRO_PLUS_TIER:08X}"); return 0

    if write_bytes(hproc, tier_va, struct.pack('<I', PRO_PLUS_TIER)):
        print(f"    [+] 0x{cur_tier:08X} -> 0x{PRO_PLUS_TIER:08X} (Pro+)"); return 1

    print(f"    [!] WriteProcessMemory échoué (err {kernel32.GetLastError()})"); return -1


def run(dry_run: bool):
    label = "Checker" if dry_run else "Apply"
    print(f"[HeavyM 2 - Unlocker - {label} | T @Kertopia / Nezuloxx]")

    pid = find_pid("HeavyM 2.exe")
    if not pid: print("[!] HeavyM 2.exe non trouvé."); sys.exit(1)
    print(f"[+] PID {pid}")

    base, mod_size = get_module_info(pid, "HeavyM 2.exe")
    if not base: print("[!] Module introuvable."); sys.exit(1)
    print(f"[+] Base 0x{base:016X}  Taille 0x{mod_size:X}")

    hproc = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not hproc:
        print(f"[!] OpenProcess échoué (err {kernel32.GetLastError()}) - lancer en Admin.")
        sys.exit(1)

    print(f"[*] Scan ({len(PATCHES)} sigs) ...")
    t0 = time.perf_counter()
    scan(hproc, base, mod_size, PATCHES)
    print(f"[+] {time.perf_counter() - t0:.2f}s\n")

    applied = already = failed = 0

    for p in PATCHES:
        if not p.found:
            print(f"[!] {p.name}\n    Signature NON TROUVÉE")
            failed += 1
            continue

        print(f"[*] {p.name}")
        print(f"    sig @ 0x{p.hit_va:016X}  patch @ 0x{p.patch_va:016X}")

        if p.tier_chain:
            r = apply_tier_chain(hproc, p, dry_run)
            if   r > 0: applied += 1
            elif r < 0: failed  += 1
            else:       already += 1
            continue

        if p.is_patched:
            print(f"    [+] déjà appliqué")
            already += 1
            continue

        if dry_run:
            print(f"    [~] {p.orig.hex()} -> {p.patched.hex()}")
            continue

        cur = read_bytes(hproc, p.patch_va, len(p.orig))
        if cur != p.orig:
            print(f"    [!] bytes inattendus : {cur.hex(' ').upper()}")
            failed += 1
            continue

        if write_bytes(hproc, p.patch_va, p.patched):
            print(f"    [+] {p.orig.hex()} -> {p.patched.hex()}")
            applied += 1
        else:
            print(f"    [!] WriteProcessMemory échoué (err {kernel32.GetLastError()})")
            failed += 1

    print(f"\n{'─' * 50}")
    print(f"  Appliqués : {applied}   Déjà en place : {already}   Échecs : {failed}")
    kernel32.CloseHandle(hproc)
    if not dry_run and not failed:
        print("\n-> Ferme et rouvre la fenêtre projecteur.")
    print("[+] Terminé.")


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--checker", action="store_true")
    run(dry_run=not ap.parse_args().checker)
