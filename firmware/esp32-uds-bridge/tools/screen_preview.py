# Copyright 2026 Azahar Emulator Project. Licensed under GPLv2 or any later version.
"""Previews the board's screen on a PC, without flashing: builds the firmware's own drawing code (main/scene.c,
main/screen.c) with a PC compiler, draws every clip listed in tools/screen_preview/preview.c and writes them as pictures.

    python tools/screen_preview.py                  -> tools/screen_preview/out/
    python tools/screen_preview.py --color twotone  (the 0.96" modules with a yellow top band)
    python tools/screen_preview.py --only radio     (just the clips whose name contains "radio")

Per clip: <name>.png (its first frame, enlarged) and, when it has more than one frame, <name>.gif (animated, at the
board's 50 ms per frame). all.png puts every clip's first frame on one sheet.

Needs a C compiler for Windows on the PC: MSYS2's gcc (E:/msys64/ucrt64/bin, C:/msys64/ucrt64/bin or on PATH) is found
by itself; --cc names another (clang, or gcc somewhere else).
"""
import argparse
import os
import shutil
import struct
import subprocess
import sys

from pngio import write_png, write_gif

HERE = os.path.dirname(os.path.abspath(__file__))
FIRMWARE = os.path.dirname(HERE)
PREVIEW = os.path.join(HERE, "screen_preview")
W, H = 128, 64
FRAME_BYTES = W * H // 8
FRAME_CS = 5  # 50 ms, in the GIF's hundredths of a second

COLOURS = {
    "white": ((235, 245, 255), None),
    "blue": ((90, 190, 255), None),
    "yellow": ((255, 220, 60), None),
    "twotone": ((255, 220, 60), (90, 190, 255)),  # rows 0-15 yellow, the rest blue
}
OFF = (8, 10, 16)
BORDER = (45, 45, 50)


def find_compiler(requested):
    if requested:
        return requested
    for candidate in ("gcc", "E:/msys64/ucrt64/bin/gcc.exe", "C:/msys64/ucrt64/bin/gcc.exe",
                      "E:/msys64/mingw64/bin/gcc.exe", "C:/msys64/mingw64/bin/gcc.exe", "clang"):
        found = shutil.which(candidate) or (candidate if os.path.isfile(candidate) else None)
        if found:
            return found
    raise SystemExit("No C compiler found. Install MSYS2's gcc (pacman -S mingw-w64-ucrt-x86_64-gcc) or pass --cc.")


def build_and_run(cc):
    build = os.path.join(PREVIEW, "build")
    os.makedirs(build, exist_ok=True)
    exe = os.path.join(build, "preview.exe" if os.name == "nt" else "preview")
    command = [cc, "-std=c11", "-O1", "-Wall", "-Wextra", "-Wno-unused-function",
               "-I", os.path.join(PREVIEW, "stub"), "-I", os.path.join(FIRMWARE, "main"),
               os.path.join(PREVIEW, "preview.c"), os.path.join(FIRMWARE, "main", "screen.c"), "-o", exe]
    env = dict(os.environ)
    # MSYS2's gcc finds its own helpers (cc1, as, ld) through PATH.
    env["PATH"] = os.path.dirname(cc) + os.pathsep + env.get("PATH", "") if os.path.dirname(cc) else env.get("PATH", "")
    result = subprocess.run(command, env=env, capture_output=True, text=True)
    if result.stdout or result.stderr:
        print(result.stdout + result.stderr, end="", file=sys.stderr)
    if result.returncode:
        raise SystemExit("The preview did not compile (errors above).")
    frames_file = os.path.join(build, "frames.bin")
    subprocess.run([exe, frames_file], env=env, check=True)
    return open(frames_file, "rb").read()


def parse(data):
    clips, pos = [], 0
    while pos < len(data):
        end = data.index(b"\0", pos)
        name = data[pos:end].decode()
        count = struct.unpack("<H", data[end + 1:end + 3])[0]
        pos = end + 3
        frames = [data[pos + i * FRAME_BYTES:pos + (i + 1) * FRAME_BYTES] for i in range(count)]
        pos += count * FRAME_BYTES
        clips.append((name, frames))
    return clips


def lit(frame, x, y):
    return frame[x + W * (y // 8)] >> (y % 8) & 1


def colour_rows(frame, scale, colour):
    top, rest = COLOURS[colour]
    rows = []
    for y in range(H):
        on = top if rest is None or y < 16 else rest
        row = []
        for x in range(W):
            row += [on if lit(frame, x, y) else OFF] * scale
        rows += [row] * scale
    return rows


def index_rows(frame, scale, colour):
    """For the GIF: 0 off, 1 lit (top band), 2 lit (rest)."""
    rest = COLOURS[colour][1]
    rows = []
    for y in range(H):
        on = 1 if rest is None or y < 16 else 2
        row = []
        for x in range(W):
            row += [on if lit(frame, x, y) else 0] * scale
        rows += [row] * scale
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", default=os.path.join(PREVIEW, "out"), help="where the pictures go")
    parser.add_argument("--scale", type=int, default=4, help="screen pixels per picture pixel (default 4)")
    parser.add_argument("--color", choices=sorted(COLOURS), default="white", help="the panel's colour")
    parser.add_argument("--only", help="only clips whose name contains this")
    parser.add_argument("--cc", help="the C compiler to use")
    args = parser.parse_args()

    clips = parse(build_and_run(find_compiler(args.cc)))
    if args.only:
        clips = [c for c in clips if args.only in c[0]]
    os.makedirs(args.out, exist_ok=True)
    top, rest = COLOURS[args.color]
    palette = [OFF, top, rest or top]
    for name, frames in clips:
        write_png(os.path.join(args.out, f"{name}.png"), W * args.scale, H * args.scale,
                  colour_rows(frames[0], args.scale, args.color))
        if len(frames) > 1:
            write_gif(os.path.join(args.out, f"{name}.gif"), W * args.scale, H * args.scale,
                      [index_rows(f, args.scale, args.color) for f in frames], palette, FRAME_CS)

    # The sheet: every clip's first frame, two across, with a border.
    scale, gap, across = 2, 6, 2
    cell_w, cell_h = W * scale + gap, H * scale + gap
    down = (len(clips) + across - 1) // across
    sheet = [[BORDER] * (cell_w * across + gap) for _ in range(cell_h * down + gap)]
    for i, (_, frames) in enumerate(clips):
        x0, y0 = gap + (i % across) * cell_w, gap + (i // across) * cell_h
        for y, row in enumerate(colour_rows(frames[0], scale, args.color)):
            sheet[y0 + y][x0:x0 + len(row)] = row
    write_png(os.path.join(args.out, "all.png"), len(sheet[0]), len(sheet), sheet)
    print(f"{len(clips)} clip(s) -> {args.out}")


if __name__ == "__main__":
    main()
