# Copyright 2026 Azahar Emulator Project. Licensed under GPLv2 or any later version.
"""Turns PNG pictures into one-bit images for the board's screen, as a C header that main/ includes.

    python tools/img2c.py -o main/images.h art/ball.png art/cable.png
    python tools/img2c.py -o main/images.h --mode dark art/logo.png        (drawn black on white)
    python tools/img2c.py -o main/images.h --frames 4 art/ball_spin.png    (four frames side by side)
    python tools/img2c.py -o main/sprites.h --mode sprite --size 48 25.png (a colour Pokemon sprite)

Each picture becomes `kImg<Name>` with `IMG_<NAME>_W` / `IMG_<NAME>_H`, drawn with
`fb_image(fb, x, y, IMG_<NAME>_W, IMG_<NAME>_H, kImg<Name>, true)` (screen.h). With --frames the array has one entry per
frame and `IMG_<NAME>_FRAMES` says how many; the width is one frame's.

Which pixels light up (--mode):
  light   bright, opaque pixels (art drawn light on black or on transparency). The default.
  dark    dark, opaque pixels (art drawn black on white, as in most paint programs).
  alpha   every opaque pixel, whatever its colour (silhouettes).
  sprite  colour pixel art such as Pokemon sprites: cropped to what is visible, the body lit, the dark outline and the
          darker inner lines (eyes, mouth, limbs) left dark, with the cut chosen per picture so dark Pokemon still show.
--size N shrinks a picture to fit N x N (never enlarges); --threshold sets the light/dark cut (0..255) for light and dark.
Every picture is also printed to the terminal so the result can be checked before building.
"""
import argparse
import os
import re
import sys

from pngio import read_png, write_png


def luma(pixel):
    return (299 * pixel[0] + 587 * pixel[1] + 114 * pixel[2]) // 1000


def crop_visible(rows):
    """Crops to the opaque pixels; returns rows unchanged when nothing is opaque."""
    points = [(x, y) for y, row in enumerate(rows) for x, p in enumerate(row) if p[3] >= 128]
    if not points:
        return rows
    x0, x1 = min(x for x, _ in points), max(x for x, _ in points) + 1
    y0, y1 = min(y for _, y in points), max(y for _, y in points) + 1
    return [row[x0:x1] for row in rows[y0:y1]]


def shrink(rows, size):
    """Fits rows into size x size by area: a target pixel is opaque when at least half its box is, and takes the darker
    third of the box's opaque pixels so a thin outline crossing it survives."""
    height, width = len(rows), len(rows[0])
    factor = max(width, height) / size
    if factor <= 1:
        return rows
    out = []
    for ty in range(max(1, round(height / factor))):
        y0, y1 = int(ty * factor), max(int(ty * factor) + 1, int((ty + 1) * factor))
        row = []
        for tx in range(max(1, round(width / factor))):
            x0, x1 = int(tx * factor), max(int(tx * factor) + 1, int((tx + 1) * factor))
            box = [rows[y][x] for y in range(y0, min(y1, height)) for x in range(x0, min(x1, width))]
            opaque = sorted((p for p in box if p[3] >= 128), key=luma)
            if box and len(opaque) * 2 >= len(box):
                pick = opaque[len(opaque) // 3]
                row.append((pick[0], pick[1], pick[2], 255))
            else:
                row.append((0, 0, 0, 0))
        out.append(row)
    return out


def sprite_bits(rows):
    """Colour pixel art to lit body / dark lines."""
    lumas = sorted(luma(p) for row in rows for p in row if p[3] >= 128)
    if not lumas:
        return [[False] * len(rows[0]) for _ in rows]
    # Outlines are the darkest tenth or so of a sprite; the cut sits just above them, so a dark Pokemon keeps its body.
    cut = min(70, max(24, lumas[len(lumas) // 10] + 8))
    height, width = len(rows), len(rows[0])
    lit = [[rows[y][x][3] >= 128 and luma(rows[y][x]) > cut for x in range(width)] for y in range(height)]
    bits = [row[:] for row in lit]
    for y in range(height):
        for x in range(width):
            if not lit[y][x]:
                continue
            here = luma(rows[y][x])
            neighbours = [luma(rows[j][i]) for i, j in ((x - 1, y), (x + 1, y), (x, y - 1), (x, y + 1))
                          if 0 <= i < width and 0 <= j < height and rows[j][i][3] >= 128]
            # A pixel clearly darker than the brightest one beside it is an inner line: leave it dark.
            if neighbours and max(neighbours) - here > 45 and here * 10 < max(neighbours) * 7:
                bits[y][x] = False
    return bits


def to_bits(rows, mode, threshold):
    if mode == "sprite":
        return sprite_bits(rows)
    if mode == "alpha":
        return [[p[3] >= 128 for p in row] for row in rows]
    if mode == "dark":
        return [[p[3] >= 128 and luma(p) < threshold for p in row] for row in rows]
    return [[p[3] >= 128 and luma(p) >= threshold for p in row] for row in rows]


def pack(bits):
    """Rows padded to whole bytes, most significant bit leftmost (fb_image's layout)."""
    out = bytearray()
    for row in bits:
        for start in range(0, len(row), 8):
            byte = 0
            for i, on in enumerate(row[start:start + 8]):
                if on:
                    byte |= 0x80 >> i
            out.append(byte)
    return bytes(out)


def c_name(path):
    """ball_spin.png -> ("BallSpin", "BALL_SPIN"); a name starting with a digit (25.png) gets an N in front."""
    stem = os.path.splitext(os.path.basename(path))[0]
    words = [w for w in re.split(r"[^A-Za-z0-9]+", stem) if w]
    if not words:
        raise SystemExit(f"{path}: cannot make a C name from this file name")
    prefix = "N" if words[0][0].isdigit() else ""
    camel = prefix + "".join(w[:1].upper() + w[1:] for w in words)
    upper = prefix + "_".join(w.upper() for w in words)
    return camel, upper


def show(name, bits):
    print(f"{name}: {len(bits[0]) if bits else 0} x {len(bits)}")
    for row in bits:
        print("".join("#" if on else "." for on in row))
    print()


def c_array(data, indent="    "):
    lines = []
    for start in range(0, len(data), 16):
        lines.append(indent + ", ".join(f"0x{b:02X}" for b in data[start:start + 16]) + ",")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("images", nargs="+", help="PNG files; the file name becomes the C name (ball_spin.png -> kImgBallSpin)")
    parser.add_argument("-o", "--output", required=True, help="the header to write, e.g. main/images.h")
    parser.add_argument("--mode", choices=("light", "dark", "alpha", "sprite"), default="light")
    parser.add_argument("--threshold", type=int, default=128, help="light/dark cut for --mode light and dark (default 128)")
    parser.add_argument("--size", type=int, help="shrink each picture (or frame) to fit size x size")
    parser.add_argument("--frames", type=int, default=1, help="the picture holds this many frames side by side")
    parser.add_argument("--preview", help="also write the result, enlarged, to this PNG")
    parser.add_argument("--quiet", action="store_true", help="do not print the pictures")
    args = parser.parse_args()

    blocks, previews = [], []
    for path in args.images:
        width, height, rows = read_png(path)
        if args.frames < 1 or width % args.frames:
            raise SystemExit(f"{path}: {width} pixels wide does not split into {args.frames} equal frames")
        frame_width = width // args.frames
        frames = []
        for f in range(args.frames):
            frame = [row[f * frame_width:(f + 1) * frame_width] for row in rows]
            if args.mode == "sprite":
                frame = crop_visible(frame)
            if args.size:
                frame = shrink(frame, args.size)
            frames.append(to_bits(frame, args.mode, args.threshold))
        sizes = {(len(b[0]), len(b)) for b in frames}
        if len(sizes) > 1:
            raise SystemExit(f"{path}: the frames came out different sizes {sorted(sizes)}; use a mode other than sprite")
        camel, upper = c_name(path)
        w, h = sizes.pop()
        if w > 128 or h > 64:
            print(f"warning: {path} is {w} x {h}, larger than the 128 x 64 screen; --size shrinks it", file=sys.stderr)
        if not args.quiet:
            for i, bits in enumerate(frames):
                show(f"kImg{camel}" + (f"[{i}]" if args.frames > 1 else ""), bits)
        packed = [pack(bits) for bits in frames]
        block = [f"/* {os.path.basename(path)} */", f"#define IMG_{upper}_W {w}", f"#define IMG_{upper}_H {h}"]
        if args.frames > 1:
            block.append(f"#define IMG_{upper}_FRAMES {args.frames}")
            block.append(f"static const uint8_t kImg{camel}[{args.frames}][{len(packed[0])}] = {{")
            for data in packed:
                block += ["    {", c_array(data, "        "), "    },"]
            block.append("};")
        else:
            block += [f"static const uint8_t kImg{camel}[{len(packed[0])}] = {{", c_array(packed[0]), "};"]
        blocks.append("\n".join(block))
        previews += frames

    guard = "UDS_" + re.sub(r"[^A-Z0-9]+", "_", os.path.basename(args.output).upper())
    command = "python tools/img2c.py " + " ".join(a.replace("\\", "/") for a in sys.argv[1:])
    header = "\n".join([
        "/* Generated by tools/img2c.py: do not edit by hand; change the pictures and run it again:",
        f" *   {command}",
        " */",
        f"#ifndef {guard}",
        f"#define {guard}",
        "",
        "#include <stdint.h>",
        "",
        "\n\n".join(blocks),
        "",
        "#endif",
        "",
    ])
    with open(args.output, "w", newline="\n") as out:
        out.write(header)
    print(f"wrote {args.output}: {len(blocks)} picture(s)")

    if args.preview:
        scale, gap = 4, 4
        width = max(len(b[0]) for b in previews) * scale
        height = sum(len(b) * scale + gap for b in previews)
        canvas = [[(40, 40, 40)] * width for _ in range(height)]
        y = 0
        for bits in previews:
            for row_index, row in enumerate(bits):
                for col, on in enumerate(row):
                    colour = (230, 240, 255) if on else (0, 0, 0)
                    for dy in range(scale):
                        for dx in range(scale):
                            canvas[y + row_index * scale + dy][col * scale + dx] = colour
            y += len(bits) * scale + gap
        write_png(args.preview, width, height, canvas)
        print(f"wrote {args.preview}")


if __name__ == "__main__":
    main()
