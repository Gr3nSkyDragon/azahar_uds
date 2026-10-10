# Copyright 2026 Azahar Emulator Project. Licensed under GPLv2 or any later version.
"""PNG reading and writing, and animated GIF writing, with nothing outside the standard library.

The screen tools use these so that no image package (Pillow) has to be installed.
"""
import struct
import zlib

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_CHANNELS = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}  # colour type -> samples per pixel


def read_png(path):
    """-> (width, height, rows), each row a list of (r, g, b, a) tuples, 0..255.

    Reads every non-interlaced PNG: greyscale, RGB, palette, with or without alpha, at any bit depth (16-bit samples keep
    their high byte). Transparency from a tRNS chunk becomes alpha."""
    data = open(path, "rb").read()
    if data[:8] != PNG_SIGNATURE:
        raise ValueError(f"{path}: not a PNG file")
    chunks, idat, pos = {}, bytearray(), 8
    while pos + 8 <= len(data):
        length, kind = struct.unpack(">I4s", data[pos:pos + 8])
        body = data[pos + 8:pos + 8 + length]
        if kind == b"IDAT":
            idat += body
        else:
            chunks.setdefault(kind, body)
        pos += 12 + length
        if kind == b"IEND":
            break
    width, height, depth, colour, _, _, interlace = struct.unpack(">IIBBBBB", chunks[b"IHDR"])
    if interlace:
        raise ValueError(f"{path}: interlaced PNGs are not supported; save it without interlacing")
    if colour not in _CHANNELS:
        raise ValueError(f"{path}: unknown PNG colour type {colour}")
    raw = zlib.decompress(bytes(idat))
    samples = _CHANNELS[colour]
    bits_per_pixel = samples * depth
    stride = (width * bits_per_pixel + 7) // 8
    step = max(1, bits_per_pixel // 8)  # the filter's "previous pixel" distance in bytes
    palette = chunks.get(b"PLTE", b"")
    trns = chunks.get(b"tRNS", b"")

    def sample(line, index):
        """The index-th sample of a row, scaled to 0..255 (palette indices stay raw)."""
        if depth == 8:
            return line[index]
        if depth == 16:
            return line[index * 2]
        bit = index * depth
        value = (line[bit // 8] >> (8 - depth - bit % 8)) & ((1 << depth) - 1)
        return value if colour == 3 else value * 255 // ((1 << depth) - 1)

    def raw_sample(line, index):
        """The index-th sample unscaled, for comparing with a tRNS key."""
        if depth == 16:
            return line[index * 2] << 8 | line[index * 2 + 1]
        if depth == 8:
            return line[index]
        bit = index * depth
        return (line[bit // 8] >> (8 - depth - bit % 8)) & ((1 << depth) - 1)

    rows, previous = [], bytearray(stride)
    for y in range(height):
        start = y * (stride + 1)
        kind = raw[start]
        line = bytearray(raw[start + 1:start + 1 + stride])
        for i in range(stride):
            left = line[i - step] if i >= step else 0
            up = previous[i]
            up_left = previous[i - step] if i >= step else 0
            if kind == 1:
                line[i] = (line[i] + left) & 0xFF
            elif kind == 2:
                line[i] = (line[i] + up) & 0xFF
            elif kind == 3:
                line[i] = (line[i] + (left + up) // 2) & 0xFF
            elif kind == 4:
                guess = left + up - up_left
                distances = (abs(guess - left), abs(guess - up), abs(guess - up_left))
                nearest = left if distances[0] <= distances[1] and distances[0] <= distances[2] else \
                    up if distances[1] <= distances[2] else up_left
                line[i] = (line[i] + nearest) & 0xFF
        previous = line
        row = []
        for x in range(width):
            if colour == 3:
                index = sample(line, x)
                r, g, b = palette[index * 3:index * 3 + 3] or (0, 0, 0)
                row.append((r, g, b, trns[index] if index < len(trns) else 255))
            elif colour == 0:
                grey = sample(line, x)
                key = struct.unpack(">H", trns[:2])[0] if len(trns) >= 2 else None
                row.append((grey, grey, grey, 0 if raw_sample(line, x) == key else 255))
            elif colour == 4:
                grey = sample(line, x * 2)
                row.append((grey, grey, grey, sample(line, x * 2 + 1)))
            elif colour == 2:
                rgb = tuple(sample(line, x * 3 + c) for c in range(3))
                key = struct.unpack(">HHH", trns[:6]) if len(trns) >= 6 else None
                raw_rgb = tuple(raw_sample(line, x * 3 + c) for c in range(3))
                row.append(rgb + (0 if raw_rgb == key else 255,))
            else:
                row.append(tuple(sample(line, x * 4 + c) for c in range(4)))
        rows.append(row)
    return width, height, rows


def write_png(path, width, height, rgb_rows):
    """Writes an 8-bit RGB PNG; rgb_rows is a list of rows of (r, g, b)."""
    raw = b"".join(b"\0" + bytes(c for pixel in row for c in pixel) for row in rgb_rows)

    def chunk(kind, body):
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body) & 0xFFFFFFFF)

    with open(path, "wb") as out:
        out.write(PNG_SIGNATURE)
        out.write(chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)))
        out.write(chunk(b"IDAT", zlib.compress(raw, 9)))
        out.write(chunk(b"IEND", b""))


def _lzw(indices, min_code_size):
    """GIF's variable-width LZW, emitting a clear code whenever the table fills."""
    clear, end = 1 << min_code_size, (1 << min_code_size) + 1
    out, bit_buffer, bit_count = bytearray(), 0, 0

    def emit(code, width):
        nonlocal bit_buffer, bit_count
        bit_buffer |= code << bit_count
        bit_count += width
        while bit_count >= 8:
            out.append(bit_buffer & 0xFF)
            bit_buffer >>= 8
            bit_count -= 8

    def reset():
        return {(i,): i for i in range(clear)}, end + 1, min_code_size + 1

    table, next_code, width = reset()
    emit(clear, width)
    current = ()
    for index in indices:
        candidate = current + (index,)
        if candidate in table:
            current = candidate
            continue
        emit(table[current], width)
        if next_code < 4096:
            table[candidate] = next_code
            next_code += 1
            if next_code > (1 << width) and width < 12:
                width += 1
        else:
            emit(clear, width)
            table, next_code, width = reset()
        current = (index,)
    if current:
        emit(table[current], width)
    emit(end, width)
    if bit_count:
        out.append(bit_buffer & 0xFF)
    return bytes(out)


def write_gif(path, width, height, frames, palette, delay_cs):
    """Writes a looping animated GIF. frames: list of index rows (lists of palette indices); palette: up to four (r, g, b);
    delay_cs: each frame's time in hundredths of a second."""
    palette = list(palette) + [(0, 0, 0)] * (4 - len(palette))
    with open(path, "wb") as out:
        out.write(b"GIF89a" + struct.pack("<HHBBB", width, height, 0x81, 0, 0))  # global table of 4 colours
        out.write(bytes(c for colour in palette[:4] for c in colour))
        out.write(b"\x21\xFF\x0BNETSCAPE2.0\x03\x01\x00\x00\x00")  # loop forever
        for frame in frames:
            out.write(b"\x21\xF9\x04\x00" + struct.pack("<H", delay_cs) + b"\x00\x00")
            out.write(b"\x2C" + struct.pack("<HHHHB", 0, 0, width, height, 0))
            data = _lzw([i for row in frame for i in row], 2)
            out.write(b"\x02")
            for i in range(0, len(data), 255):
                block = data[i:i + 255]
                out.write(bytes([len(block)]) + block)
            out.write(b"\x00")
        out.write(b"\x3B")
