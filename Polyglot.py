#!/usr/bin/env python3
"""
PNG <-> PDF dual-header polyglot maker (GUI)
- Select a PDF and a PNG.
- The script inserts an uncompressed iTXt chunk immediately after the IHDR chunk
  whose payload begins with the PDF bytes (so %PDF is within the first ~100 bytes).
- The result is a single file that most PNG viewers will show as an image, and
  most PDF viewers will detect %PDF early and display the PDF.
"""

import struct
import zlib
import tkinter as tk
from tkinter import filedialog, messagebox
import os

def make_png_chunk(chunk_type: bytes, data: bytes) -> bytes:
    """Return a PNG chunk: length(4) + type(4) + data + crc(4)."""
    assert len(chunk_type) == 4
    length = struct.pack(">I", len(data))
    crc = struct.pack(">I", zlib.crc32(chunk_type + data) & 0xFFFFFFFF)
    return length + chunk_type + data + crc

def create_itxt_with_pdf(keyword: str, pdf_bytes: bytes) -> bytes:
    """
    Build an iTXt chunk whose text payload begins with the raw PDF bytes.
    iTXt format: keyword\0 compression_flag(1) compression_method(1) language_tag\0 translated_keyword\0 text
    We will set compression_flag=0 (no compression) and leave language_tag and translated_keyword empty.
    """
    # keyword must be 1-79 bytes; use latin-1 safe encoding
    kw = keyword.encode("latin-1")
    compression_flag = b"\x00"   # 0 = uncompressed
    compression_method = b"\x00" # irrelevant when flag=0
    language_tag_terminated = b"\x00"  # empty language tag, terminated
    translated_keyword_terminated = b"\x00"  # empty translated keyword, terminated

    # iTXt data = keyword + \0 + compression_flag + compression_method + language_tag\0 + translated_keyword\0 + text
    data = kw + b"\x00" + compression_flag + compression_method + language_tag_terminated + translated_keyword_terminated + pdf_bytes

    return make_png_chunk(b"iTXt", data)

def find_ihdr_end(png_bytes: bytes) -> int:
    """
    Locate IHDR chunk and return the byte index immediately after the IHDR chunk (i.e., insertion point).
    PNG layout: 8-byte signature, then chunks.
    Each chunk: length(4) big-endian, type(4), data(length), crc(4)
    We'll find the first occurrence of b'IHDR' after offset 8 and compute its end.
    """
    sig_len = 8
    ihdr_pos = png_bytes.find(b"IHDR", sig_len)
    if ihdr_pos == -1:
        raise ValueError("IHDR not found in PNG.")
    # length field is 4 bytes immediately before IHDR
    length_bytes = png_bytes[ihdr_pos - 4:ihdr_pos]
    if len(length_bytes) != 4:
        raise ValueError("Failed to read IHDR length.")
    length = struct.unpack(">I", length_bytes)[0]
    # end = start_of_type (ihdr_pos) + 4 (type) + length (data) + 4 (crc)
    ihdr_end = ihdr_pos + 4 + length + 4
    return ihdr_end

def make_dual_header_polyglot(pdf_path: str, png_path: str, out_path: str, keyword: str = "polyglot_pdf"):
    # read files
    with open(pdf_path, "rb") as f:
        pdf_bytes = f.read()
    with open(png_path, "rb") as f:
        png_bytes = f.read()

    # basic validation
    if not pdf_bytes.startswith(b"%PDF"):
        raise ValueError("Selected file does not look like a PDF (missing %PDF header).")
    png_sig = b"\x89PNG\r\n\x1a\n"
    if not png_bytes.startswith(png_sig):
        raise ValueError("Selected file does not look like a PNG (missing PNG signature).")

    # find IHDR end and construct new PNG:
    ihdr_end = find_ihdr_end(png_bytes)

    # Build iTXt chunk that begins with the PDF bytes (so %PDF appears early)
    itxt_chunk = create_itxt_with_pdf(keyword, pdf_bytes)

    # Insert iTXt right after IHDR chunk
    before = png_bytes[:ihdr_end]
    after = png_bytes[ihdr_end:]
    new_png = before + itxt_chunk + after

    # write out
    with open(out_path, "wb") as f:
        f.write(new_png)

def gui_main():
    root = tk.Tk()
    root.title("PNG ↔ PDF Dual-Header Polyglot Maker")
    root.geometry("520x220")
    root.resizable(False, False)

    lbl = tk.Label(root, text="Create a single file that acts as both PNG (image) and PDF (document).", wraplength=480, justify="left")
    lbl.pack(padx=12, pady=(12,6))

    info = tk.Label(root, text="Select a PDF and a PNG. Result will contain the PDF inside an iTXt chunk\ninserted immediately after the PNG IHDR.",
                    fg="gray", wraplength=480, justify="left")
    info.pack(padx=12)

    def pick_and_build():
        try:
            pdf_path = filedialog.askopenfilename(title="Select PDF file", filetypes=[("PDF files","*.pdf"),("All files","*.*")])
            if not pdf_path:
                return
            png_path = filedialog.askopenfilename(title="Select PNG file", filetypes=[("PNG files","*.png"),("All files","*.*")])
            if not png_path:
                return

            suggested_name = os.path.splitext(os.path.basename(pdf_path))[0] + "_polyglot"
            save_path = filedialog.asksaveasfilename(title="Save polyglot as...", initialfile=suggested_name, defaultextension=".pdf", filetypes=[("PDF file","*.pdf"),("PNG file","*.png"),("All files","*.*")])
            if not save_path:
                return

            make_dual_header_polyglot(pdf_path, png_path, save_path)
            messagebox.showinfo("Done", f"Polyglot created:\n{save_path}\n\n- Open as .pdf to see the PDF.\n- Rename to .png to view the image.")
        except Exception as e:
            messagebox.showerror("Error", f"{type(e).__name__}: {e}")

    btn = tk.Button(root, text="Select PDF & PNG → Build Polyglot", command=pick_and_build, padx=8, pady=8)
    btn.pack(pady=(14,6))

    note = tk.Label(root, text="Heads up: Some PDF viewers might still reject unusual files. If one reader fails, try another (e.g., SumatraPDF, Okular, Adobe Reader, or poppler's pdftotext).", fg="darkred", wraplength=480, justify="left")
    note.pack(padx=12, pady=(6,10))

    root.mainloop()

if __name__ == "__main__":
    gui_main()
