import os
import struct
import json
import math

def calculate_density(weight_g, diameter_mm, length_m):
    if not weight_g or not diameter_mm or not length_m:
        return None

    diameter_cm = diameter_mm / 10
    length_cm = length_m * 100
    radius_cm = diameter_cm / 2

    volume_cm3 = math.pi * (radius_cm ** 2) * length_cm

    if volume_cm3 == 0:
        return None

    density = weight_g / volume_cm3
    return round(density, 3)

def extract_blocks(blocks, start, end):
    return b''.join(
        blocks[i] for i in range(start, end + 1)
        if i % 4 != 3 and i < len(blocks)  # exclude MIFARE trailer blocks
    )

def is_block_empty(data, block_index):
    offset = block_index * 16
    block = data[offset:offset + 16]
    return block == b'\x00' * 16

def parse_rfid_tag(file_path, extract_bin):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()

        if not len(data) == 1024:
            # print(f"[I] Skip file {file_path} due to invalid length.")
            return None

        block = lambda n: n * 16
        
        acl = data[block(3) + 6:block(3) + 10]
        if not acl == b'\x87\x87\x87\x69':
            print(f"[E] Skip file {file_path} due to invalid ACL.")
            return None
        
        # List of blocks that should be empty
        blocks_to_check = [18, 20, 21, 22, 24, 25, 26, 28, 29, 30, 32, 33, 34, 36, 37, 38]
        all_empty = True
        for block_index in blocks_to_check:
            if not is_block_empty(data, block_index):
                print(f"[D] Block {block_index} is not empty!")
                all_empty = False

        get_str = lambda offset, length: data[offset:offset+length].split(b'\x00')[0].decode('utf-8', errors='ignore').strip()
        get_u8 = lambda offset: struct.unpack('<B', data[offset:offset+1])[0]
        get_u16 = lambda offset: struct.unpack('<H', data[offset:offset+2])[0]
        get_float = lambda offset: struct.unpack('<f', data[offset:offset+4])[0]
        get_color = lambda offset: tuple(data[offset:offset+4])

        def rgba_to_hex(rgba):
            r, g, b, _ = rgba
            return f"#{r:02X}{g:02X}{b:02X}"

        def rgba_to_str(rgba):
            r, g, b, a = rgba
            return f"rgba({r},{g},{b},{a})"

        def abgr_to_hex(abgr):
            _, b, g, r = abgr
            return f"#{r:02X}{g:02X}{b:02X}"

        def abgr_to_str(abgr):
            a, b, g, r = abgr
            return f"rgba({r},{g},{b},{a})"

        rgba = get_color(block(5) + 0)
        second_color = get_color(block(16) + 4)
        weight_g = get_u16(block(5) + 4)
        diameter_mm = round(get_float(block(5) + 8), 3)
        filament_length_m = get_u16(block(14) + 4)
        density_calc = calculate_density(weight_g, diameter_mm, filament_length_m)
        tag_uid = data[block(0):block(0) + 4].hex().upper()

        if extract_bin:
            base_path = os.path.dirname(file_path)
            blocks = [data[i:i+16] for i in range(0, len(data), 16)]
            data_bytes = extract_blocks(blocks, 0, 38)
            sig_bytes = extract_blocks(blocks, 42, 62)
            with open(os.path.join(base_path, f"{tag_uid}_data.bin"), "wb") as f:
                f.write(data_bytes)
            with open(os.path.join(base_path, f"{tag_uid}_data.sig"), "wb") as f:
                f.write(sig_bytes)

        return {
            "File": os.path.basename(file_path),
            "Tag UID": tag_uid,
            "Manufacturer data": data[block(0) + 4:block(0) + 16].hex().upper(),
            "Material ID": get_str(block(1) + 8, 8),
            "Variant ID": get_str(block(1), 8),
            "Filament type": get_str(block(2), 16),
            "Detailed type": get_str(block(4), 16),
            "Color HEX": rgba_to_hex(rgba),
            "Color RGBA": rgba_to_str(rgba),
            "Weight [g]": weight_g,
            "Diameter [mm]": diameter_mm,
            "Dry temp [°C]": get_u16(block(6)),
            "Dry time [h]": get_u16(block(6) + 2),
            "Bed temp type": get_u16(block(6) + 4),
            "Bed temp [°C]": get_u16(block(6) + 6),
            "Hotend temp max [°C]": get_u16(block(6) + 8),
            "Hotend temp min [°C]": get_u16(block(6) + 10),
            "X cam info": data[block(8):block(8) + 12].hex().upper(),
            "Min nozzle diameter [mm]": round(get_float(block(8) + 12), 2), # deviating from Bambu-Research-Group RFID-Tag-Guide -> it's the MIN nozzle diameter
            "Tray UID raw": data[block(9):block(9) + 16].hex().upper(), # deviating from Bambu-Research-Group RFID-Tag-Guide -> doesn't seem to be a string
            "Manufacturer ID": get_u16(block(10) + 4), # deviating from Bambu-Research-Group RFID-Tag-Guide -> Doesn't seem to be the spool width -> but filament manufacturer ID ?
            "Prod Date Time [yyyy_MM_dd_HH_mm]": get_str(block(12), 16),
            "Batch ID": get_str(block(13), 16), # deviating from Bambu-Research-Group RFID-Tag-Guide -> Doesn't seem to be short production date string -> but a batch ID by filament manufacturer -> The different formats fit well with the manufacturer ID
            "Filament length [m]": filament_length_m,
            "Format ID": get_u16(block(16)),
            "Color count": get_u16(block(16) + 2),
            "Second Color HEX": abgr_to_hex(second_color),
            "Second Color RGBA": abgr_to_str(second_color),
            # "unknown": data[block(16):block(16) + 2].hex().upper(),
            "Is dual color": get_u8(block(17)) == 1, # deviating from Bambu-Research-Group RFID-Tag-Guide -> Block 17, index 0, length 1, type: boolean? -> Dual Color flag? Only PLA Silk Dual Color has set this flag. PLA Basic with Gradient has not set this flag.
            "Signed?": get_u8(block(40)) == 1, # Block 40, index 0, length 1, type: boolean? -> Signed flag?
            "Density calculated" : density_calc,
            "Empty blocks are empty" : all_empty
        }

    except Exception as e:
        print(f"[E] Error while parsing of {file_path}: {e}")
        return None

def find_all_bin_files(root_dir):
    all_files = []
    for root, _, files in os.walk(root_dir):
        for file in files:
            if file.lower().endswith('.bin'):
                all_files.append(os.path.join(root, file))
    return all_files

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Parse RFID-Dumps")
    parser.add_argument("input_dir", help="Directory with RFID-Binary files")
    parser.add_argument("--output", default="rfid_tags.json", help="Output file (JSON)")
    parser.add_argument("--extract-bin", action="store_true", help="Extract raw binary and signature files")
    args = parser.parse_args()

    # G:\BambuFilaments\Dumps --extract-bin

    all_bins = find_all_bin_files(args.input_dir)
    print(f"[I] {len(all_bins)} files found.")

    seen_uids = set()
    parsed_data = []
    for file_path in all_bins:
        result = parse_rfid_tag(file_path, args.extract_bin)
        if result:
            uid = result.get("Tag UID")
            if uid:
                if uid not in seen_uids:
                    parsed_data.append(result)
                    seen_uids.add(uid)
                    print(f"[I] Parsed file {file_path} with tag UID {uid}.")
                elif uid in seen_uids:
                    print(f"[I] The file {file_path} was identified as a duplicate based on the tag UID {uid}.")

    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(parsed_data, f, indent=2, ensure_ascii=False)

    print(f"[I] Done! {len(parsed_data)} Tags written in {args.output} .")

if __name__ == "__main__":
    main()
