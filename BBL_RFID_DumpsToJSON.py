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

def parse_rfid_tag(file_path):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()

        if len(data) < 18 * 16:
            print(f"Skip file {file_path} due to descender.")
            return None

        get_str = lambda offset, length: data[offset:offset+length].split(b'\x00')[0].decode('utf-8', errors='ignore').strip()
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

        block = lambda n: n * 16

        rgba = get_color(block(5) + 0)
        second_color = get_color(block(16) + 4)
        weight_g = get_u16(block(5) + 4)
        diameter_mm = round(get_float(block(5) + 8), 3)
        filament_length_m = get_u16(block(14) + 4)
        density_calc = calculate_density(weight_g, diameter_mm, filament_length_m)

        return {
            "file": os.path.basename(file_path),
            "tag_uid": data[block(0):block(0) + 4].hex().upper(),
            "manufacturer_data": data[block(0) + 4:block(0) + 16].hex().upper(),
            "material_id": get_str(block(1) + 8, 8),
            "variant_id": get_str(block(1), 8),
            "filament_type": get_str(block(2), 16),
            "detailed_type": get_str(block(4), 16),
            "color_hex": rgba_to_hex(rgba),
            "color_rgba": rgba_to_str(rgba),
            "weight_g": weight_g,
            "diameter_mm": diameter_mm,
            "dry_temp_c": get_u16(block(6)),
            "dry_time_h": get_u16(block(6) + 2),
            "bed_temp_type": get_u16(block(6) + 4),
            "bed_temp_c": get_u16(block(6) + 6),
            "hotend_temp_max": get_u16(block(6) + 8),
            "hotend_temp_min": get_u16(block(6) + 10),
            "x_cam_info": data[block(8):block(8) + 12].hex().upper(),
            "min_nozzle_diameter": round(get_float(block(8) + 12), 2), # deviating from Bambu-Research-Group RFID-Tag-Guide -> it's the MIN nozzle diameter
            "tray_uid_raw": data[block(9):block(9) + 16].hex().upper(), # deviating from Bambu-Research-Group RFID-Tag-Guide -> doesn't seem to be a string
            "manufacturer_id": get_u16(block(10) + 4), # deviating from Bambu-Research-Group RFID-Tag-Guide -> Doesn't seem to be the spool width -> but filament manufacturer ID ?
            "prod_datetime": get_str(block(12), 16),
            "batch_id": get_str(block(13), 16), # deviating from Bambu-Research-Group RFID-Tag-Guide -> Doesn't seem to be short production date string -> but a batch ID by filament manufacturer -> The different formats fit well with the manufacturer ID
            "filament_length_m": filament_length_m,
            "format_id": get_u16(block(16)),
            "color_count": get_u16(block(16) + 2),
            "second_color_hex": abgr_to_hex(second_color),
            "second_color_rgba": abgr_to_str(second_color),
            "unknown": data[block(16):block(16) + 2].hex().upper(),
            "unknown_uint16": get_u16(block(16)),
            "density_calculated" : density_calc
        }

    except Exception as e:
        print(f"Error while parsing of {file_path}: {e}")
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
    args = parser.parse_args()

    all_bins = find_all_bin_files(args.input_dir)
    print(f"{len(all_bins)} files found.")

    seen_uids = set()
    parsed_data = []
    for file_path in all_bins:
        result = parse_rfid_tag(file_path)
        if result:
            uid = result.get("tag_uid")
            if uid and uid not in seen_uids:
                parsed_data.append(result)
                seen_uids.add(uid)
            elif uid and uid in seen_uids:
                print(f"The file {file_path} was identified as a duplicate based on the tag UID.")

    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(parsed_data, f, indent=2, ensure_ascii=False)

    print(f"Done! {len(parsed_data)} Tags written in {args.output} .")

if __name__ == "__main__":
    main()

