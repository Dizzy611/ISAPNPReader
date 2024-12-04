#!/usr/bin/env python
import sys
import os

tag_types_short = [ "unknown", "pnpver", "logicalid", "compatid", "irq", "dma", "configstart", "configend", "io", "fixedio", "reserved_a", "reserved_b", "reserved_c", "reserved_d", "vendorshort", "end" ]
tag_types_long = [ "unknown", "memrange", "ansistr", "unistr", "vendorlong", "32memrange", "fix32memrange" ]
struct_mode = False

def read_devids():
    if not os.path.isfile("./devids.dat"):
        devid_dict = {}
    else:
        with open("devids.dat", "r") as devid_file:
            devids = devid_file.readlines()
        devid_dict = {}
        for devid in devids:
            devid_dict[devid.split(':')[0].upper()] = devid.split(':')[1].strip()
    return devid_dict

def read_venids():
    if not os.path.isfile("./venids.dat"):
        venid_dict = {}
    else:
        with open("venids.dat", "r") as venid_file:
            venids = venid_file.readlines()
        venid_dict = {}
        for venid in venids:
            venid_dict[venid.split(':')[0].upper()] = venid.split(':')[1].strip()
    return venid_dict

def bool_to_yesno(mybool):
    if (mybool == True):
        return "Yes"
    else:
        return "No"

def format_id(vid):
    binary = ''.join(format(byte, '08b') for byte in vid)
    if int(binary[0]) != 0:
        struct_print("ERROR: Invalid ID")
        return None
    shortname = ""
    vendorname = ""
    productnum = ""
    revisionnum = ""
    # Vendor IDs are in a compressed ASCII format, see ISAPnP Spec.
    # Compressed ASCII is 5 bits and starts from a 0 of ASCII ordinal 64 (@)
    # The bit positions specified here are from the spec.
    # The following code turns these into normal ASCII and adds them to a string
    vendorname += chr(64+int(binary[1:6], 2))
    vendorname += chr(64+int(binary[6:11], 2))
    vendorname += chr(64+int(binary[11:16], 2))

    # Product ID is a series of hex digits compressed into 4 bit sections of the remaining 16 bits of the vendor ID
    # The following code turns these into the resulting hex digits.
    productnum += format(int(binary[16:20], 2), "x")
    productnum += format(int(binary[20:24], 2), "x")
    productnum += format(int(binary[24:28], 2), "x")

    # Revision number is a final hex digit compressed into the final 4 bit section of the vendor ID
    revisionnum += format(int(binary[28:32], 2), "x")

    # Required-for-boot flag
    if (len(binary) > 32): # we have final bytes for the boot flag and optional commands. We don't parse the optional commands, but the boot flag may be important
        boot_participating = bool(int(binary[39]))
    else:
        boot_participating = False

    # Create the "short version" of the vendor ID by appending these three. For our example, the result should be "BOX0001"
    shortname += vendorname
    shortname += productnum
    shortname += revisionnum

    # Return a tuple
    return (shortname, vendorname, productnum, revisionnum, boot_participating)

def read_tag(tagbyte):
    binary = format(tagbyte, "08b")
    if int(binary[0]) == 0:          # Short tag
        tag = int(binary[1:5], 2)    # Tag name
        length = int(binary[5:8], 2) # Tag length
        tag_type = 1                 # Short tag type
    else:                            # Long tag
        tag = int(binary[1:8], 2)    # Tag name
        length = -1                  # Length is on the next two bytes
        tag_type = 2                 # Long tag type
    return tag_type, tag, length

def tag_ansistr(input_bytes):
    return input_bytes.decode('ascii')

def tag_unistr(input_bytes):
    # IS this utf-8? It just says "unicode" and I can't find a single example explaining what kind of unicode or for that matter ever showing a device using it.
    return input_bytes.decode('utf-8')

def tag_pnp_version(input_bytes):
    bcd = format(input_bytes[0], "x")      # Read byte as an integer, convert to hexadecimal
    pretty_version = bcd[0] + "." + bcd[1] # Create version string as major.minor
    if len(input_bytes) > 1:
        ven_spec = format(input_bytes[1], "x")
    else:
        ven_spec = "none"
    return pretty_version, ven_spec

def tag_id(input_bytes):
    shnm, _, _, _, _ = format_id(input_bytes)
    return shnm

def tag_logical(input_bytes):
    shnm, _, _, _, boot_participating = format_id(input_bytes)
    return shnm, boot_participating

def parse_irqinfo(binary_irqinfo):
    if int(binary_irqinfo[0:4]) != 0:
        struct_print("ERROR: Malformed IRQ edge/level trigger mask")
        return False, False, False, False
    else:
        level_low = bool(int(binary_irqinfo[4]))
        level_high = bool(int(binary_irqinfo[5]))
        edge_low = bool(int(binary_irqinfo[6]))
        edge_high = bool(int(binary_irqinfo[7]))
        return level_low, level_high, edge_low, edge_high

def tag_irq(input_bytes):
    binary_lowirq = format(input_bytes[0], "08b")
    binary_highirq = format(input_bytes[1], "08b")
    if len(input_bytes) > 2:
        binary_irqinfo = format(input_bytes[2], "08b")
        level_low, level_high, edge_low, edge_high = parse_irqinfo(binary_irqinfo)
        irqinfo_specified = True
    else:
        binary_irqinfo = ""
        level_low, level_high, edge_low, edge_high = False, False, False, True # Default if not specified is edge-triggered high per ISA spec
        irqinfo_specified = False
    irqlist = []
    for i in range(0, 7):
        if binary_lowirq[i] == "1":
            irqlist.append(7-i)
    for i in range(0, 7):
        if binary_highirq[i] == "1":
            irqlist.append(15-i)
    irqlist.sort()
    return irqlist, level_low, level_high, edge_low, edge_high, irqinfo_specified

def tag_configstart(input_bytes):
    if ((len(input_bytes) == 0) or (input_bytes[0] == 1)):
        return "acceptable"
    elif input_bytes[0] == 0:
        return "preferred"
    elif input_bytes[0] == 2:
        return "suboptimal"
    else:
        return "unknown (" + str(input_bytes[0]) + ")"

def tag_dma(input_bytes):
    binary_dma = format(input_bytes[0], "08b")
    binary_dmaflags = format(input_bytes[1], "08b")
    dmalist = []
    for i in range(0, 7):
        if binary_dma[i] == "1":
            dmalist.append(7-i)
    dmalist.sort()
    if binary_dmaflags[0] != "0":
        struct_print("ERROR: Malformed DMA flags.")
        return dmalist, "error", 0, 0, 0, "error"
    else:
        binary_speed = binary_dmaflags[1:3]
        if binary_speed == "00":
            speed = "compatibility"
        elif binary_speed == "01":
            speed = "typeA"
        elif binary_speed == "10":
            speed = "typeB"
        else:
            speed = "typeF"
        count_by_word = bool(int(binary_dmaflags[3]))
        count_by_byte = bool(int(binary_dmaflags[4]))
        bus_master    = bool(int(binary_dmaflags[5]))
        binary_type   = binary_dmaflags[6:8]
        if binary_type == "00":
            type = "8-bit"
        elif binary_type == "01":
            type = "8-bit/16-bit"
        elif binary_type == "10":
            type = "16-bit"
        else:
            type = "reserved (invalid)"
        return dmalist, speed, count_by_word, count_by_byte, bus_master, type

def tag_io(input_bytes):
    binary_iotype = format(input_bytes[0], "08b")
    min_address = format(int.from_bytes(input_bytes[1:3], "little"), "x")
    max_address = format(int.from_bytes(input_bytes[3:5], "little"), "x")
    alignment = int(input_bytes[5])
    num_ports = int(input_bytes[6])
    if int(binary_iotype[0:7]) != 0:
        struct_print("ERROR: Malformed I/O port definition.")
        return -1, "0", "0", -1, -1
    else:
        return bool(int(binary_iotype[7])), min_address, max_address, alignment, num_ports

def tag_fixed_io(input_bytes):
    address = format(int.from_bytes(input_bytes[0:2], "little"), "x")
    num_ports = int(input_bytes[2])
    return address, num_ports

def tag_vendor(input_bytes):
    hex_vendor = format(int.from_bytes(input_bytes, "little"), "x")
    try:
        ascii_vendor = input_bytes.decode("ascii")
    except:
        ascii_vendor = "Invalid ASCII"
    return hex_vendor, ascii_vendor

def parse_meminfo(binary_meminfo, is_32bit):
    if binary_meminfo[0] != "0":
        struct_print("ERROR: Malformed memory range definition")
        return False, False, "error", False, False, False
    else:
        expansion_rom = bool(int(binary_meminfo[1]))
        shadowable = bool(int(binary_meminfo[2]))
        if (binary_meminfo[3:5] == "00"):
            bitsize = "8-bit"
        elif (binary_meminfo[3:5] == "01"):
            bitsize = "16-bit"
        elif (binary_meminfo[3:5] == "10"):
            bitsize = "8-bit/16-bit"
        elif (is_32bit):
            bitsize = "32-bit"
        else:
            bitsize = "reserved (invalid)"
        high_or_range = bool(int(binary_meminfo[5]))
        cacheable = bool(int(binary_meminfo[6]))
        writeable = bool(int(binary_meminfo[7]))
        return expansion_rom, shadowable, bitsize, high_or_range, cacheable, writeable

def tag_memrange(input_bytes):
    binary_meminfo = format(input_bytes[0], "08b")
    min_address = format(int.from_bytes(input_bytes[1:3], "little"), "x")
    max_address = format(int.from_bytes(input_bytes[3:5], "little"), "x")
    alignment = format(int.from_bytes(input_bytes[5:7], "little"), "x")
    length = format(int.from_bytes(input_bytes[7:9], "little"), "x")
    expansion_rom, shadowable, bitsize, high_or_range, cacheable, writeable = parse_meminfo(binary_meminfo, False)
    return expansion_rom, shadowable, bitsize, high_or_range, cacheable, writeable, min_address, max_address, alignment, length

def tag_32memrange(input_bytes):
    binary_meminfo = format(input_bytes[0], "08b")
    min_address = format(int.from_bytes(input_bytes[1:5], "little"), "x")
    max_address = format(int.from_bytes(input_bytes[5:9], "little"), "x")
    alignment = format(int.from_bytes(input_bytes[9:13], "little"), "x")
    length = format(int.from_bytes(input_bytes[13:17], "little"), "x")
    expansion_rom, shadowable, bitsize, high_or_range, cacheable, writeable = parse_meminfo(binary_meminfo, True)
    return expansion_rom, shadowable, bitsize, high_or_range, cacheable, writeable, min_address, max_address, alignment, length

def tag_fix32memrange(input_bytes):
    binary_meminfo = format(input_bytes[0], "08b")
    address = format(int.from_bytes(input_bytes[1:5], "little"), "x")
    length = format(int.from_bytes(input_bytes[5:9], "little"), "x")
    expansion_rom, shadowable, bitsize, high_or_range, cacheable, writeable = parse_meminfo(binary_meminfo, True)
    return expansion_rom, shadowable, bitsize, high_or_range, cacheable, writeable, address, length

def struct_print(string):
    if struct_mode:
        print("/* " + string + " */")
    else:
        print(string)

def struct_format(bytes, end=False):
    if struct_mode:
        outstr = "    "
        for byte in bytes:
            outstr += "0x" + format(int(byte), "02x") + ", "
        if end:
            outstr = outstr[:-2]
        else:
            outstr = outstr[:-1]
        print(outstr)

if __name__ == "__main__":
    struct_mode = False
    if len(sys.argv) > 2:
        if (sys.argv[2] == "--struct") or (sys.argv[2] == "-s"):
            struct_mode = True
    if len(sys.argv) <= 1:
        struct_print("ERROR: Must specify a ROM on the command line.")
    else:
        devids = read_devids()
        venids = read_venids()
        if not os.path.isfile(sys.argv[1]):
            struct_print("ERROR: " + sys.argv[1] + " not found or not a file.")
            sys.exit(1)
        try:
            with open(sys.argv[1], "rb") as rom_file:
                rom_bytes = rom_file.read()
        except Exception as e:
            struct_print("ERROR: Unable to read " + sys.argv[1] + ": " + str(e))
            sys.exit(1)
        header = rom_bytes[0:9]
        try:
            shortname, vendorname, productnum, revisionnum, _ = format_id(header[0:4])
        except:
            print("Invalid header encountered. Malformed ROM? Exiting.")
            sys.exit(1)
        serial = header[4:8]
        checksum = header[8]
        if not struct_mode:
            print("Header encountered and parsed, hardware data is as follows:")
        else:
            print("static const uint8_t pnp_rom[] = {")
        struct_print("Short name: " + shortname + ", Vendor ID: " + vendorname + ", Product ID: " + productnum + ", Revision: " + revisionnum + ", Serial Number: " + str(int.from_bytes(serial, "little")) + ", Checksum: " + str(checksum))
        if vendorname in venids:
            struct_print("Vendor ID matches " + venids[vendorname])
        struct_format(rom_bytes[0:9])
        cursor = 9
        while (cursor <= len(rom_bytes)):
            tag_type, tag, length = read_tag(rom_bytes[cursor])
            cursor += 1
            if tag_type == 1:
                if (tag <= (len(tag_types_short) - 1)):
                    tag_name = tag_types_short[tag]
                else:
                    tag_name = "unknown"
                # process tag here
                if (tag_name == "pnpver"):
                    version, venspec = tag_pnp_version(rom_bytes[cursor:cursor+length])
                    if venspec == "none":
                        struct_print("PnP Version: " + version)
                    else:
                        struct_print("PnP Version: " + version + ", vendor-specific version 0x" + venspec)
                elif (tag_name == "irq"):
                    irqlist, level_low, level_high, edge_low, edge_high, irqinfo_specified = tag_irq(rom_bytes[cursor:cursor+length])
                    outstr = ""
                    for irq in irqlist:
                        outstr += str(irq) + " "
                    outstr = outstr[:-1]
                    irqinfostr = ""
                    irqinfostr += "level triggered (low), " if level_low else ""
                    irqinfostr += "level triggered (high), " if level_high else ""
                    irqinfostr += "edge triggered (low), " if edge_low else ""
                    irqinfostr += "edge triggered (high), " if edge_high else ""
                    irqinfostr = irqinfostr[:-2]
                    if (irqinfo_specified == True):
                        struct_print("IRQs: " + outstr + ", IRQ triggers (Specified in tag): " + irqinfostr)
                    else:
                        struct_print("IRQs: " + outstr + ", IRQ triggers (Inferred from ISA spec): " + irqinfostr)
                elif (tag_name == "dma"):
                    dmalist, speed, count_by_word, count_by_byte, bus_master, type = tag_dma(rom_bytes[cursor:cursor+length])
                    outstr = ""
                    for dma in dmalist:
                        outstr += str(dma) + " "
                    outstr = outstr[:-1]
                    cbwstr = bool_to_yesno(count_by_word)
                    cbbstr = bool_to_yesno(count_by_byte)
                    bmstr  = bool_to_yesno(bus_master)
                    struct_print("DMAs: " + outstr + ", Speed: " + speed + ", Count-by-Word: " + cbwstr + ", Count-by-Byte: " + cbbstr + ", Bus Mastering: " + bmstr + ", DMA Type: " + type)
                elif (tag_name == "io"):
                    iotype, min, max, alignment, portnum = tag_io(rom_bytes[cursor:cursor+length])
                    if iotype == True:
                        iotypestr = "16-bit decoding"
                    else:
                        iotypestr = "10-bit decoding"
                    struct_print("I/O (" + iotypestr + ") Port Min: 0x" + min + ", Max: 0x" + max + ", Alignment: " + str(alignment) + ", Ports Requested: " + str(portnum))
                elif (tag_name == "fixedio"):
                    address, portnum = tag_fixed_io(rom_bytes[cursor:cursor+length])
                    struct_print("Fixed I/O Port: 0x" + address + ", Ports Requested: " + str(portnum))
                elif (tag_name == "configstart"):
                    config_type = tag_configstart(rom_bytes[cursor:cursor+length])
                    struct_print("Dependent function: Configuration type '" + config_type + "'")
                elif (tag_name == "configend"):
                    struct_print("End dependent functions.")
                elif (tag_name == "logicalid"):
                    shortname, boot_participating = tag_logical(rom_bytes[cursor:cursor+length])
                    struct_print("Logical ID: " + shortname + ", Participates in boot: " + bool_to_yesno(boot_participating))
                    if shortname.upper() in devids:
                        struct_print("Logical ID maps to " + devids[shortname.upper()])
                elif (tag_name == "compatid"):
                    shortname = tag_id(rom_bytes[cursor:cursor+length])
                    struct_print("Compatible ID: " + shortname)
                    if shortname.upper() in devids:
                        struct_print("Compatible ID maps to " + devids[shortname.upper()])
                elif (tag_name == "vendorshort"):
                    hex, ascii = tag_vendor(rom_bytes[cursor:cursor+length])
                    struct_print("Vendor Defined Tag (Short): " + hex + " (ASCII: " + ascii + ")")
                elif (tag_name == "end"):
                    checksum = 0
                    for i in range(9, cursor):
                        checksum = (checksum + rom_bytes[i]) & 255
                    checksum = (256 - checksum) & 255
                    if checksum == int(rom_bytes[cursor]):
                        struct_print("End of PnP ROM. Checksum matches: Calculated [" + str(checksum) + "], Provided [" + str(int(rom_bytes[cursor])) + "]")
                    else:
                        struct_print("End of PnP ROM. Checksum does not match: Calculated [" + str(checksum) + "], Provided [" + str(int(rom_bytes[cursor])) + "]")
                    struct_format(rom_bytes[cursor-1:cursor+length], tag_name == "end")
                    break
                else:
                    struct_print("Encountered unhandled short tag ID " + str(tag) + " (" + tag_name + ") of length " + str(length) + ".")
                struct_format(rom_bytes[cursor-1:cursor+length], tag_name == "end")
                cursor += length
            elif tag_type == 2:
                if (tag <= (len(tag_types_long) - 1)):
                    tag_name = tag_types_long[tag]
                else:
                    tag_name = "unknown"
                length = int.from_bytes(rom_bytes[cursor:cursor+1], "little")
                # process tag here
                if (tag_name == "ansistr"):
                    struct_print("ANSI String: " + tag_ansistr(rom_bytes[cursor+2:cursor+2+length]))
                elif (tag_name == "unistr"):
                    struct_print("Unicode String: " + tag_unistr(rom_bytes[cursor+2:cursor+2+length]))
                elif (tag_name == "memrange"):
                    expansion_rom, shadowable, bitsize, high_or_range, cacheable, writeable, min_address, max_address, alignment, memlength = tag_memrange(rom_bytes[cursor+2:cursor+2+length])
                    expromstr = bool_to_yesno(expansion_rom)
                    shadowstr = bool_to_yesno(shadowable)
                    horstr    = "high address" if high_or_range else "range length"
                    cachestr  = bool_to_yesno(cacheable)
                    writestr  = bool_to_yesno(writeable)
                    struct_print("Memory Range: Min Address: 0x" + min_address + ", Max Address: 0x" + max_address + ", Alignment: 0x" + alignment + ", Length: 0x" + memlength +
                          "\n\tExpansion ROM: " + expromstr + ", Shadowable: " + shadowstr + ", Bit Size: " + bitsize + ", Decode Supports: " + horstr + ", Cacheable: " + cachestr + ", Writeable: " + writestr)
                elif (tag_name == "32memrange"):
                    expansion_rom, shadowable, bitsize, high_or_range, cacheable, writeable, min_address, max_address, alignment, memlength = tag_32memrange(rom_bytes[cursor+2:cursor+2+length])
                    expromstr = bool_to_yesno(expansion_rom)
                    shadowstr = bool_to_yesno(shadowable)
                    horstr    = "high address" if high_or_range else "range length"
                    cachestr  = bool_to_yesno(cacheable)
                    writestr  = bool_to_yesno(writeable)
                    struct_print("32-Bit Memory Range: Min Address: 0x" + min_address + ", Max Address: 0x" + max_address + ", Alignment: 0x" + alignment + ", Length: 0x" + memlength +
                          "\n\tExpansion ROM: " + expromstr + ", Shadowable: " + shadowstr + ", Bit Size: " + bitsize + ", Decode Supports: " + horstr + ", Cacheable: " + cachestr + ", Writeable: " + writestr)
                elif (tag_name == "fix32memrange"):
                    expansion_rom, shadowable, bitsize, high_or_range, cacheable, writeable, address, memlength = tag_fix32memrange(rom_bytes[cursor+2:cursor+2+length])
                    expromstr = bool_to_yesno(expansion_rom)
                    shadowstr = bool_to_yesno(shadowable)
                    horstr    = "high address" if high_or_range else "range length"
                    cachestr  = bool_to_yesno(cacheable)
                    writestr  = bool_to_yesno(writeable)
                    struct_print("Fixed 32-Bit Memory Range: Address: 0x" + address + ", Length: 0x" + memlength +
                          "\n\tExpansion ROM: " + expromstr + ", Shadowable: " + shadowstr + ", Bit Size: " + bitsize + ", Decode Supports: " + horstr + ", Cacheable: " + cachestr + ", Writeable: " + writestr)
                elif (tag_name == "vendorlong"):
                    hex, ascii = tag_vendor(rom_bytes[cursor+2:cursor+2+length])
                    struct_print("Vendor Defined Tag (Long): " + hex + " (ASCII: " + ascii + ")")
                else:
                    struct_print("Encountered unhandled long tag ID " + str(tag) + " (" + tag_name + ") of length " + str(length) + ".")
                struct_format(rom_bytes[cursor-1:cursor+2+length], tag_name == "end")
                cursor += length+2
            else:
                struct_print("ERROR: Encountered unknown tag type.")
        if struct_mode:
            print("};")
