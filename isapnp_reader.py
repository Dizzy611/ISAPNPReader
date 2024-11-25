#!/usr/bin/env python
import sys

tag_types_short = [ "unknown", "pnpver", "logicalid", "compatid", "irq", "dma", "configstart", "configend", "io", "fixedio", "reserved_a", "reserved_b", "reserved_c", "reserved_d", "vendorshort", "end" ]
tag_types_long = [ "unknown", "memrange", "ansistr", "unistr", "vendorlong", "32memrange", "fix32memrange" ]
 
def format_id(vid):
    binary = ''.join(format(byte, '08b') for byte in vid)
    if int(binary[0]) != 0:
        print("ERROR: Invalid ID")
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

    # Create the "short version" of the vendor ID by appending these three. For our example, the result should be "BOX0001"
    shortname += vendorname
    shortname += productnum
    shortname += revisionnum

    # Return a tuple 
    return (shortname, vendorname, productnum, revisionnum)

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

def tag_pnp_version(input_bytes):
    bcd = format(input_bytes[0], "x")      # Read byte as an integer, convert to hexadecimal 
    pretty_version = bcd[0] + "." + bcd[1] # Create version string as major.minor 
    return pretty_version

def tag_id(input_bytes):
    shnm, _, _, _ = format_id(input_bytes)
    return shnm

def tag_irq(input_bytes): # TODO: Turn bitmasks into lists of supported IRQs, description of triggering type 
    binary_lowirq = format(input_bytes[0], "08b")
    binary_highirq = format(input_bytes[1], "08b")
    binary_irqinfo = format(input_bytes[2], "08b")
    irqlist = []
    for i in range(0, 7):
        if binary_lowirq[i] == "1":
            irqlist.append(7-i)
    for i in range(0, 7):
        if binary_highirq[i] == "1":
            irqlist.append(15-i)
    irqlist.sort()
    return irqlist, binary_irqinfo

def tag_dma(input_bytes):
    pass

def tag_dependent_function(input_bytes):
    pass

def tag_io(input_bytes):
    pass

def tag_fixed_io(input_bytes):
    pass

def tag_vendor(input_bytes):
    pass

if __name__ == "__main__":
    if len(sys.argv) <= 1:
        print("ERROR: Must specify a ROM on the command line.")
    else:
        with open(sys.argv[1], "rb") as rom_file:
            rom_bytes = rom_file.read()
        header = rom_bytes[0:9]
        shortname, vendorname, productnum, revisionnum = format_id(header[0:4])
        serial = header[4:8]
        checksum = header[8]
        print("Header encountered and parsed, hardware data is as follows:")
        print("Short name: " + shortname + ", Vendor ID: " + vendorname + ", Product ID: " + productnum + ", Revision: " + revisionnum + ", Serial Number: " + str(int.from_bytes(serial, "little")) + ", Checksum: " + str(checksum))
        cursor = 9
        while (cursor <= len(rom_bytes)):
            tag_type, tag, length = read_tag(rom_bytes[cursor])
            cursor += 1
            if tag_type == 1:
                if (tag <= (len(tag_types_short) - 1)):
                    tag_name = tag_types_short[tag]
                else:
                    tag_name = "unknown"
                print("Encountered short tag ID " + str(tag) + " (" + tag_name + ") of length " + str(length) + ".")
                # process tag here
                cursor += length
            elif tag_type == 2:
                if (tag <= (len(tag_types_long) - 1)):
                    tag_name = tag_types_long[tag]
                else:
                    tag_name = "unknown"
                length = int.from_bytes(rom_bytes[cursor:cursor+1], "little")
                print("Encountered long tag ID " + str(tag) + " (" + tag_name + ") of length " + str(length) + ".")
                # process tag here
                cursor += length+2
            else:
                print("ERROR: Encountered unknown tag type.")
