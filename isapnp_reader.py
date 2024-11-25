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
    shnm, _, _, _ = format_id(input_bytes)
    return shnm

def tag_irq(input_bytes): # TODO: Turn info bitmask into description of triggering type
    binary_lowirq = format(input_bytes[0], "08b")
    binary_highirq = format(input_bytes[1], "08b")
    if len(input_bytes) > 2:
        binary_irqinfo = format(input_bytes[2], "08b")
    else:
        binary_irqinfo = ""
    irqlist = []
    for i in range(0, 7):
        if binary_lowirq[i] == "1":
            irqlist.append(7-i)
    for i in range(0, 7):
        if binary_highirq[i] == "1":
            irqlist.append(15-i)
    irqlist.sort()
    return irqlist, binary_irqinfo

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
        print("ERROR: Malformed DMA flags.")
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
        binary_type = binary_dmaflags[6:8]
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
        print("ERROR: Malformed I/O port definition.")
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
                # process tag here
                if (tag_name == "pnpver"):
                    version, venspec = tag_pnp_version(rom_bytes[cursor:cursor+length])
                    if venspec == "none":
                        print("PnP Version: " + version)
                    else:
                        print("PnP Version: " + version + ", vendor-specific version 0x" + venspec)
                elif (tag_name == "irq"):
                    irqlist, binary_irqinfo = tag_irq(rom_bytes[cursor:cursor+length])
                    outstr = ""
                    for irq in irqlist:
                        outstr += str(irq) + " "
                    outstr = outstr[:-1]
                    if (binary_irqinfo != ""):
                        print("IRQs: " + outstr + ", IRQ edge/level trigger mask: " + binary_irqinfo)
                    else:
                        print("IRQs: " + outstr)
                elif (tag_name == "dma"):
                    dmalist, speed, count_by_word, count_by_byte, bus_master, type = tag_dma(rom_bytes[cursor:cursor+length])
                    outstr = ""
                    for dma in dmalist:
                        outstr += str(dma) + " "
                    outstr = outstr[:-1]
                    if count_by_word == True:
                        cbwstr = "Yes"
                    else:
                        cbwstr = "No"
                    if count_by_byte == True:
                        cbbstr = "Yes"
                    else:
                        cbbstr = "No"
                    if bus_master == True:
                        bmstr = "Yes"
                    else:
                        bmstr = "No"
                    print("DMAs: " + outstr + ", Speed: " + speed + ", Count-by-Word: " + cbwstr + ", Count-by-Byte: " + cbbstr + ", Bus Mastering: " + bmstr + ", DMA Type: " + type)
                elif (tag_name == "io"):
                    iotype, min, max, alignment, portnum = tag_io(rom_bytes[cursor:cursor+length])
                    if iotype == True:
                        iotypestr = "16-bit decoding"
                    else:
                        iotypestr = "8-bit decoding"
                    print("I/O (" + iotypestr + ") Port Min: 0x" + min + ", Max: 0x" + max + ", Alignment: " + str(alignment) + ", Ports Requested: " + str(portnum))
                elif (tag_name == "fixedio"):
                    address, portnum = tag_fixed_io(rom_bytes[cursor:cursor+length])
                    print("Fixed I/O Port: 0x" + address + ", Ports Requested: " + str(portnum))
                elif (tag_name == "configstart"):
                    config_type = tag_configstart(rom_bytes[cursor:cursor+length])
                    print("Dependent function: Configuration type '" + config_type + "'")
                elif (tag_name == "configend"):
                    print("End dependent functions.")
                elif (tag_name == "logicalid"):
                    shortname = tag_id(rom_bytes[cursor:cursor+length])
                    print("Logical ID: " + shortname)
                elif (tag_name == "compatid"):
                    shortname = tag_id(rom_bytes[cursor:cursor+length])
                    print("Compatible ID: " + shortname)
                elif (tag_name == "vendorshort"):
                    hex, ascii = tag_vendor(rom_bytes[cursor:cursor+length])
                    print("Vendor Defined Tag: " + hex + " (ASCII: " + ascii + ")")
                elif (tag_name == "end"):
                    print("End of PnP ROM, rest of data ignored.")
                    break
                else:
                    print("Encountered unhandled short tag ID " + str(tag) + " (" + tag_name + ") of length " + str(length) + ".")
                cursor += length
            elif tag_type == 2:
                if (tag <= (len(tag_types_long) - 1)):
                    tag_name = tag_types_long[tag]
                else:
                    tag_name = "unknown"
                length = int.from_bytes(rom_bytes[cursor:cursor+1], "little")
                # process tag here
                if (tag_name == "ansistr"):
                    print("ANSI String: " + tag_ansistr(rom_bytes[cursor+2:cursor+2+length]))
                elif (tag_name == "unistr"):
                    print("Unicode String: " + tag_unistr(rom_bytes[cursor+2:cursor+2+length]))
                else:
                    print("Encountered unhandled long tag ID " + str(tag) + " (" + tag_name + ") of length " + str(length) + ".")
                cursor += length+2
            else:
                print("ERROR: Encountered unknown tag type.")
