#!/usr/bin/env python

def format_id(vid):
    binary = format(vid, "032b")
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
        
    print("TAG_TYPE: ", tag_type, "TAG: ", tag, "LENGTH :", length)

def tag_pnp_version(input_bytes):
    bcd = format(input_bytes[0], "x")      # Read byte as an integer, convert to hexadecimal 
    pretty_version = bcd[0] + "." + bcd[1] # Create version string as major.minor 
    print("PnP Specification Version: " + pretty_version)
    pass
    
def tag_logical_id(input_bytes):
    shnm, _, _, _ = format_id(input_bytes)
    print("Logical Id: " + shnm)
    
def tag_compatible_id(input_bytes):
    shnm, _, _, _ = format_id(input_bytes)
    print("Compatible Id: " + shnm)
        
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
    outstr = ""
    for irq in irqlist:
        outstr += str(irq) + " "
    print("Acceptable IRQs: " + outstr)
    print("IRQ level/edge sensitive, high/low mask: " + binary_irqinfo)
    pass
    
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
    
    
# Various tests on different functions

# Resulting short name should be BOX0001    
myshnm, vendor, product, revision = format_id(167247873)
print("Vendor: " + vendor + ",", "Product Number: " + product + ",", "Revision: " + revision + ",", "Short Name: " + myshnm)
# Identifier string, long tag  
read_tag(0x82)
# IRQ short tag data test
tag_irq(bytes.fromhex('A00200'))

