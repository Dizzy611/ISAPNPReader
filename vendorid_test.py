#!/usr/bin/env python

def format_vendorid(vid):
    binary = format(vid, "032b")
    if int(binary[0]) != 0:
        print("ERROR: Invalid Vendor ID")
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
    

# Resulting short name should be BOX0001    
myshnm, vendor, product, revision = format_vendorid(167247873)
print("Vendor: " + vendor + ",", "Product Number: " + product + ",", "Revision: " + revision + ",", "Short Name: " + myshnm)
