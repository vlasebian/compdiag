def bytesToHexString(bArr):
    """
    Converts byte array to hex string.
    """

    hex_str = ''

    for b in bArr:
        hex_str += '{:02x}'.format(b) + ' '

    return hex_str

def nl(line):
    """
    Add '\n' to a string. Every PlantUML statement needs to have a newline
    appended, this method should improve readability.
    """
    return line + '\n'

