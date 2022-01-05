rule xored_pefile_mini {
	meta:
		author = "Tillmann Werner"
		date = "2021-10-29"
		description = "detects files with a PE header at uint32(0x3c), xored with a key of 1, 2 or 4 bytes"

        condition:
                // exclude trivial key of 0x00000000
                uint32(0x1c) != 0x00000000

                // assumption: reserved 8 bytes at offset 0x1c are zero
                and uint8(0x1c) == uint8(0x20)
                and uint8(0x1d) == uint8(0x21)
                and uint8(0x1e) == uint8(0x22)
                and uint8(0x1f) == uint8(0x23)

                // check for 'PE' signature
                and uint32(uint16(0x3c) ^ uint16(0x1c)) ^ uint32(0x1c) == 0x00004550
}
