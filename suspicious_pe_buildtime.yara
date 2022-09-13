rule suspicious_pe_buildtime { 
	meta:
		author = "Tillmann Werner"
		date = "2022-09-05"
		description = "matches on PE files with a export table timestamp greater than the PE header build timestamp"

        condition: 
                // basic PE header sanity check
                uint16(0) == 0x5a4d and uint32(uint32(0x3c)) == 0x4550

                // make sure a non-empty export directory exists
                and for all exprva in (uint32(uint32(0x3c) + 0x78)):
                (
                        exprva != 0 
                        and for all expsize in (uint16(uint32(0x3c) + 0x7c)):
                        (
                                expsize != 0
  
                                // iterate through sections to find export table
                                and for any i in (0..(uint16(uint32(0x3c) + 0x6))):
                                (
                                        // check if the current section contains the export table
                                        exprva >= (uint32(uint32(0x3c) + uint16(uint32(0x3c) + 0x14) + 0x18 + (i * 0x28) + 0x0c))
  
                                        and exprva + expsize <= (
                                                // section virtual address
                                                uint32(uint32(0x3c) + uint16(uint32(0x3c) + 0x14) + 0x18 + (i * 0x28) + 0x0c)
                                                // section size
                                                + uint32(uint32(0x3c) + uint16(uint32(0x3c) + 0x14) + 0x18 + (i * 0x28) + 0x08)
                                        )

                                        // check if export table timestamp it is bigger than the PE build timestamp
                                        and uint32(
                                                // relative offset
                                                exprva + 4
                                                // subtract virtual address
                                                - uint32(uint32(0x3c) + uint16(uint32(0x3c) + 0x14) + 0x18 + (i * 0x28) + 0x0c)
                                                // add pointer to raw data
                                                + uint32(uint32(0x3c) + uint16(uint32(0x3c) + 0x14) + 0x18 + (i * 0x28) + 0x14)
                                        ) > uint32(uint32(0x3c) + 8)

                                        // exclude export table timestamps of 0xffffffff
                                        and uint32(
                                                // relative offset
                                                exprva + 4
                                                // subtract virtual address
                                                - uint32(uint32(0x3c) + uint16(uint32(0x3c) + 0x14) + 0x18 + (i * 0x28) + 0x0c)
                                                // add pointer to raw data
                                                + uint32(uint32(0x3c) + uint16(uint32(0x3c) + 0x14) + 0x18 + (i * 0x28) + 0x14)
                                        ) != 0xffffffff
                                )
                        )
                )
}
