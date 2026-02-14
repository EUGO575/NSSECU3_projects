/*
 * Optimized YARA rules for 220 target files
 * Combines size-header junction, groups identical headers, wildcards ZIP timestamps,
 * and adds filename constraint to eliminate false positives.
 */

rule Suspect_Group_PE_DOS_Stub {
    meta:
        description = "Matches multiple PE files with standard DOS stub"
        author = "Forensics Deduplication Script"
        is_generic = "true"
    strings:
        $dos_stub = { 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $dos_stub at 0 and 
        (
            filesize == 10768 or filesize == 2560 or filesize == 3072 or 
            filesize == 23832 or filesize == 3584 or filesize == 11280 or 
            filesize == 1082258 or filesize == 716249 or filesize == 11272 or 
            filesize == 11792 or filesize == 341331 or filesize == 412847 or 
            filesize == 259805 or filesize == 12816 or filesize == 1063014 or 
            filesize == 1080656 or filesize == 472874 or filesize == 4096 or 
            filesize == 12440 or filesize == 19232 or filesize == 12064 or 
            filesize == 2071847 or filesize == 867014 or filesize == 726251 or 
            filesize == 66043
        ) 
        and filename matches /File\d{3}/
}

/* ----------------------------------------------------------------------------
   Individual rules for unique headers (non‑PE, non‑duplicate)
   Each rule uses the exact 50‑byte header from file_headers.csv,
   combined with the exact file size and the filename constraint.
   For ZIP files, the 4 bytes at offsets 10‑13 (mod time/date) are wildcarded.
   ---------------------------------------------------------------------------- */

rule Suspect_Group_File002 {
    meta:
        description = "Matches File002"
        author = "Forensics Deduplication Script"
    strings:
        $header = { ef bb bf 3c 23 0a 2e 53 59 4e 4f 50 53 49 53 0a 09 49 6e 73 74 61 6c 6c 73 20 5a 6f 6f 6d 0a 2e 44 45 53 43 52 49 50 54 49 4f 4e 0a 09 54 68 69 73 20 }
    condition:
        $header at 0 and filesize == 556 and filename matches /File\d{3}/
}

rule Suspect_Group_File003 {
    meta:
        description = "Matches File003"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 43 6f 70 79 72 69 67 68 74 20 28 63 29 20 5b 79 65 61 72 5d 20 5b 66 75 6c 6c 6e 61 6d 65 5d 0d 0a 0d 0a 54 68 65 20 55 6e 69 76 65 72 73 61 6c 20 50 }
    condition:
        $header at 0 and filesize == 1855 and filename matches /File\d{3}/
}

rule Suspect_Group_File004 {
    meta:
        description = "Matches File004"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 40 65 63 68 6f 20 6f 66 66 0d 0a 73 65 74 20 2f 61 20 6c 69 6e 65 3d 25 72 61 6e 64 6f 6d 25 20 25 25 20 35 20 2b 20 31 0d 0a 66 6f 72 20 2f 66 20 22 }
    condition:
        $header at 0 and filesize == 149 and filename matches /File\d{3}/
}

rule Suspect_Group_File006 {
    meta:
        description = "Matches File006 (ZIP archive)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 50 4b 03 04 0a 00 00 00 00 00 ?? ?? ?? ?? ff ff ff ff 11 02 00 00 11 02 00 00 10 00 00 00 5b 74 72 61 73 68 5d 2f 30 30 30 30 2e 64 61 74 ff ff ff ff }
    condition:
        $header at 0 and filesize == 4319474 and filename matches /File\d{3}/
}

rule Suspect_Group_File007 {
    meta:
        description = "Matches File007 (ZIP archive)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 ?? ?? ?? ?? d4 a2 46 3f d9 01 00 00 ec 09 00 00 13 00 d3 01 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 1013332 and filename matches /File\d{3}/
}

rule Suspect_Group_File008 {
    meta:
        description = "Matches File008 (PNG image)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 4c 45 4e 5a 00 00 03 88 00 00 04 ec 08 06 00 00 00 c2 72 ac 0c 00 01 00 00 49 44 41 54 78 9c ec fd 79 9c 6d d9 75 }
    condition:
        $header at 0 and filesize == 1617304 and filename matches /File\d{3}/
}

rule Suspect_Group_File009 {
    meta:
        description = "Matches File009 (PNG image)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49 48 44 52 00 00 03 88 00 00 04 ec 08 06 00 00 00 c2 72 ac 0c 00 01 00 00 49 44 41 54 78 9c ec fd 59 93 24 39 92 }
    condition:
        $header at 0 and filesize == 1726586 and filename matches /File\d{3}/
}

rule Suspect_Group_File010 {
    meta:
        description = "Matches File010 (ZIP archive)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 ?? ?? ?? ?? 3c f3 21 f4 57 02 00 00 9f 16 00 00 13 00 c0 01 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 4155280 and filename matches /File\d{3}/
}

rule Suspect_Group_File011 {
    meta:
        description = "Matches File011 (ZIP archive)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 50 4b 03 04 0a 00 00 00 00 00 ?? ?? ?? ?? ff ff ff ff 0f 02 00 00 0f 02 00 00 10 00 00 00 5b 74 72 61 73 68 5d 2f 30 30 30 30 2e 64 61 74 ff ff ff ff }
    condition:
        $header at 0 and filesize == 12996644 and filename matches /File\d{3}/
}

rule Suspect_Group_File012 {
    meta:
        description = "Matches File012 (ZIP archive)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 ?? ?? ?? ?? 04 e8 63 06 f7 01 00 00 9b 0a 00 00 13 00 08 02 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 28659 and filename matches /File\d{3}/
}

rule Suspect_Group_File013 {
    meta:
        description = "Matches File013"
        author = "Forensics Deduplication Script"
    strings:
        $header = { ef bb bf 3c 23 0a 2e 53 59 4e 4f 50 53 49 53 0a 09 50 72 69 6e 74 73 20 74 68 65 20 4d 44 35 20 63 68 65 63 6b 73 75 6d 20 6f 66 20 61 20 66 69 6c 65 }
    condition:
        $header at 0 and filesize == 814 and filename matches /File\d{3}/
}

rule Suspect_Group_File014 {
    meta:
        description = "Matches File014 (ZIP archive)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 ?? ?? ?? ?? e4 a7 b0 6f eb 01 00 00 35 0d 00 00 13 00 08 02 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 3050393 and filename matches /File\d{3}/
}

rule Suspect_Group_File015 {
    meta:
        description = "Matches File015"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 40 65 63 68 6f 20 6f 66 66 0d 0a 73 65 74 20 2f 61 20 63 6f 75 6e 74 3d 25 72 61 6e 64 6f 6d 25 20 25 25 20 32 30 20 2b 20 31 0d 0a 65 63 68 6f 20 47 }
    condition:
        $header at 0 and filesize == 164 and filename matches /File\d{3}/
}

rule Suspect_Group_File016 {
    meta:
        description = "Matches File016"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 40 65 63 68 6f 20 6f 66 66 0d 0a 73 65 74 20 2f 61 20 68 65 78 3d 25 72 61 6e 64 6f 6d 25 20 25 25 20 32 35 35 0d 0a 73 65 74 20 2f 61 20 68 65 78 32 }
    condition:
        $header at 0 and filesize == 87 and filename matches /File\d{3}/
}

rule Suspect_Group_File017 {
    meta:
        description = "Matches File017 (ZIP archive)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 50 4b 03 04 0a 00 00 00 00 00 ?? ?? ?? ?? ff ff ff ff 0d 02 00 00 0d 02 00 00 10 00 00 00 5b 74 72 61 73 68 5d 2f 30 30 30 30 2e 64 61 74 ff ff ff ff }
    condition:
        $header at 0 and filesize == 4810789 and filename matches /File\d{3}/
}

rule Suspect_Group_File018 {
    meta:
        description = "Matches File018 (PDF)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 25 50 44 46 2d 31 2e 35 0a 25 f6 e4 fc df 0a 31 20 30 20 6f 62 6a 0a 3c 3c 0a 2f 54 79 70 65 20 2f 43 61 74 61 6c 6f 67 0a 2f 50 61 67 65 73 20 32 20 }
    condition:
        $header at 0 and filesize == 407134 and filename matches /File\d{3}/
}

rule Suspect_Group_File019 {
    meta:
        description = "Matches File019 (PNG)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49 48 44 52 00 00 03 88 00 00 04 ec 08 06 00 00 00 c2 72 ac 0c 00 01 00 00 49 44 41 54 78 9c ec fd 79 b0 25 d7 79 }
    condition:
        $header at 0 and filesize == 1651234 and filename matches /File\d{3}/
}

rule Suspect_Group_File020 {
    meta:
        description = "Matches File020"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 41 00 74 00 74 00 72 00 69 00 62 00 75 00 74 00 69 00 6f 00 6e 00 20 00 34 00 2e 00 30 00 20 00 49 00 6e 00 74 00 65 00 72 00 6e 00 61 00 74 00 69 00 }
    condition:
        $header at 0 and filesize == 38102 and filename matches /File\d{3}/
}

rule Suspect_Group_File021 {
    meta:
        description = "Matches File021"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 47 4e 55 20 41 46 46 45 52 4f 20 47 45 4e 45 52 41 4c 20 50 55 42 4c 49 43 20 4c 49 43 45 }
    condition:
        $header at 0 and filesize == 35182 and filename matches /File\d{3}/
}

rule Suspect_Group_File022 {
    meta:
        description = "Matches File022 (PDF)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 25 50 44 46 2d 31 2e 37 0a 25 f6 e4 fc df 0a 31 20 30 20 6f 62 6a 0a 3c 3c 0a 2f 50 61 67 65 73 20 32 20 30 20 52 0a 2f 54 79 70 65 20 2f 43 61 74 61 }
    condition:
        $header at 0 and filesize == 185443 and filename matches /File\d{3}/
}

rule Suspect_Group_File023 {
    meta:
        description = "Matches File023 (ID3)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 49 44 33 00 01 01 00 00 00 08 00 10 00 ff ff 08 00 00 01 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $header at 0 and filesize == 686849 and filename matches /File\d{3}/
}

rule Suspect_Group_File026 {
    meta:
        description = "Matches File026"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 47 4e 55 20 47 45 4e 45 52 41 4c 20 50 55 42 4c 49 43 20 4c 49 43 45 4e 53 45 0d 0a 20 20 }
    condition:
        $header at 0 and filesize == 35821 and filename matches /File\d{3}/
}

rule Suspect_Group_File028 {
    meta:
        description = "Matches File028"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 40 65 63 68 6f 20 6f 66 66 0d 0a 73 65 74 20 2f 61 20 64 69 65 31 3d 25 72 61 6e 64 6f 6d 25 20 25 25 20 36 20 2b 20 31 0d 0a 73 65 74 20 2f 61 20 64 }
    condition:
        $header at 0 and filesize == 109 and filename matches /File\d{3}/
}

rule Suspect_Group_File029 {
    meta:
        description = "Matches File029"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 40 65 63 68 6f 20 6f 66 66 0d 0a 66 6f 72 20 2f 66 20 22 74 6f 6b 65 6e 73 3d 31 2d 34 20 64 65 6c 69 6d 73 3d 2f 20 22 20 25 25 61 20 69 6e 20 28 22 }
    condition:
        $header at 0 and filesize == 273 and filename matches /File\d{3}/
}

rule Suspect_Group_File030 {
    meta:
        description = "Matches File030 (ZIP archive)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 50 4b 03 04 0a 00 00 00 00 00 ?? ?? ?? ?? ff ff ff ff 64 02 00 00 64 02 00 00 10 00 00 00 5b 74 72 61 73 68 5d 2f 30 30 30 30 2e 64 61 74 ff ff ff ff }
    condition:
        $header at 0 and filesize == 5379567 and filename matches /File\d{3}/
}

rule Suspect_Group_File031 {
    meta:
        description = "Matches File031 (ZIP archive)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 ?? ?? ?? ?? 98 84 f0 a8 eb 01 00 00 22 0a 00 00 13 00 ca 01 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 59159 and filename matches /File\d{3}/
}

rule Suspect_Group_File032 {
    meta:
        description = "Matches File032 (ZIP archive)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 ?? ?? ?? ?? e6 79 a3 97 ba 01 00 00 7d 0d 00 00 13 00 08 02 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 176259 and filename matches /File\d{3}/
}

rule Suspect_Group_File033 {
    meta:
        description = "Matches File033 (ZIP archive)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 43 44 30 30 14 00 06 00 08 00 ?? ?? ?? ?? aa f7 58 a4 79 01 00 00 14 06 00 00 13 00 08 02 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 31332 and filename matches /File\d{3}/
}

rule Suspect_Group_File034 {
    meta:
        description = "Matches File034"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 40 65 63 68 6f 20 6f 66 66 0d 0a 73 65 74 20 2f 61 20 6e 75 6d 3d 25 72 61 6e 64 6f 6d 25 20 25 25 20 31 30 30 30 30 0d 0a 65 63 68 6f 20 59 6f 75 72 }
    condition:
        $header at 0 and filesize == 77 and filename matches /File\d{3}/
}

rule Suspect_Group_File035 {
    meta:
        description = "Matches File035 (ZIP archive)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 50 4b 03 04 14 00 00 00 08 00 ?? ?? ?? ?? 61 0d d4 92 42 02 00 00 75 14 00 00 13 00 00 00 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c cc }
    condition:
        $header at 0 and filesize == 3097388 and filename matches /File\d{3}/
}

rule Suspect_Group_File036 {
    meta:
        description = "Matches File036 (PNG)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49 48 44 52 00 00 03 88 00 00 04 ec 08 06 00 00 00 c2 72 ac 0c 00 01 00 00 49 44 41 54 78 9c ec fd 69 b0 65 59 76 }
    condition:
        $header at 0 and filesize == 1417519 and filename matches /File\d{3}/
}

rule Suspect_Group_File037 {
    meta:
        description = "Matches File037 (ZIP archive)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 50 4b 03 04 0a 00 00 00 00 00 ?? ?? ?? ?? ff ff ff ff 35 02 00 00 35 02 00 00 10 00 00 00 5b 74 72 61 73 68 5d 2f 30 30 30 30 2e 64 61 74 ff ff ff ff }
    condition:
        $header at 0 and filesize == 266343 and filename matches /File\d{3}/
}

rule Suspect_Group_File038 {
    meta:
        description = "Matches File038 (CD)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 43 44 30 30 31 2e 36 0a 25 f6 e4 fc df 0a 31 20 30 20 6f 62 6a 0a 3c 3c 0a 2f 4d 65 74 61 64 61 74 61 20 32 20 30 20 52 0a 2f 4c 61 6e 67 20 28 65 6e }
    condition:
        $header at 0 and filesize == 5125758 and filename matches /File\d{3}/
}

rule Suspect_Group_File039 {
    meta:
        description = "Matches File039"
        author = "Forensics Deduplication Script"
    strings:
        $header = { ef bb bf 3c 23 0a 2e 53 59 4e 4f 50 53 49 53 0a 09 49 6e 73 74 61 6c 6c 73 20 44 69 73 63 6f 72 64 0a 2e 44 45 53 43 52 49 50 54 49 4f 4e 0a 09 54 68 }
    condition:
        $header at 0 and filesize == 608 and filename matches /File\d{3}/
}

rule Suspect_Group_File040 {
    meta:
        description = "Matches File040"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 40 65 63 68 6f 20 6f 66 66 0d 0a 73 65 74 20 69 6e 70 75 74 3d 68 65 6c 6c 6f 0d 0a 73 65 74 20 72 65 76 65 72 73 65 64 3d 0d 0a 66 6f 72 20 2f 6c 20 }
    condition:
        $header at 0 and filesize == 168 and filename matches /File\d{3}/
}

rule Suspect_Group_File041 {
    meta:
        description = "Matches File041 (PNG)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49 48 44 52 00 00 03 88 00 00 04 ec 08 06 00 00 00 c2 72 ac 0c 00 01 00 00 49 44 41 54 78 9c ec fd e9 92 24 4b 92 }
    condition:
        $header at 0 and filesize == 1640375 and filename matches /File\d{3}/
}

rule Suspect_Group_File043 {
    meta:
        description = "Matches File043 (ZIP archive - Word document)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 50 4b 03 04 14 00 02 00 08 00 ?? ?? ?? ?? 4a 24 76 59 fb 70 55 3b 11 53 00 00 49 4e 03 00 11 00 11 00 77 6f 72 64 2f 64 6f 63 75 6d 65 6e 74 2e 78 6d 6c 55 54 0d }
    condition:
        $header at 0 and filesize == 106799 and filename matches /File\d{3}/
}

rule Suspect_Group_File044 {
    meta:
        description = "Matches File044"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 40 65 63 68 6f 20 6f 66 66 0d 0a 73 65 74 6c 6f 63 61 6c 20 65 6e 61 62 6c 65 64 65 6c 61 79 65 64 65 78 70 61 6e 73 69 6f 6e 0d 0a 73 65 74 20 77 6f }
    condition:
        $header at 0 and filesize == 229 and filename matches /File\d{3}/
}

rule Suspect_Group_File045 {
    meta:
        description = "Matches File045 (JPEG)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { ff d8 ff e1 00 10 4a 46 49 46 00 01 01 00 00 01 00 01 00 00 ff db 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0a 0c 14 0d 0c 0b 0b 0c 19 12 13 0f }
    condition:
        $header at 0 and filesize == 137878 and filename matches /File\d{3}/
}

rule Suspect_Group_File046 {
    meta:
        description = "Matches File046 (MZ)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 4d 5a 00 01 01 00 00 00 08 00 10 00 ff ff 08 00 00 01 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $header at 0 and filesize == 80947 and filename matches /File\d{3}/
}

rule Suspect_Group_File048 {
    meta:
        description = "Matches File048"
        author = "Forensics Deduplication Script"
    strings:
        $header = { ef bb bf 3c 23 0a 2e 53 59 4e 4f 50 53 49 53 0a 09 50 72 69 6e 74 73 20 74 68 65 20 53 48 41 31 20 68 61 73 68 20 6f 66 20 61 20 66 69 6c 65 0a 2e 44 }
    condition:
        $header at 0 and filesize == 831 and filename matches /File\d{3}/
}

rule Suspect_Group_File049 {
    meta:
        description = "Matches File049"
        author = "Forensics Deduplication Script"
    strings:
        $header = { ef bb bf 3c 23 0a 2e 53 59 4e 4f 50 53 49 53 0a 09 49 6e 73 74 61 6c 6c 73 20 62 61 73 69 63 20 61 70 70 73 0a 2e 44 45 53 43 52 49 50 54 49 4f 4e 0a }
    condition:
        $header at 0 and filesize == 1804 and filename matches /File\d{3}/
}

rule Suspect_Group_File050 {
    meta:
        description = "Matches File050"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 40 65 63 68 6f 20 6f 66 66 0d 0a 73 65 74 20 2f 61 20 63 6f 6c 6f 72 3d 25 72 61 6e 64 6f 6d 25 20 25 25 20 31 36 0d 0a 63 6f 6c 6f 72 20 25 63 6f 6c }
    condition:
        $header at 0 and filesize == 86 and filename matches /File\d{3}/
}

rule Suspect_Group_File052 {
    meta:
        description = "Matches File052 (JPEG)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { ff d8 ff e0 00 10 4a 46 49 46 00 01 01 00 00 01 00 01 00 00 ff db 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0a 0c 14 0d 0c 0b 0b 0c 19 12 13 0f }
    condition:
        $header at 0 and filesize == 146273 and filename matches /File\d{3}/
}

rule Suspect_Group_File053 {
    meta:
        description = "Matches File053 (JPEG)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { ff d8 ff e0 00 10 4a 46 49 46 00 01 01 00 00 01 00 01 00 00 ff db 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0a 0c 14 0d 0c 0b 0b 0c 19 12 13 0f }
    condition:
        $header at 0 and filesize == 173909 and filename matches /File\d{3}/
}

rule Suspect_Group_File054 {
    meta:
        description = "Matches File054"
        author = "Forensics Deduplication Script"
    strings:
        $header = { ef bb bf 3c 23 0a 2e 53 59 4e 4f 50 53 49 53 0a 09 49 6e 73 74 61 6c 6c 73 20 47 69 74 20 66 6f 72 20 57 69 6e 64 6f 77 73 0a 2e 44 45 53 43 52 49 50 }
    condition:
        $header at 0 and filesize == 628 and filename matches /File\d{3}/
}

rule Suspect_Group_File055 {
    meta:
        description = "Matches File055 (ZIP archive - PowerPoint)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 43 44 30 30 14 00 06 00 08 00 ?? ?? ?? ?? a9 90 c0 ad 7b 03 00 00 d3 10 00 00 14 00 00 00 70 70 74 2f 70 72 65 73 65 6e 74 61 74 69 6f 6e 2e 78 6d 6c }
    condition:
        $header at 0 and filesize == 844097 and filename matches /File\d{3}/
}

rule Suspect_Group_File056 {
    meta:
        description = "Matches File056 (ZIP archive)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 50 4b 03 04 0a 00 00 00 00 00 ?? ?? ?? ?? ff ff ff ff f3 01 00 00 f3 01 00 00 10 00 00 00 5b 74 72 61 73 68 5d 2f 30 30 30 30 2e 64 61 74 ff ff ff ff }
    condition:
        $header at 0 and filesize == 340390 and filename matches /File\d{3}/
}

rule Suspect_Group_File057 {
    meta:
        description = "Matches File057"
        author = "Forensics Deduplication Script"
    strings:
        $header = { ef bb bf 3c 23 0a 2e 53 59 4e 4f 50 53 49 53 0a 09 45 6e 61 62 6c 65 73 20 74 68 65 20 67 6f 64 20 6d 6f 64 65 0a 2e 44 45 53 43 52 49 50 54 49 4f 4e }
    condition:
        $header at 0 and filesize == 691 and filename matches /File\d{3}/
}

rule Suspect_Group_File058 {
    meta:
        description = "Matches File058"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 }
    condition:
        $header at 0 and filesize == 23112 and filename matches /File\d{3}/
}

rule Suspect_Group_File059 {
    meta:
        description = "Matches File059 (PNG)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49 48 44 52 00 00 03 88 00 00 04 ec 08 06 00 00 00 c2 72 ac 0c 00 01 00 00 49 44 41 54 78 9c ec fd e9 b3 6d 49 76 }
    condition:
        $header at 0 and filesize == 1720207 and filename matches /File\d{3}/
}

rule Suspect_Group_File061 {
    meta:
        description = "Matches File061"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 40 65 63 68 6f 20 6f 66 66 0d 0a 73 65 74 20 2f 61 20 64 65 6c 61 79 3d 25 72 61 6e 64 6f 6d 25 20 25 25 20 35 20 2b 20 31 0d 0a 74 69 6d 65 6f 75 74 }
    condition:
        $header at 0 and filesize == 106 and filename matches /File\d{3}/
}

rule Suspect_Group_File063 {
    meta:
        description = "Matches File063 (ID3)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 49 44 33 31 2e 34 0d 25 80 84 88 8c 90 94 98 9c a0 a4 a8 ac b0 b4 b8 bc c0 c4 c8 cc d0 d4 d8 dc e0 e4 e8 ec f0 f4 f8 fc 0d 0d 31 20 30 20 6f 62 6a 0d }
    condition:
        $header at 0 and filesize == 1962050 and filename matches /File\d{3}/
}

rule Suspect_Group_File064 {
    meta:
        description = "Matches File064"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 5b 4c 6f 63 61 6c 69 7a 65 64 46 69 6c 65 4e 61 6d 65 73 5d 0d 0a 62 69 6f 63 68 65 6d 5f 6d 65 64 2d 32 33 2d 32 2d 31 34 33 2d 33 2e 70 64 66 3d 40 }
    condition:
        $header at 0 and filesize == 2138 and filename matches /File\d{3}/
}

rule Suspect_Group_File065 {
    meta:
        description = "Matches File065"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 49 53 43 20 4c 69 63 65 6e 73 65 0d 0a 0d 0a 43 6f 70 79 72 69 67 68 74 20 28 63 29 20 5b 79 65 61 72 5d 20 5b 66 75 6c 6c 6e 61 6d 65 5d 0d 0a 0d 0a }
    condition:
        $header at 0 and filesize == 756 and filename matches /File\d{3}/
}

rule Suspect_Group_File066 {
    meta:
        description = "Matches File066 (PDF)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 25 50 44 46 2d 31 2e 37 0a 25 e2 e3 cf d3 0a 36 20 30 20 6f 62 6a 0a 3c 3c 2f 46 69 6c 74 65 72 2f 46 6c 61 74 65 44 65 63 6f 64 65 2f 4c 65 6e 67 74 }
    condition:
        $header at 0 and filesize == 3259060 and filename matches /File\d{3}/
}

rule Suspect_Group_File067 {
    meta:
        description = "Matches File067 (MZ variant)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 4d 5a 93 00 03 00 00 00 20 00 00 00 ff ff 07 00 00 01 65 40 00 00 00 00 40 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $header at 0 and filesize == 366608 and filename matches /File\d{3}/
}

rule Suspect_Group_File068 {
    meta:
        description = "Matches File068 (PNG)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49 48 44 52 00 00 03 88 00 00 04 ec 08 06 00 00 00 c2 72 ac 0c 00 01 00 00 49 44 41 54 78 9c ec fd 59 af 24 4b 92 }
    condition:
        $header at 0 and filesize == 1485481 and filename matches /File\d{3}/
}

rule Suspect_Group_File069 {
    meta:
        description = "Matches File069 (PNG/JPEG hybrid)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 89 50 4e 47 0d 0a 1a 0a e0 00 10 4a 46 49 46 00 01 01 00 00 01 00 01 00 00 ff db 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0a 0c 14 0d 0c 0b 0b }
    condition:
        $header at 0 and filesize == 170993 and filename matches /File\d{3}/
}

rule Suspect_Group_File070 {
    meta:
        description = "Matches File070 (PNG)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49 48 44 52 00 00 03 88 00 00 04 ec 08 06 00 00 00 c2 72 ac 0c 00 01 00 00 49 44 41 54 78 9c ec fd 49 b3 65 4b 76 }
    condition:
        $header at 0 and filesize == 1645439 and filename matches /File\d{3}/
}

rule Suspect_Group_File072 {
    meta:
        description = "Matches File072 (PNG)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49 48 44 52 00 00 03 88 00 00 04 ec 08 06 00 00 00 c2 72 ac 0c 00 01 00 00 49 44 41 54 78 9c ec fd 69 97 25 c9 71 }
    condition:
        $header at 0 and filesize == 1655833 and filename matches /File\d{3}/
}

rule Suspect_Group_File073 {
    meta:
        description = "Matches File073 (JPEG)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { ff d8 ff e0 00 10 4a 46 49 46 00 01 01 00 00 01 00 01 00 00 ff db 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0a 0c 14 0d 0c 0b 0b 0c 19 12 13 0f }
    condition:
        $header at 0 and filesize == 157801 and filename matches /File\d{3}/
}

rule Suspect_Group_File074 {
    meta:
        description = "Matches File074 (ZIP archive)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 50 4b 03 04 0a 00 00 00 00 00 ?? ?? ?? ?? ff ff ff ff 2d 02 00 00 2d 02 00 00 10 00 00 00 5b 74 72 61 73 68 5d 2f 30 30 30 30 2e 64 61 74 ff ff ff ff }
    condition:
        $header at 0 and filesize == 7213107 and filename matches /File\d{3}/
}

rule Suspect_Group_File076 {
    meta:
        description = "Matches File076 (ZIP archive - Word header)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 50 4b 03 04 14 00 08 08 08 00 ?? ?? ?? ?? ab 0b 76 59 00 00 00 00 00 00 00 00 00 00 00 00 10 00 00 00 77 6f 72 64 2f 68 65 61 64 65 72 31 2e 78 6d 6c cd 96 db 8e }
    condition:
        $header at 0 and filesize == 115731 and filename matches /File\d{3}/
}

rule Suspect_Group_File077 {
    meta:
        description = "Matches File077"
        author = "Forensics Deduplication Script"
    strings:
        $header = { ef bb bf 3c 23 0a 2e 53 59 4e 4f 50 53 49 53 0a 09 49 6e 73 74 61 6c 6c 73 20 43 68 72 6f 6d 65 0a 2e 44 45 53 43 52 49 50 54 49 4f 4e 0a 09 54 68 69 }
    condition:
        $header at 0 and filesize == 603 and filename matches /File\d{3}/
}

rule Suspect_Group_File078 {
    meta:
        description = "Matches File078 (JPEG)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { ff d8 ff e0 00 10 4a 46 49 46 00 01 01 00 00 01 00 01 00 00 ff db 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0a 0c 14 0d 0c 0b 0b 0c 19 12 13 0f }
    condition:
        $header at 0 and filesize == 160610 and filename matches /File\d{3}/
}

rule Suspect_Group_File079 {
    meta:
        description = "Matches File079 (MZ variant)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { ff fb 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $header at 0 and filesize == 339655 and filename matches /File\d{3}/
}

rule Suspect_Group_File082 {
    meta:
        description = "Matches File082"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 40 65 63 68 6f 20 6f 66 66 0d 0a 73 65 74 20 70 61 74 68 73 3d 43 3a 5c 57 69 6e 64 6f 77 73 5c 20 43 3a 5c 55 73 65 72 73 5c 20 43 3a 5c 50 72 6f 67 }
    condition:
        $header at 0 and filesize == 147 and filename matches /File\d{3}/
}

rule Suspect_Group_File083 {
    meta:
        description = "Matches File083"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 40 65 63 68 6f 20 6f 66 66 0d 0a 73 65 74 20 2f 61 20 6e 75 6d 3d 25 72 61 6e 64 6f 6d 25 20 25 25 20 32 36 20 2b 20 36 35 0d 0a 66 6f 72 20 2f 66 20 }
    condition:
        $header at 0 and filesize == 124 and filename matches /File\d{3}/
}

rule Suspect_Group_File084 {
    meta:
        description = "Matches File084 (PDF)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 25 50 44 46 2d 31 2e 33 0a 25 e2 e3 cf d3 0a 31 20 30 20 6f 62 6a 0a 3c 3c 0a 2f 54 79 70 65 20 2f 50 61 67 65 73 0a 2f 43 6f 75 6e 74 20 33 33 0a 2f }
    condition:
        $header at 0 and filesize == 417316 and filename matches /File\d{3}/
}

rule Suspect_Group_File085 {
    meta:
        description = "Matches File085 (ZIP archive - .rels)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 ?? ?? ?? ?? b5 cf 3e 7b 02 01 00 00 bb 02 00 00 0b 00 ed 01 5f 72 65 6c 73 2f 2e 72 65 6c 73 20 a2 e9 01 28 a0 00 02 00 }
    condition:
        $header at 0 and filesize == 406205 and filename matches /File\d{3}/
}

rule Suspect_Group_File086 {
    meta:
        description = "Matches File086"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 42 53 44 20 5a 65 72 6f 20 43 6c 61 75 73 65 20 4c 69 63 65 6e 73 65 0d 0a 0d 0a 43 6f 70 79 72 69 67 68 74 20 28 63 29 20 5b 79 65 61 72 5d 20 5b 66 }
    condition:
        $header at 0 and filesize == 677 and filename matches /File\d{3}/
}

rule Suspect_Group_File087 {
    meta:
        description = "Matches File087 (ZIP archive)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 ?? ?? ?? ?? 8f bf f1 36 23 04 00 00 c5 4e 00 00 13 00 08 02 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 288249 and filename matches /File\d{3}/
}

rule Suspect_Group_File088 {
    meta:
        description = "Matches File088"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 40 65 63 68 6f 20 6f 66 66 0d 0a 66 6f 72 20 2f 6c 20 25 25 69 20 69 6e 20 28 31 2c 31 2c 33 32 29 20 64 6f 20 28 0d 0a 20 20 20 20 73 65 74 20 2f 61 }
    condition:
        $header at 0 and filesize == 100 and filename matches /File\d{3}/
}

rule Suspect_Group_File089 {
    meta:
        description = "Matches File089 (JPEG)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { ff d8 ff e0 00 10 4a 46 49 46 00 01 01 00 00 01 00 01 00 00 ff db 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0a 0c 14 0d 0c 0b 0b 0c 19 12 13 0f }
    condition:
        $header at 0 and filesize == 180248 and filename matches /File\d{3}/
}

rule Suspect_Group_File090 {
    meta:
        description = "Matches File090 (JPEG)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { ff d8 ff e0 00 10 4a 46 49 46 00 01 01 00 00 01 00 01 00 00 ff db 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0a 0c 14 0d 0c 0b 0b 0c 19 12 13 0f }
    condition:
        $header at 0 and filesize == 169745 and filename matches /File\d{3}/
}

rule Suspect_Group_File091 {
    meta:
        description = "Matches File091"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 20 20 20 20 20 20 20 20 20 20 20 20 44 4f 20 57 48 41 54 20 54 48 45 20 46 55 43 4b 20 59 4f 55 20 57 41 4e 54 20 54 4f 20 50 55 42 4c 49 43 20 4c 49 }
    condition:
        $header at 0 and filesize == 494 and filename matches /File\d{3}/
}

rule Suspect_Group_File093 {
    meta:
        description = "Matches File093 (ZIP archive)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 ?? ?? ?? ?? 9d 7c 73 2a e3 01 00 00 b5 0c 00 00 13 00 08 02 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 3038333 and filename matches /File\d{3}/
}

rule Suspect_Group_File094 {
    meta:
        description = "Matches File094 (ZIP archive)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 ?? ?? ?? ?? 81 71 7d 3c f8 01 00 00 ba 0c 00 00 13 00 cd 01 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 62950 and filename matches /File\d{3}/
}

rule Suspect_Group_File096 {
    meta:
        description = "Matches File096 (ZIP archive)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 ?? ?? ?? ?? d5 71 95 3e e1 01 00 00 7a 09 00 00 13 00 08 02 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 187180 and filename matches /File\d{3}/
}

rule Suspect_Group_File097 {
    meta:
        description = "Matches File097 (JPEG)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { ff d9 ff e0 00 10 4a 46 49 46 00 01 01 00 00 01 00 01 00 00 ff db 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0a 0c 14 0d 0c 0b 0b 0c 19 12 13 0f }
    condition:
        $header at 0 and filesize == 132678 and filename matches /File\d{3}/
}

rule Suspect_Group_File098 {
    meta:
        description = "Matches File098 (PNG)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49 48 44 52 00 00 03 88 00 00 04 ec 08 06 00 00 00 c2 72 ac 0c 00 01 00 00 49 44 41 54 78 9c ec fd 69 ac 6d db 75 }
    condition:
        $header at 0 and filesize == 1684054 and filename matches /File\d{3}/
}

rule Suspect_Group_File099 {
    meta:
        description = "Matches File099"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 0a 22 31 2e 20 49 6e 73 74 61 6c 6c 20 61 6e 64 20 63 6f 6e 66 69 67 75 72 65 20 74 68 65 20 6e 65 63 65 73 73 61 72 79 20 64 65 70 65 6e 64 65 6e 63 }
    condition:
        $header at 0 and filesize == 352 and filename matches /File\d{3}/
}

rule Suspect_Group_File100 {
    meta:
        description = "Matches File100 (ZIP archive)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 ?? ?? ?? ?? 1e 27 60 70 88 01 00 00 ae 05 00 00 13 00 08 02 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 27963 and filename matches /File\d{3}/
}

rule Suspect_Group_File102 {
    meta:
        description = "Matches File102 (RIFF WAVE)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 52 49 46 46 57 41 56 45 2d 31 2e 36 0d 25 e2 e3 cf d3 0d 0a 35 39 20 30 20 6f 62 6a 20 3c 3c 2f 4c 69 6e 65 61 72 69 7a 65 64 20 31 2f 4c 20 31 39 36 }
    condition:
        $header at 0 and filesize == 196042 and filename matches /File\d{3}/
}

rule Suspect_Group_File103 {
    meta:
        description = "Matches File103 (PDF)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 25 50 44 46 2d 31 2e 34 0a 25 f6 e4 fc df 0a 31 20 30 20 6f 62 6a 0a 3c 3c 0a 2f 54 79 70 65 20 2f 43 61 74 61 6c 6f 67 0a 2f 56 65 72 73 69 6f 6e 20 }
    condition:
        $header at 0 and filesize == 7474390 and filename matches /File\d{3}/
}

rule Suspect_Group_File104 {
    meta:
        description = "Matches File104 (ZIP archive)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 ?? ?? ?? ?? 2b 54 51 0e d9 02 00 00 a6 24 00 00 13 00 ba 01 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 1286316 and filename matches /File\d{3}/
}

rule Suspect_Group_File105 {
    meta:
        description = "Matches File105 (PNG)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49 48 44 52 00 00 03 88 00 00 04 ec 08 06 00 00 00 c2 72 ac 0c 00 01 00 00 49 44 41 54 78 9c ec fd f9 93 24 5b 76 }
    condition:
        $header at 0 and filesize == 1426547 and filename matches /File\d{3}/
}

rule Suspect_Group_File106 {
    meta:
        description = "Matches File106"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 45 00 63 00 6c 00 69 00 70 00 73 00 65 00 20 00 50 00 75 00 62 00 6c 00 69 00 63 00 20 00 4c 00 69 00 63 00 65 00 6e 00 73 00 65 00 20 00 2d 00 20 00 }
    condition:
        $header at 0 and filesize == 28944 and filename matches /File\d{3}/
}

rule Suspect_Group_File107 {
    meta:
        description = "Matches File107 (JPEG)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { ff d8 ff e0 00 10 4a 46 49 46 00 01 01 00 00 01 00 01 00 00 ff db 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0a 0c 14 0d 0c 0b 0b 0c 19 12 13 0f }
    condition:
        $header at 0 and filesize == 142129 and filename matches /File\d{3}/
}

rule Suspect_Group_File108 {
    meta:
        description = "Matches File108 (PNG)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49 48 44 52 00 00 03 88 00 00 04 ec 08 06 00 00 00 c2 72 ac 0c 00 01 00 00 49 44 41 54 78 9c ec fd e9 b2 2c 49 92 }
    condition:
        $header at 0 and filesize == 1544836 and filename matches /File\d{3}/
}

rule Suspect_Group_File109 {
    meta:
        description = "Matches File109 (RIFF WAVE)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 52 49 46 46 57 41 56 45 2d 31 2e 33 0a 25 e2 e3 cf d3 0a 31 20 30 20 6f 62 6a 0a 3c 3c 0a 2f 54 79 70 65 20 2f 50 61 67 65 73 0a 2f 43 6f 75 6e 74 20 }
    condition:
        $header at 0 and filesize == 556987 and filename matches /File\d{3}/
}

rule Suspect_Group_File110 {
    meta:
        description = "Matches File110"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 4d 69 63 72 6f 73 6f 66 74 20 50 75 62 6c 69 63 20 4c 69 63 65 6e 73 65 20 28 4d 73 2d 50 4c 29 0d 0a 0d 0a 54 68 69 73 20 6c 69 63 65 6e 73 65 20 67 }
    condition:
        $header at 0 and filesize == 2828 and filename matches /File\d{3}/
}

rule Suspect_Group_File111 {
    meta:
        description = "Matches File111 (ZIP archive)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 ?? ?? ?? ?? 45 8c 02 3a bc 01 00 00 64 08 00 00 13 00 dc 01 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 146438 and filename matches /File\d{3}/
}

rule Suspect_Group_File112 {
    meta:
        description = "Matches File112"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 40 65 63 68 6f 20 6f 66 66 0d 0a 65 63 68 6f 20 52 61 6e 64 6f 6d 20 53 74 72 69 6e 67 3a 20 25 72 61 6e 64 6f 6d 25 0d 0a }
    condition:
        $header at 0 and filesize == 41 and filename matches /File\d{3}/
}

rule Suspect_Group_File113 {
    meta:
        description = "Matches File113 (JPEG)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { ff d8 ff e0 00 10 4a 46 49 46 00 01 01 00 00 01 00 01 00 00 ff db 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0a 0c 14 0d 0c 0b 0b 0c 19 12 13 0f }
    condition:
        $header at 0 and filesize == 160547 and filename matches /File\d{3}/
}

rule Suspect_Group_File114 {
    meta:
        description = "Matches File114 (PDF)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 25 50 44 46 2d 31 2e 33 0a 25 e2 e3 cf d3 0a 31 20 30 20 6f 62 6a 0a 3c 3c 0a 2f 54 79 70 65 20 2f 50 61 67 65 73 0a 2f 43 6f 75 6e 74 20 32 30 0a 2f }
    condition:
        $header at 0 and filesize == 527117 and filename matches /File\d{3}/
}

rule Suspect_Group_File116 {
    meta:
        description = "Matches File116 (ZIP archive)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 ?? ?? ?? ?? 74 76 54 0c d0 01 00 00 6c 0b 00 00 13 00 08 02 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 694240 and filename matches /File\d{3}/
}

rule Suspect_Group_File117 {
    meta:
        description = "Matches File117 (ZIP archive)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 ?? ?? ?? ?? 9c bd 3c e3 ce 01 00 00 c4 0b 00 00 13 00 08 02 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 64531 and filename matches /File\d{3}/
}

rule Suspect_Group_File119 {
    meta:
        description = "Matches File119"
        author = "Forensics Deduplication Script"
    strings:
        $header = { ef bb bf 3c 23 0a 2e 53 59 4e 4f 50 53 49 53 0a 09 49 6e 73 74 61 6c 6c 73 20 54 77 69 74 74 65 72 0a 2e 44 45 53 43 52 49 50 54 49 4f 4e 0a 09 54 68 }
    condition:
        $header at 0 and filesize == 555 and filename matches /File\d{3}/
}

rule Suspect_Group_File120 {
    meta:
        description = "Matches File120"
        author = "Forensics Deduplication Script"
    strings:
        $header = { ef bb bf 3c 23 0a 2e 53 59 4e 4f 50 53 49 53 0a 09 49 6e 73 74 61 6c 6c 73 20 54 68 75 6e 64 65 72 62 69 72 64 0a 2e 44 45 53 43 52 49 50 54 49 4f 4e }
    condition:
        $header at 0 and filesize == 572 and filename matches /File\d{3}/
}

rule Suspect_Group_File121 {
    meta:
        description = "Matches File121 (ZIP archive)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 ?? ?? ?? ?? 9f 04 c7 c5 38 02 00 00 54 10 00 00 13 00 c2 01 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 345850 and filename matches /File\d{3}/
}

rule Suspect_Group_File122 {
    meta:
        description = "Matches File122 (ZIP archive - Word numbering)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 50 4b 03 04 14 00 08 08 08 00 ?? ?? ?? ?? 48 a5 75 59 00 00 00 00 00 00 00 00 00 00 00 00 12 00 00 00 77 6f 72 64 2f 6e 75 6d 62 65 72 69 6e 67 2e 78 6d 6c ed 9b }
    condition:
        $header at 0 and filesize == 572074 and filename matches /File\d{3}/
}

rule Suspect_Group_File123 {
    meta:
        description = "Matches File123 (PDF)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 25 50 44 46 2d 31 2e 35 0d 0a 25 b5 b5 b5 b5 0d 0a 31 20 30 20 6f 62 6a 0d 0a 3c 3c 2f 54 79 70 65 2f 43 61 74 61 6c 6f 67 2f 50 61 67 65 73 20 32 20 }
    condition:
        $header at 0 and filesize == 521414 and filename matches /File\d{3}/
}

rule Suspect_Group_File124 {
    meta:
        description = "Matches File124 (JPEG)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { ff d8 ff e0 00 10 4a 46 49 46 00 01 01 00 00 01 00 01 00 00 ff db 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0a 0c 14 0d 0c 0b 0b 0c 19 12 13 0f }
    condition:
        $header at 0 and filesize == 173180 and filename matches /File\d{3}/
}

rule Suspect_Group_File125 {
    meta:
        description = "Matches File125 (PNG)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49 48 44 52 00 00 03 88 00 00 04 ec 08 06 00 00 00 c2 72 ac 0c 00 01 00 00 49 44 41 54 78 9c ec fd 67 b4 65 c9 75 }
    condition:
        $header at 0 and filesize == 1591997 and filename matches /File\d{3}/
}

rule Suspect_Group_File126 {
    meta:
        description = "Matches File126 (PNG)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49 48 44 52 00 00 03 88 00 00 04 ec 08 06 00 00 00 c2 72 ac 0c 00 01 00 00 49 44 41 54 78 9c ec fd 77 b0 25 c9 79 }
    condition:
        $header at 0 and filesize == 1502871 and filename matches /File\d{3}/
}

rule Suspect_Group_File127 {
    meta:
        description = "Matches File127 (JPEG)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { ff d8 ff e0 00 10 4a 46 49 46 00 01 01 00 00 01 00 01 00 00 ff db 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0a 0c 14 0d 0c 0b 0b 0c 19 12 13 0f }
    condition:
        $header at 0 and filesize == 154510 and filename matches /File\d{3}/
}

rule Suspect_Group_File128 {
    meta:
        description = "Matches File128"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 40 65 63 68 6f 20 6f 66 66 0d 0a 73 65 74 20 2f 61 20 63 6f 64 65 3d 25 72 61 6e 64 6f 6d 25 20 25 25 20 32 35 35 0d 0a 65 63 68 6f 20 45 78 69 74 69 }
    condition:
        $header at 0 and filesize == 87 and filename matches /File\d{3}/
}

rule Suspect_Group_File129 {
    meta:
        description = "Matches File129 (PDF)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 25 50 44 46 2d 31 2e 33 0a 25 e2 e3 cf d3 0a 31 20 30 20 6f 62 6a 0a 3c 3c 0a 2f 54 79 70 65 20 2f 50 61 67 65 73 0a 2f 43 6f 75 6e 74 20 31 39 0a 2f }
    condition:
        $header at 0 and filesize == 217395 and filename matches /File\d{3}/
}

rule Suspect_Group_File130 {
    meta:
        description = "Matches File130 (ZIP archive)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 ?? ?? ?? ?? 3d 57 87 34 c6 01 00 00 bf 08 00 00 13 00 08 02 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 100153 and filename matches /File\d{3}/
}

rule Suspect_Group_File131 {
    meta:
        description = "Matches File131 (ZIP archive)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 ?? ?? ?? ?? a6 74 04 52 85 01 00 00 ac 07 00 00 13 00 08 02 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 26769 and filename matches /File\d{3}/
}

rule Suspect_Group_File132 {
    meta:
        description = "Matches File132 (PDF)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 25 50 44 46 2d 31 2e 36 0d 25 e2 e3 cf d3 0d 0a 34 33 31 20 30 20 6f 62 6a 0d 3c 3c 2f 4c 69 6e 65 61 72 69 7a 65 64 20 31 2f 4c 20 35 38 38 31 35 32 }
    condition:
        $header at 0 and filesize == 588152 and filename matches /File\d{3}/
}

rule Suspect_Group_File133 {
    meta:
        description = "Matches File133 (JPEG)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { ff d8 ff e0 00 10 4a 46 49 46 00 01 01 00 00 01 00 01 00 00 ff db 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0a 0c 14 0d 0c 0b 0b 0c 19 12 13 0f }
    condition:
        $header at 0 and filesize == 159149 and filename matches /File\d{3}/
}

rule Suspect_Group_File134 {
    meta:
        description = "Matches File134 (ZIP archive)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 ?? ?? ?? ?? 3d 57 87 34 c6 01 00 00 bf 08 00 00 13 00 08 02 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 744699 and filename matches /File\d{3}/
}

rule Suspect_Group_File135 {
    meta:
        description = "Matches File135 (PDF)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 25 50 44 46 2d 31 2e 37 0d 25 e2 e3 cf d3 0d 0a 31 20 30 20 6f 62 6a 0a 3c 3c 2f 41 63 72 6f 46 6f 72 6d 20 35 20 30 20 52 2f 4c 61 6e 67 28 65 6e 29 }
    condition:
        $header at 0 and filesize == 5765224 and filename matches /File\d{3}/
}

rule Suspect_Group_File136 {
    meta:
        description = "Matches File136 (PNG)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 00 00 00 0d 49 48 44 52 00 00 03 88 00 00 04 ec 08 06 00 00 00 c2 72 ac 0c 00 01 00 00 49 44 41 54 78 9c ec fd 5b b3 24 49 92 1e 88 7d aa 66 ee 1e 71 }
    condition:
        $header at 0 and filesize == 1809714 and filename matches /File\d{3}/
}

rule Suspect_Group_File137 {
    meta:
        description = "Matches File137"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 42 6f 6f 73 74 20 53 6f 66 74 77 61 72 65 20 4c 69 63 65 6e 73 65 20 2d 20 56 65 72 73 69 6f 6e 20 31 2e 30 20 2d 20 41 75 67 75 73 74 20 31 37 74 68 }
    condition:
        $header at 0 and filesize == 1359 and filename matches /File\d{3}/
}

rule Suspect_Group_File138 {
    meta:
        description = "Matches File138 (PDF)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 25 50 44 46 2d 31 2e 37 0a 25 e2 e3 cf d3 0a 31 20 30 20 6f 62 6a 0a 3c 3c 2f 43 6f 6c 6f 72 53 70 61 63 65 2f 44 65 76 69 63 65 47 72 61 79 2f 53 75 }
    condition:
        $header at 0 and filesize == 663177 and filename matches /File\d{3}/
}

rule Suspect_Group_File139 {
    meta:
        description = "Matches File139"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 40 65 63 68 6f 20 6f 66 66 0d 0a 73 65 74 20 73 65 6e 74 65 6e 63 65 73 3d 48 65 6c 6c 6f 7c 48 6f 77 20 61 72 65 20 79 6f 75 3f 7c 4e 69 63 65 20 77 }
    condition:
        $header at 0 and filesize == 168 and filename matches /File\d{3}/
}

rule Suspect_Group_File140 {
    meta:
        description = "Matches File140 (JPEG)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { ff d8 ff e0 00 10 4a 46 49 46 00 01 01 00 00 01 00 01 00 00 ff db 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0a 0c 14 0d 0c 0b 0b 0c 19 12 13 0f }
    condition:
        $header at 0 and filesize == 157962 and filename matches /File\d{3}/
}

rule Suspect_Group_File142 {
    meta:
        description = "Matches File142 (ZIP archive - PowerPoint)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 50 4b 03 04 0a 00 00 00 08 00 ?? ?? ?? ?? 03 e4 7b fe c7 03 00 00 91 13 00 00 14 00 00 00 70 70 74 2f 70 72 65 73 65 6e 74 61 74 69 6f 6e 2e 78 6d 6c }
    condition:
        $header at 0 and filesize == 2693126 and filename matches /File\d{3}/
}

rule Suspect_Group_File143 {
    meta:
        description = "Matches File143 (PNG)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { ff d8 ff 00 00 00 0d 49 48 44 52 00 00 03 88 00 00 04 ec 08 06 00 00 00 c2 72 ac 0c 00 01 00 00 49 44 41 54 78 9c ec fd 59 93 24 49 92 26 88 7d cc 22 }
    condition:
        $header at 0 and filesize == 1635658 and filename matches /File\d{3}/
}

rule Suspect_Group_File144 {
    meta:
        description = "Matches File144 (ZIP archive)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 50 4b 03 04 0a 00 00 00 00 00 ?? ?? ?? ?? ff ff ff ff 1c 02 00 00 1c 02 00 00 10 00 00 00 5b 74 72 61 73 68 5d 2f 30 30 30 30 2e 64 61 74 ff ff ff ff }
    condition:
        $header at 0 and filesize == 2490902 and filename matches /File\d{3}/
}

rule Suspect_Group_File145 {
    meta:
        description = "Matches File145 (ZIP archive)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 ?? ?? ?? ?? ff bf 18 7a 2e 02 00 00 57 0d 00 00 13 00 c2 01 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 82840 and filename matches /File\d{3}/
}

rule Suspect_Group_File147 {
    meta:
        description = "Matches File147"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 40 65 63 68 6f 20 6f 66 66 0d 0a 73 65 74 20 6d 65 73 73 61 67 65 3d 4c 6f 61 64 69 6e 67 20 72 61 6e 64 6f 6d 20 74 65 78 74 2e 2e 2e 0d 0a 66 6f 72 }
    condition:
        $header at 0 and filesize == 156 and filename matches /File\d{3}/
}

rule Suspect_Group_File148 {
    meta:
        description = "Matches File148 (MZ variant)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { ff fb 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $header at 0 and filesize == 315392 and filename matches /File\d{3}/
}

rule Suspect_Group_File149 {
    meta:
        description = "Matches File149 (ZIP archive - Word footer)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 50 4b 03 04 14 00 08 08 08 00 ?? ?? ?? ?? ce 13 76 59 00 00 00 00 00 00 00 00 00 00 00 00 10 00 00 00 77 6f 72 64 2f 66 6f 6f 74 65 72 31 2e 78 6d 6c ed 57 ff 6e }
    condition:
        $header at 0 and filesize == 27228 and filename matches /File\d{3}/
}

rule Suspect_Group_File150 {
    meta:
        description = "Matches File150 (ZIP archive)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 50 4b 03 04 0a 00 00 00 00 00 ?? ?? ?? ?? ff ff ff ff 20 02 00 00 20 02 00 00 10 00 00 00 5b 74 72 61 73 68 5d 2f 30 30 30 30 2e 64 61 74 ff ff ff ff }
    condition:
        $header at 0 and filesize == 955283 and filename matches /File\d{3}/
}

rule Suspect_Group_File151 {
    meta:
        description = "Matches File151 (ZIP archive)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 ?? ?? ?? ?? b7 bb c7 dc a4 02 00 00 00 25 00 00 13 00 08 02 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 4723372 and filename matches /File\d{3}/
}

rule Suspect_Group_File152 {
    meta:
        description = "Matches File152 (JPEG)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { ff d8 ff e0 00 10 4a 46 49 46 00 01 01 00 00 01 00 01 00 00 ff db 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0a 0c 14 0d 0c 0b 0b 0c 19 12 13 0f }
    condition:
        $header at 0 and filesize == 151135 and filename matches /File\d{3}/
}

rule Suspect_Group_File153 {
    meta:
        description = "Matches File153 (ZIP archive - Excel comments)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 50 4b 03 04 14 00 08 08 08 00 ?? ?? ?? ?? ba bb 75 55 00 00 00 00 00 00 00 00 00 00 00 00 10 00 00 00 78 6c 2f 63 6f 6d 6d 65 6e 74 73 31 2e 78 6d 6c 8d 53 cb 6e }
    condition:
        $header at 0 and filesize == 40590 and filename matches /File\d{3}/
}

rule Suspect_Group_File154 {
    meta:
        description = "Matches File154"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 45 00 64 00 75 00 63 00 61 00 74 00 69 00 6f 00 6e 00 61 00 6c 00 20 00 43 00 6f 00 6d 00 6d 00 75 00 6e 00 69 00 74 00 79 00 20 00 4c 00 69 00 63 00 }
    condition:
        $header at 0 and filesize == 22534 and filename matches /File\d{3}/
}

rule Suspect_Group_File155 {
    meta:
        description = "Matches File155 (MZ variant)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 4d 5a 50 00 02 00 00 00 04 00 0f 00 ff ff 00 00 b8 00 00 00 00 00 00 00 40 00 1a 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $header at 0 and filesize == 301568 and filename matches /File\d{3}/
}

rule Suspect_Group_File156 {
    meta:
        description = "Matches File156 (PDF)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 25 50 44 46 2d 31 2e 37 0a 25 f6 e4 fc df 0a 31 20 30 20 6f 62 6a 0a 3c 3c 0a 2f 54 79 70 65 20 2f 43 61 74 61 6c 6f 67 0a 2f 50 61 67 65 73 20 32 20 }
    condition:
        $header at 0 and filesize == 347444 and filename matches /File\d{3}/
}

rule Suspect_Group_File157 {
    meta:
        description = "Matches File157"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 41 63 61 64 65 6d 69 63 20 46 72 65 65 20 4c 69 63 65 6e 73 65 20 28 22 41 46 4c 22 29 20 76 2e 20 33 2e 30 0d 0a 0d 0a 54 68 69 73 20 41 63 61 64 65 }
    condition:
        $header at 0 and filesize == 10483 and filename matches /File\d{3}/
}

rule Suspect_Group_File158 {
    meta:
        description = "Matches File158"
        author = "Forensics Deduplication Script"
    strings:
        $header = { ef bb bf 3c 23 0a 2e 53 59 4e 4f 50 53 49 53 0a 09 49 6e 73 74 61 6c 6c 73 20 53 70 6f 74 69 66 79 0a 2e 44 45 53 43 52 49 50 54 49 4f 4e 0a 09 54 68 }
    condition:
        $header at 0 and filesize == 631 and filename matches /File\d{3}/
}

rule Suspect_Group_File159 {
    meta:
        description = "Matches File159 (MZ variant)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 4d 5a 8b 00 03 00 00 00 20 00 00 00 ff ff 07 00 00 01 65 40 00 00 00 00 40 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $header at 0 and filesize == 317088 and filename matches /File\d{3}/
}

rule Suspect_Group_File161 {
    meta:
        description = "Matches File161 (ZIP archive - .rels)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 ?? ?? ?? ?? b5 cf 3e 7b 02 01 00 00 bb 02 00 00 0b 00 08 02 5f 72 65 6c 73 2f 2e 72 65 6c 73 20 a2 04 02 28 a0 00 02 00 }
    condition:
        $header at 0 and filesize == 50971 and filename matches /File\d{3}/
}

rule Suspect_Group_File162 {
    meta:
        description = "Matches File162 (ZIP archive)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 ?? ?? ?? ?? a4 04 cf e9 71 01 00 00 98 05 00 00 13 00 08 02 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 28514 and filename matches /File\d{3}/
}

rule Suspect_Group_File163 {
    meta:
        description = "Matches File163 (JPEG)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { ff d8 ff e0 00 10 4a 46 49 46 00 01 01 00 00 01 00 01 00 00 ff db 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0a 0c 14 0d 0c 0b 0b 0c 19 12 13 0f }
    condition:
        $header at 0 and filesize == 174733 and filename matches /File\d{3}/
}

rule Suspect_Group_File165 {
    meta:
        description = "Matches File165"
        author = "Forensics Deduplication Script"
    strings:
        $header = { ef bb bf 3c 23 0d 0a 2e 53 59 4e 4f 50 53 49 53 0d 0a 20 20 20 20 20 20 20 20 49 6e 73 74 61 6c 6c 73 20 43 68 6f 63 6f 6c 61 74 65 79 20 28 6e 65 65 }
    condition:
        $header at 0 and filesize == 696 and filename matches /File\d{3}/
}

rule Suspect_Group_File167 {
    meta:
        description = "Matches File167"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 54 68 69 73 20 69 73 20 66 72 65 65 20 61 6e 64 20 75 6e 65 6e 63 75 6d 62 65 72 65 64 20 73 6f 66 74 77 61 72 65 20 72 65 6c 65 61 73 65 64 20 69 6e }
    condition:
        $header at 0 and filesize == 1233 and filename matches /File\d{3}/
}

rule Suspect_Group_File168 {
    meta:
        description = "Matches File168"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 47 4e 55 20 4c 45 53 53 45 52 20 47 45 4e 45 52 41 4c 20 50 55 42 4c 49 43 20 4c 49 43 45 4e }
    condition:
        $header at 0 and filesize == 7815 and filename matches /File\d{3}/
}

rule Suspect_Group_File169 {
    meta:
        description = "Matches File169"
        author = "Forensics Deduplication Script"
    strings:
        $header = { ef bb bf 3c 23 0a 2e 53 59 4e 4f 50 53 49 53 0a 09 50 72 69 6e 74 73 20 74 68 65 20 53 48 41 35 31 32 20 68 61 73 68 20 6f 66 20 61 20 66 69 6c 65 0a }
    condition:
        $header at 0 and filesize == 781 and filename matches /File\d{3}/
}

rule Suspect_Group_File170 {
    meta:
        description = "Matches File170 (ZIP archive)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 ?? ?? ?? ?? c3 aa 5d 0e 8d 02 00 00 58 1d 00 00 13 00 08 02 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 6138710 and filename matches /File\d{3}/
}

rule Suspect_Group_File171 {
    meta:
        description = "Matches File171 (ZIP archive)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 ?? ?? ?? ?? 33 a5 4b 35 8a 01 00 00 99 05 00 00 13 00 08 02 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 1011368 and filename matches /File\d{3}/
}

rule Suspect_Group_File172 {
    meta:
        description = "Matches File172"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 4d 6f 7a 69 6c 6c 61 20 50 75 62 6c 69 63 20 4c 69 63 65 6e 73 65 20 56 65 72 73 69 6f 6e 20 32 2e 30 0d 0a 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d }
    condition:
        $header at 0 and filesize == 17097 and filename matches /File\d{3}/
}

rule Suspect_Group_File174 {
    meta:
        description = "Matches File174"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 40 65 63 68 6f 20 6f 66 66 0d 0a 73 65 74 20 2f 61 20 61 3d 25 72 61 6e 64 6f 6d 25 20 25 25 20 31 30 30 0d 0a 73 65 74 20 2f 61 20 62 3d 25 72 61 6e }
    condition:
        $header at 0 and filesize == 113 and filename matches /File\d{3}/
}

rule Suspect_Group_File175 {
    meta:
        description = "Matches File175"
        author = "Forensics Deduplication Script"
    strings:
        $header = { ef bb bf 3c 23 0a 2e 53 59 4e 4f 50 53 49 53 0a 09 49 6e 73 74 61 6c 6c 73 20 56 4c 43 0a 2e 44 45 53 43 52 49 50 54 49 4f 4e 0a 09 54 68 69 73 20 50 }
    condition:
        $header at 0 and filesize == 829 and filename matches /File\d{3}/
}

rule Suspect_Group_File178 {
    meta:
        description = "Matches File178"
        author = "Forensics Deduplication Script"
    strings:
        $header = { ef bb bf 3c 23 0a 2e 53 59 4e 4f 50 53 49 53 0a 09 49 6e 73 74 61 6c 6c 73 20 4e 65 74 66 6c 69 78 0a 2e 44 45 53 43 52 49 50 54 49 4f 4e 0a 09 54 68 }
    condition:
        $header at 0 and filesize == 608 and filename matches /File\d{3}/
}

rule Suspect_Group_File179 {
    meta:
        description = "Matches File179"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 09 09 20 20 20 20 20 20 20 54 68 65 20 41 72 74 69 73 74 69 63 20 4c 69 63 65 6e 73 65 20 32 2e 30 0d 0a 0d 0a 09 20 20 20 20 43 6f 70 79 72 69 67 68 }
    condition:
        $header at 0 and filesize == 9093 and filename matches /File\d{3}/
}

rule Suspect_Group_File181 {
    meta:
        description = "Matches File181 (ZIP archive)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 50 4b 03 04 14 00 00 08 08 00 ?? ?? ?? ?? 42 3d 3c 5a 47 92 44 b2 5a 01 00 00 f0 04 00 00 13 00 04 00 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 53 }
    condition:
        $header at 0 and filesize == 9567 and filename matches /File\d{3}/
}

rule Suspect_Group_File182 {
    meta:
        description = "Matches File182 (PDF)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 25 50 44 46 2d 31 2e 34 0d 25 e2 e3 cf d3 0d 0a 31 32 31 33 20 30 20 6f 62 6a 0d 3c 3c 2f 4c 69 6e 65 61 72 69 7a 65 64 20 31 2f 4c 20 34 39 30 38 36 }
    condition:
        $header at 0 and filesize == 490858 and filename matches /File\d{3}/
}

rule Suspect_Group_File183 {
    meta:
        description = "Matches File183 (ZIP archive)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 ?? ?? ?? ?? 1c ad b2 d2 fa 01 00 00 6d 0b 00 00 13 00 08 02 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 34148 and filename matches /File\d{3}/
}

rule Suspect_Group_File184 {
    meta:
        description = "Matches File184 (PNG)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49 48 44 52 00 00 03 88 00 00 04 ec 08 06 00 00 00 c2 72 ac 0c 00 01 00 00 49 44 41 54 78 9c ec fd f9 8f 24 5b 96 }
    condition:
        $header at 0 and filesize == 1660287 and filename matches /File\d{3}/
}

rule Suspect_Group_File185 {
    meta:
        description = "Matches File185 (ZIP archive)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 ?? ?? ?? ?? 96 34 82 68 62 02 00 00 28 18 00 00 13 00 c5 01 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 870117 and filename matches /File\d{3}/
}

rule Suspect_Group_File186 {
    meta:
        description = "Matches File186"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 4d 00 49 00 54 00 20 00 4c 00 69 00 63 00 65 00 6e 00 73 00 65 00 0d 00 0a 00 0d 00 0a 00 43 00 6f 00 70 00 79 00 72 00 69 00 67 00 68 00 74 00 20 00 }
    condition:
        $header at 0 and filesize == 2176 and filename matches /File\d{3}/
}

rule Suspect_Group_File187 {
    meta:
        description = "Matches File187 (ZIP archive)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 ?? ?? ?? ?? b5 f6 d3 96 8d 01 00 00 21 07 00 00 13 00 08 02 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 23570 and filename matches /File\d{3}/
}

rule Suspect_Group_File188 {
    meta:
        description = "Matches File188"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 4f 70 65 6e 20 53 6f 66 74 77 61 72 65 20 4c 69 63 65 6e 73 65 20 28 22 4f 53 4c 22 29 20 76 2e 20 33 2e 30 0d 0a 0d 0a 54 68 69 73 20 4f 70 65 6e 20 }
    condition:
        $header at 0 and filesize == 10470 and filename matches /File\d{3}/
}

rule Suspect_Group_File189 {
    meta:
        description = "Matches File189 (ZIP archive)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 ?? ?? ?? ?? 88 5e 62 0b ca 01 00 00 22 0a 00 00 13 00 08 02 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 95254 and filename matches /File\d{3}/
}

rule Suspect_Group_File190 {
    meta:
        description = "Matches File190 (PNG)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49 48 44 52 00 00 03 88 00 00 04 ec 08 06 00 00 00 c2 72 ac 0c 00 01 00 00 49 44 41 54 78 9c ec fd e9 b3 6d c7 75 }
    condition:
        $header at 0 and filesize == 1799942 and filename matches /File\d{3}/
}

rule Suspect_Group_File191 {
    meta:
        description = "Matches File191 (ZIP archive)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 ?? ?? ?? ?? 58 79 36 07 df 01 00 00 23 0a 00 00 13 00 08 02 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 148835 and filename matches /File\d{3}/
}

rule Suspect_Group_File192 {
    meta:
        description = "Matches File192 (MZ truncated?)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $header at 0 and filesize == 319563 and filename matches /File\d{3}/
}

rule Suspect_Group_File193 {
    meta:
        description = "Matches File193 (ZIP archive)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 50 4b 03 04 0a 00 00 00 00 00 ?? ?? ?? ?? ff ff ff ff 0c 02 00 00 0c 02 00 00 10 00 00 00 5b 74 72 61 73 68 5d 2f 30 30 30 30 2e 64 61 74 ff ff ff ff }
    condition:
        $header at 0 and filesize == 466915 and filename matches /File\d{3}/
}

rule Suspect_Group_File194 {
    meta:
        description = "Matches File194 (ZIP archive)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 ?? ?? ?? ?? 3e 11 88 ca 60 02 00 00 47 19 00 00 13 00 08 02 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 1641870 and filename matches /File\d{3}/
}

rule Suspect_Group_File195 {
    meta:
        description = "Matches File195 (ZIP archive)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 43 44 30 30 14 00 06 00 08 00 ?? ?? ?? ?? 71 4b 4e 12 05 02 00 00 ec 0c 00 00 13 00 cd 01 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 87316 and filename matches /File\d{3}/
}

rule Suspect_Group_File196 {
    meta:
        description = "Matches File196 (ZIP archive)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 ?? ?? ?? ?? 62 ee 9d 68 5e 01 00 00 90 04 00 00 13 00 08 02 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 1379663 and filename matches /File\d{3}/
}

rule Suspect_Group_File197 {
    meta:
        description = "Matches File197 (ZIP archive - Word header)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 50 4b 03 04 14 00 08 08 08 00 ?? ?? ?? ?? d2 41 75 59 00 00 00 00 00 00 00 00 00 00 00 00 10 00 00 00 77 6f 72 64 2f 68 65 61 64 65 72 31 2e 78 6d 6c a5 95 db 8e }
    condition:
        $header at 0 and filesize == 2454899 and filename matches /File\d{3}/
}

rule Suspect_Group_File198 {
    meta:
        description = "Matches File198 (ZIP archive - .rels)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 ?? ?? ?? ?? 99 55 7e 05 f9 00 00 00 e1 02 00 00 0b 00 f3 01 5f 72 65 6c 73 2f 2e 72 65 6c 73 20 a2 ef 01 28 a0 00 02 00 }
    condition:
        $header at 0 and filesize == 10412619 and filename matches /File\d{3}/
}

rule Suspect_Group_File199 {
    meta:
        description = "Matches File199 (PDF)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 25 50 44 46 2d 31 2e 37 0d 0a 25 b5 b5 b5 b5 0d 0a 31 20 30 20 6f 62 6a 0d 0a 3c 3c 2f 54 79 70 65 2f 43 61 74 61 6c 6f 67 2f 50 61 67 65 73 20 32 20 }
    condition:
        $header at 0 and filesize == 266057 and filename matches /File\d{3}/
}

rule Suspect_Group_File200 {
    meta:
        description = "Matches File200 (PNG)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 4d 5a 00 00 00 0d 49 48 44 52 00 00 03 88 00 00 04 ec 08 06 00 00 00 c2 72 ac 0c 00 01 00 00 49 44 41 54 78 9c ec fd 59 b3 64 49 92 1e 88 7d aa 6a 76 }
    condition:
        $header at 0 and filesize == 1543898 and filename matches /File\d{3}/
}

rule Suspect_Group_File202 {
    meta:
        description = "Matches File202 (B? variant)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 42 00 02 00 00 00 20 00 00 00 ff ff 05 00 00 01 00 00 00 00 00 00 40 00 00 00 01 00 fb 71 6a 72 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $header at 0 and filesize == 1204734 and filename matches /File\d{3}/
}

rule Suspect_Group_File203 {
    meta:
        description = "Matches File203"
        author = "Forensics Deduplication Script"
    strings:
        $header = { ef bb bf 3c 23 0a 2e 53 59 4e 4f 50 53 49 53 0a 09 50 72 69 6e 74 73 20 74 68 65 20 53 48 41 32 35 36 20 68 61 73 68 20 6f 66 20 61 20 66 69 6c 65 0a }
    condition:
        $header at 0 and filesize == 781 and filename matches /File\d{3}/
}

rule Suspect_Group_File204 {
    meta:
        description = "Matches File204"
        author = "Forensics Deduplication Script"
    strings:
        $header = { ef bb bf 3c 23 0a 2e 53 59 4e 4f 50 53 49 53 0a 09 49 6e 73 74 61 6c 6c 73 20 4f 42 53 20 53 74 75 64 69 6f 20 28 6e 65 65 64 73 20 61 64 6d 69 6e 20 }
    condition:
        $header at 0 and filesize == 681 and filename matches /File\d{3}/
}

rule Suspect_Group_File205 {
    meta:
        description = "Matches File205 (JPEG)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { ff d8 ff e0 00 10 4a 46 49 46 00 01 01 00 00 01 00 01 00 00 ff db 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0a 0c 14 0d 0c 0b 0b 0c 19 12 13 0f }
    condition:
        $header at 0 and filesize == 169050 and filename matches /File\d{3}/
}

rule Suspect_Group_File206 {
    meta:
        description = "Matches File206 (ZIP archive)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 ?? ?? ?? ?? 24 ec 50 bf 82 01 00 00 24 07 00 00 13 00 08 02 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 209333 and filename matches /File\d{3}/
}

rule Suspect_Group_File208 {
    meta:
        description = "Matches File208 (ZIP archive)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 ?? ?? ?? ?? e4 a7 b0 6f eb 01 00 00 35 0d 00 00 13 00 08 02 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 3060289 and filename matches /File\d{3}/
}

rule Suspect_Group_File209 {
    meta:
        description = "Matches File209 (PDF)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 25 50 44 46 2d 31 2e 33 0a 25 e2 e3 cf d3 0a 31 20 30 20 6f 62 6a 0a 3c 3c 0a 2f 54 79 70 65 20 2f 50 61 67 65 73 0a 2f 43 6f 75 6e 74 20 31 34 0a 2f }
    condition:
        $header at 0 and filesize == 202653 and filename matches /File\d{3}/
}

rule Suspect_Group_File210 {
    meta:
        description = "Matches File210 (ZIP archive - docProps)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 50 4b 03 04 0a 00 00 00 08 00 ?? ?? ?? ?? fc 1f ed 11 25 02 00 00 43 05 00 00 10 00 00 00 64 6f 63 50 72 6f 70 73 2f 61 70 70 2e 78 6d 6c 9c 54 df 6f }
    condition:
        $header at 0 and filesize == 184563 and filename matches /File\d{3}/
}

rule Suspect_Group_File211 {
    meta:
        description = "Matches File211 (ZIP archive - Excel presentation)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 ?? ?? ?? ?? 3b f4 79 e3 2e 03 00 00 b8 10 00 00 14 00 00 00 78 6c 2f 70 72 65 73 65 6e 74 61 74 69 6f 6e 2e 78 6d 6c ec }
    condition:
        $header at 0 and filesize == 458026 and filename matches /File\d{3}/
}

rule Suspect_Group_File212 {
    meta:
        description = "Matches File212"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 40 65 63 68 6f 20 6f 66 66 0d 0a 73 65 74 20 61 64 76 69 63 65 3d 53 74 61 79 20 70 6f 73 69 74 69 76 65 2e 7c 54 61 6b 65 20 62 72 65 61 6b 73 2e 7c }
    condition:
        $header at 0 and filesize == 182 and filename matches /File\d{3}/
}

rule Suspect_Group_File214 {
    meta:
        description = "Matches File214 (JPEG)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { ff d8 ff e0 00 10 4a 46 49 46 00 01 01 00 00 01 00 01 00 00 ff db 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0a 0c 14 0d 0c 0b 0b 0c 19 12 13 0f }
    condition:
        $header at 0 and filesize == 166868 and filename matches /File\d{3}/
}

rule Suspect_Group_File215 {
    meta:
        description = "Matches File215"
        author = "Forensics Deduplication Script"
    strings:
        $header = { ef bb bf 3c 23 0a 2e 53 59 4e 4f 50 53 49 53 0a 09 49 6e 73 74 61 6c 6c 73 20 56 69 73 75 61 6c 20 53 74 75 64 69 6f 20 43 6f 64 65 0a 2e 44 45 53 43 }
    condition:
        $header at 0 and filesize == 643 and filename matches /File\d{3}/
}

rule Suspect_Group_File216 {
    meta:
        description = "Matches File216"
        author = "Forensics Deduplication Script"
    strings:
        $header = { ef bb bf 3c 23 0a 2e 53 59 4e 4f 50 53 49 53 0a 09 49 6e 73 74 61 6c 6c 73 20 47 69 74 20 45 78 74 65 6e 73 69 6f 6e 73 0a 2e 44 45 53 43 52 49 50 54 }
    condition:
        $header at 0 and filesize == 628 and filename matches /File\d{3}/
}

rule Suspect_Group_File217 {
    meta:
        description = "Matches File217"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 45 55 52 4f 50 45 41 4e 20 55 4e 49 4f 4e 20 50 55 42 4c 49 43 20 4c 49 43 45 4e 43 }
    condition:
        $header at 0 and filesize == 14118 and filename matches /File\d{3}/
}

rule Suspect_Group_File218 {
    meta:
        description = "Matches File218 (PNG)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49 48 44 52 00 00 03 88 00 00 04 ec 08 06 00 00 00 c2 72 ac 0c 00 01 00 00 49 44 41 54 78 9c ec fd 69 b0 6d c9 75 }
    condition:
        $header at 0 and filesize == 1394042 and filename matches /File\d{3}/
}

rule Suspect_Group_File219 {
    meta:
        description = "Matches File219 (JPEG with EXIF)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { ff d8 ff e0 00 10 45 58 49 46 00 01 01 00 00 01 00 01 00 00 ff db 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0a 0c 14 0d 0c 0b 0b 0c 19 12 13 0f }
    condition:
        $header at 0 and filesize == 127189 and filename matches /File\d{3}/
}

rule Suspect_Group_File220 {
    meta:
        description = "Matches File220"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 40 65 63 68 6f 20 6f 66 66 0d 0a 73 65 74 20 77 6f 72 64 3d 68 65 6c 6c 6f 0d 0a 73 65 74 20 73 63 72 61 6d 62 6c 65 64 3d 0d 0a 66 6f 72 20 2f 6c 20 }
    condition:
        $header at 0 and filesize == 191 and filename matches /File\d{3}/
}

/*
 * Additional YARA rules for the 7 missing files (043, 076, 122, 149, 153, 181, 197)
 * Add these to the existing rule set.
 */

rule Suspect_Group_File043_2 {
    meta:
        description = "Matches File043 (ZIP archive - Word document)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 50 4b 03 04 14 00 02 00 08 00 ?? ?? ?? ?? fb 70 55 3b 11 53 00 00 49 4e 03 00 11 00 11 00 77 6f 72 64 2f 64 6f 63 75 6d 65 6e 74 2e 78 6d 6c 55 54 0d }
    condition:
        $header at 0 and filesize == 106799 and filename matches /File\d{3}/
}

rule Suspect_Group_File076_2 {
    meta:
        description = "Matches File076 (ZIP archive - Word header)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 50 4b 03 04 14 00 08 08 08 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 10 00 00 00 77 6f 72 64 2f 68 65 61 64 65 72 31 2e 78 6d 6c cd 96 db 8e }
    condition:
        $header at 0 and filesize == 115731 and filename matches /File\d{3}/
}

rule Suspect_Group_File122_2 {
    meta:
        description = "Matches File122 (ZIP archive - Word numbering)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 50 4b 03 04 14 00 08 08 08 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 12 00 00 00 77 6f 72 64 2f 6e 75 6d 62 65 72 69 6e 67 2e 78 6d 6c ed 9b }
    condition:
        $header at 0 and filesize == 572074 and filename matches /File\d{3}/
}

rule Suspect_Group_File149_2 {
    meta:
        description = "Matches File149 (ZIP archive - Word footer)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 50 4b 03 04 14 00 08 08 08 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 10 00 00 00 77 6f 72 64 2f 66 6f 6f 74 65 72 31 2e 78 6d 6c ed 57 ff 6e }
    condition:
        $header at 0 and filesize == 27228 and filename matches /File\d{3}/
}

rule Suspect_Group_File153_2 {
    meta:
        description = "Matches File153 (ZIP archive - Excel comments)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 50 4b 03 04 14 00 08 08 08 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 10 00 00 00 78 6c 2f 63 6f 6d 6d 65 6e 74 73 31 2e 78 6d 6c 8d 53 cb 6e }
    condition:
        $header at 0 and filesize == 40590 and filename matches /File\d{3}/
}

rule Suspect_Group_File181_2 {
    meta:
        description = "Matches File181 (ZIP archive - Content_Types)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 50 4b 03 04 14 00 00 08 08 00 ?? ?? ?? ?? 47 92 44 b2 5a 01 00 00 f0 04 00 00 13 00 04 00 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 53 }
    condition:
        $header at 0 and filesize == 9567 and filename matches /File\d{3}/
}

rule Suspect_Group_File197_2 {
    meta:
        description = "Matches File197 (ZIP archive - Word header)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 50 4b 03 04 14 00 08 08 08 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 10 00 00 00 77 6f 72 64 2f 68 65 61 64 65 72 31 2e 78 6d 6c a5 95 db 8e }
    condition:
        $header at 0 and filesize == 2454899 and filename matches /File\d{3}/
}