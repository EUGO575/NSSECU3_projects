rule Suspect_Group_File001 {
    meta:
        description = "Matches 1 files: File001"
        author = "Forensics Deduplication Script"
        original_size = 10768
    strings:
        $header = { 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $header at 0 and filesize == 10768
}
rule Suspect_Group_File002 {
    meta:
        description = "Matches 1 files: File002"
        author = "Forensics Deduplication Script"
        original_size = 556
    strings:
        $header = { ef bb bf 3c 23 0a 2e 53 59 4e 4f 50 53 49 53 0a 09 49 6e 73 74 61 6c 6c 73 20 5a 6f 6f 6d 0a 2e 44 45 53 43 52 49 50 54 49 4f 4e 0a 09 54 68 69 73 20 }
    condition:
        $header at 0 and filesize == 556
}
rule Suspect_Group_File003 {
    meta:
        description = "Matches 1 files: File003"
        author = "Forensics Deduplication Script"
        original_size = 1855
    strings:
        $header = { 43 6f 70 79 72 69 67 68 74 20 28 63 29 20 5b 79 65 61 72 5d 20 5b 66 75 6c 6c 6e 61 6d 65 5d 0d 0a 0d 0a 54 68 65 20 55 6e 69 76 65 72 73 61 6c 20 50 }
    condition:
        $header at 0 and filesize == 1855
}
rule Suspect_Group_File004 {
    meta:
        description = "Matches 1 files: File004"
        author = "Forensics Deduplication Script"
        original_size = 149
    strings:
        $header = { 40 65 63 68 6f 20 6f 66 66 0d 0a 73 65 74 20 2f 61 20 6c 69 6e 65 3d 25 72 61 6e 64 6f 6d 25 20 25 25 20 35 20 2b 20 31 0d 0a 66 6f 72 20 2f 66 20 22 }
    condition:
        $header at 0 and filesize == 149
}
rule Suspect_Group_File005 {
    meta:
        description = "Matches 1 files: File005"
        author = "Forensics Deduplication Script"
        original_size = 2560
    strings:
        $header = { 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $header at 0 and filesize == 2560
}
rule Suspect_Group_File006 {
    meta:
        description = "Matches 1 files: File006"
        author = "Forensics Deduplication Script"
        original_size = 4319474
    strings:
        $header = { 50 4b 03 04 0a 00 00 00 00 00 00 00 21 00 ff ff ff ff 11 02 00 00 11 02 00 00 10 00 00 00 5b 74 72 61 73 68 5d 2f 30 30 30 30 2e 64 61 74 ff ff ff ff }
    condition:
        $header at 0 and filesize == 4319474
}
rule Suspect_Group_File007 {
    meta:
        description = "Matches 1 files: File007"
        author = "Forensics Deduplication Script"
        original_size = 1013332
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 00 00 21 00 d4 a2 46 3f d9 01 00 00 ec 09 00 00 13 00 d3 01 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 1013332
}
rule Suspect_Group_File008 {
    meta:
        description = "Matches 1 files: File008"
        author = "Forensics Deduplication Script"
        original_size = 1617304
    strings:
        $header = { 89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 4c 45 4e 5a 00 00 03 88 00 00 04 ec 08 06 00 00 00 c2 72 ac 0c 00 01 00 00 49 44 41 54 78 9c ec fd 79 9c 6d d9 75 }
    condition:
        $header at 0 and filesize == 1617304
}
rule Suspect_Group_File009 {
    meta:
        description = "Matches 1 files: File009"
        author = "Forensics Deduplication Script"
        original_size = 1726586
    strings:
        $header = { 89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49 48 44 52 00 00 03 88 00 00 04 ec 08 06 00 00 00 c2 72 ac 0c 00 01 00 00 49 44 41 54 78 9c ec fd 59 93 24 39 92 }
    condition:
        $header at 0 and filesize == 1726586
}
rule Suspect_Group_File010 {
    meta:
        description = "Matches 1 files: File010"
        author = "Forensics Deduplication Script"
        original_size = 4155280
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 00 00 21 00 3c f3 21 f4 57 02 00 00 9f 16 00 00 13 00 c0 01 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 4155280
}
rule Suspect_Group_File011 {
    meta:
        description = "Matches 1 files: File011"
        author = "Forensics Deduplication Script"
        original_size = 12996644
    strings:
        $header = { 50 4b 03 04 0a 00 00 00 00 00 00 00 21 00 ff ff ff ff 0f 02 00 00 0f 02 00 00 10 00 00 00 5b 74 72 61 73 68 5d 2f 30 30 30 30 2e 64 61 74 ff ff ff ff }
    condition:
        $header at 0 and filesize == 12996644
}
rule Suspect_Group_File012 {
    meta:
        description = "Matches 1 files: File012"
        author = "Forensics Deduplication Script"
        original_size = 28659
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 00 00 21 00 04 e8 63 06 f7 01 00 00 9b 0a 00 00 13 00 08 02 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 28659
}
rule Suspect_Group_File013 {
    meta:
        description = "Matches 1 files: File013"
        author = "Forensics Deduplication Script"
        original_size = 814
    strings:
        $header = { ef bb bf 3c 23 0a 2e 53 59 4e 4f 50 53 49 53 0a 09 50 72 69 6e 74 73 20 74 68 65 20 4d 44 35 20 63 68 65 63 6b 73 75 6d 20 6f 66 20 61 20 66 69 6c 65 }
    condition:
        $header at 0 and filesize == 814
}
rule Suspect_Group_File014 {
    meta:
        description = "Matches 1 files: File014"
        author = "Forensics Deduplication Script"
        original_size = 3050393
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 00 00 21 00 e4 a7 b0 6f eb 01 00 00 35 0d 00 00 13 00 08 02 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 3050393
}
rule Suspect_Group_File015 {
    meta:
        description = "Matches 1 files: File015"
        author = "Forensics Deduplication Script"
        original_size = 164
    strings:
        $header = { 40 65 63 68 6f 20 6f 66 66 0d 0a 73 65 74 20 2f 61 20 63 6f 75 6e 74 3d 25 72 61 6e 64 6f 6d 25 20 25 25 20 32 30 20 2b 20 31 0d 0a 65 63 68 6f 20 47 }
    condition:
        $header at 0 and filesize == 164
}
rule Suspect_Group_File016 {
    meta:
        description = "Matches 1 files: File016"
        author = "Forensics Deduplication Script"
        original_size = 87
    strings:
        $header = { 40 65 63 68 6f 20 6f 66 66 0d 0a 73 65 74 20 2f 61 20 68 65 78 3d 25 72 61 6e 64 6f 6d 25 20 25 25 20 32 35 35 0d 0a 73 65 74 20 2f 61 20 68 65 78 32 }
    condition:
        $header at 0 and filesize == 87
}
rule Suspect_Group_File017 {
    meta:
        description = "Matches 1 files: File017"
        author = "Forensics Deduplication Script"
        original_size = 4810789
    strings:
        $header = { 50 4b 03 04 0a 00 00 00 00 00 00 00 21 00 ff ff ff ff 0d 02 00 00 0d 02 00 00 10 00 00 00 5b 74 72 61 73 68 5d 2f 30 30 30 30 2e 64 61 74 ff ff ff ff }
    condition:
        $header at 0 and filesize == 4810789
}
rule Suspect_Group_File018 {
    meta:
        description = "Matches 1 files: File018"
        author = "Forensics Deduplication Script"
        original_size = 407134
    strings:
        $header = { 25 50 44 46 2d 31 2e 35 0a 25 f6 e4 fc df 0a 31 20 30 20 6f 62 6a 0a 3c 3c 0a 2f 54 79 70 65 20 2f 43 61 74 61 6c 6f 67 0a 2f 50 61 67 65 73 20 32 20 }
    condition:
        $header at 0 and filesize == 407134
}
rule Suspect_Group_File019 {
    meta:
        description = "Matches 1 files: File019"
        author = "Forensics Deduplication Script"
        original_size = 1651234
    strings:
        $header = { 89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49 48 44 52 00 00 03 88 00 00 04 ec 08 06 00 00 00 c2 72 ac 0c 00 01 00 00 49 44 41 54 78 9c ec fd 79 b0 25 d7 79 }
    condition:
        $header at 0 and filesize == 1651234
}
rule Suspect_Group_File020 {
    meta:
        description = "Matches 1 files: File020"
        author = "Forensics Deduplication Script"
        original_size = 38102
    strings:
        $header = { 41 00 74 00 74 00 72 00 69 00 62 00 75 00 74 00 69 00 6f 00 6e 00 20 00 34 00 2e 00 30 00 20 00 49 00 6e 00 74 00 65 00 72 00 6e 00 61 00 74 00 69 00 }
    condition:
        $header at 0 and filesize == 38102
}
rule Suspect_Group_File021 {
    meta:
        description = "Matches 1 files: File021"
        author = "Forensics Deduplication Script"
        original_size = 35182
    strings:
        $header = { 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 47 4e 55 20 41 46 46 45 52 4f 20 47 45 4e 45 52 41 4c 20 50 55 42 4c 49 43 20 4c 49 43 45 }
    condition:
        $header at 0 and filesize == 35182
}
rule Suspect_Group_File022 {
    meta:
        description = "Matches 1 files: File022"
        author = "Forensics Deduplication Script"
        original_size = 185443
    strings:
        $header = { 25 50 44 46 2d 31 2e 37 0a 25 f6 e4 fc df 0a 31 20 30 20 6f 62 6a 0a 3c 3c 0a 2f 50 61 67 65 73 20 32 20 30 20 52 0a 2f 54 79 70 65 20 2f 43 61 74 61 }
    condition:
        $header at 0 and filesize == 185443
}
rule Suspect_Group_File023 {
    meta:
        description = "Matches 1 files: File023"
        author = "Forensics Deduplication Script"
        original_size = 686849
    strings:
        $header = { 49 44 33 00 01 01 00 00 00 08 00 10 00 ff ff 08 00 00 01 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $header at 0 and filesize == 686849
}
rule Suspect_Group_File024 {
    meta:
        description = "Matches 6 files: File024, File060, File081, File146, File166 and 1 others."
        author = "Forensics Deduplication Script"
        original_size = 3072
    strings:
        $header = { 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $header at 0 and filesize == 3072
}
rule Suspect_Group_File025 {
    meta:
        description = "Matches 1 files: File025"
        author = "Forensics Deduplication Script"
        original_size = 23832
    strings:
        $header = { 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $header at 0 and filesize == 23832
}
rule Suspect_Group_File026 {
    meta:
        description = "Matches 1 files: File026"
        author = "Forensics Deduplication Script"
        original_size = 35821
    strings:
        $header = { 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 47 4e 55 20 47 45 4e 45 52 41 4c 20 50 55 42 4c 49 43 20 4c 49 43 45 4e 53 45 0d 0a 20 20 }
    condition:
        $header at 0 and filesize == 35821
}
rule Suspect_Group_File027 {
    meta:
        description = "Matches 1 files: File027"
        author = "Forensics Deduplication Script"
        original_size = 3584
    strings:
        $header = { 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $header at 0 and filesize == 3584
}
rule Suspect_Group_File028 {
    meta:
        description = "Matches 1 files: File028"
        author = "Forensics Deduplication Script"
        original_size = 109
    strings:
        $header = { 40 65 63 68 6f 20 6f 66 66 0d 0a 73 65 74 20 2f 61 20 64 69 65 31 3d 25 72 61 6e 64 6f 6d 25 20 25 25 20 36 20 2b 20 31 0d 0a 73 65 74 20 2f 61 20 64 }
    condition:
        $header at 0 and filesize == 109
}
rule Suspect_Group_File029 {
    meta:
        description = "Matches 1 files: File029"
        author = "Forensics Deduplication Script"
        original_size = 273
    strings:
        $header = { 40 65 63 68 6f 20 6f 66 66 0d 0a 66 6f 72 20 2f 66 20 22 74 6f 6b 65 6e 73 3d 31 2d 34 20 64 65 6c 69 6d 73 3d 2f 20 22 20 25 25 61 20 69 6e 20 28 22 }
    condition:
        $header at 0 and filesize == 273
}
rule Suspect_Group_File030 {
    meta:
        description = "Matches 1 files: File030"
        author = "Forensics Deduplication Script"
        original_size = 5379567
    strings:
        $header = { 50 4b 03 04 0a 00 00 00 00 00 00 00 21 00 ff ff ff ff 64 02 00 00 64 02 00 00 10 00 00 00 5b 74 72 61 73 68 5d 2f 30 30 30 30 2e 64 61 74 ff ff ff ff }
    condition:
        $header at 0 and filesize == 5379567
}
rule Suspect_Group_File031 {
    meta:
        description = "Matches 1 files: File031"
        author = "Forensics Deduplication Script"
        original_size = 59159
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 00 00 21 00 98 84 f0 a8 eb 01 00 00 22 0a 00 00 13 00 ca 01 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 59159
}
rule Suspect_Group_File032 {
    meta:
        description = "Matches 1 files: File032"
        author = "Forensics Deduplication Script"
        original_size = 176259
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 00 00 21 00 e6 79 a3 97 ba 01 00 00 7d 0d 00 00 13 00 08 02 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 176259
}
rule Suspect_Group_File033 {
    meta:
        description = "Matches 1 files: File033"
        author = "Forensics Deduplication Script"
        original_size = 31332
    strings:
        $header = { 43 44 30 30 14 00 06 00 08 00 00 00 21 00 aa f7 58 a4 79 01 00 00 14 06 00 00 13 00 08 02 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 31332
}
rule Suspect_Group_File034 {
    meta:
        description = "Matches 1 files: File034"
        author = "Forensics Deduplication Script"
        original_size = 77
    strings:
        $header = { 40 65 63 68 6f 20 6f 66 66 0d 0a 73 65 74 20 2f 61 20 6e 75 6d 3d 25 72 61 6e 64 6f 6d 25 20 25 25 20 31 30 30 30 30 0d 0a 65 63 68 6f 20 59 6f 75 72 }
    condition:
        $header at 0 and filesize == 77
}
rule Suspect_Group_File035 {
    meta:
        description = "Matches 1 files: File035"
        author = "Forensics Deduplication Script"
        original_size = 3097388
    strings:
        $header = { 50 4b 03 04 14 00 00 00 08 00 00 00 21 00 61 0d d4 92 42 02 00 00 75 14 00 00 13 00 00 00 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c cc }
    condition:
        $header at 0 and filesize == 3097388
}
rule Suspect_Group_File036 {
    meta:
        description = "Matches 1 files: File036"
        author = "Forensics Deduplication Script"
        original_size = 1417519
    strings:
        $header = { 89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49 48 44 52 00 00 03 88 00 00 04 ec 08 06 00 00 00 c2 72 ac 0c 00 01 00 00 49 44 41 54 78 9c ec fd 69 b0 65 59 76 }
    condition:
        $header at 0 and filesize == 1417519
}
rule Suspect_Group_File037 {
    meta:
        description = "Matches 1 files: File037"
        author = "Forensics Deduplication Script"
        original_size = 266343
    strings:
        $header = { 50 4b 03 04 0a 00 00 00 00 00 00 00 21 00 ff ff ff ff 35 02 00 00 35 02 00 00 10 00 00 00 5b 74 72 61 73 68 5d 2f 30 30 30 30 2e 64 61 74 ff ff ff ff }
    condition:
        $header at 0 and filesize == 266343
}
rule Suspect_Group_File038 {
    meta:
        description = "Matches 1 files: File038"
        author = "Forensics Deduplication Script"
        original_size = 5125758
    strings:
        $header = { 43 44 30 30 31 2e 36 0a 25 f6 e4 fc df 0a 31 20 30 20 6f 62 6a 0a 3c 3c 0a 2f 4d 65 74 61 64 61 74 61 20 32 20 30 20 52 0a 2f 4c 61 6e 67 20 28 65 6e }
    condition:
        $header at 0 and filesize == 5125758
}
rule Suspect_Group_File039 {
    meta:
        description = "Matches 1 files: File039"
        author = "Forensics Deduplication Script"
        original_size = 608
    strings:
        $header = { ef bb bf 3c 23 0a 2e 53 59 4e 4f 50 53 49 53 0a 09 49 6e 73 74 61 6c 6c 73 20 44 69 73 63 6f 72 64 0a 2e 44 45 53 43 52 49 50 54 49 4f 4e 0a 09 54 68 }
    condition:
        $header at 0 and filesize == 608
}
rule Suspect_Group_File040 {
    meta:
        description = "Matches 1 files: File040"
        author = "Forensics Deduplication Script"
        original_size = 168
    strings:
        $header = { 40 65 63 68 6f 20 6f 66 66 0d 0a 73 65 74 20 69 6e 70 75 74 3d 68 65 6c 6c 6f 0d 0a 73 65 74 20 72 65 76 65 72 73 65 64 3d 0d 0a 66 6f 72 20 2f 6c 20 }
    condition:
        $header at 0 and filesize == 168
}
rule Suspect_Group_File041 {
    meta:
        description = "Matches 1 files: File041"
        author = "Forensics Deduplication Script"
        original_size = 1640375
    strings:
        $header = { 89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49 48 44 52 00 00 03 88 00 00 04 ec 08 06 00 00 00 c2 72 ac 0c 00 01 00 00 49 44 41 54 78 9c ec fd e9 92 24 4b 92 }
    condition:
        $header at 0 and filesize == 1640375
}
rule Suspect_Group_File042 {
    meta:
        description = "Matches 1 files: File042"
        author = "Forensics Deduplication Script"
        original_size = 11280
    strings:
        $header = { 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $header at 0 and filesize == 11280
}
rule Suspect_Group_File043 {
    meta:
        description = "Matches 1 files: File043"
        author = "Forensics Deduplication Script"
        original_size = 106799
    strings:
        $header = { 50 4b 03 04 14 00 02 00 08 00 4a 24 76 59 fb 70 55 3b 11 53 00 00 49 4e 03 00 11 00 11 00 77 6f 72 64 2f 64 6f 63 75 6d 65 6e 74 2e 78 6d 6c 55 54 0d }
    condition:
        $header at 0 and filesize == 106799
}
rule Suspect_Group_File044 {
    meta:
        description = "Matches 1 files: File044"
        author = "Forensics Deduplication Script"
        original_size = 229
    strings:
        $header = { 40 65 63 68 6f 20 6f 66 66 0d 0a 73 65 74 6c 6f 63 61 6c 20 65 6e 61 62 6c 65 64 65 6c 61 79 65 64 65 78 70 61 6e 73 69 6f 6e 0d 0a 73 65 74 20 77 6f }
    condition:
        $header at 0 and filesize == 229
}
rule Suspect_Group_File045 {
    meta:
        description = "Matches 1 files: File045"
        author = "Forensics Deduplication Script"
        original_size = 137878
    strings:
        $header = { ff d8 ff e1 00 10 4a 46 49 46 00 01 01 00 00 01 00 01 00 00 ff db 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0a 0c 14 0d 0c 0b 0b 0c 19 12 13 0f }
    condition:
        $header at 0 and filesize == 137878
}
rule Suspect_Group_File046 {
    meta:
        description = "Matches 1 files: File046"
        author = "Forensics Deduplication Script"
        original_size = 80947
    strings:
        $header = { 4d 5a 00 01 01 00 00 00 08 00 10 00 ff ff 08 00 00 01 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $header at 0 and filesize == 80947
}
rule Suspect_Group_File047 {
    meta:
        description = "Matches 1 files: File047"
        author = "Forensics Deduplication Script"
        original_size = 1082258
    strings:
        $header = { 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $header at 0 and filesize == 1082258
}
rule Suspect_Group_File048 {
    meta:
        description = "Matches 1 files: File048"
        author = "Forensics Deduplication Script"
        original_size = 831
    strings:
        $header = { ef bb bf 3c 23 0a 2e 53 59 4e 4f 50 53 49 53 0a 09 50 72 69 6e 74 73 20 74 68 65 20 53 48 41 31 20 68 61 73 68 20 6f 66 20 61 20 66 69 6c 65 0a 2e 44 }
    condition:
        $header at 0 and filesize == 831
}
rule Suspect_Group_File049 {
    meta:
        description = "Matches 1 files: File049"
        author = "Forensics Deduplication Script"
        original_size = 1804
    strings:
        $header = { ef bb bf 3c 23 0a 2e 53 59 4e 4f 50 53 49 53 0a 09 49 6e 73 74 61 6c 6c 73 20 62 61 73 69 63 20 61 70 70 73 0a 2e 44 45 53 43 52 49 50 54 49 4f 4e 0a }
    condition:
        $header at 0 and filesize == 1804
}
rule Suspect_Group_File050 {
    meta:
        description = "Matches 1 files: File050"
        author = "Forensics Deduplication Script"
        original_size = 86
    strings:
        $header = { 40 65 63 68 6f 20 6f 66 66 0d 0a 73 65 74 20 2f 61 20 63 6f 6c 6f 72 3d 25 72 61 6e 64 6f 6d 25 20 25 25 20 31 36 0d 0a 63 6f 6c 6f 72 20 25 63 6f 6c }
    condition:
        $header at 0 and filesize == 86
}
rule Suspect_Group_File051 {
    meta:
        description = "Matches 1 files: File051"
        author = "Forensics Deduplication Script"
        original_size = 716249
    strings:
        $header = { 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $header at 0 and filesize == 716249
}
rule Suspect_Group_File052 {
    meta:
        description = "Matches 1 files: File052"
        author = "Forensics Deduplication Script"
        original_size = 146273
    strings:
        $header = { ff d8 ff e0 00 10 4a 46 49 46 00 01 01 00 00 01 00 01 00 00 ff db 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0a 0c 14 0d 0c 0b 0b 0c 19 12 13 0f }
    condition:
        $header at 0 and filesize == 146273
}
rule Suspect_Group_File053 {
    meta:
        description = "Matches 1 files: File053"
        author = "Forensics Deduplication Script"
        original_size = 173909
    strings:
        $header = { ff d8 ff e0 00 10 4a 46 49 46 00 01 01 00 00 01 00 01 00 00 ff db 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0a 0c 14 0d 0c 0b 0b 0c 19 12 13 0f }
    condition:
        $header at 0 and filesize == 173909
}
rule Suspect_Group_File054 {
    meta:
        description = "Matches 1 files: File054"
        author = "Forensics Deduplication Script"
        original_size = 628
    strings:
        $header = { ef bb bf 3c 23 0a 2e 53 59 4e 4f 50 53 49 53 0a 09 49 6e 73 74 61 6c 6c 73 20 47 69 74 20 66 6f 72 20 57 69 6e 64 6f 77 73 0a 2e 44 45 53 43 52 49 50 }
    condition:
        $header at 0 and filesize == 628
}
rule Suspect_Group_File055 {
    meta:
        description = "Matches 1 files: File055"
        author = "Forensics Deduplication Script"
        original_size = 844097
    strings:
        $header = { 43 44 30 30 14 00 06 00 08 00 00 00 21 00 a9 90 c0 ad 7b 03 00 00 d3 10 00 00 14 00 00 00 70 70 74 2f 70 72 65 73 65 6e 74 61 74 69 6f 6e 2e 78 6d 6c }
    condition:
        $header at 0 and filesize == 844097
}
rule Suspect_Group_File056 {
    meta:
        description = "Matches 1 files: File056"
        author = "Forensics Deduplication Script"
        original_size = 340390
    strings:
        $header = { 50 4b 03 04 0a 00 00 00 00 00 00 00 21 00 ff ff ff ff f3 01 00 00 f3 01 00 00 10 00 00 00 5b 74 72 61 73 68 5d 2f 30 30 30 30 2e 64 61 74 ff ff ff ff }
    condition:
        $header at 0 and filesize == 340390
}
rule Suspect_Group_File057 {
    meta:
        description = "Matches 1 files: File057"
        author = "Forensics Deduplication Script"
        original_size = 691
    strings:
        $header = { ef bb bf 3c 23 0a 2e 53 59 4e 4f 50 53 49 53 0a 09 45 6e 61 62 6c 65 73 20 74 68 65 20 67 6f 64 20 6d 6f 64 65 0a 2e 44 45 53 43 52 49 50 54 49 4f 4e }
    condition:
        $header at 0 and filesize == 691
}
rule Suspect_Group_File058 {
    meta:
        description = "Matches 1 files: File058"
        author = "Forensics Deduplication Script"
        original_size = 23112
    strings:
        $header = { 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 }
    condition:
        $header at 0 and filesize == 23112
}
rule Suspect_Group_File059 {
    meta:
        description = "Matches 1 files: File059"
        author = "Forensics Deduplication Script"
        original_size = 1720207
    strings:
        $header = { 89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49 48 44 52 00 00 03 88 00 00 04 ec 08 06 00 00 00 c2 72 ac 0c 00 01 00 00 49 44 41 54 78 9c ec fd e9 b3 6d 49 76 }
    condition:
        $header at 0 and filesize == 1720207
}
rule Suspect_Group_File061 {
    meta:
        description = "Matches 1 files: File061"
        author = "Forensics Deduplication Script"
        original_size = 106
    strings:
        $header = { 40 65 63 68 6f 20 6f 66 66 0d 0a 73 65 74 20 2f 61 20 64 65 6c 61 79 3d 25 72 61 6e 64 6f 6d 25 20 25 25 20 35 20 2b 20 31 0d 0a 74 69 6d 65 6f 75 74 }
    condition:
        $header at 0 and filesize == 106
}
rule Suspect_Group_File062 {
    meta:
        description = "Matches 1 files: File062"
        author = "Forensics Deduplication Script"
        original_size = 11272
    strings:
        $header = { 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $header at 0 and filesize == 11272
}
rule Suspect_Group_File063 {
    meta:
        description = "Matches 1 files: File063"
        author = "Forensics Deduplication Script"
        original_size = 1962050
    strings:
        $header = { 49 44 33 31 2e 34 0d 25 80 84 88 8c 90 94 98 9c a0 a4 a8 ac b0 b4 b8 bc c0 c4 c8 cc d0 d4 d8 dc e0 e4 e8 ec f0 f4 f8 fc 0d 0d 31 20 30 20 6f 62 6a 0d }
    condition:
        $header at 0 and filesize == 1962050
}
rule Suspect_Group_File064 {
    meta:
        description = "Matches 1 files: File064"
        author = "Forensics Deduplication Script"
        original_size = 2138
    strings:
        $header = { 5b 4c 6f 63 61 6c 69 7a 65 64 46 69 6c 65 4e 61 6d 65 73 5d 0d 0a 62 69 6f 63 68 65 6d 5f 6d 65 64 2d 32 33 2d 32 2d 31 34 33 2d 33 2e 70 64 66 3d 40 }
    condition:
        $header at 0 and filesize == 2138
}
rule Suspect_Group_File065 {
    meta:
        description = "Matches 1 files: File065"
        author = "Forensics Deduplication Script"
        original_size = 756
    strings:
        $header = { 49 53 43 20 4c 69 63 65 6e 73 65 0d 0a 0d 0a 43 6f 70 79 72 69 67 68 74 20 28 63 29 20 5b 79 65 61 72 5d 20 5b 66 75 6c 6c 6e 61 6d 65 5d 0d 0a 0d 0a }
    condition:
        $header at 0 and filesize == 756
}
rule Suspect_Group_File066 {
    meta:
        description = "Matches 1 files: File066"
        author = "Forensics Deduplication Script"
        original_size = 3259060
    strings:
        $header = { 25 50 44 46 2d 31 2e 37 0a 25 e2 e3 cf d3 0a 36 20 30 20 6f 62 6a 0a 3c 3c 2f 46 69 6c 74 65 72 2f 46 6c 61 74 65 44 65 63 6f 64 65 2f 4c 65 6e 67 74 }
    condition:
        $header at 0 and filesize == 3259060
}
rule Suspect_Group_File067 {
    meta:
        description = "Matches 1 files: File067"
        author = "Forensics Deduplication Script"
        original_size = 366608
    strings:
        $header = { 4d 5a 93 00 03 00 00 00 20 00 00 00 ff ff 07 00 00 01 65 40 00 00 00 00 40 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $header at 0 and filesize == 366608
}
rule Suspect_Group_File068 {
    meta:
        description = "Matches 1 files: File068"
        author = "Forensics Deduplication Script"
        original_size = 1485481
    strings:
        $header = { 89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49 48 44 52 00 00 03 88 00 00 04 ec 08 06 00 00 00 c2 72 ac 0c 00 01 00 00 49 44 41 54 78 9c ec fd 59 af 24 4b 92 }
    condition:
        $header at 0 and filesize == 1485481
}
rule Suspect_Group_File069 {
    meta:
        description = "Matches 1 files: File069"
        author = "Forensics Deduplication Script"
        original_size = 170993
    strings:
        $header = { 89 50 4e 47 0d 0a 1a 0a e0 00 10 4a 46 49 46 00 01 01 00 00 01 00 01 00 00 ff db 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0a 0c 14 0d 0c 0b 0b }
    condition:
        $header at 0 and filesize == 170993
}
rule Suspect_Group_File070 {
    meta:
        description = "Matches 1 files: File070"
        author = "Forensics Deduplication Script"
        original_size = 1645439
    strings:
        $header = { 89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49 48 44 52 00 00 03 88 00 00 04 ec 08 06 00 00 00 c2 72 ac 0c 00 01 00 00 49 44 41 54 78 9c ec fd 49 b3 65 4b 76 }
    condition:
        $header at 0 and filesize == 1645439
}
rule Suspect_Group_File071 {
    meta:
        description = "Matches 2 files: File071, File080"
        author = "Forensics Deduplication Script"
        original_size = 11792
    strings:
        $header = { 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $header at 0 and filesize == 11792
}
rule Suspect_Group_File072 {
    meta:
        description = "Matches 1 files: File072"
        author = "Forensics Deduplication Script"
        original_size = 1655833
    strings:
        $header = { 89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49 48 44 52 00 00 03 88 00 00 04 ec 08 06 00 00 00 c2 72 ac 0c 00 01 00 00 49 44 41 54 78 9c ec fd 69 97 25 c9 71 }
    condition:
        $header at 0 and filesize == 1655833
}
rule Suspect_Group_File073 {
    meta:
        description = "Matches 1 files: File073"
        author = "Forensics Deduplication Script"
        original_size = 157801
    strings:
        $header = { ff d8 ff e0 00 10 4a 46 49 46 00 01 01 00 00 01 00 01 00 00 ff db 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0a 0c 14 0d 0c 0b 0b 0c 19 12 13 0f }
    condition:
        $header at 0 and filesize == 157801
}
rule Suspect_Group_File074 {
    meta:
        description = "Matches 1 files: File074"
        author = "Forensics Deduplication Script"
        original_size = 7213107
    strings:
        $header = { 50 4b 03 04 0a 00 00 00 00 00 00 00 21 00 ff ff ff ff 2d 02 00 00 2d 02 00 00 10 00 00 00 5b 74 72 61 73 68 5d 2f 30 30 30 30 2e 64 61 74 ff ff ff ff }
    condition:
        $header at 0 and filesize == 7213107
}
rule Suspect_Group_File075 {
    meta:
        description = "Matches 1 files: File075"
        author = "Forensics Deduplication Script"
        original_size = 341331
    strings:
        $header = { 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $header at 0 and filesize == 341331
}
rule Suspect_Group_File076 {
    meta:
        description = "Matches 1 files: File076"
        author = "Forensics Deduplication Script"
        original_size = 115731
    strings:
        $header = { 50 4b 03 04 14 00 08 08 08 00 ab 0b 76 59 00 00 00 00 00 00 00 00 00 00 00 00 10 00 00 00 77 6f 72 64 2f 68 65 61 64 65 72 31 2e 78 6d 6c cd 96 db 8e }
    condition:
        $header at 0 and filesize == 115731
}
rule Suspect_Group_File077 {
    meta:
        description = "Matches 1 files: File077"
        author = "Forensics Deduplication Script"
        original_size = 603
    strings:
        $header = { ef bb bf 3c 23 0a 2e 53 59 4e 4f 50 53 49 53 0a 09 49 6e 73 74 61 6c 6c 73 20 43 68 72 6f 6d 65 0a 2e 44 45 53 43 52 49 50 54 49 4f 4e 0a 09 54 68 69 }
    condition:
        $header at 0 and filesize == 603
}
rule Suspect_Group_File078 {
    meta:
        description = "Matches 1 files: File078"
        author = "Forensics Deduplication Script"
        original_size = 160610
    strings:
        $header = { ff d8 ff e0 00 10 4a 46 49 46 00 01 01 00 00 01 00 01 00 00 ff db 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0a 0c 14 0d 0c 0b 0b 0c 19 12 13 0f }
    condition:
        $header at 0 and filesize == 160610
}
rule Suspect_Group_File079 {
    meta:
        description = "Matches 1 files: File079"
        author = "Forensics Deduplication Script"
        original_size = 339655
    strings:
        $header = { ff fb 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $header at 0 and filesize == 339655
}
rule Suspect_Group_File082 {
    meta:
        description = "Matches 1 files: File082"
        author = "Forensics Deduplication Script"
        original_size = 147
    strings:
        $header = { 40 65 63 68 6f 20 6f 66 66 0d 0a 73 65 74 20 70 61 74 68 73 3d 43 3a 5c 57 69 6e 64 6f 77 73 5c 20 43 3a 5c 55 73 65 72 73 5c 20 43 3a 5c 50 72 6f 67 }
    condition:
        $header at 0 and filesize == 147
}
rule Suspect_Group_File083 {
    meta:
        description = "Matches 1 files: File083"
        author = "Forensics Deduplication Script"
        original_size = 124
    strings:
        $header = { 40 65 63 68 6f 20 6f 66 66 0d 0a 73 65 74 20 2f 61 20 6e 75 6d 3d 25 72 61 6e 64 6f 6d 25 20 25 25 20 32 36 20 2b 20 36 35 0d 0a 66 6f 72 20 2f 66 20 }
    condition:
        $header at 0 and filesize == 124
}
rule Suspect_Group_File084 {
    meta:
        description = "Matches 1 files: File084"
        author = "Forensics Deduplication Script"
        original_size = 417316
    strings:
        $header = { 25 50 44 46 2d 31 2e 33 0a 25 e2 e3 cf d3 0a 31 20 30 20 6f 62 6a 0a 3c 3c 0a 2f 54 79 70 65 20 2f 50 61 67 65 73 0a 2f 43 6f 75 6e 74 20 33 33 0a 2f }
    condition:
        $header at 0 and filesize == 417316
}
rule Suspect_Group_File085 {
    meta:
        description = "Matches 1 files: File085"
        author = "Forensics Deduplication Script"
        original_size = 406205
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 00 00 21 00 b5 cf 3e 7b 02 01 00 00 bb 02 00 00 0b 00 ed 01 5f 72 65 6c 73 2f 2e 72 65 6c 73 20 a2 e9 01 28 a0 00 02 00 }
    condition:
        $header at 0 and filesize == 406205
}
rule Suspect_Group_File086 {
    meta:
        description = "Matches 1 files: File086"
        author = "Forensics Deduplication Script"
        original_size = 677
    strings:
        $header = { 42 53 44 20 5a 65 72 6f 20 43 6c 61 75 73 65 20 4c 69 63 65 6e 73 65 0d 0a 0d 0a 43 6f 70 79 72 69 67 68 74 20 28 63 29 20 5b 79 65 61 72 5d 20 5b 66 }
    condition:
        $header at 0 and filesize == 677
}
rule Suspect_Group_File087 {
    meta:
        description = "Matches 1 files: File087"
        author = "Forensics Deduplication Script"
        original_size = 288249
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 00 00 21 00 8f bf f1 36 23 04 00 00 c5 4e 00 00 13 00 08 02 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 288249
}
rule Suspect_Group_File088 {
    meta:
        description = "Matches 1 files: File088"
        author = "Forensics Deduplication Script"
        original_size = 100
    strings:
        $header = { 40 65 63 68 6f 20 6f 66 66 0d 0a 66 6f 72 20 2f 6c 20 25 25 69 20 69 6e 20 28 31 2c 31 2c 33 32 29 20 64 6f 20 28 0d 0a 20 20 20 20 73 65 74 20 2f 61 }
    condition:
        $header at 0 and filesize == 100
}
rule Suspect_Group_File089 {
    meta:
        description = "Matches 1 files: File089"
        author = "Forensics Deduplication Script"
        original_size = 180248
    strings:
        $header = { ff d8 ff e0 00 10 4a 46 49 46 00 01 01 00 00 01 00 01 00 00 ff db 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0a 0c 14 0d 0c 0b 0b 0c 19 12 13 0f }
    condition:
        $header at 0 and filesize == 180248
}
rule Suspect_Group_File090 {
    meta:
        description = "Matches 1 files: File090"
        author = "Forensics Deduplication Script"
        original_size = 169745
    strings:
        $header = { ff d8 ff e0 00 10 4a 46 49 46 00 01 01 00 00 01 00 01 00 00 ff db 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0a 0c 14 0d 0c 0b 0b 0c 19 12 13 0f }
    condition:
        $header at 0 and filesize == 169745
}
rule Suspect_Group_File091 {
    meta:
        description = "Matches 1 files: File091"
        author = "Forensics Deduplication Script"
        original_size = 494
    strings:
        $header = { 20 20 20 20 20 20 20 20 20 20 20 20 44 4f 20 57 48 41 54 20 54 48 45 20 46 55 43 4b 20 59 4f 55 20 57 41 4e 54 20 54 4f 20 50 55 42 4c 49 43 20 4c 49 }
    condition:
        $header at 0 and filesize == 494
}
rule Suspect_Group_File092 {
    meta:
        description = "Matches 1 files: File092"
        author = "Forensics Deduplication Script"
        original_size = 412847
    strings:
        $header = { 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $header at 0 and filesize == 412847
}
rule Suspect_Group_File093 {
    meta:
        description = "Matches 1 files: File093"
        author = "Forensics Deduplication Script"
        original_size = 3038333
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 00 00 21 00 9d 7c 73 2a e3 01 00 00 b5 0c 00 00 13 00 08 02 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 3038333
}
rule Suspect_Group_File094 {
    meta:
        description = "Matches 1 files: File094"
        author = "Forensics Deduplication Script"
        original_size = 62950
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 00 00 21 00 81 71 7d 3c f8 01 00 00 ba 0c 00 00 13 00 cd 01 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 62950
}
rule Suspect_Group_File095 {
    meta:
        description = "Matches 1 files: File095"
        author = "Forensics Deduplication Script"
        original_size = 259805
    strings:
        $header = { 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $header at 0 and filesize == 259805
}
rule Suspect_Group_File096 {
    meta:
        description = "Matches 1 files: File096"
        author = "Forensics Deduplication Script"
        original_size = 187180
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 00 00 21 00 d5 71 95 3e e1 01 00 00 7a 09 00 00 13 00 08 02 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 187180
}
rule Suspect_Group_File097 {
    meta:
        description = "Matches 1 files: File097"
        author = "Forensics Deduplication Script"
        original_size = 132678
    strings:
        $header = { ff d9 ff e0 00 10 4a 46 49 46 00 01 01 00 00 01 00 01 00 00 ff db 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0a 0c 14 0d 0c 0b 0b 0c 19 12 13 0f }
    condition:
        $header at 0 and filesize == 132678
}
rule Suspect_Group_File098 {
    meta:
        description = "Matches 1 files: File098"
        author = "Forensics Deduplication Script"
        original_size = 1684054
    strings:
        $header = { 89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49 48 44 52 00 00 03 88 00 00 04 ec 08 06 00 00 00 c2 72 ac 0c 00 01 00 00 49 44 41 54 78 9c ec fd 69 ac 6d db 75 }
    condition:
        $header at 0 and filesize == 1684054
}
rule Suspect_Group_File099 {
    meta:
        description = "Matches 1 files: File099"
        author = "Forensics Deduplication Script"
        original_size = 352
    strings:
        $header = { 0a 22 31 2e 20 49 6e 73 74 61 6c 6c 20 61 6e 64 20 63 6f 6e 66 69 67 75 72 65 20 74 68 65 20 6e 65 63 65 73 73 61 72 79 20 64 65 70 65 6e 64 65 6e 63 }
    condition:
        $header at 0 and filesize == 352
}
rule Suspect_Group_File100 {
    meta:
        description = "Matches 1 files: File100"
        author = "Forensics Deduplication Script"
        original_size = 27963
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 00 00 21 00 1e 27 60 70 88 01 00 00 ae 05 00 00 13 00 08 02 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 27963
}
rule Suspect_Group_File101 {
    meta:
        description = "Matches 1 files: File101"
        author = "Forensics Deduplication Script"
        original_size = 12816
    strings:
        $header = { 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $header at 0 and filesize == 12816
}
rule Suspect_Group_File102 {
    meta:
        description = "Matches 1 files: File102"
        author = "Forensics Deduplication Script"
        original_size = 196042
    strings:
        $header = { 52 49 46 46 57 41 56 45 2d 31 2e 36 0d 25 e2 e3 cf d3 0d 0a 35 39 20 30 20 6f 62 6a 20 3c 3c 2f 4c 69 6e 65 61 72 69 7a 65 64 20 31 2f 4c 20 31 39 36 }
    condition:
        $header at 0 and filesize == 196042
}
rule Suspect_Group_File103 {
    meta:
        description = "Matches 1 files: File103"
        author = "Forensics Deduplication Script"
        original_size = 7474390
    strings:
        $header = { 25 50 44 46 2d 31 2e 34 0a 25 f6 e4 fc df 0a 31 20 30 20 6f 62 6a 0a 3c 3c 0a 2f 54 79 70 65 20 2f 43 61 74 61 6c 6f 67 0a 2f 56 65 72 73 69 6f 6e 20 }
    condition:
        $header at 0 and filesize == 7474390
}
rule Suspect_Group_File104 {
    meta:
        description = "Matches 1 files: File104"
        author = "Forensics Deduplication Script"
        original_size = 1286316
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 00 00 21 00 2b 54 51 0e d9 02 00 00 a6 24 00 00 13 00 ba 01 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 1286316
}
rule Suspect_Group_File105 {
    meta:
        description = "Matches 1 files: File105"
        author = "Forensics Deduplication Script"
        original_size = 1426547
    strings:
        $header = { 89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49 48 44 52 00 00 03 88 00 00 04 ec 08 06 00 00 00 c2 72 ac 0c 00 01 00 00 49 44 41 54 78 9c ec fd f9 93 24 5b 76 }
    condition:
        $header at 0 and filesize == 1426547
}
rule Suspect_Group_File106 {
    meta:
        description = "Matches 1 files: File106"
        author = "Forensics Deduplication Script"
        original_size = 28944
    strings:
        $header = { 45 00 63 00 6c 00 69 00 70 00 73 00 65 00 20 00 50 00 75 00 62 00 6c 00 69 00 63 00 20 00 4c 00 69 00 63 00 65 00 6e 00 73 00 65 00 20 00 2d 00 20 00 }
    condition:
        $header at 0 and filesize == 28944
}
rule Suspect_Group_File107 {
    meta:
        description = "Matches 1 files: File107"
        author = "Forensics Deduplication Script"
        original_size = 142129
    strings:
        $header = { ff d8 ff e0 00 10 4a 46 49 46 00 01 01 00 00 01 00 01 00 00 ff db 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0a 0c 14 0d 0c 0b 0b 0c 19 12 13 0f }
    condition:
        $header at 0 and filesize == 142129
}
rule Suspect_Group_File108 {
    meta:
        description = "Matches 1 files: File108"
        author = "Forensics Deduplication Script"
        original_size = 1544836
    strings:
        $header = { 89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49 48 44 52 00 00 03 88 00 00 04 ec 08 06 00 00 00 c2 72 ac 0c 00 01 00 00 49 44 41 54 78 9c ec fd e9 b2 2c 49 92 }
    condition:
        $header at 0 and filesize == 1544836
}
rule Suspect_Group_File109 {
    meta:
        description = "Matches 1 files: File109"
        author = "Forensics Deduplication Script"
        original_size = 556987
    strings:
        $header = { 52 49 46 46 57 41 56 45 2d 31 2e 33 0a 25 e2 e3 cf d3 0a 31 20 30 20 6f 62 6a 0a 3c 3c 0a 2f 54 79 70 65 20 2f 50 61 67 65 73 0a 2f 43 6f 75 6e 74 20 }
    condition:
        $header at 0 and filesize == 556987
}
rule Suspect_Group_File110 {
    meta:
        description = "Matches 1 files: File110"
        author = "Forensics Deduplication Script"
        original_size = 2828
    strings:
        $header = { 4d 69 63 72 6f 73 6f 66 74 20 50 75 62 6c 69 63 20 4c 69 63 65 6e 73 65 20 28 4d 73 2d 50 4c 29 0d 0a 0d 0a 54 68 69 73 20 6c 69 63 65 6e 73 65 20 67 }
    condition:
        $header at 0 and filesize == 2828
}
rule Suspect_Group_File111 {
    meta:
        description = "Matches 1 files: File111"
        author = "Forensics Deduplication Script"
        original_size = 146438
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 00 00 21 00 45 8c 02 3a bc 01 00 00 64 08 00 00 13 00 dc 01 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 146438
}
rule Suspect_Group_File112 {
    meta:
        description = "Matches 1 files: File112"
        author = "Forensics Deduplication Script"
        original_size = 41
    strings:
        $header = { 40 65 63 68 6f 20 6f 66 66 0d 0a 65 63 68 6f 20 52 61 6e 64 6f 6d 20 53 74 72 69 6e 67 3a 20 25 72 61 6e 64 6f 6d 25 0d 0a }
    condition:
        $header at 0 and filesize == 41
}
rule Suspect_Group_File113 {
    meta:
        description = "Matches 1 files: File113"
        author = "Forensics Deduplication Script"
        original_size = 160547
    strings:
        $header = { ff d8 ff e0 00 10 4a 46 49 46 00 01 01 00 00 01 00 01 00 00 ff db 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0a 0c 14 0d 0c 0b 0b 0c 19 12 13 0f }
    condition:
        $header at 0 and filesize == 160547
}
rule Suspect_Group_File114 {
    meta:
        description = "Matches 1 files: File114"
        author = "Forensics Deduplication Script"
        original_size = 527117
    strings:
        $header = { 25 50 44 46 2d 31 2e 33 0a 25 e2 e3 cf d3 0a 31 20 30 20 6f 62 6a 0a 3c 3c 0a 2f 54 79 70 65 20 2f 50 61 67 65 73 0a 2f 43 6f 75 6e 74 20 32 30 0a 2f }
    condition:
        $header at 0 and filesize == 527117
}
rule Suspect_Group_File115 {
    meta:
        description = "Matches 1 files: File115"
        author = "Forensics Deduplication Script"
        original_size = 1063014
    strings:
        $header = { 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $header at 0 and filesize == 1063014
}
rule Suspect_Group_File116 {
    meta:
        description = "Matches 1 files: File116"
        author = "Forensics Deduplication Script"
        original_size = 694240
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 00 00 21 00 74 76 54 0c d0 01 00 00 6c 0b 00 00 13 00 08 02 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 694240
}
rule Suspect_Group_File117 {
    meta:
        description = "Matches 1 files: File117"
        author = "Forensics Deduplication Script"
        original_size = 64531
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 00 00 21 00 9c bd 3c e3 ce 01 00 00 c4 0b 00 00 13 00 08 02 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 64531
}
rule Suspect_Group_File118 {
    meta:
        description = "Matches 1 files: File118"
        author = "Forensics Deduplication Script"
        original_size = 1080656
    strings:
        $header = { 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $header at 0 and filesize == 1080656
}
rule Suspect_Group_File119 {
    meta:
        description = "Matches 1 files: File119"
        author = "Forensics Deduplication Script"
        original_size = 555
    strings:
        $header = { ef bb bf 3c 23 0a 2e 53 59 4e 4f 50 53 49 53 0a 09 49 6e 73 74 61 6c 6c 73 20 54 77 69 74 74 65 72 0a 2e 44 45 53 43 52 49 50 54 49 4f 4e 0a 09 54 68 }
    condition:
        $header at 0 and filesize == 555
}
rule Suspect_Group_File120 {
    meta:
        description = "Matches 1 files: File120"
        author = "Forensics Deduplication Script"
        original_size = 572
    strings:
        $header = { ef bb bf 3c 23 0a 2e 53 59 4e 4f 50 53 49 53 0a 09 49 6e 73 74 61 6c 6c 73 20 54 68 75 6e 64 65 72 62 69 72 64 0a 2e 44 45 53 43 52 49 50 54 49 4f 4e }
    condition:
        $header at 0 and filesize == 572
}
rule Suspect_Group_File121 {
    meta:
        description = "Matches 1 files: File121"
        author = "Forensics Deduplication Script"
        original_size = 345850
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 00 00 21 00 9f 04 c7 c5 38 02 00 00 54 10 00 00 13 00 c2 01 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 345850
}
rule Suspect_Group_File122 {
    meta:
        description = "Matches 1 files: File122"
        author = "Forensics Deduplication Script"
        original_size = 572074
    strings:
        $header = { 50 4b 03 04 14 00 08 08 08 00 48 a5 75 59 00 00 00 00 00 00 00 00 00 00 00 00 12 00 00 00 77 6f 72 64 2f 6e 75 6d 62 65 72 69 6e 67 2e 78 6d 6c ed 9b }
    condition:
        $header at 0 and filesize == 572074
}
rule Suspect_Group_File123 {
    meta:
        description = "Matches 1 files: File123"
        author = "Forensics Deduplication Script"
        original_size = 521414
    strings:
        $header = { 25 50 44 46 2d 31 2e 35 0d 0a 25 b5 b5 b5 b5 0d 0a 31 20 30 20 6f 62 6a 0d 0a 3c 3c 2f 54 79 70 65 2f 43 61 74 61 6c 6f 67 2f 50 61 67 65 73 20 32 20 }
    condition:
        $header at 0 and filesize == 521414
}
rule Suspect_Group_File124 {
    meta:
        description = "Matches 1 files: File124"
        author = "Forensics Deduplication Script"
        original_size = 173180
    strings:
        $header = { ff d8 ff e0 00 10 4a 46 49 46 00 01 01 00 00 01 00 01 00 00 ff db 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0a 0c 14 0d 0c 0b 0b 0c 19 12 13 0f }
    condition:
        $header at 0 and filesize == 173180
}
rule Suspect_Group_File125 {
    meta:
        description = "Matches 1 files: File125"
        author = "Forensics Deduplication Script"
        original_size = 1591997
    strings:
        $header = { 89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49 48 44 52 00 00 03 88 00 00 04 ec 08 06 00 00 00 c2 72 ac 0c 00 01 00 00 49 44 41 54 78 9c ec fd 67 b4 65 c9 75 }
    condition:
        $header at 0 and filesize == 1591997
}
rule Suspect_Group_File126 {
    meta:
        description = "Matches 1 files: File126"
        author = "Forensics Deduplication Script"
        original_size = 1502871
    strings:
        $header = { 89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49 48 44 52 00 00 03 88 00 00 04 ec 08 06 00 00 00 c2 72 ac 0c 00 01 00 00 49 44 41 54 78 9c ec fd 77 b0 25 c9 79 }
    condition:
        $header at 0 and filesize == 1502871
}
rule Suspect_Group_File127 {
    meta:
        description = "Matches 1 files: File127"
        author = "Forensics Deduplication Script"
        original_size = 154510
    strings:
        $header = { ff d8 ff e0 00 10 4a 46 49 46 00 01 01 00 00 01 00 01 00 00 ff db 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0a 0c 14 0d 0c 0b 0b 0c 19 12 13 0f }
    condition:
        $header at 0 and filesize == 154510
}
rule Suspect_Group_File128 {
    meta:
        description = "Matches 1 files: File128"
        author = "Forensics Deduplication Script"
        original_size = 87
    strings:
        $header = { 40 65 63 68 6f 20 6f 66 66 0d 0a 73 65 74 20 2f 61 20 63 6f 64 65 3d 25 72 61 6e 64 6f 6d 25 20 25 25 20 32 35 35 0d 0a 65 63 68 6f 20 45 78 69 74 69 }
    condition:
        $header at 0 and filesize == 87
}
rule Suspect_Group_File129 {
    meta:
        description = "Matches 1 files: File129"
        author = "Forensics Deduplication Script"
        original_size = 217395
    strings:
        $header = { 25 50 44 46 2d 31 2e 33 0a 25 e2 e3 cf d3 0a 31 20 30 20 6f 62 6a 0a 3c 3c 0a 2f 54 79 70 65 20 2f 50 61 67 65 73 0a 2f 43 6f 75 6e 74 20 31 39 0a 2f }
    condition:
        $header at 0 and filesize == 217395
}
rule Suspect_Group_File130 {
    meta:
        description = "Matches 1 files: File130"
        author = "Forensics Deduplication Script"
        original_size = 100153
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 00 00 21 00 3d 57 87 34 c6 01 00 00 bf 08 00 00 13 00 08 02 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 100153
}
rule Suspect_Group_File131 {
    meta:
        description = "Matches 1 files: File131"
        author = "Forensics Deduplication Script"
        original_size = 26769
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 00 00 21 00 a6 74 04 52 85 01 00 00 ac 07 00 00 13 00 08 02 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 26769
}
rule Suspect_Group_File132 {
    meta:
        description = "Matches 1 files: File132"
        author = "Forensics Deduplication Script"
        original_size = 588152
    strings:
        $header = { 25 50 44 46 2d 31 2e 36 0d 25 e2 e3 cf d3 0d 0a 34 33 31 20 30 20 6f 62 6a 0d 3c 3c 2f 4c 69 6e 65 61 72 69 7a 65 64 20 31 2f 4c 20 35 38 38 31 35 32 }
    condition:
        $header at 0 and filesize == 588152
}
rule Suspect_Group_File133 {
    meta:
        description = "Matches 1 files: File133"
        author = "Forensics Deduplication Script"
        original_size = 159149
    strings:
        $header = { ff d8 ff e0 00 10 4a 46 49 46 00 01 01 00 00 01 00 01 00 00 ff db 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0a 0c 14 0d 0c 0b 0b 0c 19 12 13 0f }
    condition:
        $header at 0 and filesize == 159149
}
rule Suspect_Group_File134 {
    meta:
        description = "Matches 1 files: File134"
        author = "Forensics Deduplication Script"
        original_size = 744699
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 00 00 21 00 3d 57 87 34 c6 01 00 00 bf 08 00 00 13 00 08 02 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 744699
}
rule Suspect_Group_File135 {
    meta:
        description = "Matches 1 files: File135"
        author = "Forensics Deduplication Script"
        original_size = 5765224
    strings:
        $header = { 25 50 44 46 2d 31 2e 37 0d 25 e2 e3 cf d3 0d 0a 31 20 30 20 6f 62 6a 0a 3c 3c 2f 41 63 72 6f 46 6f 72 6d 20 35 20 30 20 52 2f 4c 61 6e 67 28 65 6e 29 }
    condition:
        $header at 0 and filesize == 5765224
}
rule Suspect_Group_File136 {
    meta:
        description = "Matches 1 files: File136"
        author = "Forensics Deduplication Script"
        original_size = 1809714
    strings:
        $header = { 00 00 00 0d 49 48 44 52 00 00 03 88 00 00 04 ec 08 06 00 00 00 c2 72 ac 0c 00 01 00 00 49 44 41 54 78 9c ec fd 5b b3 24 49 92 1e 88 7d aa 66 ee 1e 71 }
    condition:
        $header at 0 and filesize == 1809714
}
rule Suspect_Group_File137 {
    meta:
        description = "Matches 1 files: File137"
        author = "Forensics Deduplication Script"
        original_size = 1359
    strings:
        $header = { 42 6f 6f 73 74 20 53 6f 66 74 77 61 72 65 20 4c 69 63 65 6e 73 65 20 2d 20 56 65 72 73 69 6f 6e 20 31 2e 30 20 2d 20 41 75 67 75 73 74 20 31 37 74 68 }
    condition:
        $header at 0 and filesize == 1359
}
rule Suspect_Group_File138 {
    meta:
        description = "Matches 1 files: File138"
        author = "Forensics Deduplication Script"
        original_size = 663177
    strings:
        $header = { 25 50 44 46 2d 31 2e 37 0a 25 e2 e3 cf d3 0a 31 20 30 20 6f 62 6a 0a 3c 3c 2f 43 6f 6c 6f 72 53 70 61 63 65 2f 44 65 76 69 63 65 47 72 61 79 2f 53 75 }
    condition:
        $header at 0 and filesize == 663177
}
rule Suspect_Group_File139 {
    meta:
        description = "Matches 1 files: File139"
        author = "Forensics Deduplication Script"
        original_size = 168
    strings:
        $header = { 40 65 63 68 6f 20 6f 66 66 0d 0a 73 65 74 20 73 65 6e 74 65 6e 63 65 73 3d 48 65 6c 6c 6f 7c 48 6f 77 20 61 72 65 20 79 6f 75 3f 7c 4e 69 63 65 20 77 }
    condition:
        $header at 0 and filesize == 168
}
rule Suspect_Group_File140 {
    meta:
        description = "Matches 1 files: File140"
        author = "Forensics Deduplication Script"
        original_size = 157962
    strings:
        $header = { ff d8 ff e0 00 10 4a 46 49 46 00 01 01 00 00 01 00 01 00 00 ff db 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0a 0c 14 0d 0c 0b 0b 0c 19 12 13 0f }
    condition:
        $header at 0 and filesize == 157962
}
rule Suspect_Group_File141 {
    meta:
        description = "Matches 1 files: File141"
        author = "Forensics Deduplication Script"
        original_size = 472874
    strings:
        $header = { 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $header at 0 and filesize == 472874
}
rule Suspect_Group_File142 {
    meta:
        description = "Matches 1 files: File142"
        author = "Forensics Deduplication Script"
        original_size = 2693126
    strings:
        $header = { 50 4b 03 04 0a 00 00 00 08 00 00 00 21 00 03 e4 7b fe c7 03 00 00 91 13 00 00 14 00 00 00 70 70 74 2f 70 72 65 73 65 6e 74 61 74 69 6f 6e 2e 78 6d 6c }
    condition:
        $header at 0 and filesize == 2693126
}
rule Suspect_Group_File143 {
    meta:
        description = "Matches 1 files: File143"
        author = "Forensics Deduplication Script"
        original_size = 1635658
    strings:
        $header = { ff d8 ff 00 00 00 0d 49 48 44 52 00 00 03 88 00 00 04 ec 08 06 00 00 00 c2 72 ac 0c 00 01 00 00 49 44 41 54 78 9c ec fd 59 93 24 49 92 26 88 7d cc 22 }
    condition:
        $header at 0 and filesize == 1635658
}
rule Suspect_Group_File144 {
    meta:
        description = "Matches 1 files: File144"
        author = "Forensics Deduplication Script"
        original_size = 2490902
    strings:
        $header = { 50 4b 03 04 0a 00 00 00 00 00 00 00 21 00 ff ff ff ff 1c 02 00 00 1c 02 00 00 10 00 00 00 5b 74 72 61 73 68 5d 2f 30 30 30 30 2e 64 61 74 ff ff ff ff }
    condition:
        $header at 0 and filesize == 2490902
}
rule Suspect_Group_File145 {
    meta:
        description = "Matches 1 files: File145"
        author = "Forensics Deduplication Script"
        original_size = 82840
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 00 00 21 00 ff bf 18 7a 2e 02 00 00 57 0d 00 00 13 00 c2 01 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 82840
}
rule Suspect_Group_File147 {
    meta:
        description = "Matches 1 files: File147"
        author = "Forensics Deduplication Script"
        original_size = 156
    strings:
        $header = { 40 65 63 68 6f 20 6f 66 66 0d 0a 73 65 74 20 6d 65 73 73 61 67 65 3d 4c 6f 61 64 69 6e 67 20 72 61 6e 64 6f 6d 20 74 65 78 74 2e 2e 2e 0d 0a 66 6f 72 }
    condition:
        $header at 0 and filesize == 156
}
rule Suspect_Group_File148 {
    meta:
        description = "Matches 1 files: File148"
        author = "Forensics Deduplication Script"
        original_size = 315392
    strings:
        $header = { ff fb 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $header at 0 and filesize == 315392
}
rule Suspect_Group_File149 {
    meta:
        description = "Matches 1 files: File149"
        author = "Forensics Deduplication Script"
        original_size = 27228
    strings:
        $header = { 50 4b 03 04 14 00 08 08 08 00 ce 13 76 59 00 00 00 00 00 00 00 00 00 00 00 00 10 00 00 00 77 6f 72 64 2f 66 6f 6f 74 65 72 31 2e 78 6d 6c ed 57 ff 6e }
    condition:
        $header at 0 and filesize == 27228
}
rule Suspect_Group_File150 {
    meta:
        description = "Matches 1 files: File150"
        author = "Forensics Deduplication Script"
        original_size = 955283
    strings:
        $header = { 50 4b 03 04 0a 00 00 00 00 00 00 00 21 00 ff ff ff ff 20 02 00 00 20 02 00 00 10 00 00 00 5b 74 72 61 73 68 5d 2f 30 30 30 30 2e 64 61 74 ff ff ff ff }
    condition:
        $header at 0 and filesize == 955283
}
rule Suspect_Group_File151 {
    meta:
        description = "Matches 1 files: File151"
        author = "Forensics Deduplication Script"
        original_size = 4723372
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 00 00 21 00 b7 bb c7 dc a4 02 00 00 00 25 00 00 13 00 08 02 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 4723372
}
rule Suspect_Group_File152 {
    meta:
        description = "Matches 1 files: File152"
        author = "Forensics Deduplication Script"
        original_size = 151135
    strings:
        $header = { ff d8 ff e0 00 10 4a 46 49 46 00 01 01 00 00 01 00 01 00 00 ff db 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0a 0c 14 0d 0c 0b 0b 0c 19 12 13 0f }
    condition:
        $header at 0 and filesize == 151135
}
rule Suspect_Group_File153 {
    meta:
        description = "Matches 1 files: File153"
        author = "Forensics Deduplication Script"
        original_size = 40590
    strings:
        $header = { 50 4b 03 04 14 00 08 08 08 00 ba bb 75 55 00 00 00 00 00 00 00 00 00 00 00 00 10 00 00 00 78 6c 2f 63 6f 6d 6d 65 6e 74 73 31 2e 78 6d 6c 8d 53 cb 6e }
    condition:
        $header at 0 and filesize == 40590
}
rule Suspect_Group_File154 {
    meta:
        description = "Matches 1 files: File154"
        author = "Forensics Deduplication Script"
        original_size = 22534
    strings:
        $header = { 45 00 64 00 75 00 63 00 61 00 74 00 69 00 6f 00 6e 00 61 00 6c 00 20 00 43 00 6f 00 6d 00 6d 00 75 00 6e 00 69 00 74 00 79 00 20 00 4c 00 69 00 63 00 }
    condition:
        $header at 0 and filesize == 22534
}
rule Suspect_Group_File155 {
    meta:
        description = "Matches 1 files: File155"
        author = "Forensics Deduplication Script"
        original_size = 301568
    strings:
        $header = { 4d 5a 50 00 02 00 00 00 04 00 0f 00 ff ff 00 00 b8 00 00 00 00 00 00 00 40 00 1a 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $header at 0 and filesize == 301568
}
rule Suspect_Group_File156 {
    meta:
        description = "Matches 1 files: File156"
        author = "Forensics Deduplication Script"
        original_size = 347444
    strings:
        $header = { 25 50 44 46 2d 31 2e 37 0a 25 f6 e4 fc df 0a 31 20 30 20 6f 62 6a 0a 3c 3c 0a 2f 54 79 70 65 20 2f 43 61 74 61 6c 6f 67 0a 2f 50 61 67 65 73 20 32 20 }
    condition:
        $header at 0 and filesize == 347444
}
rule Suspect_Group_File157 {
    meta:
        description = "Matches 1 files: File157"
        author = "Forensics Deduplication Script"
        original_size = 10483
    strings:
        $header = { 41 63 61 64 65 6d 69 63 20 46 72 65 65 20 4c 69 63 65 6e 73 65 20 28 22 41 46 4c 22 29 20 76 2e 20 33 2e 30 0d 0a 0d 0a 54 68 69 73 20 41 63 61 64 65 }
    condition:
        $header at 0 and filesize == 10483
}
rule Suspect_Group_File158 {
    meta:
        description = "Matches 1 files: File158"
        author = "Forensics Deduplication Script"
        original_size = 631
    strings:
        $header = { ef bb bf 3c 23 0a 2e 53 59 4e 4f 50 53 49 53 0a 09 49 6e 73 74 61 6c 6c 73 20 53 70 6f 74 69 66 79 0a 2e 44 45 53 43 52 49 50 54 49 4f 4e 0a 09 54 68 }
    condition:
        $header at 0 and filesize == 631
}
rule Suspect_Group_File159 {
    meta:
        description = "Matches 1 files: File159"
        author = "Forensics Deduplication Script"
        original_size = 317088
    strings:
        $header = { 4d 5a 8b 00 03 00 00 00 20 00 00 00 ff ff 07 00 00 01 65 40 00 00 00 00 40 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $header at 0 and filesize == 317088
}
rule Suspect_Group_File160 {
    meta:
        description = "Matches 1 files: File160"
        author = "Forensics Deduplication Script"
        original_size = 4096
    strings:
        $header = { 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $header at 0 and filesize == 4096
}
rule Suspect_Group_File161 {
    meta:
        description = "Matches 1 files: File161"
        author = "Forensics Deduplication Script"
        original_size = 50971
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 00 00 21 00 b5 cf 3e 7b 02 01 00 00 bb 02 00 00 0b 00 08 02 5f 72 65 6c 73 2f 2e 72 65 6c 73 20 a2 04 02 28 a0 00 02 00 }
    condition:
        $header at 0 and filesize == 50971
}
rule Suspect_Group_File162 {
    meta:
        description = "Matches 1 files: File162"
        author = "Forensics Deduplication Script"
        original_size = 28514
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 00 00 21 00 a4 04 cf e9 71 01 00 00 98 05 00 00 13 00 08 02 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 28514
}
rule Suspect_Group_File163 {
    meta:
        description = "Matches 1 files: File163"
        author = "Forensics Deduplication Script"
        original_size = 174733
    strings:
        $header = { ff d8 ff e0 00 10 4a 46 49 46 00 01 01 00 00 01 00 01 00 00 ff db 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0a 0c 14 0d 0c 0b 0b 0c 19 12 13 0f }
    condition:
        $header at 0 and filesize == 174733
}
rule Suspect_Group_File164 {
    meta:
        description = "Matches 1 files: File164"
        author = "Forensics Deduplication Script"
        original_size = 12440
    strings:
        $header = { 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $header at 0 and filesize == 12440
}
rule Suspect_Group_File165 {
    meta:
        description = "Matches 1 files: File165"
        author = "Forensics Deduplication Script"
        original_size = 696
    strings:
        $header = { ef bb bf 3c 23 0d 0a 2e 53 59 4e 4f 50 53 49 53 0d 0a 20 20 20 20 20 20 20 20 49 6e 73 74 61 6c 6c 73 20 43 68 6f 63 6f 6c 61 74 65 79 20 28 6e 65 65 }
    condition:
        $header at 0 and filesize == 696
}
rule Suspect_Group_File167 {
    meta:
        description = "Matches 1 files: File167"
        author = "Forensics Deduplication Script"
        original_size = 1233
    strings:
        $header = { 54 68 69 73 20 69 73 20 66 72 65 65 20 61 6e 64 20 75 6e 65 6e 63 75 6d 62 65 72 65 64 20 73 6f 66 74 77 61 72 65 20 72 65 6c 65 61 73 65 64 20 69 6e }
    condition:
        $header at 0 and filesize == 1233
}
rule Suspect_Group_File168 {
    meta:
        description = "Matches 1 files: File168"
        author = "Forensics Deduplication Script"
        original_size = 7815
    strings:
        $header = { 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 47 4e 55 20 4c 45 53 53 45 52 20 47 45 4e 45 52 41 4c 20 50 55 42 4c 49 43 20 4c 49 43 45 4e }
    condition:
        $header at 0 and filesize == 7815
}
rule Suspect_Group_File169 {
    meta:
        description = "Matches 1 files: File169"
        author = "Forensics Deduplication Script"
        original_size = 781
    strings:
        $header = { ef bb bf 3c 23 0a 2e 53 59 4e 4f 50 53 49 53 0a 09 50 72 69 6e 74 73 20 74 68 65 20 53 48 41 35 31 32 20 68 61 73 68 20 6f 66 20 61 20 66 69 6c 65 0a }
    condition:
        $header at 0 and filesize == 781
}
rule Suspect_Group_File170 {
    meta:
        description = "Matches 1 files: File170"
        author = "Forensics Deduplication Script"
        original_size = 6138710
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 00 00 21 00 c3 aa 5d 0e 8d 02 00 00 58 1d 00 00 13 00 08 02 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 6138710
}
rule Suspect_Group_File171 {
    meta:
        description = "Matches 1 files: File171"
        author = "Forensics Deduplication Script"
        original_size = 1011368
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 00 00 21 00 33 a5 4b 35 8a 01 00 00 99 05 00 00 13 00 08 02 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 1011368
}
rule Suspect_Group_File172 {
    meta:
        description = "Matches 1 files: File172"
        author = "Forensics Deduplication Script"
        original_size = 17097
    strings:
        $header = { 4d 6f 7a 69 6c 6c 61 20 50 75 62 6c 69 63 20 4c 69 63 65 6e 73 65 20 56 65 72 73 69 6f 6e 20 32 2e 30 0d 0a 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d }
    condition:
        $header at 0 and filesize == 17097
}
rule Suspect_Group_File173 {
    meta:
        description = "Matches 1 files: File173"
        author = "Forensics Deduplication Script"
        original_size = 19232
    strings:
        $header = { 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $header at 0 and filesize == 19232
}
rule Suspect_Group_File174 {
    meta:
        description = "Matches 1 files: File174"
        author = "Forensics Deduplication Script"
        original_size = 113
    strings:
        $header = { 40 65 63 68 6f 20 6f 66 66 0d 0a 73 65 74 20 2f 61 20 61 3d 25 72 61 6e 64 6f 6d 25 20 25 25 20 31 30 30 0d 0a 73 65 74 20 2f 61 20 62 3d 25 72 61 6e }
    condition:
        $header at 0 and filesize == 113
}
rule Suspect_Group_File175 {
    meta:
        description = "Matches 1 files: File175"
        author = "Forensics Deduplication Script"
        original_size = 829
    strings:
        $header = { ef bb bf 3c 23 0a 2e 53 59 4e 4f 50 53 49 53 0a 09 49 6e 73 74 61 6c 6c 73 20 56 4c 43 0a 2e 44 45 53 43 52 49 50 54 49 4f 4e 0a 09 54 68 69 73 20 50 }
    condition:
        $header at 0 and filesize == 829
}
rule Suspect_Group_File177 {
    meta:
        description = "Matches 1 files: File177"
        author = "Forensics Deduplication Script"
        original_size = 12064
    strings:
        $header = { 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $header at 0 and filesize == 12064
}
rule Suspect_Group_File178 {
    meta:
        description = "Matches 1 files: File178"
        author = "Forensics Deduplication Script"
        original_size = 608
    strings:
        $header = { ef bb bf 3c 23 0a 2e 53 59 4e 4f 50 53 49 53 0a 09 49 6e 73 74 61 6c 6c 73 20 4e 65 74 66 6c 69 78 0a 2e 44 45 53 43 52 49 50 54 49 4f 4e 0a 09 54 68 }
    condition:
        $header at 0 and filesize == 608
}
rule Suspect_Group_File179 {
    meta:
        description = "Matches 1 files: File179"
        author = "Forensics Deduplication Script"
        original_size = 9093
    strings:
        $header = { 09 09 20 20 20 20 20 20 20 54 68 65 20 41 72 74 69 73 74 69 63 20 4c 69 63 65 6e 73 65 20 32 2e 30 0d 0a 0d 0a 09 20 20 20 20 43 6f 70 79 72 69 67 68 }
    condition:
        $header at 0 and filesize == 9093
}
rule Suspect_Group_File180 {
    meta:
        description = "Matches 1 files: File180"
        author = "Forensics Deduplication Script"
        original_size = 2071847
    strings:
        $header = { 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $header at 0 and filesize == 2071847
}
rule Suspect_Group_File181 {
    meta:
        description = "Matches 1 files: File181"
        author = "Forensics Deduplication Script"
        original_size = 9567
    strings:
        $header = { 50 4b 03 04 14 00 00 08 08 00 42 3d 3c 5a 47 92 44 b2 5a 01 00 00 f0 04 00 00 13 00 04 00 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 53 }
    condition:
        $header at 0 and filesize == 9567
}
rule Suspect_Group_File182 {
    meta:
        description = "Matches 1 files: File182"
        author = "Forensics Deduplication Script"
        original_size = 490858
    strings:
        $header = { 25 50 44 46 2d 31 2e 34 0d 25 e2 e3 cf d3 0d 0a 31 32 31 33 20 30 20 6f 62 6a 0d 3c 3c 2f 4c 69 6e 65 61 72 69 7a 65 64 20 31 2f 4c 20 34 39 30 38 36 }
    condition:
        $header at 0 and filesize == 490858
}
rule Suspect_Group_File183 {
    meta:
        description = "Matches 1 files: File183"
        author = "Forensics Deduplication Script"
        original_size = 34148
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 00 00 21 00 1c ad b2 d2 fa 01 00 00 6d 0b 00 00 13 00 08 02 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 34148
}
rule Suspect_Group_File184 {
    meta:
        description = "Matches 1 files: File184"
        author = "Forensics Deduplication Script"
        original_size = 1660287
    strings:
        $header = { 89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49 48 44 52 00 00 03 88 00 00 04 ec 08 06 00 00 00 c2 72 ac 0c 00 01 00 00 49 44 41 54 78 9c ec fd f9 8f 24 5b 96 }
    condition:
        $header at 0 and filesize == 1660287
}
rule Suspect_Group_File185 {
    meta:
        description = "Matches 1 files: File185"
        author = "Forensics Deduplication Script"
        original_size = 870117
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 00 00 21 00 96 34 82 68 62 02 00 00 28 18 00 00 13 00 c5 01 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 870117
}
rule Suspect_Group_File186 {
    meta:
        description = "Matches 1 files: File186"
        author = "Forensics Deduplication Script"
        original_size = 2176
    strings:
        $header = { 4d 00 49 00 54 00 20 00 4c 00 69 00 63 00 65 00 6e 00 73 00 65 00 0d 00 0a 00 0d 00 0a 00 43 00 6f 00 70 00 79 00 72 00 69 00 67 00 68 00 74 00 20 00 }
    condition:
        $header at 0 and filesize == 2176
}
rule Suspect_Group_File187 {
    meta:
        description = "Matches 1 files: File187"
        author = "Forensics Deduplication Script"
        original_size = 23570
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 00 00 21 00 b5 f6 d3 96 8d 01 00 00 21 07 00 00 13 00 08 02 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 23570
}
rule Suspect_Group_File188 {
    meta:
        description = "Matches 1 files: File188"
        author = "Forensics Deduplication Script"
        original_size = 10470
    strings:
        $header = { 4f 70 65 6e 20 53 6f 66 74 77 61 72 65 20 4c 69 63 65 6e 73 65 20 28 22 4f 53 4c 22 29 20 76 2e 20 33 2e 30 0d 0a 0d 0a 54 68 69 73 20 4f 70 65 6e 20 }
    condition:
        $header at 0 and filesize == 10470
}
rule Suspect_Group_File189 {
    meta:
        description = "Matches 1 files: File189"
        author = "Forensics Deduplication Script"
        original_size = 95254
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 00 00 21 00 88 5e 62 0b ca 01 00 00 22 0a 00 00 13 00 08 02 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 95254
}
rule Suspect_Group_File190 {
    meta:
        description = "Matches 1 files: File190"
        author = "Forensics Deduplication Script"
        original_size = 1799942
    strings:
        $header = { 89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49 48 44 52 00 00 03 88 00 00 04 ec 08 06 00 00 00 c2 72 ac 0c 00 01 00 00 49 44 41 54 78 9c ec fd e9 b3 6d c7 75 }
    condition:
        $header at 0 and filesize == 1799942
}
rule Suspect_Group_File191 {
    meta:
        description = "Matches 1 files: File191"
        author = "Forensics Deduplication Script"
        original_size = 148835
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 00 00 21 00 58 79 36 07 df 01 00 00 23 0a 00 00 13 00 08 02 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 148835
}
rule Suspect_Group_File192 {
    meta:
        description = "Matches 1 files: File192"
        author = "Forensics Deduplication Script"
        original_size = 319563
    strings:
        $header = { 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $header at 0 and filesize == 319563
}
rule Suspect_Group_File193 {
    meta:
        description = "Matches 1 files: File193"
        author = "Forensics Deduplication Script"
        original_size = 466915
    strings:
        $header = { 50 4b 03 04 0a 00 00 00 00 00 00 00 21 00 ff ff ff ff 0c 02 00 00 0c 02 00 00 10 00 00 00 5b 74 72 61 73 68 5d 2f 30 30 30 30 2e 64 61 74 ff ff ff ff }
    condition:
        $header at 0 and filesize == 466915
}
rule Suspect_Group_File194 {
    meta:
        description = "Matches 1 files: File194"
        author = "Forensics Deduplication Script"
        original_size = 1641870
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 00 00 21 00 3e 11 88 ca 60 02 00 00 47 19 00 00 13 00 08 02 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 1641870
}
rule Suspect_Group_File195 {
    meta:
        description = "Matches 1 files: File195"
        author = "Forensics Deduplication Script"
        original_size = 87316
    strings:
        $header = { 43 44 30 30 14 00 06 00 08 00 00 00 21 00 71 4b 4e 12 05 02 00 00 ec 0c 00 00 13 00 cd 01 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 87316
}
rule Suspect_Group_File196 {
    meta:
        description = "Matches 1 files: File196"
        author = "Forensics Deduplication Script"
        original_size = 1379663
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 00 00 21 00 62 ee 9d 68 5e 01 00 00 90 04 00 00 13 00 08 02 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 1379663
}
rule Suspect_Group_File197 {
    meta:
        description = "Matches 1 files: File197"
        author = "Forensics Deduplication Script"
        original_size = 2454899
    strings:
        $header = { 50 4b 03 04 14 00 08 08 08 00 d2 41 75 59 00 00 00 00 00 00 00 00 00 00 00 00 10 00 00 00 77 6f 72 64 2f 68 65 61 64 65 72 31 2e 78 6d 6c a5 95 db 8e }
    condition:
        $header at 0 and filesize == 2454899
}
rule Suspect_Group_File198 {
    meta:
        description = "Matches 1 files: File198"
        author = "Forensics Deduplication Script"
        original_size = 10412619
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 00 00 21 00 99 55 7e 05 f9 00 00 00 e1 02 00 00 0b 00 f3 01 5f 72 65 6c 73 2f 2e 72 65 6c 73 20 a2 ef 01 28 a0 00 02 00 }
    condition:
        $header at 0 and filesize == 10412619
}
rule Suspect_Group_File199 {
    meta:
        description = "Matches 1 files: File199"
        author = "Forensics Deduplication Script"
        original_size = 266057
    strings:
        $header = { 25 50 44 46 2d 31 2e 37 0d 0a 25 b5 b5 b5 b5 0d 0a 31 20 30 20 6f 62 6a 0d 0a 3c 3c 2f 54 79 70 65 2f 43 61 74 61 6c 6f 67 2f 50 61 67 65 73 20 32 20 }
    condition:
        $header at 0 and filesize == 266057
}
rule Suspect_Group_File200 {
    meta:
        description = "Matches 1 files: File200"
        author = "Forensics Deduplication Script"
        original_size = 1543898
    strings:
        $header = { 4d 5a 00 00 00 0d 49 48 44 52 00 00 03 88 00 00 04 ec 08 06 00 00 00 c2 72 ac 0c 00 01 00 00 49 44 41 54 78 9c ec fd 59 b3 64 49 92 1e 88 7d aa 6a 76 }
    condition:
        $header at 0 and filesize == 1543898
}
rule Suspect_Group_File201 {
    meta:
        description = "Matches 1 files: File201"
        author = "Forensics Deduplication Script"
        original_size = 867014
    strings:
        $header = { 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $header at 0 and filesize == 867014
}
rule Suspect_Group_File202 {
    meta:
        description = "Matches 1 files: File202"
        author = "Forensics Deduplication Script"
        original_size = 1204734
    strings:
        $header = { 42 00 02 00 00 00 20 00 00 00 ff ff 05 00 00 01 00 00 00 00 00 00 40 00 00 00 01 00 fb 71 6a 72 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $header at 0 and filesize == 1204734
}
rule Suspect_Group_File203 {
    meta:
        description = "Matches 1 files: File203"
        author = "Forensics Deduplication Script"
        original_size = 781
    strings:
        $header = { ef bb bf 3c 23 0a 2e 53 59 4e 4f 50 53 49 53 0a 09 50 72 69 6e 74 73 20 74 68 65 20 53 48 41 32 35 36 20 68 61 73 68 20 6f 66 20 61 20 66 69 6c 65 0a }
    condition:
        $header at 0 and filesize == 781
}
rule Suspect_Group_File204 {
    meta:
        description = "Matches 1 files: File204"
        author = "Forensics Deduplication Script"
        original_size = 681
    strings:
        $header = { ef bb bf 3c 23 0a 2e 53 59 4e 4f 50 53 49 53 0a 09 49 6e 73 74 61 6c 6c 73 20 4f 42 53 20 53 74 75 64 69 6f 20 28 6e 65 65 64 73 20 61 64 6d 69 6e 20 }
    condition:
        $header at 0 and filesize == 681
}
rule Suspect_Group_File205 {
    meta:
        description = "Matches 1 files: File205"
        author = "Forensics Deduplication Script"
        original_size = 169050
    strings:
        $header = { ff d8 ff e0 00 10 4a 46 49 46 00 01 01 00 00 01 00 01 00 00 ff db 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0a 0c 14 0d 0c 0b 0b 0c 19 12 13 0f }
    condition:
        $header at 0 and filesize == 169050
}
rule Suspect_Group_File206 {
    meta:
        description = "Matches 1 files: File206"
        author = "Forensics Deduplication Script"
        original_size = 209333
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 00 00 21 00 24 ec 50 bf 82 01 00 00 24 07 00 00 13 00 08 02 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 209333
}
rule Suspect_Group_File207 {
    meta:
        description = "Matches 1 files: File207"
        author = "Forensics Deduplication Script"
        original_size = 726251
    strings:
        $header = { 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $header at 0 and filesize == 726251
}
rule Suspect_Group_File208 {
    meta:
        description = "Matches 1 files: File208"
        author = "Forensics Deduplication Script"
        original_size = 3060289
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 00 00 21 00 e4 a7 b0 6f eb 01 00 00 35 0d 00 00 13 00 08 02 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c 20 }
    condition:
        $header at 0 and filesize == 3060289
}
rule Suspect_Group_File209 {
    meta:
        description = "Matches 1 files: File209"
        author = "Forensics Deduplication Script"
        original_size = 202653
    strings:
        $header = { 25 50 44 46 2d 31 2e 33 0a 25 e2 e3 cf d3 0a 31 20 30 20 6f 62 6a 0a 3c 3c 0a 2f 54 79 70 65 20 2f 50 61 67 65 73 0a 2f 43 6f 75 6e 74 20 31 34 0a 2f }
    condition:
        $header at 0 and filesize == 202653
}
rule Suspect_Group_File210 {
    meta:
        description = "Matches 1 files: File210"
        author = "Forensics Deduplication Script"
        original_size = 184563
    strings:
        $header = { 50 4b 03 04 0a 00 00 00 08 00 00 00 21 00 fc 1f ed 11 25 02 00 00 43 05 00 00 10 00 00 00 64 6f 63 50 72 6f 70 73 2f 61 70 70 2e 78 6d 6c 9c 54 df 6f }
    condition:
        $header at 0 and filesize == 184563
}
rule Suspect_Group_File211 {
    meta:
        description = "Matches 1 files: File211"
        author = "Forensics Deduplication Script"
        original_size = 458026
    strings:
        $header = { 50 4b 03 04 14 00 06 00 08 00 00 00 21 00 3b f4 79 e3 2e 03 00 00 b8 10 00 00 14 00 00 00 78 6c 2f 70 72 65 73 65 6e 74 61 74 69 6f 6e 2e 78 6d 6c ec }
    condition:
        $header at 0 and filesize == 458026
}
rule Suspect_Group_File212 {
    meta:
        description = "Matches 1 files: File212"
        author = "Forensics Deduplication Script"
        original_size = 182
    strings:
        $header = { 40 65 63 68 6f 20 6f 66 66 0d 0a 73 65 74 20 61 64 76 69 63 65 3d 53 74 61 79 20 70 6f 73 69 74 69 76 65 2e 7c 54 61 6b 65 20 62 72 65 61 6b 73 2e 7c }
    condition:
        $header at 0 and filesize == 182
}
rule Suspect_Group_File213 {
    meta:
        description = "Matches 1 files: File213"
        author = "Forensics Deduplication Script"
        original_size = 66043
    strings:
        $header = { 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $header at 0 and filesize == 66043
}
rule Suspect_Group_File214 {
    meta:
        description = "Matches 1 files: File214"
        author = "Forensics Deduplication Script"
        original_size = 166868
    strings:
        $header = { ff d8 ff e0 00 10 4a 46 49 46 00 01 01 00 00 01 00 01 00 00 ff db 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0a 0c 14 0d 0c 0b 0b 0c 19 12 13 0f }
    condition:
        $header at 0 and filesize == 166868
}
rule Suspect_Group_File215 {
    meta:
        description = "Matches 1 files: File215"
        author = "Forensics Deduplication Script"
        original_size = 643
    strings:
        $header = { ef bb bf 3c 23 0a 2e 53 59 4e 4f 50 53 49 53 0a 09 49 6e 73 74 61 6c 6c 73 20 56 69 73 75 61 6c 20 53 74 75 64 69 6f 20 43 6f 64 65 0a 2e 44 45 53 43 }
    condition:
        $header at 0 and filesize == 643
}
rule Suspect_Group_File216 {
    meta:
        description = "Matches 1 files: File216"
        author = "Forensics Deduplication Script"
        original_size = 628
    strings:
        $header = { ef bb bf 3c 23 0a 2e 53 59 4e 4f 50 53 49 53 0a 09 49 6e 73 74 61 6c 6c 73 20 47 69 74 20 45 78 74 65 6e 73 69 6f 6e 73 0a 2e 44 45 53 43 52 49 50 54 }
    condition:
        $header at 0 and filesize == 628
}
rule Suspect_Group_File217 {
    meta:
        description = "Matches 1 files: File217"
        author = "Forensics Deduplication Script"
        original_size = 14118
    strings:
        $header = { 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 45 55 52 4f 50 45 41 4e 20 55 4e 49 4f 4e 20 50 55 42 4c 49 43 20 4c 49 43 45 4e 43 }
    condition:
        $header at 0 and filesize == 14118
}
rule Suspect_Group_File218 {
    meta:
        description = "Matches 1 files: File218"
        author = "Forensics Deduplication Script"
        original_size = 1394042
    strings:
        $header = { 89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49 48 44 52 00 00 03 88 00 00 04 ec 08 06 00 00 00 c2 72 ac 0c 00 01 00 00 49 44 41 54 78 9c ec fd 69 b0 6d c9 75 }
    condition:
        $header at 0 and filesize == 1394042
}
rule Suspect_Group_File219 {
    meta:
        description = "Matches 1 files: File219"
        author = "Forensics Deduplication Script"
        original_size = 127189
    strings:
        $header = { ff d8 ff e0 00 10 45 58 49 46 00 01 01 00 00 01 00 01 00 00 ff db 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0a 0c 14 0d 0c 0b 0b 0c 19 12 13 0f }
    condition:
        $header at 0 and filesize == 127189
}
rule Suspect_Group_File220 {
    meta:
        description = "Matches 1 files: File220"
        author = "Forensics Deduplication Script"
        original_size = 191
    strings:
        $header = { 40 65 63 68 6f 20 6f 66 66 0d 0a 73 65 74 20 77 6f 72 64 3d 68 65 6c 6c 6f 0d 0a 73 65 74 20 73 63 72 61 6d 62 6c 65 64 3d 0d 0a 66 6f 72 20 2f 6c 20 }
    condition:
        $header at 0 and filesize == 191
}
