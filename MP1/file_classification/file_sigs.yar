// Generated from Gary Kessler File Signature Table

rule High_Efficiency_Image_Container_HEIC_1
{
    meta:
        description = "High Efficiency Image Container (HEIC)_1"
        file_class = "Multimedia"
        extensions = "AVIF"

    strings:
        $header = { 00 00 00 }

    condition:
        $header at 0
}

rule High_Efficiency_Image_Container_HEIC_2
{
    meta:
        description = "High Efficiency Image Container (HEIC)_2"
        file_class = "Multimedia"
        extensions = "HEIC"

    strings:
        $header = { 00 00 00 20 66 74 79 70 68 65 69 63 }

    condition:
        $header at 0
}

rule JPEG2000_image_files
{
    meta:
        description = "JPEG2000 image files"
        file_class = "Picture"
        extensions = "JP2"

    strings:
        $header = { 00 00 00 0C 6A 50 20 20 }

    condition:
        $header at 0
}

rule _3GPP_multimedia_files
{
    meta:
        description = "3GPP multimedia files"
        file_class = "Multimedia"
        extensions = "3GP"

    strings:
        $header = { 00 00 00 14 66 74 79 70 }

    condition:
        $header at 0
}

rule MPEG_4_v1
{
    meta:
        description = "MPEG-4 v1"
        file_class = "Multimedia"
        extensions = "MP4"

    strings:
        $header = { 00 00 00 14 66 74 79 70 69 73 6F 6D }

    condition:
        $header at 0
}

rule _3rd_Generation_Partnership_Project_3GPP
{
    meta:
        description = "3rd Generation Partnership Project 3GPP"
        file_class = "Multimedia"
        extensions = "3GG|3GP|3G2"

    strings:
        $header = { 00 00 00 14 66 74 79 70 }

    condition:
        $header at 0
}

rule Windows_Disk_Image
{
    meta:
        description = "Windows Disk Image"
        file_class = "Windows"
        extensions = "TBI"

    strings:
        $header = { 00 00 00 00 14 00 00 00 }

    condition:
        $header at 0
}

rule Bitcoin_Core_wallet_dat_file
{
    meta:
        description = "Bitcoin Core wallet.dat file"
        file_class = "Finance"
        extensions = "DAT"

    strings:
        $header = { 00 00 00 00 62 31 05 00 09 00 00 00 00 20 00 00 00 09 00 00 00 00 00 00 }

    condition:
        $header at 8
}

rule MPEG_4_video_1
{
    meta:
        description = "MPEG-4 video_1"
        file_class = "Multimedia"
        extensions = "3GP5|M4V|MP4"

    strings:
        $header = { 00 00 00 18 66 74 79 70 }

    condition:
        $header at 0
}

rule MPEG_4_video_2
{
    meta:
        description = "MPEG-4 video_2"
        file_class = "Multimedia"
        extensions = "MP4"

    strings:
        $header = { 00 00 00 1C 66 74 79 70 }

    condition:
        $header at 0
}

rule _3GPP2_multimedia_files
{
    meta:
        description = "3GPP2 multimedia files"
        file_class = "Multimedia"
        extensions = "3GP"

    strings:
        $header = { 00 00 00 20 66 74 79 70 }

    condition:
        $header at 0
}

rule Apple_audio_and_video
{
    meta:
        description = "Apple audio and video"
        file_class = "Multimedia"
        extensions = "M4A"

    strings:
        $header = { 00 00 00 20 66 74 79 70 4D 34 41 }

    condition:
        $header at 0
}

rule _3rd_Generation_Partnership_Project_3GPP2
{
    meta:
        description = "3rd Generation Partnership Project 3GPP2"
        file_class = "Multimedia"
        extensions = "3GG|3GP|3G2"

    strings:
        $header = { 00 00 00 20 66 74 79 70 }

    condition:
        $header at 0
}

rule Windows_icon_printer_spool_file
{
    meta:
        description = "Windows icon|printer spool file"
        file_class = "Windows"
        extensions = "ICO|SPL"

    strings:
        $header = { 00 00 01 00 }

    condition:
        $header at 0
}

rule MPEG_video_file
{
    meta:
        description = "MPEG video file"
        file_class = "Multimedia"
        extensions = "MPG"

    strings:
        $header = { 00 00 01 B3 }
        $trailer = { 00 00 01 B7 }

    condition:
        $header at 0 and $trailer
}

rule DVD_video_file
{
    meta:
        description = "DVD video file"
        file_class = "Multimedia"
        extensions = "MPG|VOB"

    strings:
        $header = { 00 00 01 BA }
        $trailer = { 00 00 01 B9 }

    condition:
        $header at 0 and $trailer
}

rule Windows_cursor
{
    meta:
        description = "Windows cursor"
        file_class = "Windows"
        extensions = "CUR"

    strings:
        $header = { 00 00 02 00 }

    condition:
        $header at 0
}

rule Compucon_Singer_embroidery_design_file
{
    meta:
        description = "Compucon-Singer embroidery design file"
        file_class = "Miscellaneous"
        extensions = "XXX"

    strings:
        $header = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

    condition:
        $header at 0
}

rule QuattroPro_spreadsheet
{
    meta:
        description = "QuattroPro spreadsheet"
        file_class = "Spreadsheet"
        extensions = "WB2"

    strings:
        $header = { 00 00 02 00 }

    condition:
        $header at 0
}

rule Amiga_Hunk_executable
{
    meta:
        description = "Amiga Hunk executable"
        file_class = "System"
        extensions = "(none)"

    strings:
        $header = { 00 00 03 F3 }

    condition:
        $header at 0
}

rule Wii_images_container
{
    meta:
        description = "Wii images container"
        file_class = "System"
        extensions = "TPL"

    strings:
        $header = { 00 20 AF 30 }

    condition:
        $header at 0
}

rule Lotus_1_2_3_v1_
{
    meta:
        description = "Lotus 1-2-3 (v1)"
        file_class = "Spreadsheet"
        extensions = "WK1"

    strings:
        $header = { 00 00 02 00 06 04 06 00 }

    condition:
        $header at 0
}

rule Lotus_1_2_3_v3_
{
    meta:
        description = "Lotus 1-2-3 (v3)"
        file_class = "Spreadsheet"
        extensions = "WK3"

    strings:
        $header = { 00 00 1A 00 00 10 04 00 }

    condition:
        $header at 0
}

rule Lotus_1_2_3_v4_v5_
{
    meta:
        description = "Lotus 1-2-3 (v4-v5)"
        file_class = "Spreadsheet"
        extensions = "WK4|WK5"

    strings:
        $header = { 00 00 1A 00 02 10 04 00 }

    condition:
        $header at 0
}

rule Lotus_1_2_3_v9_
{
    meta:
        description = "Lotus 1-2-3 (v9)"
        file_class = "Spreadsheet"
        extensions = "123"

    strings:
        $header = { 00 00 1A 00 05 10 04 }

    condition:
        $header at 0
}

rule Quark_Express_Intel_
{
    meta:
        description = "Quark Express (Intel)"
        file_class = "Presentation"
        extensions = "QXD"

    strings:
        $header = { 00 00 49 49 58 50 52 }

    condition:
        $header at 0
}

rule Quark_Express_Motorola_
{
    meta:
        description = "Quark Express (Motorola)"
        file_class = "Presentation"
        extensions = "QXD"

    strings:
        $header = { 00 00 4D 4D 58 50 52 }

    condition:
        $header at 0
}

rule Windows_Help_file_1
{
    meta:
        description = "Windows Help file_1"
        file_class = "Windows"
        extensions = "HLP"

    strings:
        $header = { 00 00 FF FF FF FF }

    condition:
        $header at 6
}

rule TrueType_font_file
{
    meta:
        description = "TrueType font file"
        file_class = "Windows"
        extensions = "TTF"

    strings:
        $header = { 00 01 00 00 00 }

    condition:
        $header at 0
}

rule Microsoft_Money_file
{
    meta:
        description = "Microsoft Money file"
        file_class = "Finance"
        extensions = "MNY"

    strings:
        $header = { 00 01 00 00 4D 53 49 53 41 4D 20 44 61 74 61 62 61 73 65 }

    condition:
        $header at 0
}

rule Microsoft_Access_2007
{
    meta:
        description = "Microsoft Access 2007"
        file_class = "Database"
        extensions = "ACCDB"

    strings:
        $header = { 00 01 00 00 53 74 61 6E 64 61 72 64 20 41 43 45 20 44 42 }

    condition:
        $header at 0
}

rule Microsoft_Access
{
    meta:
        description = "Microsoft Access"
        file_class = "Database"
        extensions = "MDB"

    strings:
        $header = { 00 01 00 00 53 74 61 6E 64 61 72 64 20 4A 65 74 20 44 42 }

    condition:
        $header at 0
}

rule Palm_Address_Book_Archive
{
    meta:
        description = "Palm Address Book Archive"
        file_class = "Mobile"
        extensions = "ABA"

    strings:
        $header = { 00 01 42 41 }

    condition:
        $header at 0
}

rule Palm_DateBook_Archive
{
    meta:
        description = "Palm DateBook Archive"
        file_class = "Mobile"
        extensions = "DBA"

    strings:
        $header = { 00 01 42 44 }

    condition:
        $header at 0
}

rule Netscape_Navigator_v4_database
{
    meta:
        description = "Netscape Navigator (v4) database"
        file_class = "Network"
        extensions = "DB"

    strings:
        $header = { 00 06 15 61 00 00 00 02 00 00 04 D2 00 00 10 00 }

    condition:
        $header at 0
}

rule Mbox_table_of_contents_file
{
    meta:
        description = "Mbox table of contents file"
        file_class = "E-mail"
        extensions = "(none)"

    strings:
        $header = { 00 0D BB A0 }

    condition:
        $header at 0
}

rule FLIC_animation
{
    meta:
        description = "FLIC animation"
        file_class = "Miscellaneous"
        extensions = "FLI"

    strings:
        $header = { 00 11 }

    condition:
        $header at 0
}

rule BIOS_details_in_RAM
{
    meta:
        description = "BIOS details in RAM"
        file_class = "Windows"
        extensions = "(none)"

    strings:
        $header = { 00 14 00 00 01 02 }

    condition:
        $header at 0
}

rule Netscape_Communicator_v4_mail_folder
{
    meta:
        description = "Netscape Communicator (v4) mail folder"
        file_class = "Email"
        extensions = "SNM"

    strings:
        $header = { 00 1E 84 90 00 00 00 00 }

    condition:
        $header at 0
}

rule Paessler_PRTG_Monitoring_System
{
    meta:
        description = "Paessler PRTG Monitoring System"
        file_class = "Database"
        extensions = "DB"

    strings:
        $header = { 00 3B 05 00 01 00 00 00 }

    condition:
        $header at 0
}

rule PowerPoint_presentation_subheader_1
{
    meta:
        description = "PowerPoint presentation subheader_1"
        file_class = "Presentation"
        extensions = "PPT"

    strings:
        $header = { 00 6E 1E F0 }

    condition:
        $header at 512
}

rule Webex_Advanced_Recording_Format
{
    meta:
        description = "Webex Advanced Recording Format"
        file_class = "Video"
        extensions = "ARF"

    strings:
        $header = { 01 00 02 00 }

    condition:
        $header at 0
}

rule Firebird_and_Interbase_database_files
{
    meta:
        description = "Firebird and Interbase database files"
        file_class = "Database"
        extensions = "FDB|GDB"

    strings:
        $header = { 01 00 39 30 }

    condition:
        $header at 0
}

rule The_Bat_Message_Base_Index
{
    meta:
        description = "The Bat! Message Base Index"
        file_class = "Email"
        extensions = "TBI"

    strings:
        $header = { 01 01 47 19 A4 00 00 00 00 00 00 00 }

    condition:
        $header at 0
}

rule SQL_Data_Base
{
    meta:
        description = "SQL Data Base"
        file_class = "Database"
        extensions = "MDF"

    strings:
        $header = { 01 0F 00 00 }

    condition:
        $header at 0
}

rule Novell_LANalyzer_capture_file
{
    meta:
        description = "Novell LANalyzer capture file"
        file_class = "Network"
        extensions = "TR1"

    strings:
        $header = { 01 10 }

    condition:
        $header at 0
}

rule Silicon_Graphics_RGB_Bitmap
{
    meta:
        description = "Silicon Graphics RGB Bitmap"
        file_class = "Picture"
        extensions = "RGB"

    strings:
        $header = { 01 DA 01 01 00 03 }

    condition:
        $header at 0
}

rule Micrografx_vector_graphic_file
{
    meta:
        description = "Micrografx vector graphic file"
        file_class = "Picture"
        extensions = "DRW"

    strings:
        $header = { 01 FF 02 04 03 02 }

    condition:
        $header at 0
}

rule Digital_Speech_Standard_file
{
    meta:
        description = "Digital Speech Standard file"
        file_class = "Multimedia"
        extensions = "DSS"

    strings:
        $header = { 02 64 73 73 }

    condition:
        $header at 0
}

rule MapInfo_Native_Data_Format
{
    meta:
        description = "MapInfo Native Data Format"
        file_class = "Navigation"
        extensions = "DAT"

    strings:
        $header = { 03 }

    condition:
        $header at 0
}

rule dBASE_III_file
{
    meta:
        description = "dBASE III file"
        file_class = "Database"
        extensions = "DB3"

    strings:
        $header = { 03 }

    condition:
        $header at 0
}

rule Quicken_price_history
{
    meta:
        description = "Quicken price history"
        file_class = "Finance"
        extensions = "QPH"

    strings:
        $header = { 03 00 00 00 }

    condition:
        $header at 0
}

rule Nokia_PC_Suite_Content_Copier_file
{
    meta:
        description = "Nokia PC Suite Content Copier file"
        file_class = "Multimedia"
        extensions = "NFC"

    strings:
        $header = { 03 00 00 00 }

    condition:
        $header at 0
}

rule Approach_index_file
{
    meta:
        description = "Approach index file"
        file_class = "Database"
        extensions = "ADX"

    strings:
        $header = { 03 00 00 00 41 50 50 52 }

    condition:
        $header at 0
}

rule Digital_Speech_Standard_v3_
{
    meta:
        description = "Digital Speech Standard (v3)"
        file_class = "Audio"
        extensions = "DSS"

    strings:
        $header = { 03 64 73 73 }

    condition:
        $header at 0
}

rule dBASE_IV_file
{
    meta:
        description = "dBASE IV file"
        file_class = "Database"
        extensions = "DB4"

    strings:
        $header = { 04 }

    condition:
        $header at 0
}

rule INFO2_Windows_recycle_bin_1
{
    meta:
        description = "INFO2 Windows recycle bin_1"
        file_class = "Windows"
        extensions = "(none)"

    strings:
        $header = { 04 00 00 00 }

    condition:
        $header at 0
}

rule INFO2_Windows_recycle_bin_2
{
    meta:
        description = "INFO2 Windows recycle bin_2"
        file_class = "Windows"
        extensions = "(none)"

    strings:
        $header = { 05 00 00 00 }

    condition:
        $header at 0
}

rule Adobe_InDesign
{
    meta:
        description = "Adobe InDesign"
        file_class = "Media"
        extensions = "INDD"

    strings:
        $header = { 06 06 ED F5 D8 1D 46 E5 BD 31 EF E7 FE 74 B7 1D }

    condition:
        $header at 0
}

rule Material_Exchange_Format
{
    meta:
        description = "Material Exchange Format"
        file_class = "Media"
        extensions = "MXF"

    strings:
        $header = { 06 0E 2B 34 02 05 01 01 0D 01 02 01 01 02 }

    condition:
        $header at 0
}

rule Generic_drawing_programs
{
    meta:
        description = "Generic drawing programs"
        file_class = "Presentation"
        extensions = "DRW"

    strings:
        $header = { 07 }

    condition:
        $header at 0
}

rule SkinCrafter_skin
{
    meta:
        description = "SkinCrafter skin"
        file_class = "Miscellaneous"
        extensions = "SKF"

    strings:
        $header = { 07 53 4B 46 }

    condition:
        $header at 0
}

rule DesignTools_2D_Design_file
{
    meta:
        description = "DesignTools 2D Design file"
        file_class = "Miscellaneous"
        extensions = "DTD"

    strings:
        $header = { 07 64 74 32 64 64 74 64 }

    condition:
        $header at 0
}

rule dBASE_IV_or_dBFast_configuration_file
{
    meta:
        description = "dBASE IV or dBFast configuration file"
        file_class = "Database"
        extensions = "DB"

    strings:
        $header = { 08 }

    condition:
        $header at 0
}

rule Excel_spreadsheet_subheader_1
{
    meta:
        description = "Excel spreadsheet subheader_1"
        file_class = "Spreadsheet"
        extensions = "XLS"

    strings:
        $header = { 09 08 10 00 00 06 05 00 }

    condition:
        $header at 512
}

rule ZSOFT_Paintbrush_file_1
{
    meta:
        description = "ZSOFT Paintbrush file_1"
        file_class = "Presentation"
        extensions = "PCX"

    strings:
        $header = { 0A 02 01 01 }

    condition:
        $header at 0
}

rule ZSOFT_Paintbrush_file_2
{
    meta:
        description = "ZSOFT Paintbrush file_2"
        file_class = "Presentation"
        extensions = "PCX"

    strings:
        $header = { 0A 03 01 01 }

    condition:
        $header at 0
}

rule ZSOFT_Paintbrush_file_3
{
    meta:
        description = "ZSOFT Paintbrush file_3"
        file_class = "Presentation"
        extensions = "PCX"

    strings:
        $header = { 0A 05 01 01 }

    condition:
        $header at 0
}

rule MultiBit_Bitcoin_wallet_file
{
    meta:
        description = "MultiBit Bitcoin wallet file"
        file_class = "e-money"
        extensions = "WALLET"

    strings:
        $header = { 0A 16 6F 72 67 2E 62 69 74 63 6F 69 6E 2E 70 72 }

    condition:
        $header at 0
}

rule Monochrome_Picture_TIFF_bitmap
{
    meta:
        description = "Monochrome Picture TIFF bitmap"
        file_class = "Picture"
        extensions = "MP"

    strings:
        $header = { 0C ED }

    condition:
        $header at 0
}

rule DeskMate_Document
{
    meta:
        description = "DeskMate Document"
        file_class = "Word processing suite"
        extensions = "DOC"

    strings:
        $header = { 0D 44 4F 43 }

    condition:
        $header at 0
}

rule Nero_CD_compilation
{
    meta:
        description = "Nero CD compilation"
        file_class = "Miscellaneous"
        extensions = "NRI"

    strings:
        $header = { 0E 4E 65 72 6F 49 53 4F }

    condition:
        $header at 0
}

rule DeskMate_Worksheet
{
    meta:
        description = "DeskMate Worksheet"
        file_class = "Word processing suite"
        extensions = "WKS"

    strings:
        $header = { 0E 57 4B 53 }

    condition:
        $header at 0
}

rule PowerPoint_presentation_subheader_2
{
    meta:
        description = "PowerPoint presentation subheader_2"
        file_class = "Presentation"
        extensions = "PPT"

    strings:
        $header = { 0F 00 E8 03 }

    condition:
        $header at 512
}

rule Sibelius_Music_Score
{
    meta:
        description = "Sibelius Music - Score"
        file_class = "Multimedia"
        extensions = "SIB"

    strings:
        $header = { 0F 53 49 42 45 4C 49 55 53 }

    condition:
        $header at 0
}

rule Easy_CD_Creator_5_Layout_file
{
    meta:
        description = "Easy CD Creator 5 Layout file"
        file_class = "Utility"
        extensions = "CL5"

    strings:
        $header = { 10 00 00 00 }

    condition:
        $header at 0
}

rule Windows_prefetch_file
{
    meta:
        description = "Windows prefetch file"
        file_class = "Windows"
        extensions = "PF"

    strings:
        $header = { 11 00 00 00 53 43 43 41 }

    condition:
        $header at 0
}

rule Lotus_Notes_database_template
{
    meta:
        description = "Lotus Notes database template"
        file_class = "Spreadsheet"
        extensions = "NTF"

    strings:
        $header = { 1A 00 00 }

    condition:
        $header at 0
}

rule Lotus_Notes_database
{
    meta:
        description = "Lotus Notes database"
        file_class = "Spreadsheet"
        extensions = "NSF"

    strings:
        $header = { 1A 00 00 04 00 00 }

    condition:
        $header at 0
}

rule LH_archive_old_vers_type_1_
{
    meta:
        description = "LH archive (old vers.-type 1)"
        file_class = "Compressed archive"
        extensions = "ARC"

    strings:
        $header = { 1A 02 }

    condition:
        $header at 0
}

rule LH_archive_old_vers_type_2_
{
    meta:
        description = "LH archive (old vers.-type 2)"
        file_class = "Compressed archive"
        extensions = "ARC"

    strings:
        $header = { 1A 03 }

    condition:
        $header at 0
}

rule LH_archive_old_vers_type_3_
{
    meta:
        description = "LH archive (old vers.-type 3)"
        file_class = "Compressed archive"
        extensions = "ARC"

    strings:
        $header = { 1A 04 }

    condition:
        $header at 0
}

rule LH_archive_old_vers_type_4_
{
    meta:
        description = "LH archive (old vers.-type 4)"
        file_class = "Compressed archive"
        extensions = "ARC"

    strings:
        $header = { 1A 08 }

    condition:
        $header at 0
}

rule LH_archive_old_vers_type_5_
{
    meta:
        description = "LH archive (old vers.-type 5)"
        file_class = "Compressed archive"
        extensions = "ARC"

    strings:
        $header = { 1A 09 }

    condition:
        $header at 0
}

rule Compressed_archive_file
{
    meta:
        description = "Compressed archive file"
        file_class = "Compressed archive"
        extensions = "PAK"

    strings:
        $header = { 1A 0B }

    condition:
        $header at 0
}

rule WinPharoah_capture_file
{
    meta:
        description = "WinPharoah capture file"
        file_class = "Network"
        extensions = "ETH"

    strings:
        $header = { 1A 35 01 00 }

    condition:
        $header at 0
}

rule WebM_video_file
{
    meta:
        description = "WebM video file"
        file_class = "Multimedia"
        extensions = "WEBM"

    strings:
        $header = { 1A 45 DF A3 }

    condition:
        $header at 0
}

rule Matroska_stream_file_1
{
    meta:
        description = "Matroska stream file_1"
        file_class = "Multimedia"
        extensions = "MKV"

    strings:
        $header = { 1A 45 DF A3 }

    condition:
        $header at 0
}

rule Matroska_stream_file_2
{
    meta:
        description = "Matroska stream file_2"
        file_class = "Multimedia"
        extensions = "MKV"

    strings:
        $header = { 1A 45 DF A3 93 42 82 88 }

    condition:
        $header at 0
}

rule Runtime_Software_disk_image
{
    meta:
        description = "Runtime Software disk image"
        file_class = "Miscellaneous"
        extensions = "DAT"

    strings:
        $header = { 1A 52 54 53 20 43 4F 4D }

    condition:
        $header at 0
}

rule WordStar_Version_5_0_6_0_document
{
    meta:
        description = "WordStar Version 5.0-6.0 document"
        file_class = "Word processing suite"
        extensions = "WS"

    strings:
        $header = { 1D 7D }

    condition:
        $header at 0
}

rule GZIP_archive_file
{
    meta:
        description = "GZIP archive file"
        file_class = "Compressed archive"
        extensions = "GZ"

    strings:
        $header = { 1F 8B 08 }

    condition:
        $header at 0
}

rule VLC_Player_Skin_file
{
    meta:
        description = "VLC Player Skin file"
        file_class = "Miscellaneous"
        extensions = "VLT"

    strings:
        $header = { 1F 8B 08 }

    condition:
        $header at 0
}

rule Synology_router_configuration_backup_file
{
    meta:
        description = "Synology router configuration backup file"
        file_class = "Network"
        extensions = "DSS"

    strings:
        $header = { 1F 8B 08 00 }

    condition:
        $header at 0
}

rule Compressed_tape_archive_1
{
    meta:
        description = "Compressed tape archive_1"
        file_class = "Compressed archive"
        extensions = "TAR.Z"

    strings:
        $header = { 1F 9D 90 }

    condition:
        $header at 0
}

rule Compressed_tape_archive_2
{
    meta:
        description = "Compressed tape archive_2"
        file_class = "Compressed archive"
        extensions = "TAR.Z"

    strings:
        $header = { 1F A0 }

    condition:
        $header at 0
}

rule MapInfo_Sea_Chart
{
    meta:
        description = "MapInfo Sea Chart"
        file_class = "Navigation"
        extensions = "BSB"

    strings:
        $header = { 21 }

    condition:
        $header at 0
}

rule NOAA_Raster_Navigation_Chart_RNC_file
{
    meta:
        description = "NOAA Raster Navigation Chart (RNC) file"
        file_class = "Navigation"
        extensions = "BSB"

    strings:
        $header = { 21 0D 0A 43 52 52 2F 54 68 69 73 20 65 6C 65 63 }

    condition:
        $header at 0
}

rule AIN_Compressed_Archive
{
    meta:
        description = "AIN Compressed Archive"
        file_class = "Compressed archive"
        extensions = "AIN"

    strings:
        $header = { 21 12 }

    condition:
        $header at 0
}

rule Unix_archiver_ar_MS_Program_Library_Common_Object_File_Format_COFF_
{
    meta:
        description = "Unix archiver (ar)-MS Program Library Common Object File Format (COFF)"
        file_class = "Compressed archive"
        extensions = "LIB"

    strings:
        $header = { 21 3C 61 72 63 68 3E 0A }

    condition:
        $header at 0
}

rule Microsoft_Outlook_Exchange_Offline_Storage_Folder
{
    meta:
        description = "Microsoft Outlook Exchange Offline Storage Folder"
        file_class = "Email"
        extensions = "OST"

    strings:
        $header = { 21 42 44 4E }

    condition:
        $header at 0
}

rule Cerius2_file
{
    meta:
        description = "Cerius2 file"
        file_class = "Miscellaneous"
        extensions = "MSI"

    strings:
        $header = { 23 20 }

    condition:
        $header at 0
}

rule VMware_4_Virtual_Disk_description
{
    meta:
        description = "VMware 4 Virtual Disk description"
        file_class = "Miscellaneous"
        extensions = "VMDK"

    strings:
        $header = { 23 20 44 69 73 6B 20 44 }

    condition:
        $header at 0
}

rule MS_Developer_Studio_project_file
{
    meta:
        description = "MS Developer Studio project file"
        file_class = "Programming"
        extensions = "DSP"

    strings:
        $header = { 23 20 4D 69 63 72 6F 73 }

    condition:
        $header at 0
}

rule Google_Earth_Keyhole_Placemark_file
{
    meta:
        description = "Google Earth Keyhole Placemark file"
        file_class = "Navigation"
        extensions = "ETA"

    strings:
        $header = { 23 20 54 68 69 73 20 69 73 20 61 6E 20 4B 65 79 }

    condition:
        $header at 0
}

rule Adaptive_Multi_Rate_ACELP_Codec_GSM_
{
    meta:
        description = "Adaptive Multi-Rate ACELP Codec (GSM)"
        file_class = "Multimedia"
        extensions = "AMR"

    strings:
        $header = { 23 21 41 4D 52 }

    condition:
        $header at 0
}

rule Skype_audio_compression
{
    meta:
        description = "Skype audio compression"
        file_class = "Multimedia"
        extensions = "SIL"

    strings:
        $header = { 23 21 53 49 4C 4B 0A }

    condition:
        $header at 0
}

rule Radiance_High_Dynamic_Range_image_file
{
    meta:
        description = "Radiance High Dynamic Range image file"
        file_class = "Picture"
        extensions = "HDR"

    strings:
        $header = { 23 3F 52 41 44 49 41 4E }

    condition:
        $header at 0
}

rule VBScript_Encoded_script
{
    meta:
        description = "VBScript Encoded script"
        file_class = "Programming"
        extensions = "VBE"

    strings:
        $header = { 23 40 7E 5E }

    condition:
        $header at 0
}

rule NVIDIA_Scene_Graph_binary_file
{
    meta:
        description = "NVIDIA Scene Graph binary file"
        file_class = "Video"
        extensions = "NBF"

    strings:
        $header = { 23 4E 42 46 }

    condition:
        $header at 0
}

rule Brother_Babylock_Bernina_Home_Embroidery
{
    meta:
        description = "Brother-Babylock-Bernina Home Embroidery"
        file_class = "Miscellaneous"
        extensions = "PEC"

    strings:
        $header = { 23 50 45 43 30 30 30 31 }

    condition:
        $header at 0
}

rule Brother_Babylock_Bernina_Home_Embroidery_1
{
    meta:
        description = "Brother-Babylock-Bernina Home Embroidery"
        file_class = "Miscellaneous"
        extensions = "PES"

    strings:
        $header = { 23 50 45 53 30 }

    condition:
        $header at 0
}

rule SPSS_Data_file
{
    meta:
        description = "SPSS Data file"
        file_class = "Miscellaneous"
        extensions = "SAV"

    strings:
        $header = { 24 46 4C 32 40 28 23 29 }

    condition:
        $header at 0
}

rule Encapsulated_PostScript_file
{
    meta:
        description = "Encapsulated PostScript file"
        file_class = "Word processing suite"
        extensions = "EPS"

    strings:
        $header = { 25 21 50 53 2D 41 64 6F }

    condition:
        $header at 0
}

rule PostScript_file
{
    meta:
        description = "PostScript file"
        file_class = "Word processing suite"
        extensions = "PS"

    strings:
        $header = { 25 21 50 53 2D 41 64 6F 62 65 2D }

    condition:
        $header at 0
}

rule PDF_file
{
    meta:
        description = "PDF file"
        file_class = "Word processing suite"
        extensions = "PDF|FDF"

    strings:
        $header = { 25 50 44 46 }
        $trailer = { 25 25 45 4F 46 }

    condition:
        $header at 0 and $trailer
}

rule Fuzzy_bitmap_FBM_file
{
    meta:
        description = "Fuzzy bitmap (FBM) file"
        file_class = "Picture"
        extensions = "FBM"

    strings:
        $header = { 25 62 69 74 6D 61 70 }

    condition:
        $header at 0
}

rule BinHex_4_Compressed_Archive
{
    meta:
        description = "BinHex 4 Compressed Archive"
        file_class = "Compressed archive"
        extensions = "HQX"

    strings:
        $header = { 28 54 68 69 73 20 66 69 }

    condition:
        $header at 0
}

rule Symantec_Wise_Installer_log
{
    meta:
        description = "Symantec Wise Installer log"
        file_class = "Miscellaneous"
        extensions = "LOG"

    strings:
        $header = { 2A 2A 2A 20 20 49 6E 73 }

    condition:
        $header at 0
}

rule Compressed_archive
{
    meta:
        description = "Compressed archive"
        file_class = "Compressed archive"
        extensions = "LHA|LZH"

    strings:
        $header = { 2D 6C 68 }

    condition:
        $header at 2
}

rule RealPlayer_video_file_V11_
{
    meta:
        description = "RealPlayer video file (V11+)"
        file_class = "Multimedia"
        extensions = "IVR"

    strings:
        $header = { 2E 52 45 43 }

    condition:
        $header at 0
}

rule RealMedia_streaming_media
{
    meta:
        description = "RealMedia streaming media"
        file_class = "Multimedia"
        extensions = "RM|RMVB"

    strings:
        $header = { 2E 52 4D 46 }

    condition:
        $header at 0
}

rule RealAudio_file
{
    meta:
        description = "RealAudio file"
        file_class = "Multimedia"
        extensions = "RA"

    strings:
        $header = { 2E 52 4D 46 00 00 00 12 }

    condition:
        $header at 0
}

rule RealAudio_streaming_media
{
    meta:
        description = "RealAudio streaming media"
        file_class = "Multimedia"
        extensions = "RA"

    strings:
        $header = { 2E 72 61 FD 00 }

    condition:
        $header at 0
}

rule NeXT_Sun_Microsystems_audio_file
{
    meta:
        description = "NeXT-Sun Microsystems audio file"
        file_class = "Multimedia"
        extensions = "AU"

    strings:
        $header = { 2E 73 6E 64 }

    condition:
        $header at 0
}

rule Thunderbird_Mozilla_Mail_Summary_File
{
    meta:
        description = "Thunderbird-Mozilla Mail Summary File"
        file_class = "E-mail"
        extensions = "MSF"

    strings:
        $header = { 2F 2F 20 3C 21 2D 2D 20 3C 6D 64 62 3A 6D 6F 72 6B 3A 7A }

    condition:
        $header at 0
}

rule MS_security_catalog_file
{
    meta:
        description = "MS security catalog file"
        file_class = "Windows"
        extensions = "CAT"

    strings:
        $header = { 30 }

    condition:
        $header at 0
}

rule Windows_Event_Viewer_file
{
    meta:
        description = "Windows Event Viewer file"
        file_class = "Windows"
        extensions = "EVT"

    strings:
        $header = { 30 00 00 00 4C 66 4C 65 }

    condition:
        $header at 0
}

rule GEnealogical_Data_COMmunication_GEDCOM_file
{
    meta:
        description = "GEnealogical Data COMmunication (GEDCOM) file"
        file_class = "Miscellaneous"
        extensions = "GED"

    strings:
        $header = { 30 20 48 45 41 44 }

    condition:
        $header at 0
}

rule Windows_Media_Audio_Video_File
{
    meta:
        description = "Windows Media Audio-Video File"
        file_class = "Multimedia"
        extensions = "ASF|WMA|WMV"

    strings:
        $header = { 30 26 B2 75 8E 66 CF 11 }

    condition:
        $header at 0
}

rule National_Transfer_Format_Map
{
    meta:
        description = "National Transfer Format Map"
        file_class = "Miscellaneous"
        extensions = "NTF"

    strings:
        $header = { 30 31 4F 52 44 4E 41 4E }

    condition:
        $header at 0
}

rule cpio_archive
{
    meta:
        description = "cpio archive"
        file_class = "Compressed archive"
        extensions = "(none)"

    strings:
        $header = { 30 37 30 37 30 }

    condition:
        $header at 0
}

rule MS_Write_file_1
{
    meta:
        description = "MS Write file_1"
        file_class = "Word processing suite"
        extensions = "WRI"

    strings:
        $header = { 31 BE }

    condition:
        $header at 0
}

rule MS_Write_file_2
{
    meta:
        description = "MS Write file_2"
        file_class = "Word processing suite"
        extensions = "WRI"

    strings:
        $header = { 32 BE }

    condition:
        $header at 0
}

rule Pfaff_Home_Embroidery
{
    meta:
        description = "Pfaff Home Embroidery"
        file_class = "Miscellaneous"
        extensions = "PCS"

    strings:
        $header = { 32 03 10 00 00 00 00 00 00 00 80 00 00 00 FF 00 }

    condition:
        $header at 0
}

rule Tcpdump_capture_file
{
    meta:
        description = "Tcpdump capture file"
        file_class = "Network"
        extensions = "(none)"

    strings:
        $header = { 34 CD B2 A1 }

    condition:
        $header at 0
}

rule _7_Zip_compressed_file
{
    meta:
        description = "7-Zip compressed file"
        file_class = "Compressed archive"
        extensions = "7Z"

    strings:
        $header = { 37 7A BC AF 27 1C }

    condition:
        $header at 0
}

rule zisofs_compressed_file
{
    meta:
        description = "zisofs compressed file"
        file_class = "Compressed archive"
        extensions = "(none)"

    strings:
        $header = { 37 E4 53 96 C9 DB D6 07 }

    condition:
        $header at 0
}

rule Photoshop_image
{
    meta:
        description = "Photoshop image"
        file_class = "Picture"
        extensions = "PSD"

    strings:
        $header = { 38 42 50 53 }

    condition:
        $header at 0
}

rule Surfplan_kite_project_file
{
    meta:
        description = "Surfplan kite project file"
        file_class = "Miscellaneous"
        extensions = "SLE"

    strings:
        $header = { 3A 56 45 52 53 49 4F 4E }

    condition:
        $header at 0
}

rule Advanced_Stream_Redirector
{
    meta:
        description = "Advanced Stream Redirector"
        file_class = "Multimedia"
        extensions = "ASX"

    strings:
        $header = { 3C }

    condition:
        $header at 0
}

rule BizTalk_XML_Data_Reduced_Schema
{
    meta:
        description = "BizTalk XML-Data Reduced Schema"
        file_class = "Miscellaneous"
        extensions = "XDR"

    strings:
        $header = { 3C }

    condition:
        $header at 0
}

rule AOL_HTML_mail
{
    meta:
        description = "AOL HTML mail"
        file_class = "Email"
        extensions = "DCI"

    strings:
        $header = { 3C 21 64 6F 63 74 79 70 }

    condition:
        $header at 0
}

rule Windows_Script_Component
{
    meta:
        description = "Windows Script Component"
        file_class = "Windows"
        extensions = "WSC"

    strings:
        $header = { 3C 3F }

    condition:
        $header at 0
}

rule Windows_Visual_Stylesheet
{
    meta:
        description = "Windows Visual Stylesheet"
        file_class = "Programming"
        extensions = "MANIFEST"

    strings:
        $header = { 3C 3F 78 6D 6C 20 76 65 72 73 69 6F 6E 3D }

    condition:
        $header at 0
}

rule User_Interface_Language
{
    meta:
        description = "User Interface Language"
        file_class = "Miscellaneous"
        extensions = "XML"

    strings:
        $header = { 3C 3F 78 6D 6C 20 76 65 72 73 69 6F 6E 3D 22 31 2E 30 22 3F 3E }

    condition:
        $header at 0
}

rule MMC_Snap_in_Control_file
{
    meta:
        description = "MMC Snap-in Control file"
        file_class = "Windows"
        extensions = "MSC"

    strings:
        $header = { 3C 3F 78 6D 6C 20 76 65 72 73 69 6F 6E 3D 22 31 2E 30 22 3F 3E 0D 0A 3C 4D 4D 43 5F 43 6F 6E 73 6F 6C 65 46 69 6C 65 20 43 6F 6E 73 6F 6C 65 56 65 72 73 69 6F 6E 3D 22 }

    condition:
        $header at 0
}

rule Picasa_movie_project_file
{
    meta:
        description = "Picasa movie project file"
        file_class = "Multimedia"
        extensions = "MXF"

    strings:
        $header = { 3C 43 54 72 61 6E 73 54 69 6D 65 6C 69 6E 65 3E }

    condition:
        $header at 0
}

rule Csound_music
{
    meta:
        description = "Csound music"
        file_class = "Multimedia"
        extensions = "CSD"

    strings:
        $header = { 3C 43 73 6F 75 6E 64 53 79 6E 74 68 65 73 69 7A }

    condition:
        $header at 0
}

rule Google_Earth_Keyhole_Overlay_file
{
    meta:
        description = "Google Earth Keyhole Overlay file"
        file_class = "Navigation"
        extensions = "ETA"

    strings:
        $header = { 3C 4B 65 79 68 6F 6C 65 3E }

    condition:
        $header at 0
}

rule Adobe_FrameMaker
{
    meta:
        description = "Adobe FrameMaker"
        file_class = "Presentation"
        extensions = "FM|MIF"

    strings:
        $header = { 3C 4D 61 6B 65 72 46 69 }

    condition:
        $header at 0
}

rule GPS_Exchange_v1_1_
{
    meta:
        description = "GPS Exchange (v1.1)"
        file_class = "Navigation"
        extensions = "GPX"

    strings:
        $header = { 3C 67 70 78 20 76 65 72 73 69 6F 6E 3D 22 31 2E }

    condition:
        $header at 0
}

rule BASE85_file
{
    meta:
        description = "BASE85 file"
        file_class = "Word processing"
        extensions = "B85"

    strings:
        $header = { 3C 7E 36 3C 5C 25 5F 30 67 53 71 68 3B }
        $trailer = { 7E 3E 0A }

    condition:
        $header at 0 and $trailer
}

rule Quatro_Pro_for_Windows_7_0
{
    meta:
        description = "Quatro Pro for Windows 7.0"
        file_class = "Spreadsheet"
        extensions = "WB3"

    strings:
        $header = { 3E 00 03 00 FE FF 09 00 06 }

    condition:
        $header at 24
}

rule Windows_Help_file_2
{
    meta:
        description = "Windows Help file_2"
        file_class = "Windows"
        extensions = "GID|HLP"

    strings:
        $header = { 3F 5F 03 00 }

    condition:
        $header at 0
}

rule EndNote_Library_File
{
    meta:
        description = "EndNote Library File"
        file_class = "Miscellaneous"
        extensions = "ENL"

    strings:
        $header = { 40 40 40 20 00 00 40 40 40 40 }

    condition:
        $header at 32
}

rule Analog_Box_ABox_circuit_files
{
    meta:
        description = "Analog Box (ABox) circuit files"
        file_class = "Audio"
        extensions = "ABOX2"

    strings:
        $header = { 41 42 6F 78 }

    condition:
        $header at 0
}

rule Generic_AutoCAD_drawing
{
    meta:
        description = "Generic AutoCAD drawing"
        file_class = "Presentation"
        extensions = "DWG"

    strings:
        $header = { 41 43 31 30 }

    condition:
        $header at 0
}

rule Steganos_virtual_secure_drive
{
    meta:
        description = "Steganos virtual secure drive"
        file_class = "Miscellaneous"
        extensions = "SLE"

    strings:
        $header = { 41 43 76 }

    condition:
        $header at 0
}

rule AOL_parameter_info_files
{
    meta:
        description = "AOL parameter-info files"
        file_class = "Network"
        extensions = "(none)"

    strings:
        $header = { 41 43 53 44 }

    condition:
        $header at 0
}

rule Harvard_Graphics_symbol_graphic
{
    meta:
        description = "Harvard Graphics symbol graphic"
        file_class = "Presentation"
        extensions = "SYW"

    strings:
        $header = { 41 4D 59 4F }

    condition:
        $header at 0
}

rule AOL_config_files
{
    meta:
        description = "AOL config files"
        file_class = "Network"
        extensions = "ABI|ABY|BAG|IDX|IND|PFC"

    strings:
        $header = { 41 4F 4C }

    condition:
        $header at 0
}

rule AOL_and_AIM_buddy_list
{
    meta:
        description = "AOL and AIM buddy list"
        file_class = "Network"
        extensions = "BAG"

    strings:
        $header = { 41 4F 4C 20 46 65 65 64 }

    condition:
        $header at 0
}

rule AOL_address_book
{
    meta:
        description = "AOL address book"
        file_class = "Network"
        extensions = "ABY"

    strings:
        $header = { 41 4F 4C 44 42 }

    condition:
        $header at 0
}

rule AOL_user_configuration
{
    meta:
        description = "AOL user configuration"
        file_class = "Network"
        extensions = "IDX"

    strings:
        $header = { 41 4F 4C 44 42 }

    condition:
        $header at 0
}

rule AOL_client_preferences_settings_file
{
    meta:
        description = "AOL client preferences-settings file"
        file_class = "Network"
        extensions = "IND"

    strings:
        $header = { 41 4F 4C 49 44 58 }

    condition:
        $header at 0
}

rule AOL_address_book_index
{
    meta:
        description = "AOL address book index"
        file_class = "Network"
        extensions = "ABI"

    strings:
        $header = { 41 4F 4C 49 4E 44 45 58 }

    condition:
        $header at 0
}

rule AOL_personal_file_cabinet
{
    meta:
        description = "AOL personal file cabinet"
        file_class = "Network"
        extensions = "ORG|PFC"

    strings:
        $header = { 41 4F 4C 56 4D 31 30 30 }

    condition:
        $header at 0
}

rule AVG6_Integrity_database
{
    meta:
        description = "AVG6 Integrity database"
        file_class = "Database"
        extensions = "DAT"

    strings:
        $header = { 41 56 47 36 5F 49 6E 74 }

    condition:
        $header at 0
}

rule RIFF_Windows_Audio
{
    meta:
        description = "RIFF Windows Audio"
        file_class = "Multimedia"
        extensions = "AVI"

    strings:
        $header = { 41 56 49 20 4C 49 53 54 }

    condition:
        $header at 8
}

rule FreeArc_compressed_file
{
    meta:
        description = "FreeArc compressed file"
        file_class = "Compressed archive"
        extensions = "ARC"

    strings:
        $header = { 41 72 43 01 }

    condition:
        $header at 0
}

rule NTFS_MFT_BAAD_
{
    meta:
        description = "NTFS MFT (BAAD)"
        file_class = "Windows"
        extensions = "(none)"

    strings:
        $header = { 42 41 41 44 }

    condition:
        $header at 0
}

rule Google_Chrome_dictionary_file
{
    meta:
        description = "Google Chrome dictionary file"
        file_class = "System"
        extensions = "BDIC"

    strings:
        $header = { 42 44 69 63 }

    condition:
        $header at 0
}

rule vCard
{
    meta:
        description = "vCard"
        file_class = "Miscellaneous"
        extensions = "VCF"

    strings:
        $header = { 42 45 47 49 4E 3A 56 43 }

    condition:
        $header at 0
}

rule Speedtouch_router_firmware
{
    meta:
        description = "Speedtouch router firmware"
        file_class = "Network"
        extensions = "BIN|BLI|RBI"

    strings:
        $header = { 42 4C 49 32 32 33 }

    condition:
        $header at 0
}

rule Bitmap_image
{
    meta:
        description = "Bitmap image"
        file_class = "Picture"
        extensions = "BMP|DIB"

    strings:
        $header = { 42 4D }

    condition:
        $header at 0
}

rule Palmpilot_resource_file
{
    meta:
        description = "Palmpilot resource file"
        file_class = "Mobile"
        extensions = "PRC"

    strings:
        $header = { 42 4F 4F 4B 4D 4F 42 49 }

    condition:
        $header at 0
}

rule Better_Portable_Graphics
{
    meta:
        description = "Better Portable Graphics"
        file_class = "Multimedia"
        extensions = "BPG"

    strings:
        $header = { 42 50 47 FB }

    condition:
        $header at 0
}

rule bzip2_compressed_archive
{
    meta:
        description = "bzip2 compressed archive"
        file_class = "Compressed archive"
        extensions = "BZ2|TAR|BZ2|TBZ2|TB2"

    strings:
        $header = { 42 5A 68 }

    condition:
        $header at 0
}

rule Mac_Disk_image_BZ2_compressed_
{
    meta:
        description = "Mac Disk image (BZ2 compressed)"
        file_class = "Compressed archive"
        extensions = "DMG"

    strings:
        $header = { 42 5A 68 }

    condition:
        $header at 0
}

rule Puffer_ASCII_encrypted_archive
{
    meta:
        description = "Puffer ASCII encrypted archive"
        file_class = "Encryption"
        extensions = "APUF"

    strings:
        $header = { 42 65 67 69 6E 20 50 75 66 66 65 72 }

    condition:
        $header at 0
}

rule Blink_compressed_archive
{
    meta:
        description = "Blink compressed archive"
        file_class = "Compressed archive"
        extensions = "BLI"

    strings:
        $header = { 42 6C 69 6E 6B }

    condition:
        $header at 0
}

rule RagTime_document
{
    meta:
        description = "RagTime document"
        file_class = "Word processing suite"
        extensions = "RTD"

    strings:
        $header = { 43 23 2B 44 A4 43 4D A5 }

    condition:
        $header at 0
}

rule EA_Interchange_Format_File_IFF_3
{
    meta:
        description = "EA Interchange Format File (IFF)_3"
        file_class = "Multimedia"
        extensions = "IFF"

    strings:
        $header = { 43 41 54 20 }

    condition:
        $header at 0
}

rule WordPerfect_dictionary
{
    meta:
        description = "WordPerfect dictionary"
        file_class = "Word processing suite"
        extensions = "CBD"

    strings:
        $header = { 43 42 46 49 4C 45 }

    condition:
        $header at 0
}

rule ISO_9660_CD_Disc_Image
{
    meta:
        description = "ISO-9660 CD Disc Image"
        file_class = "Compressed archive"
        extensions = "ISO"

    strings:
        $header = { 43 44 30 30 31 }

    condition:
        $header at 0
}

rule RIFF_CD_audio
{
    meta:
        description = "RIFF CD audio"
        file_class = "Multimedia"
        extensions = "CDA"

    strings:
        $header = { 43 44 44 41 66 6D 74 20 }

    condition:
        $header at 8
}

rule Compressed_ISO_CD_image
{
    meta:
        description = "Compressed ISO CD image"
        file_class = "Compressed archive"
        extensions = "CSO"

    strings:
        $header = { 43 49 53 4F }

    condition:
        $header at 0
}

rule Windows_7_thumbnail
{
    meta:
        description = "Windows 7 thumbnail"
        file_class = "Windows"
        extensions = "DB"

    strings:
        $header = { 43 4D 4D 4D 15 00 00 00 }

    condition:
        $header at 0
}

rule Corel_Binary_metafile
{
    meta:
        description = "Corel Binary metafile"
        file_class = "Miscellaneous"
        extensions = "CLB"

    strings:
        $header = { 43 4D 58 31 }

    condition:
        $header at 0
}

rule COM_Catalog
{
    meta:
        description = "COM+ Catalog"
        file_class = "Miscellaneous"
        extensions = "CLB"

    strings:
        $header = { 43 4F 4D 2B }

    condition:
        $header at 0
}

rule VMware_3_Virtual_Disk
{
    meta:
        description = "VMware 3 Virtual Disk"
        file_class = "Miscellaneous"
        extensions = "VMDK"

    strings:
        $header = { 43 4F 57 44 }

    condition:
        $header at 0
}

rule Corel_Photopaint_file_1
{
    meta:
        description = "Corel Photopaint file_1"
        file_class = "Presentation"
        extensions = "CPT"

    strings:
        $header = { 43 50 54 37 46 49 4C 45 }

    condition:
        $header at 0
}

rule Corel_Photopaint_file_2
{
    meta:
        description = "Corel Photopaint file_2"
        file_class = "Presentation"
        extensions = "CPT"

    strings:
        $header = { 43 50 54 46 49 4C 45 }

    condition:
        $header at 0
}

rule Win9x_registry_hive
{
    meta:
        description = "Win9x registry hive"
        file_class = "Windows"
        extensions = "DAT"

    strings:
        $header = { 43 52 45 47 }

    condition:
        $header at 0
}

rule Crush_compressed_archive
{
    meta:
        description = "Crush compressed archive"
        file_class = "Compressed archive"
        extensions = "CRU"

    strings:
        $header = { 43 52 55 53 48 20 76 }

    condition:
        $header at 0
}

rule Shockwave_Flash_file
{
    meta:
        description = "Shockwave Flash file"
        file_class = "Multimedia"
        extensions = "SWF"

    strings:
        $header = { 43 57 53 }

    condition:
        $header at 0
}

rule Calculux_Indoor_lighting_project_file
{
    meta:
        description = "Calculux Indoor lighting project file"
        file_class = "Application"
        extensions = "CIN"

    strings:
        $header = { 43 61 6C 63 75 6C 75 78 20 49 6E 64 6F 6F 72 20 }

    condition:
        $header at 0
}

rule WhereIsIt_Catalog
{
    meta:
        description = "WhereIsIt Catalog"
        file_class = "Miscellaneous"
        extensions = "CTF"

    strings:
        $header = { 43 61 74 61 6C 6F 67 20 }

    condition:
        $header at 0
}

rule IE_History_file
{
    meta:
        description = "IE History file"
        file_class = "Network"
        extensions = "DAT"

    strings:
        $header = { 43 6C 69 65 6E 74 20 55 }

    condition:
        $header at 0
}

rule Google_Chrome_Extension
{
    meta:
        description = "Google Chrome Extension"
        file_class = "Programming"
        extensions = "CRX"

    strings:
        $header = { 43 72 32 34 }

    condition:
        $header at 0
}

rule Google_Chromium_patch_update
{
    meta:
        description = "Google Chromium patch update"
        file_class = "System"
        extensions = "CRX"

    strings:
        $header = { 43 72 4F 44 }

    condition:
        $header at 0
}

rule Creative_Voice
{
    meta:
        description = "Creative Voice"
        file_class = "Multimedia"
        extensions = "VOC"

    strings:
        $header = { 43 72 65 61 74 69 76 65 20 56 6F 69 63 65 20 46 }

    condition:
        $header at 0
}

rule PowerISO_Direct_Access_Archive_image
{
    meta:
        description = "PowerISO Direct-Access-Archive image"
        file_class = "Compressed archive"
        extensions = "DAA"

    strings:
        $header = { 44 41 41 00 00 00 00 00 }

    condition:
        $header at 0
}

rule DAX_Compressed_CD_image
{
    meta:
        description = "DAX Compressed CD image"
        file_class = "Miscellaneous"
        extensions = "DAX"

    strings:
        $header = { 44 41 58 00 }

    condition:
        $header at 0
}

rule Palm_Zire_photo_database
{
    meta:
        description = "Palm Zire photo database"
        file_class = "Mobile"
        extensions = "DB"

    strings:
        $header = { 44 42 46 48 }

    condition:
        $header at 0
}

rule Amiga_DiskMasher_compressed_archive
{
    meta:
        description = "Amiga DiskMasher compressed archive"
        file_class = "Compressed archive"
        extensions = "DMS"

    strings:
        $header = { 44 4D 53 21 }

    condition:
        $header at 0
}

rule Amiga_disk_file
{
    meta:
        description = "Amiga disk file"
        file_class = "Miscellaneous"
        extensions = "ADF"

    strings:
        $header = { 44 4F 53 }

    condition:
        $header at 0
}

rule DST_Compression
{
    meta:
        description = "DST Compression"
        file_class = "Compressed archive"
        extensions = "DST"

    strings:
        $header = { 44 53 54 62 }

    condition:
        $header at 0
}

rule DVR_Studio_stream_file
{
    meta:
        description = "DVR-Studio stream file"
        file_class = "Multimedia"
        extensions = "DVR"

    strings:
        $header = { 44 56 44 }

    condition:
        $header at 0
}

rule DVD_info_file
{
    meta:
        description = "DVD info file"
        file_class = "Multimedia"
        extensions = "IFO"

    strings:
        $header = { 44 56 44 }

    condition:
        $header at 0
}

rule Elite_Plus_Commander_game_file
{
    meta:
        description = "Elite Plus Commander game file"
        file_class = "Miscellaneous"
        extensions = "CDR"

    strings:
        $header = { 45 4C 49 54 45 20 43 6F }

    condition:
        $header at 0
}

rule VideoVCD_VCDImager_file
{
    meta:
        description = "VideoVCD-VCDImager file"
        file_class = "Miscellaneous"
        extensions = "VCD"

    strings:
        $header = { 45 4E 54 52 59 56 43 44 }

    condition:
        $header at 0
}

rule Apple_ISO_9660_HFS_hybrid_CD_image
{
    meta:
        description = "Apple ISO 9660-HFS hybrid CD image"
        file_class = "Compressed archive"
        extensions = "ISO"

    strings:
        $header = { 45 52 02 00 00 }

    condition:
        $header at 0
}

rule EasyRecovery_Saved_State_file
{
    meta:
        description = "EasyRecovery Saved State file"
        file_class = "Miscellaneous"
        extensions = "DAT"

    strings:
        $header = { 45 52 46 53 53 41 56 45 }

    condition:
        $header at 0
}

rule DSD_Storage_Facility_audio_file
{
    meta:
        description = "DSD Storage Facility audio file"
        file_class = "Multimedia"
        extensions = "DSF"

    strings:
        $header = { 44 53 44 20 }

    condition:
        $header at 0
}

rule MS_Document_Imaging_file
{
    meta:
        description = "MS Document Imaging file"
        file_class = "Word processing suite"
        extensions = "MDI"

    strings:
        $header = { 45 50 }

    condition:
        $header at 0
}

rule Expert_Witness_Compression_Format
{
    meta:
        description = "Expert Witness Compression Format"
        file_class = "Miscellaneous"
        extensions = "E01"

    strings:
        $header = { 45 56 46 09 0D 0A FF 00 }

    condition:
        $header at 0
}

rule EnCase_Evidence_File_Format_V2
{
    meta:
        description = "EnCase Evidence File Format V2"
        file_class = "Miscellaneous"
        extensions = "Ex01"

    strings:
        $header = { 45 56 46 32 0D 0A 81 }

    condition:
        $header at 0
}

rule Windows_Vista_event_log
{
    meta:
        description = "Windows Vista event log"
        file_class = "Windows"
        extensions = "EVTX"

    strings:
        $header = { 45 6C 66 46 69 6C 65 00 }

    condition:
        $header at 0
}

rule QuickBooks_backup
{
    meta:
        description = "QuickBooks backup"
        file_class = "Finance"
        extensions = "QBB"

    strings:
        $header = { 45 86 00 00 06 00 }

    condition:
        $header at 0
}

rule MS_Fax_Cover_Sheet
{
    meta:
        description = "MS Fax Cover Sheet"
        file_class = "Miscellaneous"
        extensions = "CPE"

    strings:
        $header = { 46 41 58 43 4F 56 45 52 }

    condition:
        $header at 0
}

rule Fiasco_database_definition_file
{
    meta:
        description = "Fiasco database definition file"
        file_class = "Database"
        extensions = "FDB"

    strings:
        $header = { 46 44 42 48 00 }

    condition:
        $header at 0
}

rule NTFS_MFT_FILE_
{
    meta:
        description = "NTFS MFT (FILE)"
        file_class = "Windows"
        extensions = "(none)"

    strings:
        $header = { 46 49 4C 45 }

    condition:
        $header at 0
}

rule Flash_video_file
{
    meta:
        description = "Flash video file"
        file_class = "Multimedia"
        extensions = "FLV"

    strings:
        $header = { 46 4C 56 }

    condition:
        $header at 0
}

rule IFF_ANIM_file
{
    meta:
        description = "IFF ANIM file"
        file_class = "Multimedia"
        extensions = "ANM"

    strings:
        $header = { 46 4F 52 4D }

    condition:
        $header at 0
}

rule EA_Interchange_Format_File_IFF_1
{
    meta:
        description = "EA Interchange Format File (IFF)_1"
        file_class = "Multimedia"
        extensions = "IFF"

    strings:
        $header = { 46 4F 52 4D }

    condition:
        $header at 0
}

rule Audio_Interchange_File
{
    meta:
        description = "Audio Interchange File"
        file_class = "Multimedia"
        extensions = "AIFF"

    strings:
        $header = { 46 4F 52 4D 00 }

    condition:
        $header at 0
}

rule DAKX_Compressed_Audio
{
    meta:
        description = "DAKX Compressed Audio"
        file_class = "Multimedia"
        extensions = "DAX"

    strings:
        $header = { 46 4F 52 4D 00 }

    condition:
        $header at 0
}

rule Shockwave_Flash_player
{
    meta:
        description = "Shockwave Flash player"
        file_class = "Multimedia"
        extensions = "SWF"

    strings:
        $header = { 46 57 53 }

    condition:
        $header at 0
}

rule Generic_e_mail_2
{
    meta:
        description = "Generic e-mail_2"
        file_class = "Email"
        extensions = "EML"

    strings:
        $header = { 46 72 6F 6D }

    condition:
        $header at 0
}

rule GIF_file
{
    meta:
        description = "GIF file"
        file_class = "Picture"
        extensions = "GIF"

    strings:
        $header = { 47 49 46 38 }
        $trailer = { 00 3B }

    condition:
        $header at 0 and $trailer
}

rule GIMP_pattern_file
{
    meta:
        description = "GIMP pattern file"
        file_class = "Picture"
        extensions = "PAT"

    strings:
        $header = { 47 50 41 54 }

    condition:
        $header at 0
}

rule General_Regularly_distributed_Information_GRIdded_Binary
{
    meta:
        description = "General Regularly-distributed Information (GRIdded) Binary"
        file_class = "Miscellaneous"
        extensions = "GRB"

    strings:
        $header = { 47 52 49 42 }

    condition:
        $header at 0
}

rule Show_Partner_graphics_file
{
    meta:
        description = "Show Partner graphics file"
        file_class = "Picture"
        extensions = "GX2"

    strings:
        $header = { 47 58 32 }

    condition:
        $header at 0
}

rule Genetec_video_archive
{
    meta:
        description = "Genetec video archive"
        file_class = "Multimedia"
        extensions = "G64"

    strings:
        $header = { 47 65 6E 65 74 65 63 20 4F 6D 6E 69 63 61 73 74 }

    condition:
        $header at 0
}

rule SAP_PowerBuilder_integrated_development_environment_file
{
    meta:
        description = "SAP PowerBuilder integrated development environment file"
        file_class = "Programming"
        extensions = "PBD"

    strings:
        $header = { 48 44 52 2A 50 6F 77 65 72 42 75 69 6C 64 65 72 }

    condition:
        $header at 0
}

rule SAS_Transport_dataset
{
    meta:
        description = "SAS Transport dataset"
        file_class = "Statistics"
        extensions = "XPT"

    strings:
        $header = { 48 45 41 44 45 52 20 52 45 43 4F 52 44 2A 2A 2A }

    condition:
        $header at 0
}

rule Harvard_Graphics_presentation_file
{
    meta:
        description = "Harvard Graphics presentation file"
        file_class = "Presentation"
        extensions = "SH3"

    strings:
        $header = { 48 48 47 42 31 }

    condition:
        $header at 0
}

rule TIFF_file_1
{
    meta:
        description = "TIFF file_1"
        file_class = "Picture"
        extensions = "TIF|TIFF"

    strings:
        $header = { 49 20 49 }

    condition:
        $header at 0
}

rule MP3_audio_file
{
    meta:
        description = "MP3 audio file"
        file_class = "Multimedia"
        extensions = "MP3"

    strings:
        $header = { 49 44 33 }

    condition:
        $header at 0
}

rule Sprint_Music_Store_audio
{
    meta:
        description = "Sprint Music Store audio"
        file_class = "Multimedia"
        extensions = "KOZ"

    strings:
        $header = { 49 44 33 03 00 00 00 }

    condition:
        $header at 0
}

rule Canon_RAW_file
{
    meta:
        description = "Canon RAW file"
        file_class = "Picture"
        extensions = "CRW"

    strings:
        $header = { 49 49 1A 00 00 00 48 45 }

    condition:
        $header at 0
}

rule TIFF_file_2
{
    meta:
        description = "TIFF file_2"
        file_class = "Picture"
        extensions = "TIF|TIFF"

    strings:
        $header = { 49 49 2A 00 }

    condition:
        $header at 0
}

rule Windows_7_thumbnail_2
{
    meta:
        description = "Windows 7 thumbnail_2"
        file_class = "Windows"
        extensions = "DB"

    strings:
        $header = { 49 4D 4D 4D 15 00 00 00 }

    condition:
        $header at 0
}

rule Install_Shield_compressed_file
{
    meta:
        description = "Install Shield compressed file"
        file_class = "Compressed archive"
        extensions = "CAB|HDR"

    strings:
        $header = { 49 53 63 28 }

    condition:
        $header at 0
}

rule MS_Reader_eBook
{
    meta:
        description = "MS Reader eBook"
        file_class = "Miscellaneous"
        extensions = "LIT"

    strings:
        $header = { 49 54 4F 4C 49 54 4C 53 }

    condition:
        $header at 0
}

rule MS_Compiled_HTML_Help_File
{
    meta:
        description = "MS Compiled HTML Help File"
        file_class = "Windows"
        extensions = "CHI|CHM"

    strings:
        $header = { 49 54 53 46 }

    condition:
        $header at 0
}

rule Inno_Setup_Uninstall_Log
{
    meta:
        description = "Inno Setup Uninstall Log"
        file_class = "Miscellaneous"
        extensions = "DAT"

    strings:
        $header = { 49 6E 6E 6F 20 53 65 74 }

    condition:
        $header at 0
}

rule Inter_ctive_Pager_Backup_BlackBerry_file
{
    meta:
        description = "Inter@ctive Pager Backup (BlackBerry file"
        file_class = "Mobile"
        extensions = "IPD"

    strings:
        $header = { 49 6E 74 65 72 40 63 74 69 76 65 20 50 61 67 65 }

    condition:
        $header at 0
}

rule JARCS_compressed_archive
{
    meta:
        description = "JARCS compressed archive"
        file_class = "Compressed archive"
        extensions = "JAR"

    strings:
        $header = { 4A 41 52 43 53 00 }

    condition:
        $header at 0
}

rule AOL_ART_file_1
{
    meta:
        description = "AOL ART file_1"
        file_class = "Picture"
        extensions = "JG"

    strings:
        $header = { 4A 47 03 0E }
        $trailer = { D0 CB 00 00 }

    condition:
        $header at 0 and $trailer
}

rule AOL_ART_file_2
{
    meta:
        description = "AOL ART file_2"
        file_class = "Picture"
        extensions = "JG"

    strings:
        $header = { 4A 47 04 0E }
        $trailer = { CF C7 CB }

    condition:
        $header at 0 and $trailer
}

rule VMware_4_Virtual_Disk
{
    meta:
        description = "VMware 4 Virtual Disk"
        file_class = "Miscellaneous"
        extensions = "VMDK"

    strings:
        $header = { 4B 44 4D }

    condition:
        $header at 0
}

rule KGB_archive
{
    meta:
        description = "KGB archive"
        file_class = "Compressed archive"
        extensions = "KGB"

    strings:
        $header = { 4B 47 42 5F 61 72 63 68 }

    condition:
        $header at 0
}

rule Win9x_printer_spool_file
{
    meta:
        description = "Win9x printer spool file"
        file_class = "Windows"
        extensions = "SHD"

    strings:
        $header = { 4B 49 00 00 }

    condition:
        $header at 0
}

rule KWAJ_compressed_file
{
    meta:
        description = "KWAJ (compressed) file"
        file_class = "Compressed archive"
        extensions = "(none)"

    strings:
        $header = { 4B 57 41 4A 88 F0 27 D1 }

    condition:
        $header at 0
}

rule Windows_shortcut_file
{
    meta:
        description = "Windows shortcut file"
        file_class = "Windows"
        extensions = "LNK"

    strings:
        $header = { 4C 00 00 00 01 14 02 00 }

    condition:
        $header at 0
}

rule MS_COFF_relocatable_object_code
{
    meta:
        description = "MS COFF relocatable object code"
        file_class = "Windows"
        extensions = "OBJ"

    strings:
        $header = { 4C 01 }

    condition:
        $header at 0
}

rule Tajima_emboridery
{
    meta:
        description = "Tajima emboridery"
        file_class = "Miscellaneous"
        extensions = "DST"

    strings:
        $header = { 4C 41 3A }

    condition:
        $header at 0
}

rule Windows_help_file_3
{
    meta:
        description = "Windows help file_3"
        file_class = "Windows"
        extensions = "GID|HLP"

    strings:
        $header = { 4C 4E 02 00 }

    condition:
        $header at 0
}

rule EA_Interchange_Format_File_IFF_2
{
    meta:
        description = "EA Interchange Format File (IFF)_2"
        file_class = "Multimedia"
        extensions = "IFF"

    strings:
        $header = { 4C 49 53 54 }

    condition:
        $header at 0
}

rule DeluxePaint_Animation
{
    meta:
        description = "DeluxePaint Animation"
        file_class = "Multimedia"
        extensions = "ANM"

    strings:
        $header = { 4C 50 46 20 00 01 }

    condition:
        $header at 0
}

rule Logical_File_Evidence_Format
{
    meta:
        description = "Logical File Evidence Format"
        file_class = "Miscellaneous"
        extensions = "E01"

    strings:
        $header = { 4C 56 46 09 0D 0A FF 00 }

    condition:
        $header at 0
}

rule Merriam_Webster_Pocket_Dictionary
{
    meta:
        description = "Merriam-Webster Pocket Dictionary"
        file_class = "Miscellaneous"
        extensions = "PDB"

    strings:
        $header = { 4D 2D 57 20 50 6F 63 6B }

    condition:
        $header at 0
}

rule Mozilla_archive
{
    meta:
        description = "Mozilla archive"
        file_class = "Network"
        extensions = "MAR"

    strings:
        $header = { 4D 41 52 31 00 }

    condition:
        $header at 0
}

rule Microsoft_MSN_MARC_archive
{
    meta:
        description = "Microsoft-MSN MARC archive"
        file_class = "Compressed archive"
        extensions = "MAR"

    strings:
        $header = { 4D 41 52 43 }

    condition:
        $header at 0
}

rule MATLAB_v5_workspace
{
    meta:
        description = "MATLAB v5 workspace"
        file_class = "Programming"
        extensions = "MAT"

    strings:
        $header = { 4D 41 54 4C 41 42 20 35 2E 30 20 4D 41 54 2D 66 69 6C 65 }

    condition:
        $header at 0
}

rule MAr_compressed_archive
{
    meta:
        description = "MAr compressed archive"
        file_class = "Compressed archive"
        extensions = "MAR"

    strings:
        $header = { 4D 41 72 30 00 }

    condition:
        $header at 0
}

rule TargetExpress_target_file
{
    meta:
        description = "TargetExpress target file"
        file_class = "Miscellaneous"
        extensions = "MTE"

    strings:
        $header = { 4D 43 57 20 54 65 63 68 6E 6F 67 6F 6C 69 65 73 }

    condition:
        $header at 0
}

rule Windows_dump_file
{
    meta:
        description = "Windows dump file"
        file_class = "Windows"
        extensions = "DMP|HDMP"

    strings:
        $header = { 4D 44 4D 50 93 A7 }

    condition:
        $header at 0
}

rule Milestones_project_management_file
{
    meta:
        description = "Milestones project management file"
        file_class = "Miscellaneous"
        extensions = "MLS"

    strings:
        $header = { 4D 49 4C 45 53 }

    condition:
        $header at 0
}

rule Skype_localization_data_file
{
    meta:
        description = "Skype localization data file"
        file_class = "Network"
        extensions = "MLS"

    strings:
        $header = { 4D 4C 53 57 }

    condition:
        $header at 0
}

rule TIFF_file_3
{
    meta:
        description = "TIFF file_3"
        file_class = "Picture"
        extensions = "TIF|TIFF"

    strings:
        $header = { 4D 4D 00 2A }

    condition:
        $header at 0
}

rule TIFF_file_4
{
    meta:
        description = "TIFF file_4"
        file_class = "Picture"
        extensions = "TIF|TIFF"

    strings:
        $header = { 4D 4D 00 2B }

    condition:
        $header at 0
}

rule Yamaha_Synthetic_music_Mobile_Application_Format
{
    meta:
        description = "Yamaha Synthetic music Mobile Application Format"
        file_class = "Multimedia"
        extensions = "MMF"

    strings:
        $header = { 4D 4D 4D 44 00 00 }

    condition:
        $header at 0
}

rule VMware_BIOS_state_file
{
    meta:
        description = "VMware BIOS state file"
        file_class = "Miscellaneous"
        extensions = "NVRAM"

    strings:
        $header = { 4D 52 56 4E }

    condition:
        $header at 0
}

rule Microsoft_cabinet_file
{
    meta:
        description = "Microsoft cabinet file"
        file_class = "Windows"
        extensions = "CAB"

    strings:
        $header = { 4D 53 43 46 }

    condition:
        $header at 0
}

rule OneNote_Package
{
    meta:
        description = "OneNote Package"
        file_class = "Windows"
        extensions = "ONEPKG"

    strings:
        $header = { 4D 53 43 46 }

    condition:
        $header at 0
}

rule Powerpoint_Packaged_Presentation
{
    meta:
        description = "Powerpoint Packaged Presentation"
        file_class = "Presentation"
        extensions = "PPZ"

    strings:
        $header = { 4D 53 43 46 }

    condition:
        $header at 0
}

rule MS_Access_Snapshot_Viewer_file
{
    meta:
        description = "MS Access Snapshot Viewer file"
        file_class = "Database"
        extensions = "SNP"

    strings:
        $header = { 4D 53 43 46 }

    condition:
        $header at 0
}

rule OLE_SPSS_Visual_C_library_file
{
    meta:
        description = "OLE-SPSS-Visual C++ library file"
        file_class = "Programming"
        extensions = "TLB"

    strings:
        $header = { 4D 53 46 54 02 00 01 00 }

    condition:
        $header at 0
}

rule Health_Level_7_data_pipe_delimited_file
{
    meta:
        description = "Health Level-7 data (pipe delimited) file"
        file_class = "Programming"
        extensions = "HL7"

    strings:
        $header = { 0D 53 48 7C 5E 7E 5C 26 7C }

    condition:
        $header at 0
}

rule Microsoft_Windows_Imaging_Format
{
    meta:
        description = "Microsoft Windows Imaging Format"
        file_class = "Picture"
        extensions = "WIM"

    strings:
        $header = { 4D 53 57 49 4D }

    condition:
        $header at 0
}

rule Sony_Compressed_Voice_File
{
    meta:
        description = "Sony Compressed Voice File"
        file_class = "Multimedia"
        extensions = "CDR|DVF|MSV"

    strings:
        $header = { 4D 53 5F 56 4F 49 43 45 }

    condition:
        $header at 0
}

rule MIDI_sound_file
{
    meta:
        description = "MIDI sound file"
        file_class = "Multimedia"
        extensions = "MID|MIDI"

    strings:
        $header = { 4D 54 68 64 }

    condition:
        $header at 0
}

rule Yamaha_Piano
{
    meta:
        description = "Yamaha Piano"
        file_class = "Multimedia"
        extensions = "PCS"

    strings:
        $header = { 4D 54 68 64 }

    condition:
        $header at 0
}

rule CD_Stomper_Pro_label_file
{
    meta:
        description = "CD Stomper Pro label file"
        file_class = "Miscellaneous"
        extensions = "DSN"

    strings:
        $header = { 4D 56 }

    condition:
        $header at 0
}

rule Milestones_project_management_file_1
{
    meta:
        description = "Milestones project management file_1"
        file_class = "Miscellaneous"
        extensions = "MLS"

    strings:
        $header = { 4D 56 32 31 34 }

    condition:
        $header at 0
}

rule Milestones_project_management_file_2
{
    meta:
        description = "Milestones project management file_2"
        file_class = "Miscellaneous"
        extensions = "MLS"

    strings:
        $header = { 4D 56 32 43 }

    condition:
        $header at 0
}

rule Windows_DOS_executable_file
{
    meta:
        description = "Windows-DOS executable file"
        file_class = "Windows"
        extensions = "COM|DLL|DRV|EXE|PIF|QTS|QTX|SYS"

    strings:
        $header = { 4D 5A }

    condition:
        $header at 0
}

rule MS_audio_compression_manager_driver
{
    meta:
        description = "MS audio compression manager driver"
        file_class = "Multimedia"
        extensions = "ACM"

    strings:
        $header = { 4D 5A }

    condition:
        $header at 0
}

rule Library_cache_file
{
    meta:
        description = "Library cache file"
        file_class = "Windows"
        extensions = "AX"

    strings:
        $header = { 4D 5A }

    condition:
        $header at 0
}

rule Control_panel_application
{
    meta:
        description = "Control panel application"
        file_class = "Windows"
        extensions = "CPL"

    strings:
        $header = { 4D 5A }

    condition:
        $header at 0
}

rule Font_file
{
    meta:
        description = "Font file"
        file_class = "Windows"
        extensions = "FON"

    strings:
        $header = { 4D 5A }

    condition:
        $header at 0
}

rule ActiveX_OLE_Custom_Control
{
    meta:
        description = "ActiveX-OLE Custom Control"
        file_class = "Windows"
        extensions = "OCX"

    strings:
        $header = { 4D 5A }

    condition:
        $header at 0
}

rule OLE_object_library
{
    meta:
        description = "OLE object library"
        file_class = "Windows"
        extensions = "OLB"

    strings:
        $header = { 4D 5A }

    condition:
        $header at 0
}

rule Screen_saver
{
    meta:
        description = "Screen saver"
        file_class = "Windows"
        extensions = "SCR"

    strings:
        $header = { 4D 5A }

    condition:
        $header at 0
}

rule VisualBASIC_application
{
    meta:
        description = "VisualBASIC application"
        file_class = "Programming"
        extensions = "VBX"

    strings:
        $header = { 4D 5A }

    condition:
        $header at 0
}

rule Windows_virtual_device_drivers
{
    meta:
        description = "Windows virtual device drivers"
        file_class = "Windows"
        extensions = "VXD|386"

    strings:
        $header = { 4D 5A }

    condition:
        $header at 0
}

rule Acrobat_plug_in
{
    meta:
        description = "Acrobat plug-in"
        file_class = "Word processing suite"
        extensions = "API"

    strings:
        $header = { 4D 5A 90 00 03 00 00 00 }

    condition:
        $header at 0
}

rule DirectShow_filter
{
    meta:
        description = "DirectShow filter"
        file_class = "Miscellaneous"
        extensions = "AX"

    strings:
        $header = { 4D 5A 90 00 03 00 00 00 }

    condition:
        $header at 0
}

rule Audition_graphic_filter
{
    meta:
        description = "Audition graphic filter"
        file_class = "Miscellaneous"
        extensions = "FLT"

    strings:
        $header = { 4D 5A 90 00 03 00 00 00 }

    condition:
        $header at 0
}

rule ZoneAlam_data_file
{
    meta:
        description = "ZoneAlam data file"
        file_class = "Miscellaneous"
        extensions = "ZAP"

    strings:
        $header = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF }

    condition:
        $header at 0
}

rule MS_C_debugging_symbols_file
{
    meta:
        description = "MS C++ debugging symbols file"
        file_class = "Programming"
        extensions = "PDB"

    strings:
        $header = { 4D 69 63 72 6F 73 6F 66 74 20 43 2F 43 2B 2B 20 }

    condition:
        $header at 0
}

rule Visual_Studio_NET_file
{
    meta:
        description = "Visual Studio .NET file"
        file_class = "Programming"
        extensions = "SLN"

    strings:
        $header = { 4D 69 63 72 6F 73 6F 66 74 20 56 69 73 75 61 6C }

    condition:
        $header at 0
}

rule Windows_Media_Player_playlist
{
    meta:
        description = "Windows Media Player playlist"
        file_class = "Multimedia"
        extensions = "WPL"

    strings:
        $header = { 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 4D 65 64 69 61 20 50 6C 61 79 65 72 20 2D 2D 20 }

    condition:
        $header at 84
}

rule VMapSource_GPS_Waypoint_Database
{
    meta:
        description = "VMapSource GPS Waypoint Database"
        file_class = "Navigation"
        extensions = "GDB"

    strings:
        $header = { 4D 73 52 63 66 }

    condition:
        $header at 0
}

rule TomTom_traffic_data
{
    meta:
        description = "TomTom traffic data"
        file_class = "Navigation"
        extensions = "DAT"

    strings:
        $header = { 4E 41 56 54 52 41 46 46 }

    condition:
        $header at 0
}

rule MS_Windows_journal
{
    meta:
        description = "MS Windows journal"
        file_class = "Windows"
        extensions = "JNT|JTP"

    strings:
        $header = { 4E 42 2A 00 }

    condition:
        $header at 0
}

rule NES_Sound_file
{
    meta:
        description = "NES Sound file"
        file_class = "Multimedia"
        extensions = "NSF"

    strings:
        $header = { 4E 45 53 4D 1A 01 }

    condition:
        $header at 0
}

rule National_Imagery_Transmission_Format_file
{
    meta:
        description = "National Imagery Transmission Format file"
        file_class = "Picture"
        extensions = "NTF"

    strings:
        $header = { 4E 49 54 46 30 }

    condition:
        $header at 0
}

rule Agent_newsreader_character_map
{
    meta:
        description = "Agent newsreader character map"
        file_class = "Miscellaneous"
        extensions = "COD"

    strings:
        $header = { 4E 61 6D 65 3A 20 }

    condition:
        $header at 0
}

rule _1Password_4_Cloud_Keychain
{
    meta:
        description = "1Password 4 Cloud Keychain"
        file_class = "Encryption"
        extensions = "attachment"

    strings:
        $header = { 4F 50 43 4C 44 41 54 }

    condition:
        $header at 0
}

rule Psion_Series_3_Database
{
    meta:
        description = "Psion Series 3 Database"
        file_class = "Database"
        extensions = "DBF"

    strings:
        $header = { 4F 50 4C 44 61 74 61 62 }

    condition:
        $header at 0
}

rule OpenType_font
{
    meta:
        description = "OpenType font"
        file_class = "Word processing suite"
        extensions = "OTF"

    strings:
        $header = { 4F 54 54 4F 00 }

    condition:
        $header at 0
}

rule Ogg_Vorbis_Codec_compressed_file
{
    meta:
        description = "Ogg Vorbis Codec compressed file"
        file_class = "Multimedia"
        extensions = "OGA|OGG|OGV|OGX"

    strings:
        $header = { 4F 67 67 53 00 02 00 00 }

    condition:
        $header at 0
}

rule Visio_DisplayWrite_4_text_file
{
    meta:
        description = "Visio-DisplayWrite 4 text file"
        file_class = "Presentation"
        extensions = "DW4"

    strings:
        $header = { 4F 7B }

    condition:
        $header at 0
}

rule Quicken_QuickFinder_Information_File
{
    meta:
        description = "Quicken QuickFinder Information File"
        file_class = "Finance"
        extensions = "IDX"

    strings:
        $header = { 50 00 00 00 20 00 00 00 }

    condition:
        $header at 0
}

rule Portable_Graymap_Graphic
{
    meta:
        description = "Portable Graymap Graphic"
        file_class = "Picture"
        extensions = "PGM"

    strings:
        $header = { 50 35 0A }

    condition:
        $header at 0
}

rule Quake_archive_file
{
    meta:
        description = "Quake archive file"
        file_class = "Compressed archive"
        extensions = "PAK"

    strings:
        $header = { 50 41 43 4B }

    condition:
        $header at 0
}

rule Windows_memory_dump
{
    meta:
        description = "Windows memory dump"
        file_class = "Windows"
        extensions = "DMP"

    strings:
        $header = { 50 41 47 45 44 55 }

    condition:
        $header at 0
}

rule PAX_password_protected_bitmap
{
    meta:
        description = "PAX password protected bitmap"
        file_class = "Picture"
        extensions = "PAX"

    strings:
        $header = { 50 41 58 }

    condition:
        $header at 0
}

rule PestPatrol_data_scan_strings
{
    meta:
        description = "PestPatrol data-scan strings"
        file_class = "Miscellaneous"
        extensions = "DAT"

    strings:
        $header = { 50 45 53 54 }

    condition:
        $header at 0
}

rule PGP_disk_image
{
    meta:
        description = "PGP disk image"
        file_class = "Compressed archive"
        extensions = "PGD"

    strings:
        $header = { 50 47 50 64 4D 41 49 4E }

    condition:
        $header at 0
}

rule ChromaGraph_Graphics_Card_Bitmap
{
    meta:
        description = "ChromaGraph Graphics Card Bitmap"
        file_class = "Picture"
        extensions = "IMG"

    strings:
        $header = { 50 49 43 54 00 08 }

    condition:
        $header at 0
}

rule PKZIP_archive_1
{
    meta:
        description = "PKZIP archive_1"
        file_class = "Compressed archive"
        extensions = "ZIP"

    strings:
        $header = { 50 4B 03 04 }

    condition:
        $header at 0
}

rule Android_package
{
    meta:
        description = "Android package"
        file_class = "Mobile"
        extensions = "APK"

    strings:
        $header = { 50 4B 03 04 }

    condition:
        $header at 0
}

rule MacOS_X_Dashboard_Widget
{
    meta:
        description = "MacOS X Dashboard Widget"
        file_class = "MacOS"
        extensions = "ZIP"

    strings:
        $header = { 50 4B 03 04 }

    condition:
        $header at 0
}

rule MS_Office_Open_XML_Format_Document
{
    meta:
        description = "MS Office Open XML Format Document"
        file_class = "Word processing suite"
        extensions = "DOCX|PPTX|XLSX"

    strings:
        $header = { 50 4B 03 04 }

    condition:
        $header at 0
}

rule Java_archive_1
{
    meta:
        description = "Java archive_1"
        file_class = "Programming"
        extensions = "JAR"

    strings:
        $header = { 50 4B 03 04 }

    condition:
        $header at 0
}

rule Google_Earth_session_file
{
    meta:
        description = "Google Earth session file"
        file_class = "Navigation"
        extensions = "KMZ"

    strings:
        $header = { 50 4B 03 04 }

    condition:
        $header at 0
}

rule KWord_document
{
    meta:
        description = "KWord document"
        file_class = "Word processing suite"
        extensions = "KWD"

    strings:
        $header = { 50 4B 03 04 }

    condition:
        $header at 0
}

rule OpenDocument_template
{
    meta:
        description = "OpenDocument template"
        file_class = "Word processing suite"
        extensions = "ODT|ODP|OTT"

    strings:
        $header = { 50 4B 03 04 }

    condition:
        $header at 0
}

rule Microsoft_Open_XML_paper_specification
{
    meta:
        description = "Microsoft Open XML paper specification"
        file_class = "Word processing suite"
        extensions = "OXPS"

    strings:
        $header = { 50 4B 03 04 }

    condition:
        $header at 0
}

rule OpenOffice_documents
{
    meta:
        description = "OpenOffice documents"
        file_class = "Word processing suite"
        extensions = "SXC|SXD|SXI|SXW"

    strings:
        $header = { 50 4B 03 04 }

    condition:
        $header at 0
}

rule StarOffice_spreadsheet
{
    meta:
        description = "StarOffice spreadsheet"
        file_class = "Spreadsheet"
        extensions = "SXC"

    strings:
        $header = { 50 4B 03 04 }

    condition:
        $header at 0
}

rule Windows_Media_compressed_skin_file
{
    meta:
        description = "Windows Media compressed skin file"
        file_class = "Windows"
        extensions = "WMZ"

    strings:
        $header = { 50 4B 03 04 }

    condition:
        $header at 0
}

rule Mozilla_Browser_Archive
{
    meta:
        description = "Mozilla Browser Archive"
        file_class = "Network"
        extensions = "XPI"

    strings:
        $header = { 50 4B 03 04 }

    condition:
        $header at 0
}

rule XML_paper_specification_file
{
    meta:
        description = "XML paper specification file"
        file_class = "Word processing suite"
        extensions = "XPS"

    strings:
        $header = { 50 4B 03 04 }

    condition:
        $header at 0
}

rule eXact_Packager_Models
{
    meta:
        description = "eXact Packager Models"
        file_class = "Miscellaneous"
        extensions = "XPT"

    strings:
        $header = { 50 4B 03 04 }

    condition:
        $header at 0
}

rule Open_Publication_Structure_eBook
{
    meta:
        description = "Open Publication Structure eBook"
        file_class = "Compressed archive"
        extensions = "EPUB"

    strings:
        $header = { 50 4B 03 04 0A 00 02 00 }

    condition:
        $header at 0
}

rule ZLock_Pro_encrypted_ZIP
{
    meta:
        description = "ZLock Pro encrypted ZIP"
        file_class = "Compressed archive"
        extensions = "ZIP"

    strings:
        $header = { 50 4B 03 04 14 00 01 00 }

    condition:
        $header at 0
}

rule MS_Office_2007_documents
{
    meta:
        description = "MS Office 2007 documents"
        file_class = "Word processing suite"
        extensions = "DOCX|PPTX|XLSX"

    strings:
        $header = { 50 4B 03 04 14 00 06 00 }

    condition:
        $header at 0
}

rule Java_archive_2
{
    meta:
        description = "Java archive_2"
        file_class = "Programming"
        extensions = "JAR"

    strings:
        $header = { 50 4B 03 04 14 00 08 00 }

    condition:
        $header at 0
}

rule PKZIP_archive_2
{
    meta:
        description = "PKZIP archive_2"
        file_class = "Compressed archive"
        extensions = "ZIP"

    strings:
        $header = { 50 4B 05 06 }

    condition:
        $header at 0
}

rule PKZIP_archive_3
{
    meta:
        description = "PKZIP archive_3"
        file_class = "Compressed archive"
        extensions = "ZIP"

    strings:
        $header = { 50 4B 07 08 }

    condition:
        $header at 0
}

rule PKLITE_archive
{
    meta:
        description = "PKLITE archive"
        file_class = "Compressed archive"
        extensions = "ZIP"

    strings:
        $header = { 50 4B 4C 49 54 45 }

    condition:
        $header at 30
}

rule PKSFX_self_extracting_archive
{
    meta:
        description = "PKSFX self-extracting archive"
        file_class = "Compressed archive"
        extensions = "ZIP"

    strings:
        $header = { 50 4B 53 70 58 }

    condition:
        $header at 526
}

rule Windows_Program_Manager_group_file
{
    meta:
        description = "Windows Program Manager group file"
        file_class = "Windows"
        extensions = "GRP"

    strings:
        $header = { 50 4D 43 43 }

    condition:
        $header at 0
}

rule Norton_Disk_Doctor_undo_file
{
    meta:
        description = "Norton Disk Doctor undo file"
        file_class = "Miscellaneous"
        extensions = "DAT"

    strings:
        $header = { 50 4E 43 49 55 4E 44 4F }

    condition:
        $header at 0
}

rule Microsoft_Windows_User_State_Migration_Tool
{
    meta:
        description = "Microsoft Windows User State Migration Tool"
        file_class = "Windows"
        extensions = "PMOCCMOC"

    strings:
        $header = { 50 4D 4F 43 43 4D 4F 43 }

    condition:
        $header at 0
}

rule Dreamcast_Sound_Format
{
    meta:
        description = "Dreamcast Sound Format"
        file_class = "Multimedia"
        extensions = "DSF"

    strings:
        $header = { 50 53 46 12 }

    condition:
        $header at 0
}

rule Puffer_encrypted_archive
{
    meta:
        description = "Puffer encrypted archive"
        file_class = "Encryption"
        extensions = "PUF"

    strings:
        $header = { 50 55 46 58 }

    condition:
        $header at 0
}

rule Parrot_Video_Encapsulation
{
    meta:
        description = "Parrot Video Encapsulation"
        file_class = "Multimedia"
        extensions = "(none)"

    strings:
        $header = { 50 61 56 45 }

    condition:
        $header at 0
}

rule Quicken_data
{
    meta:
        description = "Quicken data"
        file_class = "Finance"
        extensions = "QEL"

    strings:
        $header = { 51 45 4C 20 }

    condition:
        $header at 92
}

rule Qcow_Disk_Image
{
    meta:
        description = "Qcow Disk Image"
        file_class = "Miscellaneous"
        extensions = "QEMU"

    strings:
        $header = { 51 46 49 }

    condition:
        $header at 0
}

rule RIFF_Qualcomm_PureVoice
{
    meta:
        description = "RIFF Qualcomm PureVoice"
        file_class = "Multimedia"
        extensions = "QCP"

    strings:
        $header = { 51 4C 43 4D 66 6D 74 20 }

    condition:
        $header at 8
}

rule Quicken_data_file
{
    meta:
        description = "Quicken data file"
        file_class = "Finance"
        extensions = "ABD|QSD"

    strings:
        $header = { 51 57 20 56 65 72 2E 20 }

    condition:
        $header at 0
}

rule Outlook_Exchange_message_subheader
{
    meta:
        description = "Outlook-Exchange message subheader"
        file_class = "Email"
        extensions = "MSG"

    strings:
        $header = { 52 00 6F 00 6F 00 74 00 20 00 45 00 6E 00 74 00 72 00 79 00 }

    condition:
        $header at 512
}

rule Shareaza_P2P_thumbnail
{
    meta:
        description = "Shareaza (P2P) thumbnail"
        file_class = "Network"
        extensions = "DAT"

    strings:
        $header = { 52 41 5A 41 54 44 42 31 }

    condition:
        $header at 0
}

rule R_saved_work_space
{
    meta:
        description = "R saved work space"
        file_class = "Programming"
        extensions = "RDATA"

    strings:
        $header = { 52 44 58 32 0A }

    condition:
        $header at 0
}

rule WinNT_Registry_Registry_Undo_files
{
    meta:
        description = "WinNT Registry-Registry Undo files"
        file_class = "Windows"
        extensions = "REG|SUD"

    strings:
        $header = { 52 45 47 45 44 49 54 }

    condition:
        $header at 0
}

rule Antenna_data_file
{
    meta:
        description = "Antenna data file"
        file_class = "Miscellaneous"
        extensions = "AD"

    strings:
        $header = { 52 45 56 4E 55 4D 3A 2C }

    condition:
        $header at 0
}

rule Windows_animated_cursor
{
    meta:
        description = "Windows animated cursor"
        file_class = "Windows"
        extensions = "ANI"

    strings:
        $header = { 52 49 46 46 }

    condition:
        $header at 0
}

rule Corel_Presentation_Exchange_metadata
{
    meta:
        description = "Corel Presentation Exchange metadata"
        file_class = "Presentation"
        extensions = "CMX"

    strings:
        $header = { 52 49 46 46 }

    condition:
        $header at 0
}

rule CorelDraw_document
{
    meta:
        description = "CorelDraw document"
        file_class = "Presentation"
        extensions = "CDR"

    strings:
        $header = { 52 49 46 46 }

    condition:
        $header at 0
}

rule Video_CD_MPEG_movie
{
    meta:
        description = "Video CD MPEG movie"
        file_class = "Multimedia"
        extensions = "DAT"

    strings:
        $header = { 52 49 46 46 }

    condition:
        $header at 0
}

rule Micrografx_Designer_graphic
{
    meta:
        description = "Micrografx Designer graphic"
        file_class = "Picture"
        extensions = "DS4"

    strings:
        $header = { 52 49 46 46 }

    condition:
        $header at 0
}

rule _4X_Movie_video
{
    meta:
        description = "4X Movie video"
        file_class = "Multimedia"
        extensions = "4XM"

    strings:
        $header = { 52 49 46 46 }

    condition:
        $header at 0
}

rule Resource_Interchange_File_Format
{
    meta:
        description = "Resource Interchange File Format"
        file_class = "Multimedia"
        extensions = "AVI|CDA|QCP|RMI|WAV|WEBP"

    strings:
        $header = { 52 49 46 46 }

    condition:
        $header at 0
}

rule RIFF_Windows_MIDI
{
    meta:
        description = "RIFF Windows MIDI"
        file_class = "Multimedia"
        extensions = "RMI"

    strings:
        $header = { 52 4D 49 44 64 61 74 61 }

    condition:
        $header at 8
}

rule WinNT_Netmon_capture_file
{
    meta:
        description = "WinNT Netmon capture file"
        file_class = "Network"
        extensions = "CAP"

    strings:
        $header = { 52 54 53 53 }

    condition:
        $header at 0
}

rule WinRAR_compressed_archive
{
    meta:
        description = "WinRAR compressed archive"
        file_class = "Compressed archive"
        extensions = "RAR"

    strings:
        $header = { 52 61 72 21 1A 07 00 }

    condition:
        $header at 0
}

rule Generic_e_mail_1
{
    meta:
        description = "Generic e-mail_1"
        file_class = "Email"
        extensions = "EML"

    strings:
        $header = { 52 65 74 75 72 6E 2D 50 }

    condition:
        $header at 0
}

rule Windows_prefetch
{
    meta:
        description = "Windows prefetch"
        file_class = "Windows"
        extensions = "PF"

    strings:
        $header = { 53 43 43 41 }

    condition:
        $header at 4
}

rule Underground_Audio
{
    meta:
        description = "Underground Audio"
        file_class = "Multimedia"
        extensions = "AST"

    strings:
        $header = { 53 43 48 6C }

    condition:
        $header at 0
}

rule Img_Software_Bitmap
{
    meta:
        description = "Img Software Bitmap"
        file_class = "Picture"
        extensions = "IMG"

    strings:
        $header = { 53 43 4D 49 }

    condition:
        $header at 0
}

rule SMPTE_DPX_big_endian_
{
    meta:
        description = "SMPTE DPX (big endian)"
        file_class = "Picture"
        extensions = "SDPX"

    strings:
        $header = { 53 44 50 58 }

    condition:
        $header at 0
}

rule Harvard_Graphics_presentation
{
    meta:
        description = "Harvard Graphics presentation"
        file_class = "Presentation"
        extensions = "SHW"

    strings:
        $header = { 53 48 4F 57 }

    condition:
        $header at 0
}

rule Sietronics_CPI_XRD_document
{
    meta:
        description = "Sietronics CPI XRD document"
        file_class = "Miscellaneous"
        extensions = "CPI"

    strings:
        $header = { 53 49 45 54 52 4F 4E 49 }

    condition:
        $header at 0
}

rule Flexible_Image_Transport_System_FITS_file
{
    meta:
        description = "Flexible Image Transport System (FITS) file"
        file_class = "multimedia"
        extensions = "FITS"

    strings:
        $header = { 53 49 4D 50 4C 45 20 20 3D 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 54 }

    condition:
        $header at 0
}

rule StuffIt_archive
{
    meta:
        description = "StuffIt archive"
        file_class = "Compressed archive"
        extensions = "SIT"

    strings:
        $header = { 53 49 54 21 00 }

    condition:
        $header at 0
}

rule SmartDraw_Drawing_file
{
    meta:
        description = "SmartDraw Drawing file"
        file_class = "Presentation"
        extensions = "SDR"

    strings:
        $header = { 53 4D 41 52 54 44 52 57 }

    condition:
        $header at 0
}

rule StorageCraft_ShadownProtect_backup_file
{
    meta:
        description = "StorageCraft ShadownProtect backup file"
        file_class = "Backup"
        extensions = "SPF"

    strings:
        $header = { 53 50 46 49 00 }

    condition:
        $header at 0
}

rule MultiBit_Bitcoin_blockchain_file
{
    meta:
        description = "MultiBit Bitcoin blockchain file"
        file_class = "e-money"
        extensions = "SPVB"

    strings:
        $header = { 53 50 56 42 }

    condition:
        $header at 0
}

rule SQLite_database_file
{
    meta:
        description = "SQLite database file"
        file_class = "Database"
        extensions = "DB"

    strings:
        $header = { 53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00 }

    condition:
        $header at 0
}

rule DB2_conversion_file
{
    meta:
        description = "DB2 conversion file"
        file_class = "Database"
        extensions = "CNV"

    strings:
        $header = { 53 51 4C 4F 43 4F 4E 56 }

    condition:
        $header at 0
}

rule QBASIC_SZDD_file
{
    meta:
        description = "QBASIC SZDD file"
        file_class = "Compressed archive"
        extensions = "(none)"

    strings:
        $header = { 53 5A 20 88 F0 27 33 D1 }

    condition:
        $header at 0
}

rule SZDD_file_format
{
    meta:
        description = "SZDD file format"
        file_class = "Compressed archive"
        extensions = "(none)"

    strings:
        $header = { 53 5A 44 44 88 F0 27 33 }

    condition:
        $header at 0
}

rule StuffIt_compressed_archive
{
    meta:
        description = "StuffIt compressed archive"
        file_class = "Compressed archive"
        extensions = "SIT"

    strings:
        $header = { 53 74 75 66 66 49 74 20 }

    condition:
        $header at 0
}

rule SuperCalc_worksheet
{
    meta:
        description = "SuperCalc worksheet"
        file_class = "Spreadsheet"
        extensions = "CAL"

    strings:
        $header = { 53 75 70 65 72 43 61 6C }

    condition:
        $header at 0
}

rule Wii_GameCube
{
    meta:
        description = "Wii-GameCube"
        file_class = "Multimedia"
        extensions = "THP"

    strings:
        $header = { 54 48 50 00 }

    condition:
        $header at 0
}

rule GNU_Info_Reader_file
{
    meta:
        description = "GNU Info Reader file"
        file_class = "Programming"
        extensions = "INFO"

    strings:
        $header = { 54 68 69 73 20 69 73 20 }

    condition:
        $header at 0
}

rule Unicode_extensions
{
    meta:
        description = "Unicode extensions"
        file_class = "Windows"
        extensions = "UCE"

    strings:
        $header = { 55 43 45 58 }

    condition:
        $header at 0
}

rule UFA_compressed_archive
{
    meta:
        description = "UFA compressed archive"
        file_class = "Compressed archive"
        extensions = "UFA"

    strings:
        $header = { 55 46 41 C6 D2 C1 }

    condition:
        $header at 0
}

rule UFO_Capture_map_file
{
    meta:
        description = "UFO Capture map file"
        file_class = "Miscellaneous"
        extensions = "DAT"

    strings:
        $header = { 55 46 4F 4F 72 62 69 74 }

    condition:
        $header at 0
}

rule Measurement_Data_Format_file
{
    meta:
        description = "Measurement Data Format file"
        file_class = "Miscellaneous"
        extensions = "MF4"

    strings:
        $header = { 55 6E 46 69 6E 4D 46 }

    condition:
        $header at 0
}

rule Visual_C_PreCompiled_header
{
    meta:
        description = "Visual C PreCompiled header"
        file_class = "Programming"
        extensions = "PCH"

    strings:
        $header = { 56 43 50 43 48 30 }

    condition:
        $header at 0
}

rule Visual_Basic_User_defined_Control_file
{
    meta:
        description = "Visual Basic User-defined Control file"
        file_class = "Programming"
        extensions = "CTL"

    strings:
        $header = { 56 45 52 53 49 4F 4E 20 }

    condition:
        $header at 0
}

rule MapInfo_Interchange_Format_file
{
    meta:
        description = "MapInfo Interchange Format file"
        file_class = "Miscellaneous"
        extensions = "MIF"

    strings:
        $header = { 56 65 72 73 69 6F 6E 20 }

    condition:
        $header at 0
}

rule SPSS_template
{
    meta:
        description = "SPSS template"
        file_class = "Statistics"
        extensions = "SCT"

    strings:
        $header = { 57 04 00 00 53 50 53 53 20 74 65 6D 70 6C 61 74 }

    condition:
        $header at 0
}

rule RIFF_Windows_Audio_1
{
    meta:
        description = "RIFF Windows Audio"
        file_class = "Multimedia"
        extensions = "WAV"

    strings:
        $header = { 57 41 56 45 66 6D 74 20 }

    condition:
        $header at 8
}

rule RIFF_WebP
{
    meta:
        description = "RIFF WebP"
        file_class = "Multimedia"
        extensions = "WEBP"

    strings:
        $header = { 57 45 42 50 }

    condition:
        $header at 8
}

rule Walkman_MP3_file
{
    meta:
        description = "Walkman MP3 file"
        file_class = "Multimedia"
        extensions = "DAT"

    strings:
        $header = { 57 4D 4D 50 }

    condition:
        $header at 0
}

rule WordStar_for_Windows_file
{
    meta:
        description = "WordStar for Windows file"
        file_class = "Word processing suite"
        extensions = "WS2"

    strings:
        $header = { 57 53 32 30 30 30 }

    condition:
        $header at 0
}

rule WinZip_compressed_archive
{
    meta:
        description = "WinZip compressed archive"
        file_class = "Compressed archive"
        extensions = "ZIP"

    strings:
        $header = { 57 69 6E 5A 69 70 }

    condition:
        $header at 29152
}

rule Lotus_WordPro_file
{
    meta:
        description = "Lotus WordPro file"
        file_class = "Word processing suite"
        extensions = "LWP"

    strings:
        $header = { 57 6F 72 64 50 72 6F }

    condition:
        $header at 0
}

rule Exchange_e_mail
{
    meta:
        description = "Exchange e-mail"
        file_class = "Email"
        extensions = "EML"

    strings:
        $header = { 58 2D }

    condition:
        $header at 0
}

rule Packet_sniffer_files
{
    meta:
        description = "Packet sniffer files"
        file_class = "Network"
        extensions = "CAP"

    strings:
        $header = { 58 43 50 00 }

    condition:
        $header at 0
}

rule XPCOM_libraries
{
    meta:
        description = "XPCOM libraries"
        file_class = "Programming"
        extensions = "XPT"

    strings:
        $header = { 58 50 43 4F 4D 0A 54 79 }

    condition:
        $header at 0
}

rule SMPTE_DPX_file_little_endian_
{
    meta:
        description = "SMPTE DPX file (little endian)"
        file_class = "Picture"
        extensions = "DPX"

    strings:
        $header = { 58 50 44 53 }

    condition:
        $header at 0
}

rule MS_Publisher
{
    meta:
        description = "MS Publisher"
        file_class = "Word processing suite"
        extensions = "BDR"

    strings:
        $header = { 58 54 }

    condition:
        $header at 0
}

rule ZOO_compressed_archive
{
    meta:
        description = "ZOO compressed archive"
        file_class = "Compressed archive"
        extensions = "ZOO"

    strings:
        $header = { 5A 4F 4F 20 }

    condition:
        $header at 0
}

rule Macromedia_Shockwave_Flash
{
    meta:
        description = "Macromedia Shockwave Flash"
        file_class = "Multimedia"
        extensions = "SWF"

    strings:
        $header = { 5A 57 53 }

    condition:
        $header at 0
}

rule MS_Exchange_configuration_file
{
    meta:
        description = "MS Exchange configuration file"
        file_class = "Email"
        extensions = "ECF"

    strings:
        $header = { 5B 47 65 6E 65 72 61 6C }

    condition:
        $header at 0
}

rule Visual_C_Workbench_Info_File
{
    meta:
        description = "Visual C++ Workbench Info File"
        file_class = "Programming"
        extensions = "VCW"

    strings:
        $header = { 5B 4D 53 56 43 }

    condition:
        $header at 0
}

rule Dial_up_networking_file
{
    meta:
        description = "Dial-up networking file"
        file_class = "Network"
        extensions = "DUN"

    strings:
        $header = { 5B 50 68 6F 6E 65 5D }

    condition:
        $header at 0
}

rule Lotus_AMI_Pro_document_1
{
    meta:
        description = "Lotus AMI Pro document_1"
        file_class = "Word processing suite"
        extensions = "SAM"

    strings:
        $header = { 5B 56 45 52 5D }

    condition:
        $header at 0
}

rule VocalTec_VoIP_media_file
{
    meta:
        description = "VocalTec VoIP media file"
        file_class = "Multimedia"
        extensions = "VMD"

    strings:
        $header = { 5B 56 4D 44 5D }

    condition:
        $header at 0
}

rule Microsoft_Code_Page_Translation_file
{
    meta:
        description = "Microsoft Code Page Translation file"
        file_class = "Windows"
        extensions = "CPX"

    strings:
        $header = { 5B 57 69 6E 64 6F 77 73 }

    condition:
        $header at 0
}

rule Flight_Simulator_Aircraft_Configuration
{
    meta:
        description = "Flight Simulator Aircraft Configuration"
        file_class = "Games"
        extensions = "CFG"

    strings:
        $header = { 5B 66 6C 74 73 69 6D 2E }

    condition:
        $header at 0
}

rule WinAmp_Playlist
{
    meta:
        description = "WinAmp Playlist"
        file_class = "Audio"
        extensions = "PLS"

    strings:
        $header = { 5B 70 6C 61 79 6C 69 73 74 5D }

    condition:
        $header at 0
}

rule Lotus_AMI_Pro_document_2
{
    meta:
        description = "Lotus AMI Pro document_2"
        file_class = "Word processing suite"
        extensions = "SAM"

    strings:
        $header = { 5B 76 65 72 5D }

    condition:
        $header at 0
}

rule Husqvarna_Designer
{
    meta:
        description = "Husqvarna Designer"
        file_class = "Miscellaneous"
        extensions = "HUS"

    strings:
        $header = { 5D FC C8 00 }

    condition:
        $header at 0
}

rule Jar_archive
{
    meta:
        description = "Jar archive"
        file_class = "Miscellaneous"
        extensions = "JAR"

    strings:
        $header = { 5F 27 A8 89 }

    condition:
        $header at 0
}

rule EnCase_case_file
{
    meta:
        description = "EnCase case file"
        file_class = "Miscellaneous"
        extensions = "CAS|CBK"

    strings:
        $header = { 5F 43 41 53 45 5F }

    condition:
        $header at 0
}

rule Compressed_archive_file_1
{
    meta:
        description = "Compressed archive file"
        file_class = "Compressed archive"
        extensions = "ARJ"

    strings:
        $header = { 60 EA }

    condition:
        $header at 0
}

rule UUencoded_file
{
    meta:
        description = "UUencoded file"
        file_class = "Compressed archive"
        extensions = "(none)"

    strings:
        $header = { 62 65 67 69 6E }

    condition:
        $header at 0
}

rule UUencoded_BASE64_file
{
    meta:
        description = "UUencoded BASE64 file"
        file_class = "Compressed archive"
        extensions = "b64"

    strings:
        $header = { 62 65 67 69 6E 2D 62 61 73 65 36 34 }
        $trailer = { 0A 3D 3D 3D 3D 0A }

    condition:
        $header at 0 and $trailer
}

rule Binary_property_list_plist_
{
    meta:
        description = "Binary property list (plist)"
        file_class = "System"
        extensions = "(none)"

    strings:
        $header = { 62 70 6C 69 73 74 }

    condition:
        $header at 0
}

rule Apple_Core_Audio_File
{
    meta:
        description = "Apple Core Audio File"
        file_class = "Multimedia"
        extensions = "CAF"

    strings:
        $header = { 63 61 66 66 }

    condition:
        $header at 0
}

rule Macintosh_encrypted_Disk_image_v1_
{
    meta:
        description = "Macintosh encrypted Disk image (v1)"
        file_class = "Compressed archive"
        extensions = "DMG"

    strings:
        $header = { 63 64 73 61 65 6E 63 72 }

    condition:
        $header at 0
}

rule Virtual_PC_HD_image
{
    meta:
        description = "Virtual PC HD image"
        file_class = "Miscellaneous"
        extensions = "VHD"

    strings:
        $header = { 63 6F 6E 65 63 74 69 78 }

    condition:
        $header at 0
}

rule Photoshop_Custom_Shape
{
    meta:
        description = "Photoshop Custom Shape"
        file_class = "Miscellaneous"
        extensions = "CSH"

    strings:
        $header = { 63 75 73 68 00 00 00 02 }

    condition:
        $header at 0
}

rule Intel_PROset_Wireless_Profile
{
    meta:
        description = "Intel PROset-Wireless Profile"
        file_class = "Network"
        extensions = "P10"

    strings:
        $header = { 64 00 00 00 }

    condition:
        $header at 0
}

rule Torrent_file
{
    meta:
        description = "Torrent file"
        file_class = "Compressed archive"
        extensions = "TORRENT"

    strings:
        $header = { 64 38 3A 61 6E 6E 6F 75 6E 63 65 }

    condition:
        $header at 0
}

rule Dalvik_Android_executable_file
{
    meta:
        description = "Dalvik (Android) executable file"
        file_class = "Mobile"
        extensions = "dex"

    strings:
        $header = { 64 65 78 0A }

    condition:
        $header at 0
}

rule Audacity_audio_file
{
    meta:
        description = "Audacity audio file"
        file_class = "Multimedia"
        extensions = "AU"

    strings:
        $header = { 64 6E 73 2E }

    condition:
        $header at 0
}

rule MS_Visual_Studio_workspace_file
{
    meta:
        description = "MS Visual Studio workspace file"
        file_class = "Programming"
        extensions = "DSW"

    strings:
        $header = { 64 73 77 66 69 6C 65 }

    condition:
        $header at 0
}

rule Macintosh_encrypted_Disk_image_v2_
{
    meta:
        description = "Macintosh encrypted Disk image (v2)"
        file_class = "Compressed archive"
        extensions = "DMG"

    strings:
        $header = { 65 6E 63 72 63 64 73 61 }

    condition:
        $header at 0
}

rule WinNT_printer_spool_file
{
    meta:
        description = "WinNT printer spool file"
        file_class = "Windows"
        extensions = "SHD"

    strings:
        $header = { 66 49 00 00 }

    condition:
        $header at 0
}

rule Free_Lossless_Audio_Codec_file
{
    meta:
        description = "Free Lossless Audio Codec file"
        file_class = "Multimedia"
        extensions = "FLAC"

    strings:
        $header = { 66 4C 61 43 00 00 00 22 }

    condition:
        $header at 0
}

rule MPEG_4_video_file_1
{
    meta:
        description = "MPEG-4 video file_1"
        file_class = "Multimedia"
        extensions = "MP4"

    strings:
        $header = { 66 74 79 70 33 67 70 35 }

    condition:
        $header at 4
}

rule Apple_Lossless_Audio_Codec_file
{
    meta:
        description = "Apple Lossless Audio Codec file"
        file_class = "Multimedia"
        extensions = "M4A"

    strings:
        $header = { 66 74 79 70 4D 34 41 20 }

    condition:
        $header at 4
}

rule ISO_Media_MPEG_v4_iTunes_AVC_LC
{
    meta:
        description = "ISO Media-MPEG v4-iTunes AVC-LC"
        file_class = "Multimedia"
        extensions = "FLV|M4V"

    strings:
        $header = { 66 74 79 70 4D 34 56 20 }

    condition:
        $header at 4
}

rule MPEG_4_video_file_2
{
    meta:
        description = "MPEG-4 video file_2"
        file_class = "Multimedia"
        extensions = "MP4"

    strings:
        $header = { 66 74 79 70 4D 53 4E 56 }

    condition:
        $header at 4
}

rule ISO_Base_Media_file_MPEG_4_v1
{
    meta:
        description = "ISO Base Media file (MPEG-4) v1"
        file_class = "Multimedia"
        extensions = "MP4"

    strings:
        $header = { 66 74 79 70 69 73 6F 6D }

    condition:
        $header at 4
}

rule MPEG_4_video_QuickTime_file
{
    meta:
        description = "MPEG-4 video-QuickTime file"
        file_class = "Multimedia"
        extensions = "M4V"

    strings:
        $header = { 66 74 79 70 6D 70 34 32 }

    condition:
        $header at 4
}

rule QuickTime_movie_7
{
    meta:
        description = "QuickTime movie_7"
        file_class = "Multimedia"
        extensions = "MOV"

    strings:
        $header = { 66 74 79 70 71 74 20 20 }

    condition:
        $header at 4
}

rule Win2000_XP_printer_spool_file
{
    meta:
        description = "Win2000-XP printer spool file"
        file_class = "Windows"
        extensions = "SHD"

    strings:
        $header = { 67 49 00 00 }

    condition:
        $header at 0
}

rule GIMP_file
{
    meta:
        description = "GIMP file"
        file_class = "Picture"
        extensions = "XCF"

    strings:
        $header = { 67 69 6D 70 20 78 63 66 }

    condition:
        $header at 0
}

rule Win_Server_2003_printer_spool_file
{
    meta:
        description = "Win Server 2003 printer spool file"
        file_class = "Windows"
        extensions = "SHD"

    strings:
        $header = { 68 49 00 00 }

    condition:
        $header at 0
}

rule MacOS_icon_file
{
    meta:
        description = "MacOS icon file"
        file_class = "System"
        extensions = "ICNS"

    strings:
        $header = { 69 63 6E 73 }

    condition:
        $header at 0
}

rule Skype_user_data_file
{
    meta:
        description = "Skype user data file"
        file_class = "Network"
        extensions = "DBB"

    strings:
        $header = { 6C 33 33 6C }

    condition:
        $header at 0
}

rule QuickTime_movie_1
{
    meta:
        description = "QuickTime movie_1"
        file_class = "Multimedia"
        extensions = "MOV"

    strings:
        $header = { 6D 6F 6F 76 }

    condition:
        $header at 4
}

rule QuickTime_movie_2
{
    meta:
        description = "QuickTime movie_2"
        file_class = "Multimedia"
        extensions = "MOV"

    strings:
        $header = { 66 72 65 65 }

    condition:
        $header at 4
}

rule QuickTime_movie_3
{
    meta:
        description = "QuickTime movie_3"
        file_class = "Multimedia"
        extensions = "MOV"

    strings:
        $header = { 6D 64 61 74 }

    condition:
        $header at 4
}

rule QuickTime_movie_4
{
    meta:
        description = "QuickTime movie_4"
        file_class = "Multimedia"
        extensions = "MOV"

    strings:
        $header = { 77 69 64 65 }

    condition:
        $header at 4
}

rule QuickTime_movie_5
{
    meta:
        description = "QuickTime movie_5"
        file_class = "Multimedia"
        extensions = "MOV"

    strings:
        $header = { 70 6E 6F 74 }

    condition:
        $header at 4
}

rule QuickTime_movie_6
{
    meta:
        description = "QuickTime movie_6"
        file_class = "Multimedia"
        extensions = "MOV"

    strings:
        $header = { 73 6B 69 70 }

    condition:
        $header at 4
}

rule Internet_Explorer_v11_Tracking_Protection_List
{
    meta:
        description = "Internet Explorer v11 Tracking Protection List"
        file_class = "Programming"
        extensions = "TPL"

    strings:
        $header = { 6D 73 46 69 6C 74 65 72 4C 69 73 74 }

    condition:
        $header at 0
}

rule MultiBit_Bitcoin_wallet_information
{
    meta:
        description = "MultiBit Bitcoin wallet information"
        file_class = "E-money"
        extensions = "INFO"

    strings:
        $header = { 6D 75 6C 74 69 42 69 74 2E 69 6E 66 6F }

    condition:
        $header at 0
}

rule SMS_text_SIM_
{
    meta:
        description = "SMS text (SIM)"
        file_class = "Mobile"
        extensions = "(none)"

    strings:
        $header = { 6F 3C }

    condition:
        $header at 0
}

rule _1Password_4_Cloud_Keychain_encrypted_data
{
    meta:
        description = "1Password 4 Cloud Keychain encrypted data"
        file_class = "Encryption"
        extensions = "(none)"

    strings:
        $header = { 6F 70 64 61 74 61 30 31 }

    condition:
        $header at 0
}

rule WinNT_registry_file
{
    meta:
        description = "WinNT registry file"
        file_class = "Windows"
        extensions = "DAT"

    strings:
        $header = { 72 65 67 66 }

    condition:
        $header at 0
}

rule Sonic_Foundry_Acid_Music_File
{
    meta:
        description = "Sonic Foundry Acid Music File"
        file_class = "Multimedia"
        extensions = "AC"

    strings:
        $header = { 72 69 66 66 }

    condition:
        $header at 0
}

rule RealMedia_metafile
{
    meta:
        description = "RealMedia metafile"
        file_class = "Multimedia"
        extensions = "RAM"

    strings:
        $header = { 72 74 73 70 3A 2F 2F }

    condition:
        $header at 0
}

rule Allegro_Generic_Packfile_compressed_
{
    meta:
        description = "Allegro Generic Packfile (compressed)"
        file_class = "Miscellaneous"
        extensions = "DAT"

    strings:
        $header = { 73 6C 68 21 }

    condition:
        $header at 0
}

rule Allegro_Generic_Packfile_uncompressed_
{
    meta:
        description = "Allegro Generic Packfile (uncompressed)"
        file_class = "Miscellaneous"
        extensions = "DAT"

    strings:
        $header = { 73 6C 68 2E }

    condition:
        $header at 0
}

rule PalmOS_SuperMemo
{
    meta:
        description = "PalmOS SuperMemo"
        file_class = "Mobile"
        extensions = "PDB"

    strings:
        $header = { 73 6D 5F }

    condition:
        $header at 0
}

rule STL_STereoLithography_file
{
    meta:
        description = "STL (STereoLithography) file"
        file_class = "Multimedia"
        extensions = "STL"

    strings:
        $header = { 73 6F 6C 69 64 }

    condition:
        $header at 0
}

rule CALS_raster_bitmap
{
    meta:
        description = "CALS raster bitmap"
        file_class = "Picture"
        extensions = "CAL"

    strings:
        $header = { 73 72 63 64 6F 63 69 64 }

    condition:
        $header at 0
}

rule PowerBASIC_Debugger_Symbols
{
    meta:
        description = "PowerBASIC Debugger Symbols"
        file_class = "Programming"
        extensions = "PDB"

    strings:
        $header = { 73 7A 65 7A }

    condition:
        $header at 0
}

rule PathWay_Map_file
{
    meta:
        description = "PathWay Map file"
        file_class = "Mobile"
        extensions = "PRC"

    strings:
        $header = { 74 42 4D 50 4B 6E 57 72 }

    condition:
        $header at 60
}

rule TrueType_font
{
    meta:
        description = "TrueType font"
        file_class = "Windows"
        extensions = "TTF"

    strings:
        $header = { 74 72 75 65 00 }

    condition:
        $header at 0
}

rule Tape_Archive
{
    meta:
        description = "Tape Archive"
        file_class = "Compressed archive"
        extensions = "TAR"

    strings:
        $header = { 75 73 74 61 72 }

    condition:
        $header at 257
}

rule OpenEXR_bitmap_image
{
    meta:
        description = "OpenEXR bitmap image"
        file_class = "Picture"
        extensions = "EXR"

    strings:
        $header = { 76 2F 31 01 }

    condition:
        $header at 0
}

rule Qimage_filter
{
    meta:
        description = "Qimage filter"
        file_class = "Miscellaneous"
        extensions = "FLT"

    strings:
        $header = { 76 32 30 30 33 2E 31 30 }

    condition:
        $header at 0
}

rule Web_Open_Font_Format_2
{
    meta:
        description = "Web Open Font Format 2"
        file_class = "Open font"
        extensions = "WOFF2"

    strings:
        $header = { 77 4F 46 32 }

    condition:
        $header at 0
}

rule Web_Open_Font_Format
{
    meta:
        description = "Web Open Font Format"
        file_class = "Open font"
        extensions = "WOFF"

    strings:
        $header = { 77 4F 46 46 }

    condition:
        $header at 0
}

rule MacOS_X_image_file
{
    meta:
        description = "MacOS X image file"
        file_class = "MacOS"
        extensions = "DMG"

    strings:
        $header = { 78 01 73 0D 62 62 60 }

    condition:
        $header at 0
}

rule eXtensible_ARchive_file
{
    meta:
        description = "eXtensible ARchive file"
        file_class = "Compressed archive"
        extensions = "XAR"

    strings:
        $header = { 78 61 72 21 }

    condition:
        $header at 0
}

rule ZoomBrowser_Image_Index
{
    meta:
        description = "ZoomBrowser Image Index"
        file_class = "Miscellaneous"
        extensions = "INFO"

    strings:
        $header = { 7A 62 65 78 }

    condition:
        $header at 0
}

rule Windows_application_log
{
    meta:
        description = "Windows application log"
        file_class = "Windows"
        extensions = "LGC|LGD"

    strings:
        $header = { 7B 0D 0A 6F 20 }

    condition:
        $header at 0
}

rule Google_Drive_Drawing_link
{
    meta:
        description = "Google Drive Drawing link"
        file_class = "Word processing suite"
        extensions = "GDRAW"

    strings:
        $header = { 7B 22 75 72 6C 22 3A 20 22 68 74 74 70 73 3A 2F }

    condition:
        $header at 0
}

rule MS_WinMobile_personal_note
{
    meta:
        description = "MS WinMobile personal note"
        file_class = "Mobile"
        extensions = "PWI"

    strings:
        $header = { 7B 5C 70 77 69 }

    condition:
        $header at 0
}

rule Rich_Text_Format
{
    meta:
        description = "Rich Text Format"
        file_class = "Word processing suite"
        extensions = "RTF"

    strings:
        $header = { 7B 5C 72 74 66 31 }
        $trailer = { 5C 70 61 72 20 7D 7D }

    condition:
        $header at 0 and $trailer
}

rule Huskygram_Poem_or_Singer_embroidery
{
    meta:
        description = "Huskygram Poem or Singer embroidery"
        file_class = "Miscellaneous"
        extensions = "CSD"

    strings:
        $header = { 7C 4B C3 74 E1 C8 53 A4 79 B9 01 1D FC 4F DD 13 }

    condition:
        $header at 0
}

rule Corel_Paint_Shop_Pro_image
{
    meta:
        description = "Corel Paint Shop Pro image"
        file_class = "Presentation"
        extensions = "PSP"

    strings:
        $header = { 7E 42 4B 00 }

    condition:
        $header at 0
}

rule Easy_Street_Draw_diagram_file
{
    meta:
        description = "Easy Street Draw diagram file"
        file_class = "Presentation"
        extensions = "ESD"

    strings:
        $header = { 7E 45 53 44 77 F6 85 3E BF 6A D2 11 45 61 73 79 20 53 74 72 65 65 74 20 44 72 61 77 }

    condition:
        $header at 0
}

rule Digital_Watchdog_DW_TP_500G_audio
{
    meta:
        description = "Digital Watchdog DW-TP-500G audio"
        file_class = "Audio"
        extensions = "IMG"

    strings:
        $header = { 7E 74 2C 01 50 70 02 4D 52 }

    condition:
        $header at 0
}

rule ELF_executable
{
    meta:
        description = "ELF executable"
        file_class = "Linux-Unix"
        extensions = "(none)"

    strings:
        $header = { 7F 45 4C 46 }

    condition:
        $header at 0
}

rule Relocatable_object_code
{
    meta:
        description = "Relocatable object code"
        file_class = "Windows"
        extensions = "OBJ"

    strings:
        $header = { 80 }

    condition:
        $header at 0
}

rule Dreamcast_audio
{
    meta:
        description = "Dreamcast audio"
        file_class = "Multimedia"
        extensions = "ADX"

    strings:
        $header = { 80 00 00 20 03 12 04 }

    condition:
        $header at 0
}

rule Kodak_Cineon_image
{
    meta:
        description = "Kodak Cineon image"
        file_class = "Picture"
        extensions = "CIN"

    strings:
        $header = { 80 2A 5F D7 }

    condition:
        $header at 0
}

rule Outlook_Express_address_book_Win95_
{
    meta:
        description = "Outlook Express address book (Win95)"
        file_class = "Email"
        extensions = "WAB"

    strings:
        $header = { 81 32 84 C1 85 05 D0 11 }

    condition:
        $header at 0
}

rule WordPerfect_text
{
    meta:
        description = "WordPerfect text"
        file_class = "Word processing suite"
        extensions = "WPF"

    strings:
        $header = { 81 CD AB }

    condition:
        $header at 0
}

rule PNG_image
{
    meta:
        description = "PNG image"
        file_class = "Picture"
        extensions = "PNG"

    strings:
        $header = { 89 50 4E 47 0D 0A 1A 0A }
        $trailer = { 49 45 4E 44 AE 42 60 82 }

    condition:
        $header at 0 and $trailer
}

rule MS_Answer_Wizard
{
    meta:
        description = "MS Answer Wizard"
        file_class = "Windows"
        extensions = "AW"

    strings:
        $header = { 8A 01 09 00 00 00 E1 08 }

    condition:
        $header at 0
}

rule Hamarsoft_compressed_archive
{
    meta:
        description = "Hamarsoft compressed archive"
        file_class = "Compressed archive"
        extensions = "HAP"

    strings:
        $header = { 91 33 48 46 }

    condition:
        $header at 0
}

rule PGP_secret_keyring_1
{
    meta:
        description = "PGP secret keyring_1"
        file_class = "Miscellaneous"
        extensions = "SKR"

    strings:
        $header = { 95 00 }

    condition:
        $header at 0
}

rule PGP_secret_keyring_2
{
    meta:
        description = "PGP secret keyring_2"
        file_class = "Miscellaneous"
        extensions = "SKR"

    strings:
        $header = { 95 01 }

    condition:
        $header at 0
}

rule JBOG2_image_file
{
    meta:
        description = "JBOG2 image file"
        file_class = "Picture"
        extensions = "JB2"

    strings:
        $header = { 97 4A 42 32 0D 0A 1A 0A }
        $trailer = { 03 33 00 01 00 00 00 00 }

    condition:
        $header at 0 and $trailer
}

rule GPG_public_keyring
{
    meta:
        description = "GPG public keyring"
        file_class = "Miscellaneous"
        extensions = "GPG"

    strings:
        $header = { 99 }

    condition:
        $header at 0
}

rule PGP_public_keyring
{
    meta:
        description = "PGP public keyring"
        file_class = "Miscellaneous"
        extensions = "PKR"

    strings:
        $header = { 99 01 }

    condition:
        $header at 0
}

rule Outlook_address_file
{
    meta:
        description = "Outlook address file"
        file_class = "Email"
        extensions = "WAB"

    strings:
        $header = { 9C CB CB 8D 13 75 D2 11 }

    condition:
        $header at 0
}

rule tcpdump_libpcap_capture_file
{
    meta:
        description = "tcpdump (libpcap) capture file"
        file_class = "Network"
        extensions = "(none)"

    strings:
        $header = { A1 B2 C3 D4 }

    condition:
        $header at 0
}

rule Extended_tcpdump_libpcap_capture_file
{
    meta:
        description = "Extended tcpdump (libpcap) capture file"
        file_class = "Network"
        extensions = "(none)"

    strings:
        $header = { A1 B2 CD 34 }

    condition:
        $header at 0
}

rule Access_Data_FTK_evidence
{
    meta:
        description = "Access Data FTK evidence"
        file_class = "Miscellaneous"
        extensions = "DAT"

    strings:
        $header = { A9 0D 00 00 00 00 00 00 }

    condition:
        $header at 0
}

rule Khronos_texture_file
{
    meta:
        description = "Khronos texture file"
        file_class = "Picture"
        extensions = "KTX"

    strings:
        $header = { AB 4B 54 58 20 31 31 BB 0D 0A 1A 0A }

    condition:
        $header at 0
}

rule Quicken_data_1
{
    meta:
        description = "Quicken data"
        file_class = "Finance"
        extensions = "QDF"

    strings:
        $header = { AC 9E BD 8F 00 00 }

    condition:
        $header at 0
}

rule PowerPoint_presentation_subheader_3
{
    meta:
        description = "PowerPoint presentation subheader_3"
        file_class = "Presentation"
        extensions = "PPT"

    strings:
        $header = { A0 46 1D F0 }

    condition:
        $header at 512
}

rule Java_serialization_data
{
    meta:
        description = "Java serialization data"
        file_class = "Programming"
        extensions = "(none)"

    strings:
        $header = { AC ED }

    condition:
        $header at 0
}

rule BGBlitz_position_database_file
{
    meta:
        description = "BGBlitz position database file"
        file_class = "Miscellaneous"
        extensions = "PDB"

    strings:
        $header = { AC ED 00 05 73 72 00 12 }

    condition:
        $header at 0
}

rule Win95_password_file
{
    meta:
        description = "Win95 password file"
        file_class = "Windows"
        extensions = "PWL"

    strings:
        $header = { B0 4D 46 43 }

    condition:
        $header at 0
}

rule PCX_bitmap
{
    meta:
        description = "PCX bitmap"
        file_class = "Presentation"
        extensions = "DCX"

    strings:
        $header = { B1 68 DE 3A }

    condition:
        $header at 0
}

rule Acronis_True_Image_1
{
    meta:
        description = "Acronis True Image_1"
        file_class = "Miscellaneous"
        extensions = "TIB"

    strings:
        $header = { B4 6E 68 44 }

    condition:
        $header at 0
}

rule Windows_calendar
{
    meta:
        description = "Windows calendar"
        file_class = "Windows"
        extensions = "CAL"

    strings:
        $header = { B5 A2 B0 B3 B3 B0 A5 B5 }

    condition:
        $header at 0
}

rule InstallShield_Script
{
    meta:
        description = "InstallShield Script"
        file_class = "Windows"
        extensions = "INS"

    strings:
        $header = { B8 C9 0C 00 }

    condition:
        $header at 0
}

rule MS_Write_file_3
{
    meta:
        description = "MS Write file_3"
        file_class = "Word processing suite"
        extensions = "WRI"

    strings:
        $header = { BE 00 00 00 AB }

    condition:
        $header at 0
}

rule Palm_Desktop_DateBook
{
    meta:
        description = "Palm Desktop DateBook"
        file_class = "Mobile"
        extensions = "DAT"

    strings:
        $header = { BE BA FE CA 0F 50 61 6C 6D 53 47 20 44 61 74 61 }

    condition:
        $header at 0
}

rule MS_Agent_Character_file
{
    meta:
        description = "MS Agent Character file"
        file_class = "Windows"
        extensions = "ACS"

    strings:
        $header = { C3 AB CD AB }

    condition:
        $header at 0
}

rule Adobe_encapsulated_PostScript
{
    meta:
        description = "Adobe encapsulated PostScript"
        file_class = "Word processing suite"
        extensions = "EPS"

    strings:
        $header = { C5 D0 D3 C6 }

    condition:
        $header at 0
}

rule Jeppesen_FliteLog_file
{
    meta:
        description = "Jeppesen FliteLog file"
        file_class = "Miscellaneous"
        extensions = "LBK"

    strings:
        $header = { C8 00 79 00 }

    condition:
        $header at 0
}

rule Java_bytecode
{
    meta:
        description = "Java bytecode"
        file_class = "Programming"
        extensions = "CLASS"

    strings:
        $header = { CA FE BA BE }

    condition:
        $header at 0
}

rule Nokia_phone_backup_file
{
    meta:
        description = "Nokia phone backup file"
        file_class = "Mobile"
        extensions = "NBU"

    strings:
        $header = { CC 52 33 FC E9 2C 18 48 AF E3 36 30 1A 39 40 06 }

    condition:
        $header at 0
}

rule NAV_quarantined_virus_file
{
    meta:
        description = "NAV quarantined virus file"
        file_class = "Miscellaneous"
        extensions = "(none)"

    strings:
        $header = { CD 20 AA AA 02 00 00 00 }

    condition:
        $header at 0
}

rule Acronis_True_Image_2
{
    meta:
        description = "Acronis True Image_2"
        file_class = "Multimedia"
        extensions = "TIB"

    strings:
        $header = { CE 24 B9 A2 20 00 00 00 }

    condition:
        $header at 0
}

rule Java_Cryptography_Extension_keystore
{
    meta:
        description = "Java Cryptography Extension keystore"
        file_class = "Encryption"
        extensions = "JCEKS"

    strings:
        $header = { CE CE CE CE }

    condition:
        $header at 0
}

rule OS_X_ABI_Mach_O_binary_32_bit_reverse_
{
    meta:
        description = "OS X ABI Mach-O binary (32-bit reverse)"
        file_class = "Programming"
        extensions = "(none)"

    strings:
        $header = { CE FA ED FE }

    condition:
        $header at 0
}

rule Perfect_Office_document
{
    meta:
        description = "Perfect Office document"
        file_class = "Word processing suite"
        extensions = "DOC"

    strings:
        $header = { CF 11 E0 A1 B1 1A E1 00 }

    condition:
        $header at 0
}

rule Outlook_Express_e_mail_folder
{
    meta:
        description = "Outlook Express e-mail folder"
        file_class = "Email"
        extensions = "DBX"

    strings:
        $header = { CF AD 12 FE }

    condition:
        $header at 0
}

rule OS_X_ABI_Mach_O_binary_64_bit_reverse_
{
    meta:
        description = "OS X ABI Mach-O binary (64-bit reverse)"
        file_class = "Programming"
        extensions = "(none)"

    strings:
        $header = { CF FA ED FE }

    condition:
        $header at 0
}

rule Microsoft_Office_document
{
    meta:
        description = "Microsoft Office document"
        file_class = "Word processing suite"
        extensions = "DOC|DOT|PPS|PPT|XLA|XLS|WIZ"

    strings:
        $header = { D0 CF 11 E0 A1 B1 1A E1 }

    condition:
        $header at 0
}

rule CaseWare_Working_Papers
{
    meta:
        description = "CaseWare Working Papers"
        file_class = "Miscellaneous"
        extensions = "AC_"

    strings:
        $header = { D0 CF 11 E0 A1 B1 1A E1 }

    condition:
        $header at 0
}

rule Access_project_file
{
    meta:
        description = "Access project file"
        file_class = "Database"
        extensions = "ADP"

    strings:
        $header = { D0 CF 11 E0 A1 B1 1A E1 }

    condition:
        $header at 0
}

rule Lotus_IBM_Approach_97_file
{
    meta:
        description = "Lotus-IBM Approach 97 file"
        file_class = "Database"
        extensions = "APR"

    strings:
        $header = { D0 CF 11 E0 A1 B1 1A E1 }

    condition:
        $header at 0
}

rule MSWorks_database_file
{
    meta:
        description = "MSWorks database file"
        file_class = "Database"
        extensions = "DB"

    strings:
        $header = { D0 CF 11 E0 A1 B1 1A E1 }

    condition:
        $header at 0
}

rule Microsoft_Common_Console_Document
{
    meta:
        description = "Microsoft Common Console Document"
        file_class = "Windows"
        extensions = "MSC"

    strings:
        $header = { D0 CF 11 E0 A1 B1 1A E1 }

    condition:
        $header at 0
}

rule Microsoft_Installer_package
{
    meta:
        description = "Microsoft Installer package"
        file_class = "Windows"
        extensions = "MSI"

    strings:
        $header = { D0 CF 11 E0 A1 B1 1A E1 }

    condition:
        $header at 0
}

rule Microsoft_Installer_Patch
{
    meta:
        description = "Microsoft Installer Patch"
        file_class = "Windows"
        extensions = "MSP"

    strings:
        $header = { D0 CF 11 E0 A1 B1 1A E1 }

    condition:
        $header at 0
}

rule Minitab_data_file
{
    meta:
        description = "Minitab data file"
        file_class = "Statistics"
        extensions = "MTW"

    strings:
        $header = { D0 CF 11 E0 A1 B1 1A E1 }

    condition:
        $header at 0
}

rule ArcMap_GIS_project_file
{
    meta:
        description = "ArcMap GIS project file"
        file_class = "Miscellaneous"
        extensions = "MXD"

    strings:
        $header = { D0 CF 11 E0 A1 B1 1A E1 }

    condition:
        $header at 0
}

rule Developer_Studio_File_Options_file
{
    meta:
        description = "Developer Studio File Options file"
        file_class = "Programming"
        extensions = "OPT"

    strings:
        $header = { D0 CF 11 E0 A1 B1 1A E1 }

    condition:
        $header at 0
}

rule MS_Publisher_file
{
    meta:
        description = "MS Publisher file"
        file_class = "Word processing suite"
        extensions = "PUB"

    strings:
        $header = { D0 CF 11 E0 A1 B1 1A E1 }

    condition:
        $header at 0
}

rule Revit_Project_file
{
    meta:
        description = "Revit Project file"
        file_class = "Miscellaneous"
        extensions = "RVT"

    strings:
        $header = { D0 CF 11 E0 A1 B1 1A E1 }

    condition:
        $header at 0
}

rule Visual_Studio_Solution_User_Options_file
{
    meta:
        description = "Visual Studio Solution User Options file"
        file_class = "Programming"
        extensions = "SOU"

    strings:
        $header = { D0 CF 11 E0 A1 B1 1A E1 }

    condition:
        $header at 0
}

rule SPSS_output_file
{
    meta:
        description = "SPSS output file"
        file_class = "Miscellaneous"
        extensions = "SPO"

    strings:
        $header = { D0 CF 11 E0 A1 B1 1A E1 }

    condition:
        $header at 0
}

rule Visio_file
{
    meta:
        description = "Visio file"
        file_class = "Miscellaneous"
        extensions = "VSD"

    strings:
        $header = { D0 CF 11 E0 A1 B1 1A E1 }

    condition:
        $header at 0
}

rule MSWorks_text_document
{
    meta:
        description = "MSWorks text document"
        file_class = "Word processing suite"
        extensions = "WPS"

    strings:
        $header = { D0 CF 11 E0 A1 B1 1A E1 }

    condition:
        $header at 0
}

rule WinPharoah_filter_file
{
    meta:
        description = "WinPharoah filter file"
        file_class = "Network"
        extensions = "FTR"

    strings:
        $header = { D2 0A 00 00 }

    condition:
        $header at 0
}

rule AOL_history_typed_URL_files
{
    meta:
        description = "AOL history|typed URL files"
        file_class = "Network"
        extensions = "ARL|AUT"

    strings:
        $header = { D4 2A }

    condition:
        $header at 0
}

rule WinDump_winpcap_capture_file
{
    meta:
        description = "WinDump (winpcap) capture file"
        file_class = "Network"
        extensions = "(none)"

    strings:
        $header = { D4 C3 B2 A1 }

    condition:
        $header at 0
}

rule Windows_graphics_metafile
{
    meta:
        description = "Windows graphics metafile"
        file_class = "Windows"
        extensions = "WMF"

    strings:
        $header = { D7 CD C6 9A }

    condition:
        $header at 0
}

rule Word_2_0_file
{
    meta:
        description = "Word 2.0 file"
        file_class = "Word processing"
        extensions = "DOC"

    strings:
        $header = { DB A5 2D 00 }

    condition:
        $header at 0
}

rule Corel_color_palette
{
    meta:
        description = "Corel color palette"
        file_class = "Presentation"
        extensions = "CPL"

    strings:
        $header = { DC DC }

    condition:
        $header at 0
}

rule eFax_file
{
    meta:
        description = "eFax file"
        file_class = "Miscellaneous"
        extensions = "EFX"

    strings:
        $header = { DC FE }

    condition:
        $header at 0
}

rule Amiga_icon
{
    meta:
        description = "Amiga icon"
        file_class = "Miscellaneous"
        extensions = "INFO"

    strings:
        $header = { E3 10 00 01 00 00 00 00 }

    condition:
        $header at 0
}

rule Win98_password_file
{
    meta:
        description = "Win98 password file"
        file_class = "Windows"
        extensions = "PWL"

    strings:
        $header = { E3 82 85 96 }

    condition:
        $header at 0
}

rule MS_OneNote_note
{
    meta:
        description = "MS OneNote note"
        file_class = "Miscellaneous"
        extensions = "ONE"

    strings:
        $header = { E4 52 5C 7B 8C D8 A7 4D }

    condition:
        $header at 0
}

rule Windows_executable_file_1
{
    meta:
        description = "Windows executable file_1"
        file_class = "Windows"
        extensions = "COM|SYS"

    strings:
        $header = { E8 }

    condition:
        $header at 0
}

rule Windows_executable_file_2
{
    meta:
        description = "Windows executable file_2"
        file_class = "Windows"
        extensions = "COM|SYS"

    strings:
        $header = { E9 }

    condition:
        $header at 0
}

rule Windows_executable_file_3
{
    meta:
        description = "Windows executable file_3"
        file_class = "Windows"
        extensions = "COM|SYS"

    strings:
        $header = { EB }

    condition:
        $header at 0
}

rule GEM_Raster_file
{
    meta:
        description = "GEM Raster file"
        file_class = "Picture"
        extensions = "IMG"

    strings:
        $header = { EB 3C 90 2A }

    condition:
        $header at 0
}

rule BitLocker_boot_sector_Vista_
{
    meta:
        description = "BitLocker boot sector (Vista)"
        file_class = "Windows"
        extensions = "(none)"

    strings:
        $header = { EB 52 90 2D 46 56 45 2D }

    condition:
        $header at 0
}

rule BitLocker_boot_sector_Win7_
{
    meta:
        description = "BitLocker boot sector (Win7)"
        file_class = "Windows"
        extensions = "(none)"

    strings:
        $header = { EB 58 90 2D 46 56 45 2D }

    condition:
        $header at 0
}

rule Word_document_subheader
{
    meta:
        description = "Word document subheader"
        file_class = "Word processing suite"
        extensions = "DOC"

    strings:
        $header = { EC A5 C1 00 }

    condition:
        $header at 512
}

rule RedHat_Package_Manager
{
    meta:
        description = "RedHat Package Manager"
        file_class = "Compressed archive"
        extensions = "RPM"

    strings:
        $header = { ED AB EE DB }

    condition:
        $header at 0
}

rule UTF_8_file
{
    meta:
        description = "UTF-8 file"
        file_class = "Windows"
        extensions = "(none)"

    strings:
        $header = { EF BB BF }

    condition:
        $header at 0
}

rule Windows_Script_Component_UTF_8_1
{
    meta:
        description = "Windows Script Component (UTF-8)_1"
        file_class = "Windows"
        extensions = "WSF"

    strings:
        $header = { EF BB BF 3C }

    condition:
        $header at 0
}

rule Windows_Script_Component_UTF_8_2
{
    meta:
        description = "Windows Script Component (UTF-8)_2"
        file_class = "Windows"
        extensions = "WSC"

    strings:
        $header = { EF BB BF 3C 3F }

    condition:
        $header at 0
}

rule YouTube_Timed_Text_subtitle_file
{
    meta:
        description = "YouTube Timed Text (subtitle) file"
        file_class = "Video"
        extensions = "YTT"

    strings:
        $header = { EF BB BF 3C 3F 78 6D 6C 20 76 65 72 73 69 6F 6E }

    condition:
        $header at 0
}

rule FAT12_File_Allocation_Table
{
    meta:
        description = "FAT12 File Allocation Table"
        file_class = "Windows"
        extensions = "(none)"

    strings:
        $header = { F0 FF FF }

    condition:
        $header at 0
}

rule FAT16_File_Allocation_Table
{
    meta:
        description = "FAT16 File Allocation Table"
        file_class = "Windows"
        extensions = "(none)"

    strings:
        $header = { F8 FF FF FF }

    condition:
        $header at 0
}

rule FAT32_File_Allocation_Table_1
{
    meta:
        description = "FAT32 File Allocation Table_1"
        file_class = "Windows"
        extensions = "(none)"

    strings:
        $header = { F8 FF FF 0F FF FF FF 0F }

    condition:
        $header at 0
}

rule FAT32_File_Allocation_Table_2
{
    meta:
        description = "FAT32 File Allocation Table_2"
        file_class = "Windows"
        extensions = "(none)"

    strings:
        $header = { F8 FF FF 0F FF FF FF FF }

    condition:
        $header at 0
}

rule Bitcoin_Qt_blockchain_block_file
{
    meta:
        description = "Bitcoin-Qt blockchain block file"
        file_class = "E-money"
        extensions = "DAT"

    strings:
        $header = { F9 BE B4 D9 }

    condition:
        $header at 0
}

rule XZ_archive
{
    meta:
        description = "XZ archive"
        file_class = "Compressed archive"
        extensions = "XZ"

    strings:
        $header = { FD 37 7A 58 5A 00 }

    condition:
        $header at 0
}

rule MS_Publisher_subheader
{
    meta:
        description = "MS Publisher subheader"
        file_class = "Word processing"
        extensions = "PUB"

    strings:
        $header = { FD 37 7A 58 5A 00 }

    condition:
        $header at 512
}

rule Thumbs_db_subheader
{
    meta:
        description = "Thumbs.db subheader"
        file_class = "Windows"
        extensions = "DB"

    strings:
        $header = { FD FF FF FF }

    condition:
        $header at 512
}

rule MS_Publisher_file_subheader
{
    meta:
        description = "MS Publisher file subheader"
        file_class = "Word processing suite"
        extensions = "PUB"

    strings:
        $header = { FD FF FF FF 02 }

    condition:
        $header at 512
}

rule Microsoft_Outlook_Exchange_Message
{
    meta:
        description = "Microsoft Outlook-Exchange Message"
        file_class = "Email"
        extensions = "MSG"

    strings:
        $header = { FD FF FF FF 04 }

    condition:
        $header at 512
}

rule QuickBooks_Portable_Company_File
{
    meta:
        description = "QuickBooks Portable Company File"
        file_class = "Financial"
        extensions = "QBM"

    strings:
        $header = { FD FF FF FF 04 }

    condition:
        $header at 512
}

rule Visual_Studio_Solution_subheader
{
    meta:
        description = "Visual Studio Solution subheader"
        file_class = "Programming"
        extensions = "SUO"

    strings:
        $header = { FD FF FF FF 04 }

    condition:
        $header at 512
}

rule PowerPoint_presentation_subheader_4
{
    meta:
        description = "PowerPoint presentation subheader_4"
        file_class = "Presentation"
        extensions = "PPT"

    strings:
        $header = { FD FF FF FF 0E 00 00 00 }

    condition:
        $header at 512
}

rule Excel_spreadsheet_subheader_2
{
    meta:
        description = "Excel spreadsheet subheader_2"
        file_class = "Spreadsheet"
        extensions = "XLS"

    strings:
        $header = { FD FF FF FF 10 }

    condition:
        $header at 512
}

rule PowerPoint_presentation_subheader_5
{
    meta:
        description = "PowerPoint presentation subheader_5"
        file_class = "Presentation"
        extensions = "PPT"

    strings:
        $header = { FD FF FF FF 1C 00 00 00 }

    condition:
        $header at 512
}

rule Excel_spreadsheet_subheader_3
{
    meta:
        description = "Excel spreadsheet subheader_3"
        file_class = "Spreadsheet"
        extensions = "XLS"

    strings:
        $header = { FD FF FF FF 1F }

    condition:
        $header at 512
}

rule Developer_Studio_subheader
{
    meta:
        description = "Developer Studio subheader"
        file_class = "Programming"
        extensions = "OPT"

    strings:
        $header = { FD FF FF FF 20 }

    condition:
        $header at 512
}

rule Excel_spreadsheet_subheader_4
{
    meta:
        description = "Excel spreadsheet subheader_4"
        file_class = "Spreadsheet"
        extensions = "XLS"

    strings:
        $header = { FD FF FF FF 22 }

    condition:
        $header at 512
}

rule Excel_spreadsheet_subheader_5
{
    meta:
        description = "Excel spreadsheet subheader_5"
        file_class = "Spreadsheet"
        extensions = "XLS"

    strings:
        $header = { FD FF FF FF 23 }

    condition:
        $header at 512
}

rule Excel_spreadsheet_subheader_6
{
    meta:
        description = "Excel spreadsheet subheader_6"
        file_class = "Spreadsheet"
        extensions = "XLS"

    strings:
        $header = { FD FF FF FF 28 }

    condition:
        $header at 512
}

rule Excel_spreadsheet_subheader_7
{
    meta:
        description = "Excel spreadsheet subheader_7"
        file_class = "Spreadsheet"
        extensions = "XLS"

    strings:
        $header = { FD FF FF FF 29 }

    condition:
        $header at 512
}

rule PowerPoint_presentation_subheader_6
{
    meta:
        description = "PowerPoint presentation subheader_6"
        file_class = "Presentation"
        extensions = "PPT"

    strings:
        $header = { FD FF FF FF 43 00 00 00 }

    condition:
        $header at 512
}

rule OS_X_ABI_Mach_O_binary_32_bit_
{
    meta:
        description = "OS X ABI Mach-O binary (32-bit)"
        file_class = "Programming"
        extensions = "(none)"

    strings:
        $header = { FE ED FA CE }

    condition:
        $header at 0
}

rule OS_X_ABI_Mach_O_binary_64_bit_
{
    meta:
        description = "OS X ABI Mach-O binary (64-bit)"
        file_class = "Programming"
        extensions = "(none)"

    strings:
        $header = { FE ED FA CF }

    condition:
        $header at 0
}

rule JavaKeyStore
{
    meta:
        description = "JavaKeyStore"
        file_class = "Programming"
        extensions = "(none)"

    strings:
        $header = { FE ED FE ED }

    condition:
        $header at 0
}

rule Symantex_Ghost_image_file
{
    meta:
        description = "Symantex Ghost image file"
        file_class = "Compressed archive"
        extensions = "GHO|GHS"

    strings:
        $header = { FE EF }

    condition:
        $header at 0
}

rule UTF_16_UCS_2_file
{
    meta:
        description = "UTF-16-UCS-2 file"
        file_class = "Windows"
        extensions = "(none)"

    strings:
        $header = { FE FF }

    condition:
        $header at 0
}

rule Windows_executable
{
    meta:
        description = "Windows executable"
        file_class = "Windows"
        extensions = "SYS"

    strings:
        $header = { FF }

    condition:
        $header at 0
}

rule Works_for_Windows_spreadsheet
{
    meta:
        description = "Works for Windows spreadsheet"
        file_class = "Spreadsheet"
        extensions = "WKS"

    strings:
        $header = { FF 00 02 00 04 04 05 54 }

    condition:
        $header at 0
}

rule QuickReport_Report
{
    meta:
        description = "QuickReport Report"
        file_class = "Financial"
        extensions = "QRP"

    strings:
        $header = { FF 0A 00 }

    condition:
        $header at 0
}

rule Windows_international_code_page
{
    meta:
        description = "Windows international code page"
        file_class = "Windows"
        extensions = "CPI"

    strings:
        $header = { FF 46 4F 4E 54 }

    condition:
        $header at 0
}

rule Keyboard_driver_file
{
    meta:
        description = "Keyboard driver file"
        file_class = "Windows"
        extensions = "SYS"

    strings:
        $header = { FF 4B 45 59 42 20 20 20 }

    condition:
        $header at 0
}

rule WordPerfect_text_and_graphics
{
    meta:
        description = "WordPerfect text and graphics"
        file_class = "Word processing suite"
        extensions = "WP|WPD|WPG|WPP|WP5|WP6"

    strings:
        $header = { FF 57 50 43 }

    condition:
        $header at 0
}

rule Generic_JPEG_Image_file
{
    meta:
        description = "Generic JPEG Image file"
        file_class = "Picture"
        extensions = "JPE|JPEG|JPG"

    strings:
        $header = { FF D8 }
        $trailer = { FF D9 }

    condition:
        $header at 0 and $trailer
}

rule JPEG_EXIF_SPIFF_images
{
    meta:
        description = "JPEG-EXIF-SPIFF images"
        file_class = "Picture"
        extensions = "JFIF|JPE|JPEG|JPG"

    strings:
        $header = { FF D8 FF }
        $trailer = { FF D9 }

    condition:
        $header at 0 and $trailer
}

rule MPEG_4_AAC_audio
{
    meta:
        description = "MPEG-4 AAC audio"
        file_class = "Audio"
        extensions = "AAC"

    strings:
        $header = { FF F1 }

    condition:
        $header at 0
}

rule MPEG_2_AAC_audio
{
    meta:
        description = "MPEG-2 AAC audio"
        file_class = "Audio"
        extensions = "AAC"

    strings:
        $header = { FF F9 }

    condition:
        $header at 0
}

rule Windows_Registry_file
{
    meta:
        description = "Windows Registry file"
        file_class = "Windows"
        extensions = "REG"

    strings:
        $header = { FF FE }

    condition:
        $header at 0
}

rule UTF_32_UCS_2_file
{
    meta:
        description = "UTF-32-UCS-2 file"
        file_class = "Windows"
        extensions = "(none)"

    strings:
        $header = { FF FE }

    condition:
        $header at 0
}

rule UTF_32_UCS_4_file
{
    meta:
        description = "UTF-32-UCS-4 file"
        file_class = "Windows"
        extensions = "(none)"

    strings:
        $header = { FF FE 00 00 }

    condition:
        $header at 0
}

rule MSinfo_file
{
    meta:
        description = "MSinfo file"
        file_class = "Windows"
        extensions = "MOF"

    strings:
        $header = { FF FE 23 00 6C 00 69 00 }

    condition:
        $header at 0
}

rule DOS_system_driver
{
    meta:
        description = "DOS system driver"
        file_class = "Windows"
        extensions = "SYS"

    strings:
        $header = { FF FF FF FF }

    condition:
        $header at 0
}
