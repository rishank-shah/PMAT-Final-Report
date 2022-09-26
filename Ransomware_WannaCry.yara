rule Ransomware_WannaCry {
    
  meta: 
    last_updated = "2022-09-26"
    author = "rishank-shah"
    description = "Yara rule for WannaCry Ransomware"

  strings:
    $string1 = "attrib +h ." fullword ascii
    $string2 = "icacls . /grant Everyone:F /T /C /Q"	fullword ascii
    $string3 = "C:\\%s\\qeriuwjhrf" fullword ascii
    $string4 = "WNcry@2ol7" fullword ascii
    $string5 = "wnry" ascii
    $url = "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii
    $payload = "tasksche.exe" ascii
    $PE_magic_byte = "MZ"  

  condition:
    $PE_magic_byte at 0 and 
    ($url or 1 of ($string*) or $payload)
}