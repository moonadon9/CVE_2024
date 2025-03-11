# CVE_2024_44866

# Vulnerability Title
MuseScore Arbitrary Code Execution Vulnerability Due to Stack Buffer Overflow
    
# High-level overview of the vulnerability and the possible effect of using it
    
A critical vulnerability has been identified in the ‘tuning’ array within the ‘GuitarPro1::read’ function in the ‘importgtp.cpp’ file.
This stack buffer overflow can be exploited by attackers to execute arbitrary code, potentially leading to severe security issues.
    
Exploiting this vulnerability allows attackers to gain control of the system, resulting in:
    
- Sensitive data leakage
- System instability
- Installation of malicious programs
    
It is essential to address and fix this vulnerability promptly to prevent potential security breaches.
    
# Exact product that was found to be vulnerable including complete version information
    
**MuseScore Studio 64-bit ver 4.3.2**
**Proof Environment : windows10, windows11**
    
# Root Cause Analysis (recommended but not required)
    
src/importexport/guitarpro/internal/importgtp.cpp
    
```
bool GuitarPro1::read(IODevice* io)
{
    
...
    
    for (size_t i = 0; i < staves; ++i) {
        int tuning[GP_MAX_STRING_NUMBER];    // [1]
    
        int strings  = version > 101 ? readInt() : 6;    // [2]
        for (int j = 0; j < strings; ++j) {
            tuning[j] = readInt();          // [3]
        }
    }
}
```
    
src/importexport/guitarpro/internal/importgtp.h
    
```
namespace mu::iex::guitarpro {
    static constexpr int GP_MAX_LYRIC_LINES = 5;   
    static constexpr int GP_MAX_TRACK_NUMBER = 32;
    static constexpr int GP_MAX_STRING_NUMBER = 7;    // [4]
```
    
1. **Array Declaration with Fixed Size:**
In step [1], an array is declared with a constant size. The size of this array is confirmed to be 7 in step [4].
2. **Determination of Strings Value Based on Version:**
In step [2], if the ‘`version`' is greater than 101, the value of ‘`strings`' is determined through ‘`readInt`'.
Therefore, by setting the ‘`version`' to greater than 101, the ‘`strings`' value can be set greater than the array size of 7,
causing a stack buffer overflow.
3. **Injection of Malicious Data into Buffer:**
In step [3], an attacker can input desired values into the buffer.
    
In the ‘`importScore`' function within the ‘`src/importexport/guitarpro/internal/importgtp.cpp`' file,
the GuitarPro file is parsed. This function verifies the signature and version of the GuitarPro
file and then parses the data using the appropriate ‘`read`' function based on the version.
If the version is 1.??, it calls the vulnerable ‘`GuitarPro1::read`' function.
    
To prevent this vulnerability, add code to compare the ‘`strings`' value with ‘`GP_MAX_STRING_NUMBER`'
after receiving the ‘`strings`' value as input. If the ‘`strings`' value is greater than the buffer size,
handle the exception accordingly.
    
Below is the ‘`importScore`' function from the ‘`src/importexport/guitarpro/internal/importgtp.cpp`' file mentioned above.
    
```c
static Err importScore(MasterScore* score, muse::io::IODevice* io, bool experimental = false)
{
    if (!io->open(IODevice::ReadOnly)) {
        return Err::FileOpenError;
    }
    
    score->loadStyle(u":/engraving/styles/gp-style.mss");
    if (experimental) {
        score->loadStyle(u":/engraving/styles/gp-style-experimental.mss");
    }
    
    score->checkChordList();
    io->seek(0);
    char header[5];
    io->read((uint8_t*)(header), 4);
    header[4] = 0;
    io->seek(0);
    if (strcmp(header, "ptab") == 0) {
        PowerTab ptb(io, score);
        return ptb.read();
    }
    
    ...
    
    // otherwise it's an older version - check the header
    else if (strcmp(&header[1], "FIC") == 0) {
        uint8_t l;
        io->read((uint8_t*)&l, 1);
        char ss[30];
        io->read((uint8_t*)(ss), 30);
        ss[l] = 0;
        String s = String::fromUtf8(ss);
        if (s.startsWith(u"FICHIER GUITAR PRO ")) {
            s = s.mid(20);
        } else if (s.startsWith(u"FICHIER GUITARE PRO ")) {
            s = s.mid(21);
        } else {
            LOGD("unknown gtp format <%s>", ss);
            return Err::FileBadFormat;
        }
        int a = s.left(1).toInt();
        int b = s.mid(2).toInt();
        int version = a * 100 + b;
        if (a == 1) {
            gp = new GuitarPro1(score, version);
        } else if (a == 2) {
            gp = new GuitarPro2(score, version);
        } else if (a == 3) {
            gp = new GuitarPro3(score, version);
        } else if (a == 4) {
            gp = new GuitarPro4(score, version);
        } else if (a == 5) {
            gp = new GuitarPro5(score, version);
        } else {
            LOGD("unknown gtp format %d", version);
            return Err::FileBadFormat;
        }
        readResult = gp->read(io); //guitarpro1::read
    ```
    
# Proof-of-Concept
    
    The proof-of-concept includes two files, both demonstrating arbitrary code execution by launching the calculator.
    
    ## Verification Environment
    
    The verification was conducted on the following environments:
    
    - Windows 11 Version 23H2 (OS build 22631.3737)
    - Windows 11 Version 23H2 (OS build 22631.3447)
    - Windows 10 Version 22H2 (OS build 19045.4529)
    
    ## Proof-of-Concept Details
    
    - **musescore_exploit_doubleclick.gtp**: This file can be verified by double-clicking it to run the program in MuseScore.
    - **musescore_exploit_inopen.gtp**: This file can be verified by first launching the MuseScore program,
    then navigating to File → Open in the top left, and opening the file.
    
    The proof-of-concept is accompanied by demonstration videos. For verification steps, please refer to the demonstration videos.
    Proof-of-concept files and videos are attached.

# code patch
It has been patched in MuseScore Studio 64-bit ver 4.4.4
https://github.com/musescore/MuseScore/commit/0630461b734201db24139b0dc1657371fce41fb9
