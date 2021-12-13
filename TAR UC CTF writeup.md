Sadly these flags were not found during the contest but after on the rehosted version haha, and got a lots of hints from other participants and gamemasters.

There are 23 flags altogether in original version and 22 flags on rehosted version at https://canyouseeme.ml/ (submit flags at verdesec.net/)

Extra flag in original version is embedded in an access token sent to participants in email upon successful registration, base64 decode the access token to capture flag.

The following flag list is given during the contest as hint

Flag list:
flag #1: Participant Access Kit
flag #2: Linux App
flag #3: Firebase Storage
flag #4: 404
flag #5: Main page
flag #6: Main page
flag #7: Firebase Stoage
flag #8: Windows App
flag #9: Firebase Auth
flag #10: Firebase
flag #11: Windows App
flag #12: "Give me the flag!"
flag #13: Site Picture
flag #14: 404
flag #15: Hint 1
flag #16: Linux App
flag #17: Windows App
flag #18: DNS
flag #19: Github
flag #20: Favicon
flag #21: Github
flag #22: Site Picture
flag #23: Favicon

Flag #1 is only available in original version.

Flag #2: Linux App

verdesec{NUM83r_6U3551N6_M4573r_8r4V0}

First download linux binary from website homepage, put into reverse engineering tool such as Ghidra/radare2. Analyse the binary 
found that the random prime number is generated only after user input, therefore it is practically imporssible to guess the number without bypassing the check.

The related code section is around 0x4A1FB2, after taking user input and generating random prime number, checks for input length and content are performed. The jumps
instructions at 0x4A2017 and 0x4A202D are patched to Nop instructions to skip checks. Run the binary and input anything to capture flag.

The output of linux binary shows not only flag#2 but also a suspicious string which is later revealed to be flag#16.


Flag #3: Firebase Storage

verdesec{53Cr37_5P4M_1N_CL0UD_570r463}

In website main page, open console then try to list files in firebase storage bucket using following js code:

a = firebase.storage();
zref = a.ref('/');
zref.listAll().then((res) => {
    res.prefixes.forEach((folderRef) => {
      // All the prefixes under listRef.
      // You may call listAll() recursively on them.
console.log(folderRef.fullPath)
console.log(folderRef.name)
    });
    res.items.forEach((itemRef) => {
      // All the items under listRef.
console.log(itemRef.fullPath)
console.log(itemRef.name)
itemRef.getDownloadURL().then((url)=>{console.log(url)})
    });
  }).catch((error) => {
    // Uh-oh, an error occurred!
console.error("err")
  })

A suspicious file named "5p4MM1m1C.txt" with spam looking texts inside is found, the file name ressembled word "spammimic", google searching the word revealed it is a stegno tool,
https://www.spammimic.com/decode.cgi, decode file content and capture flag.

Flag #4: 404

verdesec{4N_1NN0C3N7_H77P_H34D3r_1N_404}

Goto any site URL that will cause 404, capture the HTTP response and inspect headers to capture flag.

Flag #5: Main page

verdesec{H0W_480U7_50M3_r074710N5_HUH}

Inspect main page source code comment and found string "T6P56Q64Yj_(0pt_&s0q_|o0P_sps`_}q0j&jA", I don't really have any idea during the contest but with hints after contest ended
I foudn out it needs to be first decrypted using rot 13 then decrypt the result again using rot 47, then final result is the flag.

Flag #6: Main page

verdesec{W3LC0M3_70_7H3_F1r57_3V3r_74R_UC_C7F}

Easiest flag to capture, inspect site home page source code, flag plaintext inside.

Flag #7: Firebase Stoage

verdesec{F1L3_M374D474_0N_CL0UD_570r463}

Open browser dev console on home page, use following js to get file metadata for files in firebase storage
a = firebase.storage();
zref = a.ref('/');

zref.listAll().then((res) => {
    res.items.forEach((itemRef) => {
      // All the items under listRef.
itemRef.getMetadata().then(e=>console.log(e))
    });
  }).catch((error) => {
    // Uh-oh, an error occurred!
console.error("err")
  })
  
The file metadata of "5p4MM1m1C.txt" has a flag hidden inside, inspect and capture.

Flag #8: Windows App

verdesec{xor_is_always_here}

Download from homepage and put windows binary in reverse engineering tool, investigate function flag3::process at address 0x41C008, look at argument of qmemcpy at 0x41C020, 
follow the offset to 0x4A20A0 and get hex string "382B3C2A2B3D2B2D3536213C11273D112F22392F373D11262B3C2B33", 
which is later found to be xor encrypted, continue looking at previous function's for loop we know that the string is decrypted with key 0x4E, decrypt to capture flag.

decrypt tool: https://www.dcode.fr/xor-cipher

Flag #9: Firebase Auth

verdesec{1MM4_r361573r_MY_0WN_3M41L}

Ppen browser console at main page, use following js to create account and sent verification email

a = firebase.auth()
//make sure you are able to receive email with the email address
a.createUserWithEmailAndPassword("example@example.com", "anydummypassword")
//wait a while for the account to be created, then run following line to sent verfication email
a.currentUser.sendEmailVerification()

wait for verification email and flag is in the verification link, decode the URL to get flag

Verification link example:
https://taruc.ctf/verdesec%7B1MM4_r361573r_MY_0WN_3M41L%7D?mode=verifyEmail&oobCode=kHbw9Q2zbsmQM9GIA21zSxKEE0BYB3vvs7vr91jXZg4AAAF9dAupig&apiKey=AIzaSyBd-14q8AXdaKbMpMQ1PnRqIy8Z-pksYfA&lang=en

Flag #10: Firebase

verdesec{53CUr17Y_rUL35_84D_Pr4C71C3}

Open dev console at main page, get firebase credential info by looking at variable "firebaseConfig", get database url, append "/.json", 
found out db has been configured to allowed unauthenticated access which "leak" the flag
https://aad1smlehqrwz9dab038e2ovicvcw3-default-rtdb.asia-southeast1.firebasedatabase.app/.json
{"flag":"verdesec{53CUr17Y_rUL35_84D_Pr4C71C3}","welcome":{"subtitle":"I've dropped 22 flags in this website, gotta capture 'em all!","title":"Can You See Me?"}}

Flag #11: Windows App

verdesec{beginner_re_challenge}

Download and put windows binary in reverse engineer tool, follow flag2::process at address 0x41BEF0, look at argument of qmemcpy at 0x41BF5C, 
follow to address 0x4A2020, flag plaintext at there.

Flag #12: "Give me the flag!"

verdesec{345Y_J5_4ND_H45H_r3V3r53_L00KUP}

Goto main page, find 5Cr1P7-2.js, extract obfuscated js expression from just before the ternary operator "?" that return success or error message "Nope, this is not ...", 
use eval to evaluate the expression and get sha256 of flag: 8dc3b04e3fd82036e8875c7806ba3e110e30f96684bba85f957c5864d15c52c6

The method I know the string is a sha256 hash is by using same method above, the parameter of hash function in same file is obfuscated with same technique.
Crack hash and capture flag at
https://md5hashing.net/hash/sha256/8dc3b04e3fd82036e8875c7806ba3e110e30f96684bba85f957c5864d15c52c6

Initially I tried to brute force using hashcat and failed. Maybe try to grab a list of hash cracking sites for CTF next time is a good idea.

Flag #13: Site Picture

verdesec{845364_3NC0D3D_1N_D474_80U7_D474}

Open main page source code, download "apple-touch-icon.png", put in aperi solve (https://aperisolve.fr/), find exif comment string, base64 decode to capture flag.

Flag #14: 404

verdesec{P3rH4P5_CH3CK_0U7_7H3_84CK6r0UND}

Goto any URL leads to 404 page, inspecting source code and stylesheet(404.css) found strings encoded in hex, inspect element 404 page and uncheck all hidden/invisible attribute
to reveal flag.

Flag #15: Hint 1

verdesec{H11_C4N_Y0U_H34r_M3}

goto site https://canyouseeme.ml/robots.txt, found a path to an audio file 5UP3r-DUP3r-53Cr37-F1L3.mp3, download it and use dtmf decoder on https://github.com/lzxuan/dtmf-decoder
get an ascii char code string 118 101 114 100 101 115 101 99 123 72 49 49 95 67 52 78 95 89 48 85 95 72 51 52 114 95 77 51 125
convert to string for flag.

Flag #16: Linux App

verdesec{600D_64M3_W3LL_PL4Y3D}

When Flag #2 is captured, the linux binary gave a weird string "~hfym~q~s;$-LR")E>KJ;AXBXA D;Ii". By tracing through the binary with debugger and looking at the for loop processing the 
weird string, I found that the string is encrypted using 4 bytes xor key, as the modulo=4, 
at 0x4A22C7, rax is divided with r8, the remainder is stored in rdx, then at 0x4A222E, the rdx is used as an index to access a byte used as key to xor with the weird string.
By placing breakpoints, I was able to determien r8's value is 4 (the modulo).

However the key seems is not inside the binary itself. Since it is known that flag starts with "verd", by XORing "verd" with "~hfy", we get xor key 0x08 0x0D 0x14 0x1D, 
and using https://www.dcode.fr/xor-cipher, the flag is decrypted and captured.

Update 13Dec2021: Actually the key can be found in the binary according to the official writeup released at https://bit.ly/TARUCCTF2021WriteUp 

Flag #17: Windows App

verdesec{nonstop_netflag_november}

Download and put windows binary in reverse engineering tool, and look at function flag1::process at 0x41BEF0, follow the flow of the function at found plaintext flag at 0x4A406C.

Flag #18: DNS

verdesec{W04H_4_DN5_7X7_r3C0rD_F0r_FUN}

Use any DNS TXT record lookup tool on challenge site domain name canyouseeme.ml, plaintext flag in TXT records.

Flag #19: Github

verdesec{H1D1N6_1N_H1570rY}

From https://github.com/lzxuan/canyouseeme (this github repo is found by looking at url of challenge site 404 page background image), branch "flag", second oldest commit, 
flag.txt contains string "n,2MMr9F4VimF^\W7S5mW7T&:W3!/$lbMQ"
decode using base 85, then use cyberchef magic recipe to brute force xor key and decrypt

Flag #20: Favicon

verdesec{L00K_0U7_7r41L1N6_D474_4F73r_13ND}

Download site favicon "favicon-16x16.png" found from main page source, inspect with hex editor, found plaintext flag at end of file.

Flag #21: Github

verdesec{3Y3516H7_73571N6_0N3_7W0_7Hr33}

From site 404 page, inspect css file, find bg img url which lead to github repo, goto branch flag, goto commit "update", download maintenance.jpg, put into aperisolve
https://aperisolve.fr/779d62f602e3a4a3606024fbf4cce5c5
Look at result of aperisolve and get flag. The flag is found by submitting every image found on challenge site onto aperisolve.

Flag #22: Site Picture

verdesec{Qr_C0D3_r3C0V3rY_M4573r}

Inspect main page source and download canyouseeme.ml/android-chrome-192x192.png, run binwalk on it and found extra png file inside, 
extracted it out seems to be qr code but scanner fail to scan
Attemping to fix the qr code, first fix the alignment patern (usually there is a square with dot inside at qr code right bottom corner) using any image editor, 
then goto https://merricx.github.io/qrazybox/, upload partially fixed image and set error correction level to L, mask pattern to 2 (the correct combination is found by brute force),
finally extract data for flag.

Flag #23: Favicon

verdesec{1M463_H1D1N6_1N_F4V1C0N1C0}

Download canyouseeme.ml/favicon.ico

Open in image editor, flag hidden in fourth image layer.
