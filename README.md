# ShaRKF00D
ShaRKF00D is an all in one extractor, decrypter, and installer for SceShaccCg module which complements vitaShaRK https://github.com/Rinnegatamante/vitaShaRK

This project makes use of many already existing tools and is just put together to make it easier to obtain the SceShaccCg module.

# Install Instructions
First you will need to install PSM Runtime **with 2.01 patch update**.
You will need to make sure you have 2.01 patch version as this installer is not compatible with just PSM Runtime 1.0 installed.

Download and install ShaRKF00D.vpk using Vita Shell.
Run the app and wait for it to exit out. There is no user dialogue for now.

You should now have libshacccg.suprx module in ur0:/data/. You can check with VitaShell or ftp.
The decrypted elf version of the file will be under ux0:/ShaRKF00D/. You may delete this if you like.

# Build Instructions
```
chmod +x build.sh
mkdir build && cd build
../build.sh
```

# Credits

**TheFlow** for VitaShell.
**CelesteBlue/dots-tb** for FAGDec.
All of whom that were involved with the development of vita-make-fself.

