# Famine
This project consist to create a simple virus. Famine is an executable file than will infect all other binaries in the target folders appending itself ,so adding new functionalities to target binaries.

# This project has educationals purposes only
This a self replicating virus with a non malicious code source, but malicous code can be added to Famine.
This proyect was done for educational purposes only, i disclaim the responsability if it used for malicous purposes.

# Specifications
- Famine's execution image applies his signature from infected files.
- The signature is: "Famine version 1.0 (c)oded by plamtenz-xxxxxxxx".
- The target folders by default are "/tmp/test/" and "/tmp/test2".
- Famine must infect once each binary.
- Famine has no return, takes no arguments and obiouslly never crash or warning.
- The target environement is Linux x64_86 GNU/Linux (only 64 bits architecture).

# How it works ?
Famine is a very simple virus, a sumary of its architecture is :
    1) Check all the files in the target folders
    2) If file is elf64 and not alreaddy infected
    3) Infect it.
    
# Advanced explenation:

1) Famine will loop into all the target folders.
2) Famine will open the files into this directories.
3) Famine will check if the current file is an elf file. If not, go to next file.
4) Famine will check header and offset sanity.
5) If all is right, is time to get find the PT_LOAD segment who contains the .TEXT and the entry point
6) Check if the file is alreaddy infected
7) If not, save offset addr where code will be writed and the original entry point
8) Find the new entry point
9) Check if there are enought room space to write the code in .TEXT. If space skip 10.
10) No space ? Modify offsets of program, segment and folowing sections, add padding respecting the page size align.
11) Re-write the file adding famines code now is known that there are enought space and offset are shifted.
12) Add padding ultil page size.
13) Famine readdy to infect ! Have a nice day.

# About the project
This is the first virus i've done. Virus branch are so interesting. Next virus is called Pestilence, it will be takes famine's code but will be indetectable.

# TO DO
The code is only written in C i have obiouslly to write it in ASM x64
