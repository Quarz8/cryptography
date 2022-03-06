# cryptography
Coding done in my Advanced Cryptography class. Each .java file is it's own stand-alone project. I'm just putting them on here for record keeping.
EuclideanAlgorithm.java and ExtendedEuclideanAlgorithm.java are what they sound like; implementations of the Euclidean and Extended Euclidean algorithms respectively. Each file contains its own main method with various hard-coded test cases.
AES128.java contains methods to encrypt a block of hexidecimal data using the AES128 encryption standard, implemented by me. There is a main method which tests the different parts of AES (subBytes, shiftRows, mixColumns, scheduleRound, and addRoundKey) which all come together to complete the enryption of the hexidecimal plaintext.txt file into the ciphertext.txt file. File paths will obviously need to be changed if you want to run AES128.java yourself.
As for decryption... well, you're on your own for that, haha.
