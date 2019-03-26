# Algorithm-Project

The RSA algorithm is one of the most important algorithms. It is the cornerstone of computer communication security, ensuring that encrypted data will not be cracked. Prior to 1976, all encryption methods were "Symmetric-key algorithm". It is characterized by the same key used for both encryption and decryption, that is, the encryption key can also be used as a decryption key. This method is called symmetric encryption algorithm in cryptography. It has features such as simple, fast use, short key, and difficult to decrypt. However, this encryption method has one of the biggest weaknesses: sender must tell receiver the encryption rules, otherwise it cannot be decrypted. If one of the keys is compromised, the encrypted information is not safe.
In 1976, two American computer scientists, Whitfield Diffie and Martin Hellman, proposed a new concept that could be decrypted without directly passing the key
, which is called the "Diffie-Hellman Key Exchange Algorithm." If the public key encrypted information is only unlocked by the private key, the communication is safe as long as the private key does not leak. It is recognized that encryption and decryption can use different rules as long as there is some correspondence between the two rules, thus avoiding the direct transfer of the key. This new encryption mode is called an "asymmetric encryption algorithm." Asymmetric encryption is more secure than symmetric encryption. However, its disadvantage is that encryption and decryption take a long time and it is only suitable for encrypting a small amount of data.
In 1977, three scientists Rivest, Shamir, and Adleman designed an algorithm that could implement asymmetric encryption. This algorithm is named with their names, called the RSA algorithm. The RSA encryption algorithm is the most commonly used asymmetric encryption algorithm. RSA is also the first well-established public key algorithm that can be used for both encryption and digital signatures. Without the RSA algorithm, the current online world is not secure, and it is impossible to have online transactions today. For example, the SSH protocol is based on RSA encryption to ensure that communications are encrypted and reliable.

This algorithm is very reliable, and the longer the key, the harder it is to crack. The RSA algorithm is based on a very simple theory of number theory: it is very easy to multiply two large prime numbers, but it is extremely difficult to factorize the product. Therefore, the product can be exposed as an encryption key. The security of RSA is based on the difficulty of large number decomposition. The difficulty of recovering plaintext from a public key and ciphertext is equivalent to decomposing the product of two large prime numbers, which is recognized as a difficult mathematical problem. If you want to crack the RSA, you must calculate the private key based on the public key. There is no relatively good algorithm for the large number decomposition. It's easy to break down a four-digit number, but for a forty digit it's probably not that easy. 
