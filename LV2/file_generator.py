import base64


class CryptoFileCreator:
    """
         Metoda koja datoteku u koju se piše željeni tekst.
    """

    @staticmethod
    def create_msg_file(msg):
        file = open("Datoteka.x", "w")
        file.write(msg)

    """
        Metoda koja stvara pocečetni dio datoteke koji je jednak svima(description, method).
    """

    @staticmethod
    def create_default_file(file_name, description, method):
        file = open(file_name, "w")
        file.write("---BEGIN OS2 CRYPTO DATA---\n")
        file.write("Description:\n")
        file.write("    {}\n".format(description))
        file.write("\n")
        file.write("Method:\n")
        file.write("    {}\n".format(method))
        file.write("\n")
        return file

    """
        Metoda za segmentaciju podataka na traženu duljinu od 60 elemenata po redu, 
        nakon čega je potrebno početi zapisivati u novi red.
    """

    @staticmethod
    def write_large_hex_data(file, hex_data):
        chunks = [hex_data[i:i + 60] for i in range(0, len(hex_data), 60)]
        for chunk in chunks:
            file.write("    {}\n".format(chunk))
        file.write("\n")

    """
        Metoda koja stvara datoteke s RSA ključevima pošiljatelja i primatelja.
    """

    @staticmethod
    def create_RSA_crypto_file(origin, key, key_type):
        if key_type == "private":
            file_name = origin + "_RSA_private_key.x"
            description = "Private Key"
        else:  # else public
            file_name = origin + "_RSA_public_key.x"
            description = "Public Key"
        file = CryptoFileCreator.create_default_file(file_name, description, "RSA")
        file.write("Key length:\n")
        key_length = key.n.bit_length()
        key_length = hex(key_length)[2:]
        if len(key_length) % 2 != 0:
            key_length = "0" + key_length
        file.write("    {}\n".format(key_length))
        file.write("\n")
        file.write("Modulus:\n")
        hex_key_modulus = hex(key.n)[2:]
        CryptoFileCreator.write_large_hex_data(file, hex_key_modulus)
        if key_type == "private":
            file.write("Private exponent:\n")
            hex_key_exponent = hex(key.d)[2:]
        else:
            file.write("Private exponent:\n")
            hex_key_exponent = hex(key.e)[2:]
            if len(hex_key_exponent) % 2 != 0:
                hex_key_exponent = "0" + hex_key_exponent
        CryptoFileCreator.write_large_hex_data(file, hex_key_exponent)
        file.write("---END OS2 CRYPTO DATA---")
        file.close()

    """
        Metoda koja stvara datoteke vezane uz simetrične algoritme (DES, AES).
    """

    @staticmethod
    def create_sym_system_crypto_files(type, mode, msg, secret_key):
        # Napravi [AES, DES] kriptiranu datoteku.
        if mode == "CBC":
            # CBC ima incijalizacijski vektor, a ECB nema
            str_msg = str(msg[1])[2:-1] + str(msg[0])[2:-1]
        else:
            str_msg = str(msg[0])[2:-1]
        method = type + "\n    " + mode
        file = CryptoFileCreator.create_default_file(str(type) + "_crypted_file.x", "Crypted file", method)
        file.write("File Name:\n")
        file.write("    Datoteka.x\n")
        file.write("\n")
        file.write("Data:\n")
        str_msg = str_msg.encode("utf-8")
        encoded_msg = base64.b64encode(str_msg)
        encoded_msg = str(encoded_msg)[2:-1]
        CryptoFileCreator.write_large_hex_data(file, encoded_msg)
        file.write("---END OS2 CRYPTO DATA---")
        file.close()

        # Napravi datoteku s [AES, DES] sjedničkim ključem.
        file = CryptoFileCreator.create_default_file(str(type) + "_session_key.x", "Secret key", method)
        file.write("Secret Key:\n")
        secret_key = str(secret_key)[2:-1]
        secret_key = secret_key.encode("utf-8")
        encoded_key = base64.b64encode(secret_key)
        encoded_key = str(encoded_key)[2:-1]
        file.write("    {}\n".format(encoded_key))
        file.write("\n")
        file.write("---END OS2 CRYPTO DATA---")
        file.close()

    """
         Metoda koja stvara datoteku s potpisom.
    """

    @staticmethod
    def create_sig_file(sha_version, rsa_key_size, signature):
        file = open("signature_file.x", "w")
        file.write("---BEGIN OS2 CRYPTO DATA---\n")
        file.write("Description:\n")
        file.write("    Signature\n")
        file.write("\n")
        file.write("File name:\n")
        file.write("    Datoteka.x\n")
        file.write("\n")
        file.write("Method:\n")
        sha_version = str(sha_version).replace("_", "-")
        file.write("    SHA{}\n".format(sha_version))
        file.write("    RSA\n")
        if sha_version == "3-256":
            key_len = 256
        else:  # 3-512
            key_len = 512
        key_len = str(hex(key_len))[2:]
        if len(key_len) % 2 != 0:
            key_len = "0" + key_len
        file.write("Key length:\n")
        file.write("    {}\n".format(key_len))
        rsa_key_size = str(hex(rsa_key_size))[2:]
        if len(rsa_key_size) % 2 != 0:
            rsa_key_size = "0" + rsa_key_size
        file.write("    {}\n".format(rsa_key_size))
        file.write("\n")
        file.write("Signature:\n")
        signature = str(hex(signature))[2:]
        CryptoFileCreator.write_large_hex_data(file, signature)
        file.write("---END OS2 CRYPTO DATA---")
        file.close()

    """
            Metoda koja stvara datoteku omotnice.
    """

    @staticmethod
    def create_env_file(rsa_key_size, sym_system_type, sym_key_size, crypt_key, envelope_data):
        file = open("envelope_file.x", "w")
        file.write("---BEGIN OS2 CRYPTO DATA---\n")
        file.write("Description:\n")
        file.write("    Envelope\n")
        file.write("\n")
        file.write("File name:\n")
        file.write("    Datoteka.x\n")
        file.write("\n")
        file.write("Method:\n")
        file.write("    {}\n".format(str(sym_system_type)))
        file.write("    RSA\n")
        file.write("Key length:\n")
        sym_key_size = sym_key_size * 8
        if sym_system_type == "DES3":
            if sym_key_size == 128:
                sym_key_size = 112
            elif sym_key_size == 192:
                sym_key_size = 168
        sym_key_size = hex(sym_key_size)[2:]
        if len(sym_key_size) % 2 != 0:
            sym_key_size = "0" + sym_key_size
        file.write("    {}\n".format(sym_key_size))
        rsa_key_size = str(hex(rsa_key_size))[2:]
        if len(rsa_key_size) % 2 != 0:
            rsa_key_size = "0" + rsa_key_size
        file.write("    {}\n".format(rsa_key_size))
        file.write("\n")
        file.write("Envelope data:\n")

        if len(envelope_data) == 2:  # CBC
            envelope_data = str(envelope_data[0])[2:-1] + str(envelope_data[1])[2:-1]
        else:  # ECB
            envelope_data = str(envelope_data[0])[2:-1]

        envelope_data = envelope_data.encode("utf-8")
        encoded_data = base64.b64encode(envelope_data)
        encoded_data = str(encoded_data)[2:-1]
        CryptoFileCreator.write_large_hex_data(file, encoded_data)
        file.write("Envelope crypt key:\n")
        crypt_key = crypt_key.hex()
        CryptoFileCreator.write_large_hex_data(file, crypt_key)
        file.write("---END OS2 CRYPTO DATA---")
        file.close()
