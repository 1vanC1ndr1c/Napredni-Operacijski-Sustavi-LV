import pbkdf2 as pbkdf2
from Crypto.Cipher import AES, DES3
import os


# ======================================================================================================================
# ================================== AES implementacija ================================================================
class AESImplementation:

    """
        Metoda generira simetrični ključ K koji se koristi u enkripciji i dekripciji tokom procesa AES kriptosustava.
        Ključ se generira na temelju imena pošiljatelja. Zadaje se veličina ključa (defaultna veličina je 16 B).
    """
    @staticmethod
    def generate_key_k(name, key_size=16):
        if key_size != 16 and key_size != 24 and key_size != 32:
            key_size = 16
        password = name
        salt = os.urandom(key_size)
        aes_key = pbkdf2.PBKDF2(password, salt).read(key_size)    # 16, 24 ILI 32 B
        return aes_key

    """
        Metoda enkriptira poruku P AES kriptosustavom na temelju ključa K.
        Argumentom 'mode' se bira način kriptiranja (ECB, CBC)
    """
    @staticmethod
    def aes_encrypt(message, key_K, mode):
        # Kod preuzet i modificiran sa adrese:
        # https://www.novixys.com/blog/using-aes-encryption-decryption-python-pycrypto/

        # Inicijalizacijski vektor se koristi kako bi svaka enkripcija dala različiti rezultat.
        # Vektor se šalje zajedno s enkriptiranom porukom. Nije potrebno da je tajan.

        if mode == "ECB":
            aes = AES.new(key_K, AES.MODE_ECB)
            initialization_vector = None                        # Vektor nije potreban kod ECB.
        else:  # else CBC
            initialization_vector = os.urandom(16)
            aes = AES.new(key_K, AES.MODE_CBC, initialization_vector)

        data = bytes(message, 'utf-8')                          # Pretvori poruku iz str u bajtove.
        length = 16 - (len(data) % 16)                          # Dopuni poruku ako je potrebno.
        data += bytes([length]) * length
        encrypted_message = aes.encrypt(data)                   # Napravi AES enkripciju.

        # Povratna vrijednost je poruka i pripadni inicijalizacijski vektor (ako je potreban).
        if mode == "ECB":
            encrypted_message = [encrypted_message]
        else:  # else CBC
            encrypted_message = [encrypted_message, initialization_vector]
        return encrypted_message

    """
        Metoda koja obavlja dekripciju  AES sustava.
        Metoda prima ulazne podatke(poruku i vektor) i potrebni ključ K, te način rada (ECB ili CBC).
    """
    @staticmethod
    def aes_decrypt(key_K, message, initialization_vector, mode):

        if mode == "ECB":
            aes = AES.new(key_K, AES.MODE_ECB)
        else:  # else CBC
            aes = AES.new(key_K, AES.MODE_CBC, initialization_vector)

        decrypted_msg = aes.decrypt(message)
        # Ukloni padding na kraju poruke
        decrypted_msg = decrypted_msg[:-decrypted_msg[-1]]
        return decrypted_msg


# ======================================================================================================================
# ================================== DES-3 implementacija ==============================================================
class DES3Implementation:
    """
        Metoda generira simetrični ključ K koji se koristi u enkripciji i dekripciji tokom procesa DES kriptosustava.
        Ključ se generira na temelju imena pošiljatelja.
    """
    @staticmethod
    def generate_key_k(name,  key_size=8):
        if key_size != 8 and key_size != 16 and key_size != 24:
            key_size = 8
        password = name
        salt = os.urandom(key_size)
        des_key = pbkdf2.PBKDF2(password, salt).read(key_size)  # Key sizes	168, 112 or 56 bits
        return des_key

    """
        Metoda enkriptira poruku P DES3 kriptosustavom na temelju ključa K.
        Argumentom 'mode' se bira način kriptiranja (ECB, CBC).
    """
    @staticmethod
    def des3_encrypt(message, key_K, mode):

        # Inicijalizacijski vektor se koristi kako bi svaka enkripcija dala različiti rezultat.
        # Vektor se šalje zajedno s enkriptiranom porukom. Nije potrebno da je tajan.

        if mode == "ECB":
            des3 = DES3.new(key_K, DES3.MODE_ECB)
            initialization_vector = None                        # Vektor nije potreban kod ECB.
        else:  # else CBC
            des3 = DES3.new(key_K, DES3.MODE_CBC)
            initialization_vector = des3.iv

        data = bytes(message, 'utf-8')                          # Pretvori poruku iz str u bajtove
        length = 16 - (len(data) % 16)                          # Dopuni poruku ako je potrebno
        data += bytes([length]) * length
        encrypted_message = des3.encrypt(data)                  # Napravi DES enkripciju

        # Povratna vrijednost je poruka i pripadni inicijalizacijski vektor (ako je potreban).
        if mode == "ECB":
            return_value = [encrypted_message]
        else:  # else CBC
            return_value = [encrypted_message, initialization_vector]

        return return_value

    """
        Metoda koja obavlja dekripciju  AES sustava
        Metoda prima ulazne podatke(poruku i vektor) i potrebni ključ K te način rada (ECB ili CBC).
    """
    @staticmethod
    def des3_decrypt(key_K, message, initialization_vector, mode):
        if mode == "ECB":
            des3 = DES3.new(key_K, DES3.MODE_ECB )
        else:  # CBC mode
            des3 = DES3.new(key_K, DES3.MODE_CBC, initialization_vector)

        decrypted_msg = des3.decrypt(message)
        # Ukloni padding na kraju poruke
        decrypted_msg = decrypted_msg[:-decrypted_msg[-1]]
        return decrypted_msg
