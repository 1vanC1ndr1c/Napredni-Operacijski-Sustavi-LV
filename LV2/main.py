import pbkdf2 as pbkdf2
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
import os


# ================================== Implementacija Digitalne omotnice =================================================
class Envelope:

    # Metoda koja šalje omotnicu.
    # Metoda prima željenu poruku, javni ključ primatelja, te simetrični ključ pošiljatelja(K).
    @staticmethod
    def envelope_send(message, receiver_public_key, symmetric_key_K):
        # Odabran je proizvoljni simetrični ključ K u pripadnoj metodi gdje je ključ generiran.
        # Ključ može biti generiran u AESImplementation.generate_key_k() ili DESImplementation.generate_key_k().
        # AES ili DES-3 se odabire na početku izvršavanja programa.

        # TODO odabir DES, AES
        # Kriptiraj tekst P simetričnom funkcijom (DES, AES). Rezultat je poruka C1.
        # C1 = DES (ili AES) (P, K).
        encrypted_message_and_vector_C1 = AESImplementation.aes_encrypt(message, symmetric_key_K)

        # Javnim ključem primatelja KE kriptiraj ključ K. Rezultat je poruka C2.
        # C2 = RSA(K, KE).
        encryptor = PKCS1_OAEP.new(receiver_public_key)                                         # RSA
        encrypted_message_C2 = encryptor.encrypt(symmetric_key_K)

        # Omotnicom se šalje poruka M(C1, C2).
        return encrypted_message_and_vector_C1, encrypted_message_C2


    # Metoda koja čita poslanu omotnicu.
    # Metoda prima poruku M(C1, C2) te privatni ključ primatelja.
    # C1 = Poslana poruka kriptirana simetričnim ključem K pošiljatelja.
    # C2 = Simetrični ključ pošiljatelja kriptiran javnim ključem primatelja.
    @staticmethod
    def envelope_receive(self_private_key, message_and_vector_c1, message_c2):

        # Dekriptiraj poruku C2 svojim privatnim ključem KD i saznaj  ključ K.
        # K = RSA^-1 (RSA(K,KE), KD).
        decryptor = PKCS1_OAEP.new(self_private_key)
        secret_key_K = decryptor.decrypt(message_c2)

        # Razdvoji poruku C1 na podatak i inicijalizacijski vektor.
        c1_data = message_and_vector_c1[0]
        c1_vector = message_and_vector_c1[1]

        # Dobivenim ključem K dekriptiraj poruku C1 da dobiješ izvorni tekst P.
        # P = AES (ili DES) ^-1 (AES(ili DES)(P, K)).
        original_message = AESImplementation.aes_decrypt(secret_key_K, c1_data, c1_vector)
        print(original_message)


# ======================================================================================================================
# ================================== AES implementacija ================================================================
class AESImplementation:

    # Metoda generira simetrični ključ K koji se koristi u enkripciji i dekripciji tokom procesa AES kriptosustava.
    # Ključ se generira na temelju imena pošiljatelja
    # TODO Moguće je odabrati ključ veličine 16, 24 ili 32 bajta
    @staticmethod
    def generate_key_k(name):
        password = name
        salt = os.urandom(16)
        aes_key = pbkdf2.PBKDF2(password, salt).read(24)  # 16, 24 ILI 32
        return aes_key

    # Metoda enkriptira poruku P AES kriptosustavom na temelju ključa K.
    @staticmethod
    def aes_encrypt(message, key_K):
        # Kod preuzet i modificiran sa adrese:
        # https://www.novixys.com/blog/using-aes-encryption-decryption-python-pycrypto/

        # Inicijalizacijski vektor se koristi kako bi svaka enkripcija dala različiti rezultat.
        # Vektor se šalje zajedno s enkriptiranom porukom. Nije potrebno da je tajan.
        initialization_vector = os.urandom(16)
        #TODO odaberi MODE, trenutno je CBC
        aes = AES.new(key_K, AES.MODE_CBC, initialization_vector)
        # Pretvori poruku iz str u bajtove
        data = bytes(message, 'utf-8')
        # Dopuni poruku ako je potrebno
        length = 16 - (len(data) % 16)
        data += bytes([length]) * length
        # Napravi AES enkripciju
        encrypted_message = aes.encrypt(data)

        # Povratna vrijednost je poruka i pripadni inicijalizacijski vektor
        encrypted_message_and_vector = [encrypted_message, initialization_vector]
        return encrypted_message_and_vector

    # Metoda koja obavlja dekripciju  AES sustava
    # Metoda prima ulazne podatke(poruku i vektor) i potrebni ključ K.
    @staticmethod
    def aes_decrypt(key_K, message, initialization_vector):
        # TODO dati i ostale EBC, CBC, ECB whatever
        aes = AES.new(key_K, AES.MODE_CBC, initialization_vector)
        decrypted_msg = aes.decrypt(message)
        # Ukloni padding na kraju poruke
        decrypted_msg = decrypted_msg[:-decrypted_msg[-1]]
        return decrypted_msg


# ======================================================================================================================
# ========================================= Razred Pošiljatelja i primatelja ===========================================
class CommunicationEndPoint:

    def __init__(self, name):
        # TODO ponuditi razlicite velicine kljuceva
        key_size = 1024
        # Generiraj javne kljuceve
        key_pair = RSA.generate(key_size)

        # Ime pošiljatelja, odnosno primatelja
        self.name = name
        # TODO kljuc se generira ovisno o metodi AES ili DES, slozi
        self.symmetric_key = AESImplementation.generate_key_k(self.name)
        self.public_key = key_pair.publickey()
        self.private_key = key_pair
        self.encrypted_message_C1 = None
        self.encrypted_message_C2 = None

    # Metoda šalje traženu poruku na odabran način (odabir pečata, omotnice ili potpisa).
    def send(self, chosen_format, message, receiver_public_key):
        if chosen_format == "envelope":
            self.encrypted_message_C1, self.encrypted_message_C2 \
                = Envelope.envelope_send(message, receiver_public_key, self.symmetric_key)

    # Metoda čita dobivenu poruku.
    def receive(self, c1, c2):
        Envelope.envelope_receive(self.private_key, c1, c2)

    # Getteri za varijable razreda.
    def get_encrypted_message_C1(self):
        return self.encrypted_message_C1

    def get_encrypted_message_C2(self):
        return self.encrypted_message_C2

    def get_public_key(self):
        return self.public_key

# ======================================================================================================================
# ========================================= Glavni Program =============================================================
if __name__ == '__main__':

    # Stvori pošiljatelja
    sender = CommunicationEndPoint("Posiljatelj")
    # Stvori primatelja
    receiver = CommunicationEndPoint("Primatelj")

    # Posalji metodom "envelope" poruku "Test 12345"
    message_to_send = "Srbija do tokija"
    chosen_format = "envelope"
    sender.send(chosen_format, message_to_send, receiver.get_public_key())

    # Primi poruku
    receiver.receive(sender.get_encrypted_message_C1(), sender.get_encrypted_message_C2())
