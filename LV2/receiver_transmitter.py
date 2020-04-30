from Crypto.PublicKey import RSA
from symmetric_cryptography import DES3Implementation
from symmetric_cryptography import AESImplementation
from mode_of_communication import Envelope
from mode_of_communication import Signature
from mode_of_communication import Seal


"""
    Razred CommunicationEndPoint služi za stvaranje objekata pošiljatelja i primatelja.
    Razred pohranjuje potrebne parametre (ključevi, algoritmi, dužine) te poziva metode potrebne
    za obradu podataka koji se prenose kriptosustavima.
    Razred također sadrži metode za komunikaciju (send i receive).
"""


# ======================================================================================================================
# ========================================= Razred Pošiljatelja i primatelja ===========================================
class CommunicationEndPoint:

    def __init__(self, name):
        self.name = name                                        # Ime pošiljatelja, odnosno primatelja.
        self.symmetric_cryptosystem_type = None                 # Vrsta simetričnog kriptosustava (AES, DES3)
        self.symmetric_cryptosystem_type_mode = None            # Način rada simetričnog kriptosustava (CBC, ECB)
        self.sym_secret_key = None                              # Ključ simetričnog sustava.
        self.public_key = None                                  # Javni ključ asimetričnog sustava.
        self.private_key = None                                 # Privatni ključ.
        self.encrypted_message_C1 = None                        # Poruka kriptirana simetričnim sustavom.
        self.encrypted_message_C2 = None                        # Poruka kriptirana asimetričnim sustavom RSA.
        self.encrypted_message_C3 = None                        # Digitalni potpis.

    """Metoda šalje traženu poruku na odabran način (odabir pečata, omotnice ili potpisa)."""
    def send(self, chosen_format, message, receiver_public_key, chosen_sha_format):
        if chosen_format == "signature":
            self.encrypted_message_C1, self.encrypted_message_C3 = \
                Signature.signature_send(message, self.private_key, chosen_sha_format)

        elif chosen_format == "seal":
            self.encrypted_message_C1, self.encrypted_message_C2, self.encrypted_message_C3 \
                = Seal.seal_send(message, receiver_public_key, self.sym_secret_key,
                                 self.symmetric_cryptosystem_type, self.symmetric_cryptosystem_type_mode,
                                 self.private_key, chosen_sha_format)
        else: # chosen_format == "envelope":
            self.encrypted_message_C1, self.encrypted_message_C2 \
                = Envelope.envelope_send(message, receiver_public_key, self.sym_secret_key,
                                         self.symmetric_cryptosystem_type, self.symmetric_cryptosystem_type_mode)

    """Metoda čita dobivenu poruku na odabran način (odabir pečata, omotnice ili potpisa)."""
    def receive(self, chosen_format, msg_part1, msg_part2, sender_public_key, chosen_sha_format, msg_part3):
        if chosen_format == "signature":
            Signature.signature_receive(msg_part1, msg_part2, sender_public_key, chosen_sha_format)

        elif chosen_format == "seal":
            Seal.seal_receive(self.private_key, msg_part1, msg_part2,
                              self.symmetric_cryptosystem_type, self.symmetric_cryptosystem_type_mode,
                              sender_public_key, chosen_sha_format, msg_part3)

        else: # chosen_format == "envelope":
            Envelope.envelope_receive(self.private_key, msg_part1, msg_part2,
                                      self.symmetric_cryptosystem_type, self.symmetric_cryptosystem_type_mode)

    """Getteri za varijable razreda."""
    def get_encrypted_message_C1(self):
        return self.encrypted_message_C1

    def get_encrypted_message_C2(self):
        return self.encrypted_message_C2

    def get_encrypted_message_C3(self):
        return self.encrypted_message_C3

    def get_public_key(self):
        return self.public_key

    def get_private_key(self):
        return self.private_key

    def get_secret_key(self):
        return self.sym_secret_key

    """Metoda za generiranje rsa ključa na temelju tražene veličine."""
    def generate_rsa_key(self, key_size):
        if self.name == "Posiljatelj":
            who_is_generating = "Pošiljatelj"
        else:
            who_is_generating = "Primatelj"
        print("     {} generira  RSA ključ...".format(who_is_generating))
        key_pair = RSA.generate(key_size)                       # Generiraj ključeve.
        self.public_key = key_pair.publickey()                  # Spremi javni ključ.
        self.private_key = key_pair                             # Spremi privatni ključ.
        print("         Generirani javni ključ: {}".format(self.public_key.export_key()))
        print("         Generirani privatni ključ: {}".format(self.private_key.export_key()))

    """Metoda koja postavlja vrstu simetričnog kriptosustava koji se koristi."""
    def set_symmetric_cryptosystem(self, system_type, sym_system_type_mode, key_size):
        if self.name == "Posiljatelj":
            who_is_generating = "Pošiljatelj"
        else:
            who_is_generating = "Primatelj"
        print("     {} generira  {} - {} ključ...".format(who_is_generating, system_type, sym_system_type_mode))
        # Spremi vrstu simetričnog sustava (AES, DES3).
        self.symmetric_cryptosystem_type = system_type
        # Spremi način kriptiranja (CBC, ECB).
        self.symmetric_cryptosystem_type_mode = sym_system_type_mode

        # Generiraj pripadne ključeve.
        if system_type == "DES3":
            self.sym_secret_key = DES3Implementation.generate_key_k(self.name, key_size)
        else:                                                   # else AES
            self.sym_secret_key = AESImplementation.generate_key_k(self.name, key_size)

        print("         Generirani tajni ključ: {}".format(self.sym_secret_key))
# ======================================================================================================================
