from receiver_transmitter import CommunicationEndPoint
from file_generator import CryptoFileCreator

'''
    Funkcije koje obavljaju pokretanje backend dio programa.
    start_envelope, start_signature i start_seal stvaraju dva razreda
    pošiljatelja i primatelja (tip CommunicationEndPoint).
    Na temelju dobivenih parametara (ključevi, duljine, vrste kriptostustava)
    obrađuju podatke i pozivaju funkcije za generiranje potrebnih datoteka
    te ostvaruju komunikaciju između genrirarnih pošiljatelja i primatelja.
    
'''


# ======================================================================================================================
# ======================================= OMOTNICA =====================================================================
def start_envelope(message_to_send, rsa_key_size, sym_system_type, sym_system_type_mode, sym_key_size):
    print("====================START=========================")
    print("Odabrana metoda: Omotnica.")
    chosen_format = "envelope"

    # Stvori pošiljatelja i primatelja.
    sender = CommunicationEndPoint("Posiljatelj")
    receiver = CommunicationEndPoint("Primatelj")

    # Generiraj ključeve zadane dužine (1024, 1500, 2048 b)
    print("Odabran RSA ključ veličine: {} bitova.".format(rsa_key_size))
    sender.generate_rsa_key(rsa_key_size)
    receiver.generate_rsa_key(rsa_key_size)

    # Postavi parametre simetričnog kriptosustava pošiljatelju i primatelju.
    print("Odabrani simetrični kriptosustav: {}.".format(sym_system_type))
    print("Odabrani način kriptiranja: {}.".format(sym_system_type_mode))
    # DES3 u pozadini radi s ključevima potencije broja 2, ali na ekranu se prikazuju teoretske vrijednosti.
    screen_key_size = int(sym_key_size) * 8
    if str(sym_system_type) != "AES":
        if int(sym_key_size) == 16:
            screen_key_size = 112
        else:
            screen_key_size = 168
    print("Odabrana veličina {} ključa za {}: {}.".format(sym_system_type_mode, sym_system_type, screen_key_size))
    sender.set_symmetric_cryptosystem(sym_system_type, sym_system_type_mode, sym_key_size)
    receiver.set_symmetric_cryptosystem(sym_system_type, sym_system_type_mode, sym_key_size)

    # Pošalji poruku s pošiljatelja.
    print("******SLANJE PORUKE******************************************************")
    sender.send(chosen_format, message_to_send, receiver.get_public_key(), None)
    print("******KRAJ SLANJA PORUKE**************************************************")

    # Generiraj datoteke.
    print("Generirane Datoteke.........")
    CryptoFileCreator.create_msg_file(message_to_send)
    CryptoFileCreator.create_RSA_crypto_file("posiljatelj", sender.get_private_key(), "private")
    CryptoFileCreator.create_RSA_crypto_file("posiljatelj", sender.get_public_key(), "public")
    CryptoFileCreator.create_RSA_crypto_file("primatelj", receiver.get_private_key(), "private")
    CryptoFileCreator.create_RSA_crypto_file("primatelj", receiver.get_public_key(), "public")
    CryptoFileCreator.create_sym_system_crypto_files(sym_system_type,
                                                     sym_system_type_mode, sender.get_encrypted_message_C1(),
                                                     sender.get_secret_key())
    CryptoFileCreator.create_env_file(rsa_key_size, sym_system_type, sym_key_size,
                                      sender.get_encrypted_message_C2(), sender.get_encrypted_message_C1())
    # Primi poruku na primatelju.
    print("******PORUKA PRIMLJENA*********")
    receiver.receive(
        chosen_format,
        sender.get_encrypted_message_C1(), sender.get_encrypted_message_C2(),
        sender.get_public_key(), None, None)
    print("====================END=========================")


# ======================================================================================================================
# ======================================= POTPIS =======================================================================
def start_signature(message_to_send, rsa_key_size, chosen_sha_format):
    print("====================START=========================")
    print("Odabrana metoda: Potpis.")
    chosen_format = "signature"

    # Stvori pošiljatelja i primatelja.
    sender = CommunicationEndPoint("Posiljatelj")
    receiver = CommunicationEndPoint("Primatelj")

    # Generiraj ključeve zadane dužine (1024, 1500, 2048 b)
    print("Odabran RSA ključ veličine: {} bitova.".format(rsa_key_size))
    sender.generate_rsa_key(rsa_key_size)
    receiver.generate_rsa_key(rsa_key_size)

    # Pošalji poruku s pošiljatelja.
    print("******SLANJE PORUKE******************************************************")
    sender.send(chosen_format, message_to_send, receiver.get_public_key(), chosen_sha_format)
    print("******KRAJ SLANJA PORUKE**************************************************")

    # Generiraj datoteke.
    print("Generirane Datoteke.........")
    CryptoFileCreator.create_msg_file(message_to_send)
    CryptoFileCreator.create_RSA_crypto_file("posiljatelj", sender.get_private_key(), "private")
    CryptoFileCreator.create_RSA_crypto_file("posiljatelj", sender.get_public_key(), "public")
    CryptoFileCreator.create_RSA_crypto_file("primatelj", receiver.get_private_key(), "private")
    CryptoFileCreator.create_RSA_crypto_file("primatelj", receiver.get_public_key(), "public")
    CryptoFileCreator.create_sig_file(chosen_sha_format, rsa_key_size, sender.get_encrypted_message_C3())

    # Primi poruku na primatelju.
    print("******PORUKA PRIMLJENA*********")
    receiver.receive(
        chosen_format,
        sender.get_encrypted_message_C1(), sender.get_encrypted_message_C3(),
        sender.get_public_key(), chosen_sha_format, None)
    print("====================END=========================")


# ======================================================================================================================
# ======================================= PEČAT ========================================================================
def start_seal(message_to_send, rsa_key_size, sym_system_type, sym_system_type_mode, sym_key_size, chosen_sha_format):
    print("====================START=========================")
    print("Odabrana metoda: Pečat.")
    chosen_format = "seal"

    # Stvori pošiljatelja i primatelja.
    sender = CommunicationEndPoint("Posiljatelj")
    receiver = CommunicationEndPoint("Primatelj")

    # Generiraj ključeve zadane dužine (1024, 1500, 2048 b)
    print("Odabran RSA ključ veličine: {} bitova.".format(rsa_key_size))
    sender.generate_rsa_key(rsa_key_size)
    receiver.generate_rsa_key(rsa_key_size)

    # Postavi parametre simetričnog kriptosustava pošiljatelju i primatelju.
    print("Odabrani simetrični kriptosustav: {}.".format(sym_system_type))
    print("Odabrani način kriptiranja: {}.".format(sym_system_type_mode))
    # DES3 u pozadini radi s ključevima potencije broja 2, ali na ekranu se prikazuju teoretske vrijednosti.
    screen_key_size = int(sym_key_size) * 8
    if str(sym_system_type) != "AES":
        if int(sym_key_size) == 16:
            screen_key_size = 112
        else:
            screen_key_size = 168
    print("Odabrana veličina {} ključa za {}: {}.".format(sym_system_type_mode, sym_system_type, screen_key_size))
    sender.set_symmetric_cryptosystem(sym_system_type, sym_system_type_mode, sym_key_size)
    receiver.set_symmetric_cryptosystem(sym_system_type, sym_system_type_mode, sym_key_size)

    # Pošalji poruku s pošiljatelja.
    print("******SLANJE PORUKE******************************************************")
    sender.send(chosen_format, message_to_send, receiver.get_public_key(), chosen_sha_format)
    print("******KRAJ SLANJA PORUKE**************************************************")

    # Generiraj datoteke.
    print("Generirane Datoteke.........")
    CryptoFileCreator.create_msg_file(message_to_send)
    CryptoFileCreator.create_RSA_crypto_file("posiljatelj", sender.get_private_key(), "private")
    CryptoFileCreator.create_RSA_crypto_file("posiljatelj", sender.get_public_key(), "public")
    CryptoFileCreator.create_RSA_crypto_file("primatelj", receiver.get_private_key(), "private")
    CryptoFileCreator.create_RSA_crypto_file("primatelj", receiver.get_public_key(), "public")
    CryptoFileCreator.create_sym_system_crypto_files(sym_system_type,
                                                     sym_system_type_mode, sender.get_encrypted_message_C1(),
                                                     sender.get_secret_key())
    CryptoFileCreator.create_sig_file(chosen_sha_format, rsa_key_size, sender.get_encrypted_message_C3())
    CryptoFileCreator.create_env_file(rsa_key_size, sym_system_type, sym_key_size,
                                      sender.get_encrypted_message_C2(), sender.get_encrypted_message_C1())
    # Primi poruku na primatelju.
    print("******PORUKA PRIMLJENA*********")
    receiver.receive(
        chosen_format,
        sender.get_encrypted_message_C1(), sender.get_encrypted_message_C2(),
        sender.get_public_key(), chosen_sha_format, sender.get_encrypted_message_C3())
    print("====================END=========================")
