from Crypto.Cipher import PKCS1_OAEP
from symmetric_cryptography import DES3Implementation
from symmetric_cryptography import AESImplementation
from hashlib import sha3_512, sha3_256

"""
    Implementacije omotnice, potpisa i pečata su međusobno vrlo slične te bi se kod
    mogao strukturirati da se neki dijelovi dodatno segmentiraju, no zbog boljeg razumijevanja,
    odlučio sam svaki algoritam raspisati neovisno od drugih.
"""


# ======================================================================================================================
# ================================== Implementacija Digitalne omotnice =================================================
class Envelope:
    """
    Metoda koja šalje omotnicu.
    Metoda prima:
          željenu poruku, javni ključ primatelja, simetrični ključ pošiljatelja(K),
          vrstu simetričnog kriptosustava(AES, DES3) te način rada tog kriptosustava(CBC ili ECB)
    """
    @staticmethod
    def envelope_send(message, receiver_public_key, symmetric_key_K, symmetric_system_type, sym_system_mode):
        print("  ////////Proces slanja omotnice.////////")

        # Odabran je proizvoljni simetrični ključ K u pripadnoj metodi gdje je ključ generiran.
        # Ključ može biti generiran u AESImplementation.generate_key_k() ili DESImplementation.generate_key_k().
        print("     Odabran je ključ 'K': {}".format(symmetric_key_K))

        # C1 = DES (ili AES) (P, K).
        print("     Kriptiraj tekst P simetričnom funkcijom {}. Rezultat je poruka C1.".format(symmetric_system_type))
        print("         ==== >  C1 = {}(P, K)".format(sym_system_mode))
        print("         Tekst P: {}.".format(message))
        print("             {} - {} enkripcija....".format(symmetric_system_type, sym_system_mode))
        if symmetric_system_type == "DES3":
            encrypted_message_C1 = DES3Implementation.des3_encrypt(message, symmetric_key_K, sym_system_mode)
        else:                                                       # else AES
            encrypted_message_C1 = AESImplementation.aes_encrypt(message, symmetric_key_K, sym_system_mode)
        print("         Dobivena enkriptirana poruka C1:{}".format(encrypted_message_C1))

        print("     Javnim ključem primatelja KE kriptiraj tajni ključ K. Rezultat je poruka C2.")
        print("         ==== >  C2 = RSA(K, KE)")
        print("         Javni ključ primatelja KE: {}.".format(receiver_public_key.export_key()))
        print("         Tajni ključ  K: {}.".format(symmetric_key_K))
        print("             RSA enkripcija....")
        encryptor_RSA = PKCS1_OAEP.new(receiver_public_key)         # RSA.
        encrypted_message_C2 = encryptor_RSA.encrypt(symmetric_key_K)
        print("         Dobivena enkriptirana poruka C2:{}".format(encrypted_message_C2))

        # Omotnicom se šalje poruka M(C1, C2).
        print("     Omotnicom se šalje poruka M(C1, C2).")
        print("  ////////Kraj procesa slanja omotnice.////////")
        return encrypted_message_C1, encrypted_message_C2

    """
    Metoda koja čita poslanu omotnicu.
    Metoda prima poruku M(C1, C2) te privatni ključ primatelja, vrstu simetričnog sustava te način rada.
    C1 = Poslana poruka kriptirana simetričnim ključem K pošiljatelja.
    C2 = Simetrični ključ pošiljatelja kriptiran javnim ključem primatelja.
    """
    @staticmethod
    def envelope_receive(self_private_key, message_c1, message_c2, symmetric_system_type, sym_system_mode):
        print("  ////////Proces čitanja omotnice.////////")

        print("     Dekriptiraj poruku C2 svojim privatnim ključem KD i saznaj  ključ K..")
        print("         ==== >  K = RSA^-1 (RSA(K,KE), KD)")
        print("         Poruka C2: {}".format(message_c2))
        print("         Privatni ključ KD: {}".format(self_private_key.export_key()))
        print("             RSA dekripcija....")
        decryptor = PKCS1_OAEP.new(self_private_key)
        secret_key_K = decryptor.decrypt(message_c2)
        print("         Dobiveni tajni ključ K:{}".format(secret_key_K))

        # Razdvoji poruku C1 na podatak i inicijalizacijski vektor (ako je potrebno).
        c1_data = message_c1[0]
        if sym_system_mode != "ECB":                            # Ako je CBC, ima inicijalizacijski vektor.
            c1_vector = message_c1[1]
        else:                                                   # Ako je ECB, nema inicijalizacijski vektor.
            c1_vector = None

        print("     Dobivenim ključem K dekriptiraj poruku C1 da dobiješ izvorni tekst P.")
        print("         ==== >  P = {} ^-1 {}(P, K)).".format(symmetric_system_type, symmetric_system_type))
        print("         Poruka C1: {}".format(message_c1))
        print("             {} - {} dekripcija....".format(symmetric_system_type, sym_system_mode))
        if symmetric_system_type == "DES3":
            original_message = DES3Implementation.des3_decrypt(secret_key_K, c1_data, c1_vector, sym_system_mode)
        else:                                                   # else AES
            original_message = AESImplementation.aes_decrypt(secret_key_K, c1_data, c1_vector, sym_system_mode)
        print("         Dobiveni izvorni tekst P:{}".format(str(original_message)[2:-1]))
        print("  ////////Kraj procesa čitanja omotnice.////////")


# ======================================================================================================================
# ================================== Implementacija Digitalnog Potpisa =================================================
class Signature:
    """
    Metoda koja potpisuje i šalje poruku potpis.
    Metoda prima željenu poruku ,vlastiti privatni ključ te inačicu sha algoritma.
    """
    @staticmethod
    def signature_send(message, self_private_key, chosen_sha_format):
        # Kod preuzet i modificiran sa:
        # https://cryptobook.nakov.com/digital-signatures/rsa-sign-verify-examples
        print("  ////////Proces slanja potpisa.////////")

        # Pretvori poruku u bajtove.
        message = bytes(message, 'utf-8')

        print("     Izračunaj sažetak poruke H(P), gdje je 'P' poruka")
        print("         Poruka P: {}".format(message))
        if chosen_sha_format == "3_256":
            print("             Računanje sažetka pomoću SHA3-256...")
            h = int.from_bytes(sha3_256(message).digest(), byteorder='big')
        else:  # else sha3_512
            print("             Računanje sažetka pomoću SHA3-512...")
            h = int.from_bytes(sha3_512(message).digest(), byteorder='big')
        print("         Dobiveni sažetak H(P): {}".format(str(hex(h))))

        # Generiraj potpis (Digni hash na potenciju d modulo n).
        print("     Generiraj potpis tako da kriptiraš sažetak poruke H svojim privatnim ključem KD...")
        print("         ==== >  sig = RSA(H(P), KD)")
        print("         Privatni ključ KD: {}".format(self_private_key.export_key()))
        print("             Generiranje potpisa...")
        signature = pow(h, self_private_key.d, self_private_key.n)
        print("         Potpis P: {}".format(str(hex(signature))))

        print("         Pošalji poruku i potpis.")
        print("         ==== >  M = (P,RSA(H(P), KD)).")
        print("  ////////Kraj slanja potpisa.////////")
        return message, signature

    """
    Metoda koja prima potpisanu poruku.
    Ulazni argumenti su poruka, potpis, javni ključ pošiljatelja te inačica algoritma(256 ili 512).
    """
    @staticmethod
    def signature_receive(message, signature, sender_public_key, chosen_sha_format):
        print("  ////////Proces čitanja potpisa.////////")

        print("     Na temelju dolazne poruke P izračunaj sažetak H1(P)")
        print("         Dolazna poruka P: {}".format(message))
        if chosen_sha_format == "3_256":
            h = int.from_bytes(sha3_256(message).digest(), byteorder='big')
            print("             Računanje sažetka pomoću SHA3-256...")
        else:  # else sha3_512
            h = int.from_bytes(sha3_512(message).digest(), byteorder='big')
            print("             Računanje sažetka pomoću SHA3-512...")
        print("         Dobiveni sažetak H1(P): {}".format(str(hex(h))))

        print("     Dekriptiraj poslani sažetak H2(P) javnim ključem pošiljatelja KE.")
        print("         ==== >  H2(P) = RSA^-1(RSA(H(P), KD)), KE)")
        print("         Poslani kriptirani sažetak H2(P): {}".format(str(hex(signature))))
        print("         Javni ključ pošiljatelja: {}".format(sender_public_key.export_key()))
        print("             Dekriptiraj sažetak...")
        hash_from_signature = pow(signature, sender_public_key.e, sender_public_key.n)
        print("         Dekriptirani sažetak H2(P): {}".format(str(hex(hash_from_signature))))

        print("     Usporedi ta dva sažetka.")
        print("         ==== >  (H1(P) == H2(P)) = ?")
        print("         Dobiveni sažetak H1(P): {}".format(str(hex(h))))
        print("         Dekriptirani sažetak H2(P): {}".format(str(hex(hash_from_signature))))
        print("         Sažetci su jednaki? ", h == hash_from_signature)

        print("         Dobiveni izvorni tekst P:{}".format(str(message)[2:-1]))
        print("  ////////Kraj  čitanja potpisa.////////")

# ======================================================================================================================
# ================================== Implementacija Digitalnog Pečata ==================================================
class Seal:

    """
    Metoda koja generira pečat.
    Metoda prima:
          željenu poruku, javni ključ primatelja, simetrični ključ pošiljatelja(K),
          vrstu simetričnog kriptosustava(AES, DES3),način rada tog kriptosustava(CBC ili ECB)
          vlastiti privatni ključ te format za SHA sažimanje.
    """
    @staticmethod
    def seal_send(msg, receiver_pub_key, symm_key_K, sym_system_type, sym_system_mode, self_private_key, sha_format):
        print("  ////////Proces slanja pečata.////////")

        # Odabran je proizvoljni simetrični ključ K u pripadnoj metodi gdje je ključ generiran.
        # Ključ može biti generiran u AESImplementation.generate_key_k() ili DESImplementation.generate_key_k().
        print("     Odabran je ključ 'K': {}".format(symm_key_K))

        # C1 = DES (ili AES) (P, K).
        print("     Kriptiraj tekst P simetričnom funkcijom {}. Rezultat je poruka C1.".format(sym_system_type))
        print("         ==== >  C1 = {}(P, K)".format(sym_system_mode))
        print("         Tekst P: {}.".format(msg))
        print("             {} - {} enkripcija....".format(sym_system_type, sym_system_mode))
        if sym_system_type == "DES3":
            encrypted_message_C1 = DES3Implementation.des3_encrypt(msg, symm_key_K, sym_system_mode)
        else:  # else AES
            encrypted_message_C1 = AESImplementation.aes_encrypt(msg, symm_key_K, sym_system_mode)
        print("         Dobivena enkriptirana poruka C1:{}".format(encrypted_message_C1))

        print("     Javnim ključem primatelja KE kriptiraj tajni ključ K. Rezultat je poruka C2.")
        print("         ==== >  C2 = RSA(K, KE)")
        print("         Javni ključ primatelja KE: {}.".format(receiver_pub_key.export_key()))
        print("         Tajni ključ  K: {}.".format(symm_key_K))
        print("             RSA enkripcija....")
        encryptor_RSA = PKCS1_OAEP.new(receiver_pub_key)  # RSA.
        encrypted_message_C2 = encryptor_RSA.encrypt(symm_key_K)
        print("         Dobivena enkriptirana poruka C2:{}".format(encrypted_message_C2))

        print("     Izračunaj sažetak poruka C1 i C2 H(C1, C2) pomoću svojeg privatnog ključa KD.")
        print("         ==== >  S = H(C1, C2).")
        print("             Računanje sažetka H(C1, C2)....")
        # Spoji poruke C1 i C2.
        if len(encrypted_message_C1) == 2:
            shc1c2 = \
                str(encrypted_message_C1[0])[2:-1] + \
                str(encrypted_message_C1[1])[2:-1] + str(encrypted_message_C2)[2:-1]
        else:
            shc1c2 = \
                str(encrypted_message_C1)[2:-1] + str(encrypted_message_C2)[2:-1]
        shc1c2 = bytes(shc1c2, 'utf-8')                         # Ponovo pretvori u bajtove
        if sha_format == "3_256":                               # Provedi sažimanje ovisno o odabranoj inačici.
            print("             Računanje sažetka pomoću SHA3-256...")
            h = int.from_bytes(sha3_256(shc1c2).digest(), byteorder='big')
        else:                                                   # else sha3_512
            print("             Računanje sažetka pomoću SHA3-512...")
            h = int.from_bytes(sha3_512(shc1c2).digest(), byteorder='big')
        print("         Dobiveni sažetak H(C1,C2): {}".format(str(hex(h))))

        print("     Generiraj potpis tako da kriptiraš sažetak poruke S = H(C1, C2) svojim privatnim ključem KD...")
        print("         ==== >  sig = RSA(S, KD)")
        print("         Privatni ključ KD: {}".format(self_private_key.export_key()))
        print("             Generiranje potpisa...")
        # Generiraj potpis (Digni hash na potenciju d modulo n).
        signature_C3 = pow(h, self_private_key.d, self_private_key.n)
        print("         Potpis P: {}".format(str(hex(signature_C3))))

        print("         Omotnicom se šalje poruka M(C1, C2, C3).")
        print("  ////////Kraj slanja pečata.////////")
        return encrypted_message_C1, encrypted_message_C2, signature_C3

    """
    Metoda koja čita poslanu omotnicu.
    Metoda prima poruku M(C1, C2) te privatni ključ primatelja, vrstu simetričnog sustava te način rada.
    C1 = Poslana poruka kriptirana simetričnim ključem K pošiljatelja.
    C2 = Simetrični ključ pošiljatelja kriptiran javnim ključem primatelja.
    """
    @staticmethod
    def seal_receive(self_priv_key, msg_c1, msg_c2, sym_type, sym_mode, sender_pub_key, sha_format, msg_c3):
        print("  ////////Proces čitanja pečata.////////")

        print("     Dekriptiraj poruku C2 svojim privatnim ključem KD i saznaj  ključ K..")
        print("         ==== >  K = RSA^-1 (RSA(K,KE), KD)")
        print("         Poruka C2: {}".format(msg_c2))
        print("         Privatni ključ KD: {}".format(self_priv_key.export_key()))
        print("             RSA dekripcija....")
        decryptor = PKCS1_OAEP.new(self_priv_key)
        secret_key_K = decryptor.decrypt(msg_c2)
        print("         Dobiveni tajni ključ K:{}".format(secret_key_K))

        # Razdvoji poruku C1 na podatak i inicijalizacijski vektor(ako je potrebno).
        c1_data = msg_c1[0]
        if sym_mode != "ECB":                                   # Ako je CBC, ima inicijalizacijski vektor.
            c1_vector = msg_c1[1]
        else:                                                   # Ako je ECB, nema inicijalizacijski vektor.
            c1_vector = None

        print("     Dobivenim ključem K dekriptiraj poruku C1 da dobiješ izvorni tekst P.")
        print("         ==== >  P = {} ^-1 {}(P, K)).".format(sym_type, sym_type))
        print("         Poruka C1: {}".format(msg_c1))
        print("             {} - {} dekripcija....".format(sym_type, sym_mode))
        if sym_type == "DES3":
            original_message = DES3Implementation.des3_decrypt(secret_key_K, c1_data, c1_vector, sym_mode)
        else:  # else AES
            original_message = AESImplementation.aes_decrypt(secret_key_K, c1_data, c1_vector, sym_mode)
        print("         Dobiveni izvorni tekst P:{}".format(str(original_message)[2:-1]))

        print("     Na temelju dolazne poruke P izračunaj sažetak H1(P)")
        print("         Dolazna poruka P: {}".format(msg_c1))
        if len(msg_c1) == 2:
            shc1c2 = \
                str(msg_c1[0])[2:-1] + \
                str(msg_c1[1])[2:-1] + str(msg_c2)[2:-1]
        else:
            shc1c2 = \
                str(msg_c1)[2:-1] + str(msg_c1)[2:-1]
        shc1c2 = bytes(shc1c2, 'utf-8')  # Ponovo pretvori u bajtove
        if sha_format == "3_256":
            h = int.from_bytes(sha3_256(shc1c2).digest(), byteorder='big')
            print("             Računanje sažetka pomoću SHA3-256...")
        else:  # else sha3_512
            h = int.from_bytes(sha3_512(shc1c2).digest(), byteorder='big')
            print("             Računanje sažetka pomoću SHA3-512...")
        print("         Dobiveni sažetak H1(P): {}".format(str(hex(h))))

        print("     Dekriptiraj poslani sažetak H2(P) javnim ključem pošiljatelja KE.")
        print("         ==== >  H2(P) = RSA^-1(RSA(H(P), KD)), KE)")
        print("         Poslani kriptirani sažetak H2(P): {}".format(str(hex(msg_c3))))
        print("         Javni ključ pošiljatelja: {}".format(sender_pub_key.export_key()))
        print("             Dekriptiraj sažetak...")
        hash_from_signature = pow(msg_c3, sender_pub_key.e, sender_pub_key.n)
        print("         Dekriptirani sažetak H2(P): {}".format(str(hex(hash_from_signature))))

        print("     Usporedi ta dva sažetka.")
        print("         ==== >  (H1(P) == H2(P)) = ?")
        print("         Dobiveni sažetak H1(P): {}".format(str(hex(h))))
        print("         Dekriptirani sažetak H2(P): {}".format(str(hex(hash_from_signature))))
        print("         Sažetci su jednaki? ", h == hash_from_signature)

        print("         Dobiveni izvorni tekst P:{}".format(str(original_message)[2:-1]))
        print("  ////////Kraj procesa čitanja pečata.////////")

