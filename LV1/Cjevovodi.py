import multiprocessing
import time
import random
import datetime
########################################################################################################################
#       Glavni proces stvara N procesa dijeteta i prema svakom od N procesa stvara cjevovod (ukupno N cjevovoda).
#       Procesi djeca međusobno komuniciraju preko glavnog procesa.
#
#               cjevovod1(dijete1, glavni proces) -> cjevovod2(glavni proces, dijete2)
#       Glavni proces samo  poruke između djece i prestaje s radom kada djeca pošalju sve poruke.
#       U procesu dijeteta se odvijaju sinkronizacijski mehanizmi(protokol Ricarta i Agrawala)
#
#                                                                                                   Autor: Ivan Cindrić
########################################################################################################################


# =============================== FUNKCIJA KRITIČNOG ODSJEČKA ==========================================================
def sit_at_the_table(index):                                   # funkcija u kritičnom odsječku
    print("***Filozof " + str(index) + " je za stolom.***")    # pristupi stolu, sjedi i ispiši "Filozof i je za stolom"
    time.sleep(3)                                              # čekaj 3 sekunde
# ======================================================================================================================


# ================================ FUNKCIJA PROCESA DJETETA ============================================================
def philosopher(index, child_conn, no_of_philosophers):             # funkcija koja se izvršava u procesu dijeteta

    rnd_sleep = random.randrange(100, 2000)                         # sudjeluj na konferenciji (spavaj random vrijeme)
    time.sleep(rnd_sleep / 1000)

    # lista koja ce sadržavati procese manjeg prioriteta (procesi koji su kasnije zatražili zahtjev za K.O)
    processes_index = [i for i in range(1, no_of_philosophers + 1)]
    processes_index.remove(index)                                   # iz liste makni vlastiti indeks

    own_time = datetime.datetime.now()                              # zapamti vrijeme slanja poruke
    child_conn.send([index, own_time])                              # pošalji poruku i, T(i)

    print("SEND: Filozof", index, "šalje poruku [", index, ",", own_time, "] filozofima:", str(processes_index),
          ",jer želi pristupiti kritičnom odsječku.")

    requests = child_conn.recv()                                    # primi zahtjeve za kritičnim odsječkom
    for request in requests:
        print("RECEIVE: Filozof", index, "prima poruku [", request[1], "] od filozofa", request[0],
              ",jer filozof", request[0], "želi ući u kritični odsječak.")

    responses = []                                                  # lista za odgovore na zahtjeve
    for request in requests:                                        # iteriraj kroz zahtjeve
        if isinstance(request[1], datetime.datetime):               # provjeri radi li se o ispravnom tipu podataka
            if request[1] < own_time:                               # ako je zahtjev došao prije vlastitog, ...
                receiver = request[0]                               # ...šalje se odgovor na zahtjev
                responses.append([index, own_time, receiver])
                processes_index.remove(receiver)                    # iz liste procesa makni procese višeg prioriteta

    for response in responses:
        print("SEND: Filozof", index, "šalje poruku [", response[1], "] filozofu", response[2],
              ",jer je poslao zahtjev kasnije nego filozof", response[2], ".")

    child_conn.send(responses)                                      # odgovori na zahtjeve višeg prioriteta

    responses.clear()
    while len(responses) < no_of_philosophers - 1:                  # čekaj u petlji odgovore procesa koji je u K.O.
        while child_conn.poll() is False:                           # cekaj dok u cjevovodu nema odgovora
            pass
        msg = child_conn.recv()                                     # pročitaj odgovor
        for el in msg:
            print("RECEIVE: Filozof", index, " čeka u redu za K.O. Prima poruku [", el[0], el[1],
                  "] od filozofa", el[0], ".")
            responses.append(el)                                    # petlja se vrti dok nema N - 1 odgovora (len())

    print()
    print("Filozof P", index, "je primio poruku od svih ostalih filozofa te ulazi u kritični odsječak.")
    # KRITIČNI ODSJEČAK=====================================
    sit_at_the_table(index)
    # KRITIČNI ODSJEČAK=====================================
    rnd_sleep = random.randrange(100, 2000)                         # sudjeluj na konferenciji (spavaj random vrijeme)
    time.sleep(rnd_sleep / 1000)

    if len(processes_index) > 0:                                    # javi ako imaš kome javiti da je K.O. obavljen
        child_conn.send([index, own_time, processes_index])
        if len(processes_index) != 1:
            print("Filozof P", index, "je gotov sa kritičnim odsječkom te šalje poruku [", index, own_time,
                  "] filozofima", processes_index, ".")
        else:
            print("Filozof P", index, "je gotov sa kritičnim odsječkom te šalje poruku [", index, own_time,
                  "] filozofu", processes_index, ".")
    else:
        print("Filozof P", index, "je gotov sa kritičnim odsječkom (nikome ne šalje poruku).")

    print()
    child_conn.close()                                              # proces gotov, zatvori cjevovod
# ======================================================================================================================


# ====================================== GLAVNI PROGRAM ================================================================
if __name__ == '__main__':
    no_of_philosophers = 0                                              # broj filozofa (unosi se)

    while no_of_philosophers < 3 or no_of_philosophers > 10:            # ponavljaj dok se ne unese ispravan broj
        no_of_philosophers = int(input("Upisati broj filozofa:"))

    process_list = []                                                   # lista procesa djece
    parent_conns = []                                                   # lista  cjevovoda na strani roditelja
    child_conns = []                                                    # lista  cjevovoda na strani djeteta

    for i in range(1, no_of_philosophers + 1):                          # za svakog filozofa
        parent_conn, child_conn = multiprocessing.Pipe()                # napravi cjevovod prema roditelju
        # napravi proces djeteta, poašlji mu redni broj, cjevovod i ukupan broj filozofa
        p = multiprocessing.Process(target=philosopher, args=(i, child_conn, no_of_philosophers))
        parent_conns.append(parent_conn)                                # dodaj  cjevovod roditelja u listu
        child_conns.append(child_conn)                                  # dodaj  cjevodod dijeteta u listu
        process_list.append(p)                                          # dodaj proces u listu procesa
        p.start()                                                       # pokreni proces

    requests = []                                                       # dolazni upiti od djece
    for conn in parent_conns:                                           # spremi sve upite
        requests.append(conn.recv())

    tmp = []                                                            # filtriraj upite
    for i in range(len(requests)):                                      # proslijedi upite ostaloj djeci
        tmp = [req for req in requests if req != requests[i]]           # ne šalji vlastite upite natrag
        parent_conns[i].send(tmp)

    responses = []                                                      # dolazni odgovori od djece
    for conn in parent_conns:
        while conn.poll() is False:                                     # čekaj odgovor
            pass
        responses.append(conn.recv())                                   # dodaj odgovor u listu
    ordered_responses = []
    for response in responses:                                          # presloži višestruke odgovore u 1d listu
        if len(response) > 0:
            for el in response:
                ordered_responses.append(el)

    for i in range(len(parent_conns)):                                 # pošalji odgovore odgovarajućoj djeci
        response = [r for r in ordered_responses if r[2] == i + 1]
        if len(response) > 0:
            parent_conns[i].send(response)

    got_response = False                                                # zastavica odgovora procesa nakon K.O.
    no_of_responses = 0                                                 # nakon K.O. mora biti N - 1 odgovora
    while True:                                                         # vrti petlju dok nema N - 1 odgovora
        final_response = []                                             # varijabla za odogovor procesa nakon K.O.
        for conn in parent_conns:                                       # provjeravaj cjevovode djece
            if conn.poll() is True:                                     # čekaj dok nema poruke u cjevovodu
                final_response = conn.recv()                            # pročitaj odgovor
                got_response = True                                     # označi zastavicom da je odgovor pročitan
        if got_response is True:                                        # ako je zastavica podignuta
            if len(final_response[2]) > 0:                              # ako proces javlja drugima da je gotov
                for index in final_response[2]:                         # pronađi indekse drugih procesa kojima javlja
                    parent_conns[index - 1].send([final_response])      # pošalji im poruku
            got_response = False                                        # ponovo spusti zastavicu
            no_of_responses += 1                                        # povećaj brojač odgovora nakon K.O.
        if no_of_responses == no_of_philosophers - 1:                   # zaustavi petlju ako su pristigli svi odgovori
            break

    for conn in parent_conns:                                           # zatvori sve cjevovode
        conn.close()
    for process in process_list:
        process.join()
    print("Svi filozofi su nahranjeni!")
