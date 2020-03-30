import multiprocessing
import time
import random

#                                                                                               Autor: Ivan Cindrić


def visitor(queue_C2V, queue_V2C, process_id):                              # dretva posjetitelj

    for i in range (0, 3):                                                  # ponvaljaj 3 puta
        rnd_sleep = random.randrange(100, 2000)                             # spavaj X milisekundi
        time.sleep(rnd_sleep/1000)                                          # X je slučajan broj između 100 i 2000
        print("Posjetitelj " + str(process_id) + " se želi voziti.")
        queue_V2C.put("Želim se voziti.")                                   # pošalji vrtuljku poruku "Želim se voziti"
        if queue_C2V.get() == "Sjedi.":                                     # po ptimitku poruke "Sjedi" sjedni,
            print("Sjeo posjetitelj " + str(process_id) + ".")              # ispiši "Sjeo posjetitelj K" i čekaj
            queue_C2V.task_done()
        if queue_C2V.get() == "Ustani.":                                    # po primitku poruke "Ustani" ustani
            print("Sišao posjetitelj " + str(process_id) + ".")             # siđi i ispiši "Sišao posjetitelj K"
            queue_C2V.task_done()
    queue_V2C.put("Posjetitelj završio.")                                   # pošalji poruku  "Posjetitelj K završio."
    print("Posjetitelj " + str(process_id) + " završio.")                   # ispisi tu poruku


if __name__ == '__main__':                                                 # glavna dretva
    queue_C2V = multiprocessing.JoinableQueue()                            # red poruka od vrtuljka prema posjetiteljima
    queue_V2C = multiprocessing.JoinableQueue()                            # red poruka od posjetitelja prema vrtuljku

    process_list = []                                                      # lista nastalih procesa
    for i in range(1, 9):                                                  # potrebno je napraviti 8 procesa
        # napravi proces i pozovi funkciju 'visitor', predaj 2 reda poruka toj funkciji
        p = multiprocessing.Process(target=visitor, args=(queue_C2V, queue_V2C, i))
        process_list.append(p)                                              # dodaj proces u listu
        p.start()                                                           # pokreni proces

    time.sleep(0.5)                                                         # pricekaj pola sekunde

    no_of_visitors = len(process_list)                                      # broj posjetitelja (8)
    current_queue_size = 0                                                  # brojac trenutnih ljudi u redu

    while no_of_visitors > 0:                                               # petlja traje dok ima posjetitelja (8)
        msg = str(queue_V2C.get())                                          # procitaj prvu poruku u redu
        if msg == "Želim se voziti.":                                       # ako je poruka 'zelim se voziti',
            current_queue_size += 1                                         # povecaj broj ljudi koji cekaju

        if current_queue_size == 4:                                         # kada cetiri ljudi ceka, javi da sjednu
            for i in range(0, 4):
                queue_C2V.put("Sjedi.")
                # sa 'join' se blokira nastavak dok nema odgovora 'task done'
                queue_C2V.join()

            print("Pokrenuo vrtuljak.")

            rnd_sleep = random.randrange(1000, 3000)                        # spavaj izmedju 1 i 3 sekunde
            time.sleep(rnd_sleep / 1000)

            print("Vrtuljak zaustavljen.")
            print("")
            print("")

            for i in range(0, 4):                                           # javi posjetiteljima da ustanu
                queue_C2V.put("Ustani.")
                queue_C2V.join()

            current_queue_size -= 4                                         # smanji broj ljudi u redu

        elif msg == "Posjetitelj završio.":                                 # ako dobijes poruku,
            no_of_visitors -= 1                                             # smanji broj posjetitelja

    queue_V2C.close()                                                       # ugasi redove poruka
    queue_C2V.close()
    queue_C2V.join_thread()
    for process in process_list:
        process.join()
