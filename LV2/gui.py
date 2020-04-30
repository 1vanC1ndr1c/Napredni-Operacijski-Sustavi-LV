from tkinter import *
from tkinter.ttk import Separator

import init

"""
    Grafičko sučelje omogućuje odabir parametara kriptosustava.
    Na temelju parametara poziva prikladne metode u 'init.py'.
    Također, prikazuje informacije vezane uz izvođenje programa.
"""


def gui_init():
    window = Tk()
    # Inicijalizacija prozora.
    window.title("NOS LV 2")
    window.geometry('960x540')
    window.resizable(width=False, height=False)

    # Stvori okvir za odabir načina slanja.
    head_frame = Frame(window)
    head_frame.grid(row=0, column=0, sticky="w")
    main_frame = Frame(window)

    # Stvori header.
    select_label = Label(head_frame, text="Odaberi način komunikacije:  ")
    select_label.grid(column=0, row=0, sticky=W)
    select_list = ["Omotnica", "Potpis", "Pečat"]
    select_var = StringVar()
    select_var.set(select_list[0])
    select_option_menu = OptionMenu(head_frame, select_var, *select_list)
    select_option_menu.config(bg="LIGHTGRAY", width="10")
    select_option_menu.grid(column=1, row=0)

    # Generiraj ostale postavke kada je header odabran.
    def f_selected():

        # Resetiraj okvir (početno).
        for widget in main_frame.winfo_children():
            widget.destroy()
        main_frame.grid()

        # Unos poruke za slanje.
        msg_to_send_label = Label(main_frame, text="Unesi poruku koja se šalje: ")
        msg_to_send_label.grid(column=0, row=2, sticky=W)
        msg_var = StringVar(value="Defaultna Poruka")
        msg_entry = Entry(main_frame, width=50, textvariable=msg_var)
        msg_entry.grid(column=1, row=2)

        # Unos veličine RSA ključa.
        rsa_key_size_label = Label(main_frame, text="Odaberi veličinu RSA ključa:  ")
        rsa_key_size_label.grid(column=0, row=3, sticky=W)
        rsa_key_option_list = [1024, 1500, 2048]
        rsa_key_var = IntVar()
        rsa_key_var.set(rsa_key_option_list[0])
        rsa_key_option_menu = OptionMenu(main_frame, rsa_key_var, *rsa_key_option_list)
        rsa_key_option_menu.config(bg="LIGHTGRAY", width="10")
        rsa_key_option_menu.grid(column=1, row=3)

        # Generiranje postavki ako je odabrana omotnica. ===============================================================
        if str(select_var.get()) == "Omotnica":

            sym_frame = Frame(main_frame)
            sym_frame.grid(column=1, row=4)

            # Odabir vrste simetričnog kriptosustava.
            sym_system_label = Label(main_frame, text="Vrsta simetričnog kriptosustava: ")
            sym_system_label.grid(column=0, row=4, sticky=W)
            sym_option_list = ["AES", "DES3"]
            sym_option_var = StringVar()
            sym_option_var.set(sym_option_list[0])
            empty_label = Label(sym_frame, text="                         ")
            empty_label.grid(column=0, row=0)
            sym_option_menu = OptionMenu(sym_frame, sym_option_var, *sym_option_list)
            sym_option_menu.config(bg="LIGHTGRAY", width="10")
            sym_option_menu.grid(column=1, row=0)

            sym_key_size_var = IntVar()
            sym_button = Button(sym_frame, text="Odaberi", command=lambda: f_sym_sel(sym_option_var,
                                                                                     main_frame, sym_key_size_var),
                                bg="GREEN", width=10)
            sym_button.grid(column=2, row=0)

            # Odabir veličine ključa kriptosustava.
            label_str = "Veličina ključa simetričnog kriptosustava za AES (b): "
            sym_key_size_label = Label(main_frame, text=label_str)
            sym_key_size_label.grid(column=0, row=5, sticky=W)
            sym_key_size_list = [128, 192, 256]
            sym_key_size_var.set(sym_key_size_list[0])
            sym_key_size_menu = OptionMenu(main_frame, sym_key_size_var, *sym_key_size_list)
            sym_key_size_menu.config(bg="LIGHTGRAY", width="10")
            sym_key_size_menu.grid(column=1, row=5)

            # Odabir načina kriptiranja simetričnog kriptosustava (CBC, ECB).
            sym_mode_label = Label(main_frame, text="Način kriptiranja simetričnog kriptosustava: ")
            sym_mode_label.grid(column=0, row=6, sticky=W)
            sym_mode_list = ["CBC", "ECB"]
            sym_mode_var = StringVar()
            sym_mode_var.set(sym_mode_list[0])
            sym_mode_menu = OptionMenu(main_frame, sym_mode_var, *sym_mode_list)
            sym_mode_menu.config(bg="LIGHTGRAY", width="10")
            sym_mode_menu.grid(column=1, row=6)

            # SHA se ne koristi kod omotnice.
            sha3_var = None
        # ==============================================================================================================
        # Generiranje postavki ako je odabran potpis. ==================================================================
        elif str(select_var.get()) == "Potpis":
            # Simetrični kriptosustavi se ne koriste kod potpisa.
            sym_option_var = None
            sym_mode_var = None
            sym_key_size_var = None

            # Unos SHA3 formata
            sha3_label = Label(main_frame, text="Odaberi SHA3 verziju:  ")
            sha3_label.grid(column=0, row=7, sticky=W)
            sha3_option_list = [256, 512]
            sha3_var = IntVar()
            sha3_var.set(sha3_option_list[0])
            sha3_option_menu = OptionMenu(main_frame, sha3_var, *sha3_option_list)
            sha3_option_menu.config(bg="LIGHTGRAY", width="10")
            sha3_option_menu.grid(column=1, row=7)
        # ==============================================================================================================
        # Generiranje postavki ako je odabran pečat. ===================================================================
        else:  # seal
            sym_frame = Frame(main_frame)
            sym_frame.grid(column=1, row=4)

            # Odabir vrste simetričnog kriptosustava.
            sym_system_label = Label(main_frame, text="Vrsta simetričnog kriptosustava: ")
            sym_system_label.grid(column=0, row=4, sticky=W)
            sym_option_list = ["AES", "DES3"]
            sym_option_var = StringVar()
            sym_option_var.set(sym_option_list[0])
            empty_label = Label(sym_frame, text="                         ")
            empty_label.grid(column=0, row=0)
            sym_option_menu = OptionMenu(sym_frame, sym_option_var, *sym_option_list)
            sym_option_menu.config(bg="LIGHTGRAY", width="10")
            sym_option_menu.grid(column=1, row=0)

            sym_key_size_var = IntVar()
            sym_button = Button(sym_frame, text="Odaberi", command=lambda: f_sym_sel(sym_option_var,
                                                                                     main_frame,
                                                                                     sym_key_size_var),
                                bg="GREEN", width=10)
            sym_button.grid(column=2, row=0)

            # Odabir velicine ključa kriptosustava.
            label_str = "Veličina ključa simetričnog kriptosustava za AES (b): "
            sym_key_size_label = Label(main_frame, text=label_str)
            sym_key_size_label.grid(column=0, row=5, sticky=W)
            sym_key_size_list = [128, 192, 256]
            sym_key_size_var.set(sym_key_size_list[0])
            sym_key_size_menu = OptionMenu(main_frame, sym_key_size_var, *sym_key_size_list)
            sym_key_size_menu.config(bg="LIGHTGRAY", width="10")
            sym_key_size_menu.grid(column=1, row=5)

            # Odabir načina kriptiranja simetričnog kriptosustava.
            sym_mode_label = Label(main_frame, text="Način kriptiranja simetričnog kriptosustava: ")
            sym_mode_label.grid(column=0, row=6, sticky=W)
            sym_mode_list = ["CBC", "ECB"]
            sym_mode_var = StringVar()
            sym_mode_var.set(sym_mode_list[0])
            sym_mode_menu = OptionMenu(main_frame, sym_mode_var, *sym_mode_list)
            sym_mode_menu.config(bg="LIGHTGRAY", width="10")
            sym_mode_menu.grid(column=1, row=6)

            # Unos SHA3 formata.
            sha3_label = Label(main_frame, text="Odaberi SHA3 verziju:  ")
            sha3_label.grid(column=0, row=7, sticky=W)
            sha3_option_list = [256, 512]
            sha3_var = IntVar()
            sha3_var.set(sha3_option_list[0])
            sha3_option_menu = OptionMenu(main_frame, sha3_var, *sha3_option_list)
            sha3_option_menu.config(bg="LIGHTGRAY", width="10")
            sha3_option_menu.grid(column=1, row=7)

        # Gumb za početak slanja.
        start_process_button = Button(main_frame, text="Pokreni", command=lambda: clicked(
            rsa_key_var, msg_var, sym_option_var, sym_mode_var, sym_key_size_var, sha3_var
        ), bg="GREEN")
        start_process_button.grid(column=1, row=8, sticky="S")

        # Stvori okvir(vertikalne i horizontalne linije) oko podataka.
        sep_hor = Separator(window, orient=HORIZONTAL)
        sep_hor.grid(column=0, row=2, columnspan=3, sticky="ew")
        sep_ver = Separator(window, orient=VERTICAL)
        sep_ver.grid(column=4, row=0, rowspan=7, sticky="ns")

    # Funkcija koja obrađuje pritisak gumba za početak komunikacije.
    def clicked(rsa_key_var, msg_var, sym_option_var, sym_mode_var, sym_key_size_var, sha3_var):

        int_rsa_key_size = int(rsa_key_var.get())

        # Prevedi dobiveni sha podatak u format koji se koristi u daljnoj obradi.
        if str(select_var.get()) == "Potpis":
            if int(sha3_var.get()) == 512:
                chosen_sha_format = "3_512"
            else:  # else 256
                chosen_sha_format = "3_256"
            init.start_signature(msg_var.get(), int_rsa_key_size, chosen_sha_format)

        elif str(select_var.get()) == "Omotnica":
            # Ako je odabran DES3 ključ, proširi ga na točne vrijednosti.
            sym_key_real_size = sym_key_size_var.get()
            if sym_key_real_size == 112:
                sym_key_real_size = 128
            elif sym_key_real_size == 168:
                sym_key_real_size = 192
            sym_key_real_size = int(sym_key_real_size / 8)
            init.start_envelope(msg_var.get(), int_rsa_key_size,
                                sym_option_var.get(), sym_mode_var.get(), sym_key_real_size)

        else:  # = Pečat
            # Ako je odabran DES3 ključ, proširi ga na točne vrijednosti.
            sym_key_real_size = sym_key_size_var.get()
            if sym_key_real_size == 112:
                sym_key_real_size = 128
            elif sym_key_real_size == 168:
                sym_key_real_size = 192
            sym_key_real_size = int(sym_key_real_size / 8)
            # Prevedi dobiveni sha podatak u format koji se koristi u daljnoj obradi.
            if int(sha3_var.get()) == 512:
                chosen_sha_format = "3_512"
            else:  # else 256
                chosen_sha_format = "3_256"
            init.start_seal(msg_var.get(), int_rsa_key_size,
                            sym_option_var.get(), sym_mode_var.get(), sym_key_real_size, chosen_sha_format)

    # Početni gumb koji generira opcije ovisno o odabranom načinu komunikacije.
    first_button = Button(head_frame, text="Odaberi", command=f_selected, bg="GREEN")
    first_button.grid(column=4, row=0, sticky=W)

    # Funkcija koja obrađuje pritisak gumba za odabir vrste simetričnog kriptosustava i na temelju toga
    # generira moguće vrijednosti duljine ključa.
    def f_sym_sel(sym_option_var, main_frame, sym_key_size_var):
        sel_str = str(sym_option_var.get())
        label_str = "Veličina ključa simetričnog kriptosustava za " + sel_str + " (b): "

        # Odabir veličine ključa kriptosustava
        sym_key_size_label = Label(main_frame, text=label_str)
        sym_key_size_label.grid(column=0, row=5, sticky=W)
        if sel_str == "AES":
            sym_key_size_list = [128, 192, 256]
        else:  # DES3
            sym_key_size_list = [112, 168]
        sym_key_size_var.set(sym_key_size_list[0])
        sym_key_size_menu = OptionMenu(main_frame, sym_key_size_var, *sym_key_size_list)
        sym_key_size_menu.config(bg="LIGHTGRAY", width="10")
        sym_key_size_menu.grid(column=1, row=5)

    window.mainloop()
