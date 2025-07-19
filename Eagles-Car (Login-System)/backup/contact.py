# -------------- Library used --------------
from customtkinter import *
from PIL import ImageTk,Image
import webbrowser

set_appearance_mode("Light")  # Modes: system (default), light, dark
set_default_color_theme("blue")  # Themes: blue (default), dark-blue, green
root_contact = CTk()
root_contact.title('Eagles Car (Contact - Information)')
root_contact.geometry("400x300+700+300")
root_contact.resizable(False, False)
root_contact.focus_set()

def Facebook_function():
    link = 'https://www.facebook.com/eaglesagencycar'
    webbrowser.open_new_tab(link)

def Instagram_function():
    link = 'https://www.instagram.com/eaglesagencycar?utm_source=ig_web_button_share_sheet&igsh=ZDNlZDc0MzIxNw=='
    webbrowser.open_new_tab(link)

def Linkedin_function():
    link = 'https://www.linkedin.com/in/eagles-car-189582272/'
    webbrowser.open_new_tab(link)

def Website1_function():
    link = 'https://www.Eagles-car.com/'
    webbrowser.open_new_tab(link)

def Website2_function():
    link = 'https://www.Eagles-car.net/'
    webbrowser.open_new_tab(link)

def Mail_function():
    link = 'mailto:info@eagles-car.com'
    webbrowser.open_new_tab(link)

def Back_To_App_function():
    root_contact.destroy()
    import app

Imgg1_con = ImageTk.PhotoImage(Image.open("assets/imgs/contact2.png"))
Imgg2_face = ImageTk.PhotoImage(Image.open("assets/imgs/facebook.png"))
Imgg3_insta = ImageTk.PhotoImage(Image.open("assets/imgs/instagram.png"))
Imgg4_linked = ImageTk.PhotoImage(Image.open("assets/imgs/linkedin.png"))
Imgg5_web = ImageTk.PhotoImage(Image.open("assets/imgs/website.png"))
Imgg6_mail = ImageTk.PhotoImage(Image.open("assets/imgs/mail.png"))

lbl1 = CTkLabel(master=root_contact, text="Eagles Car (Contact Us)", font=("Cambria", 25, "bold"))
lbl1.place(relx=0.5, rely=0.1, anchor=CENTER)

lbl2 = CTkLabel(master=root_contact, text="", image=Imgg1_con)
lbl2.place(relx=0.5, rely=0.3, anchor=CENTER)

btn1 = CTkButton(master=root_contact, text="Facebook", image=Imgg2_face, width=10, command=Facebook_function)
btn1.place(relx=0.18, rely=0.5, anchor=CENTER)

btn2 = CTkButton(master=root_contact, text="Instagram", image=Imgg3_insta, width=10, fg_color="#9651a6", command=Instagram_function)
btn2.place(relx=0.51, rely=0.5, anchor=CENTER)

btn3 = CTkButton(master=root_contact, text="LinkedIn", image=Imgg4_linked, width=10, fg_color="#0078d4", command=Linkedin_function)
btn3.place(relx=0.83, rely=0.5, anchor=CENTER)
btn4 = CTkButton(master=root_contact, text="Eagles-car.com", image=Imgg5_web, width=10, fg_color="#f6a823",

        text_color="#FFF", hover_color="#956716", command=Website1_function)
btn4.place(relx=0.7, rely=0.7, anchor=CENTER)
btn5 = CTkButton(master=root_contact, text="Eagles-car.net", image=Imgg5_web, width=10, fg_color="#f6a823",

        text_color="#FFF", hover_color="#956716", command=Website2_function)
btn5.place(relx=0.3, rely=0.7, anchor=CENTER)

btn6 = CTkButton(master=root_contact, text="Mail", image=Imgg6_mail, width=10, fg_color="#36c2f1",
        text_color="#FFF", hover_color="#956716", command=Mail_function)
btn6.place(relx=0.5, rely=0.9, anchor=CENTER)

btn6 = CTkButton(master=root_contact, text="Back To App", width=10, fg_color="red",
        text_color="#FFF", hover_color="#641e16", command=Back_To_App_function)
btn6.place(relx=0.85, rely=0.93, anchor=CENTER)

root_contact.mainloop()