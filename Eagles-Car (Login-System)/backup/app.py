# -------------- Library used --------------
from tkinter import *
from tkinter.messagebox import *
from customtkinter import *
from PIL import ImageTk,Image
import webbrowser

# -------------- Customize Tkinter --------------
set_appearance_mode("Light")  # Modes: system (default), light, dark
set_default_color_theme("green")  # Themes: blue (default), dark-blue, green

# -------------- app - Customize Window --------------
app = CTk()
app.title('Eagles Car (Rental Car & Borrow Car)')
app.geometry("1200x650+200+90")
app.resizable(False, False)
app.focus_set()

# -------------- Define - Function --------------
class SlidePanel(CTkFrame):
    def __init__(self, parent, start_pos, end_pos):
        super().__init__(master=parent, fg_color="#f6a823", corner_radius=4)
        self.start_pos = start_pos
        self.end_pos = end_pos
        self.width = abs(start_pos - end_pos)
        self.pos = start_pos
        self.in_start_pos = True
        self.place(relx=self.start_pos, rely=0, relwidth=self.width, relheight=1)

    def animate(self):
        if self.in_start_pos:
            self.animate_forward()
        else:
            self.animate_backwards()

    def animate_forward(self):
        if self.pos > self.end_pos:
            self.pos -= 0.008
            self.place(relx=self.pos, rely=0.122, relwidth=self.width, relheight=0.88)
            self.after(10, self.animate_forward)
        else:
            self.in_start_pos = False

    def animate_backwards(self):
        if self.pos < self.start_pos:
            self.pos += 0.008
            self.place(relx=self.pos, rely=0.122, relwidth=self.width, relheight=0.88)
            self.after(10, self.animate_backwards)
        else:
            self.in_start_pos = True

animated_panel = SlidePanel(app, 1.1, 0.75)

def Home_function():
    pass

def Rental_function():
    pass

def Borrow_function():
    pass

def Blog_function():
    pass

def Account_Setting_function():
    pass

def Support_function():
    link = 'mailto:info@eagles-car.com'
    webbrowser.open_new_tab(link)

def Whatsapp_function():
    link = 'https://web.whatsapp.com/send?phone=97142256568&amp;text='
    webbrowser.open_new_tab(link)

def About_function():
    showinfo(title="Eagles Car (About us - Info)", message="Welcome, We are Eagles Car We Here For Rental Car or Borrow Car, We are in Egypt and in UAE, We are Trustworthy. Thank you.")

def Contact_function():
    app.destroy()
    import contact

def Logout_function():
    app.destroy()
    import login

def Exit_function():
    app.destroy()

# -------------- Images --------------
Img1 = ImageTk.PhotoImage(Image.open("assets/imgs/Eagle.png").resize((120,100)))
Img2 = ImageTk.PhotoImage(Image.open("assets/imgs/remove2.png"))
Img3 = ImageTk.PhotoImage(Image.open("assets/imgs/logout.png"))
Img4 = ImageTk.PhotoImage(Image.open("assets/imgs/more.png"))
Img5 = ImageTk.PhotoImage(Image.open("assets/imgs/remove3.png").resize((42,42)))
Img6 = ImageTk.PhotoImage(Image.open("assets/imgs/support.png"))
Img7 = ImageTk.PhotoImage(Image.open("assets/imgs/whatsapp.png"))
Img8 = ImageTk.PhotoImage(Image.open("assets/imgs/about.png"))
Img9 = ImageTk.PhotoImage(Image.open("assets/imgs/contact.png"))
Img10 = ImageTk.PhotoImage(Image.open("assets/imgs/setting2.png"))
Img11 = ImageTk.PhotoImage(Image.open("assets/imgs/home.png"))
Img12 = ImageTk.PhotoImage(Image.open("assets/imgs/car-rental.png").resize((52,52)))
Img13 = ImageTk.PhotoImage(Image.open("assets/imgs/car.png"))
Img14 = ImageTk.PhotoImage(Image.open("assets/imgs/facebook.png"))
Img15 = ImageTk.PhotoImage(Image.open("assets/imgs/instagram.png"))
Img16 = ImageTk.PhotoImage(Image.open("assets/imgs/website.png"))
Img17 = ImageTk.PhotoImage(Image.open("assets/imgs/linkedin.png"))
Img18 = ImageTk.PhotoImage(Image.open("assets/imgs/mail.png"))
Img111 = ImageTk.PhotoImage(Image.open("assets/imgs/home.png").resize((44,44)))
Img122 = ImageTk.PhotoImage(Image.open("assets/imgs/car-rental.png").resize((56,56)))
Img133 = ImageTk.PhotoImage(Image.open("assets/imgs/car.png").resize((44,44)))
Img144 = ImageTk.PhotoImage(Image.open("assets/imgs/blog.png").resize((48,48)))

# -------------- Frame --------------
Fr = CTkFrame(master=app, width=1205, height=80, fg_color="black")
Fr.place(x=0, y=0)

# -------------- Label - Images --------------
Logo = CTkLabel(master=Fr, text="",image=Img1, fg_color="#2b2b2b")
Logo.place(relx=0.038, rely=0.5, anchor=CENTER)

# -------------- Label - Frame --------------
Lb1_Fr = CTkLabel(master=Fr, text="Welcome To Eagles Car", text_color="White", font=("Cambria", 35, "bold"))
Lb1_Fr.place(relx=0.24, rely=0.5, anchor=CENTER)

Lb2_Fr = CTkLabel(master=Fr, text="(Rental Car & Borrow Car)", text_color="White", font=("Cambria", 16, "bold"))
Lb2_Fr.place(relx=0.48, rely=0.6, anchor=CENTER)

# -------------- Label --------------

# -------------- Entry --------------

# -------------- CheckBox --------------

# -------------- Buttons --------------
Bt_Fr = CTkButton(master=Fr, text="Menu", image=Img4, text_color="black", font=("Cambria", 16, "bold"),
        fg_color="white", hover_color="#5b5b5b", width=80, command= animated_panel.animate)
Bt_Fr.place(relx=0.94, rely=0.52, anchor=CENTER)

Bt_home = CTkButton(master=Fr, text="Home", image=Img11, fg_color="black",
        width=20,font=("Book Antiqua", 14, "bold"), hover_color="#3b3b3b")
Bt_home.place(relx=0.62, rely=0.53, anchor=CENTER)

Bt_rental = CTkButton(master=Fr, text="Rental Car", image=Img12, fg_color="black",
        width=20,font=("Book Antiqua", 14, "bold"), hover_color="#2471a3")
Bt_rental.place(relx=0.72, rely=0.53, anchor=CENTER)

Bt_borrow = CTkButton(master=Fr, text="Borrow Car", image=Img13, fg_color="black",
        width=20,font=("Book Antiqua", 14, "bold"), hover_color="#a93226")
Bt_borrow.place(relx=0.84, rely=0.53, anchor=CENTER)

# ----------------------------- Animated-Panel - Menu -----------------------------
# -------------- Frame - Add - Menu --------------
Fr_add1 = CTkFrame(master=animated_panel, width=450, height=5, fg_color="white")
Fr_add1.place(relx=0.35, rely=0.2, anchor=CENTER)

Fr_add2 = CTkFrame(master=animated_panel, width=450, height=5, fg_color="white")
Fr_add2.place(relx=0.35, rely=0.68, anchor=CENTER)

Fr_add3 = CTkFrame(master=animated_panel, width=450, height=5, fg_color="white")
Fr_add3.place(relx=0.35, rely=0.9, anchor=CENTER)

# -------------- Title - Frame - Menu --------------
Title = CTkLabel(master=animated_panel, text="More Options", text_color="white",
        font=("Book Antiqua", 20, "bold", "underline"))
Title.place(relx=0.35, rely=0.03, anchor=CENTER)

Title2 = CTkLabel(master=animated_panel, text="Options", text_color="white",
        font=("Book Antiqua", 20, "bold", "underline"))
Title2.place(relx=0.36, rely=0.235, anchor=CENTER)

Title3 = CTkLabel(master=animated_panel, text="Contact", text_color="white",
        font=("Book Antiqua", 20, "bold", "underline"))
Title3.place(relx=0.35, rely=0.72, anchor=CENTER)

# -------------- Label - Frame - Menu --------------
Lb1 = CTkLabel(master=animated_panel, text="Welcome : Eagles-Ahmed", text_color="white",
        font=("Book Antiqua", 16, "bold"))
Lb1.place(relx=0.25, rely=0.085, anchor=CENTER)

Lb2 = CTkLabel(master=animated_panel, text="Settings : ", text_color="white",
        font=("Book Antiqua", 16, "bold"))
Lb2.place(relx=0.115, rely=0.15, anchor=CENTER)

# -------------- Button - Frame - Menu --------------
Bt_account = CTkButton(master=animated_panel, text="Account Setting", image=Img10, fg_color="#f6a823",
        width=10, height=10, font=("Book Antiqua", 15, "bold"), hover_color="#956716", command=Account_Setting_function)
Bt_account.place(relx=0.39, rely=0.15, anchor=CENTER)

Bt_home2 = CTkButton(master=animated_panel, text="Home", image=Img111, fg_color="#f6a823",
        width=20,font=("Book Antiqua", 16, "bold"), hover_color="#3b3b3b", command=Home_function)
Bt_home2.place(relx=0.36, rely=0.32, anchor=CENTER)

Bt_rental2 = CTkButton(master=animated_panel, text="Rental Car", image=Img122, fg_color="#f6a823",
        width=20,font=("Book Antiqua", 16, "bold"), hover_color="#2471a3", command=Rental_function)
Bt_rental2.place(relx=0.36, rely=0.42, anchor=CENTER)

Bt_borrow2 = CTkButton(master=animated_panel, text="Borrow Car", image=Img133, fg_color="#f6a823",
        width=20,font=("Book Antiqua", 16, "bold"), hover_color="#a93226", command=Borrow_function)
Bt_borrow2.place(relx=0.36, rely=0.52, anchor=CENTER)

Bt_blog2 = CTkButton(master=animated_panel, text="Blog", image=Img144, fg_color="#f6a823",
        width=20,font=("Book Antiqua", 16, "bold"), hover_color="#956716", command=Blog_function)
Bt_blog2.place(relx=0.36, rely=0.62, anchor=CENTER)

Bt_support2 = CTkButton(master=animated_panel, text="Support", image=Img6, fg_color="#f6a823", width=20,
        font=("Book Antiqua", 15, "bold"), hover_color="#956716", command=Support_function)
Bt_support2.place(relx=0.16, rely=0.78, anchor=CENTER)

Bt_whats = CTkButton(master=animated_panel, text="Whatsapp", image=Img7, fg_color="#f6a823", width=20,
        font=("Book Antiqua", 15, "bold"), hover_color="#956716", command=Whatsapp_function)
Bt_whats.place(relx=0.16, rely=0.85, anchor=CENTER)

Bt_about = CTkButton(master=animated_panel, text="About us", image=Img8, fg_color="#f6a823", width=20,
        font=("Book Antiqua", 15, "bold"), hover_color="#956716", command=About_function)
Bt_about.place(relx=0.52, rely=0.78, anchor=CENTER)

Bt_contact = CTkButton(master=animated_panel, text="Contact us", image=Img9, fg_color="#f6a823", width=20,
        font=("Book Antiqua", 15, "bold"), hover_color="#956716", command=Contact_function)
Bt_contact.place(relx=0.52, rely=0.85, anchor=CENTER)

Bt_quit = CTkButton(master=animated_panel, text="Quit", image=Img2, fg_color="#f6a823", width=20,
        font=("Book Antiqua", 16, "bold"), hover_color="red", command=Exit_function)
Bt_quit.place(relx=0.52, rely=0.95, anchor=CENTER)

Bt_logout = CTkButton(master=animated_panel, text="Log out", image=Img3, fg_color="#f6a823", width=20,
        font=("Book Antiqua", 15, "bold"), hover_color="gray", command=Logout_function)
Bt_logout.place(relx=0.2, rely=0.95, anchor=CENTER)

# -------------- app - Start Main Loop --------------
app.mainloop()