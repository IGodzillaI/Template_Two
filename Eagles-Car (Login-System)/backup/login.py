# -------------- Library used --------------
from tkinter import *
from tkinter.messagebox import *
from customtkinter import *
from PIL import ImageTk,Image
from mysql.connector import connect as con_db
import mysql.connector
import time

# -------------- Customize Tkinter --------------
set_appearance_mode("Dark")  # Modes: system (default), light, dark
set_default_color_theme("blue")  # Themes: blue (default), dark-blue, green

# -------------- Root - Customize Window --------------
root = CTk()
root.title('Eagles Car (Login System) v3.5.8')
root.geometry("700x500+500+190")
root.resizable(False, False)
root.focus_set()

# -------------- Define - Function --------------
trial_no = 0
trial_no2 = 0

def trial():
    global trial_no
    trial_no +=1
    print("Trial no is ", trial_no)
    if trial_no == 3:
        showwarning("Warning !", "You have tried more then limit required !!")
        root.destroy()

def trial2():
    global trial_no2
    trial_no2 +=1
    print("Trial no is ", trial_no2)
    if trial_no2 == 3:
        showwarning("Warning !", "You have tried more then limit required !!")
        root.destroy()

def Login_function():
    global result
    email = Email_Entry.get()
    passwordd = Password_Entry.get()
    if email == "" and passwordd == "":
        LB_Error2.configure(text="Please Insert Username and Password")
        Login_Button.place(relx=0.5, rely=0.84, anchor=CENTER)
        Signup_LB.place(relx=0.4, rely=0.92, anchor=CENTER)
        Signup_Button.place(relx=0.672, rely=0.92, anchor=CENTER)
        Save_Data.place(relx=0.34, rely=0.75, anchor=CENTER)
        Forget_Button.place(relx=0.67, rely=0.75, anchor=CENTER)
        trial2()
    else:
        try:
            conn = con_db(host="localhost", user="root", password="", database="eagles-company")
            cur = conn.cursor()
            command = "SELECT username FROM eagles_accounts WHERE mail=%s and password=%s"
            cur.execute(command,(email, passwordd))
            result = cur.fetchone()
            if result == None:
                LB_Error2.configure(text="Invaild Username or Password")
                Login_Button.place(relx=0.5, rely=0.84, anchor=CENTER)
                Signup_LB.place(relx=0.4, rely=0.92, anchor=CENTER)
                Signup_Button.place(relx=0.672, rely=0.92, anchor=CENTER)
                Save_Data.place(relx=0.34, rely=0.75, anchor=CENTER)
                Forget_Button.place(relx=0.67, rely=0.75, anchor=CENTER)
                trial()
            else:
                time.sleep(0.3)
                root.destroy()
                import app
        except:
                LB_Error2.configure(text="Unknown Error, Please Try Again Later..")
                Login_Button.place(relx=0.5, rely=0.84, anchor=CENTER)
                Signup_LB.place(relx=0.4, rely=0.92, anchor=CENTER)
                Signup_Button.place(relx=0.672, rely=0.92, anchor=CENTER)
                Save_Data.place(relx=0.34, rely=0.75, anchor=CENTER)
                Forget_Button.place(relx=0.67, rely=0.75, anchor=CENTER)

def Register_function():
    root.destroy()
    time.sleep(0.1)
    import sign

def Forget_function():
    root.destroy()
    import check_forget

def Remember_function():
    if Save_Data.get() == "on":
        Email_Entry.delete(0, END)
        Password_Entry.delete(0, END)
        Email_Entry.insert(index=(0), string="Eagles-car@gmail.com")
        Password_Entry.insert(index=(0), string="admin")

def Hide_password_function():
    Password_Entry.configure(show="*")
    Close_eye_Button.destroy()
    Open_eye_Button = CTkButton(master=root, text="",image=open_eye, fg_color="#343638", border_width=None,
        width=5, height=1, corner_radius=16, hover_color="#343638", cursor="hand2", command=Show_password_function)
    Open_eye_Button.place(relx=0.638, rely=0.58, anchor=CENTER)

def Show_password_function():
    global Close_eye_Button
    Password_Entry.configure(show="")
    Open_eye_Button.destroy()
    Close_eye_Button = CTkButton(master=root, text="",image=close_eye, fg_color="#343638", border_width=None,
        width=5, height=1, corner_radius=16, hover_color="#343638", cursor="hand2", command=Hide_password_function)
    Close_eye_Button.place(relx=0.638, rely=0.579, anchor=CENTER)

# -------------- Images --------------
img = ImageTk.PhotoImage(Image.open("assets/imgs/Eagle.png").resize((150,110)))
img1 = ImageTk.PhotoImage(Image.open("assets/imgs/Eagle-Bg.png").resize((1360,768)))
open_eye = ImageTk.PhotoImage(Image.open("assets/imgs/eye2.png").resize((20,20)))
close_eye = ImageTk.PhotoImage(Image.open("assets/imgs/hidden2.png").resize((22,22)))

# -------------- Logo - Images --------------
Background_logo = CTkLabel(master=root,image=img1, text="")
Background_logo.pack()

# -------------- Frame - Logo --------------
Frame1 = CTkFrame(master=Background_logo, width=360, height=400, bg_color="transparent", fg_color="transparent")
Frame1.place(relx=0.5, rely=0.5, anchor=CENTER)

Logo_frame = CTkLabel(master=Frame1, text="",image=img)
Logo_frame.place(relx=0.5, rely=0.26, anchor=CENTER)

# -------------- Label --------------
LB_Error2 = CTkLabel(master=root, text="", corner_radius=0, fg_color="#242424", text_color="#ed230c", font=("Arial", 13, "bold"))
LB_Error2.place(relx=0.5, rely=0.64, anchor=CENTER)

LB_Title = CTkLabel(master=Frame1, text="Welcome To Eagles Car", bg_color="transparent", fg_color="#f6a823", 
        text_color="white", width=500, height=50, font=('Cambria', 29, 'bold'))
LB_Title.place(relx=0.5, rely=0.06, anchor=CENTER)

LB1 = CTkLabel(master=Frame1, text="Log into your Account", 
        font=('Cambria', 21, 'bold'))
LB1.place(relx=0.5, rely=0.4, anchor=CENTER)

Signup_LB = CTkLabel(master=Frame1, text="Don't Have Account ?", fg_color="#242424", text_color="white",
        font=("Cambria", 13.8))
Signup_LB.place(relx=0.4, rely=0.87, anchor=CENTER)

# -------------- Entry --------------
Email_Entry = CTkEntry(master=Frame1, width=230, height=30, placeholder_text='Email', 
    font=("Arial", 13, "bold"))
Email_Entry.place(relx=0.5, rely=0.5, anchor=CENTER)

Password_Entry = CTkEntry(master=Frame1, width=230, height=30, placeholder_text='Password', show="*", 
    font=("Arial", 13, "bold"))
Password_Entry.place(relx=0.5, rely=0.6, anchor=CENTER)

# -------------- CheckBox --------------
Check_var = StringVar(value="on")
Save_Data = CTkCheckBox(master=Frame1, text="Remember Me", checkbox_width=20, checkbox_height=20,
        checkmark_color="white", fg_color="black", text_color="white", hover_color="#4b4b4b", variable=Check_var, 
        onvalue="on", offvalue="off", command=Remember_function)
Save_Data.place(relx=0.34, rely=0.69, anchor=CENTER)

# -------------- Buttons --------------
Forget_Button = CTkButton(master=Frame1, text="Forget password?", font=('Century Gothic', 13, "bold", "underline"),
        fg_color="#242424", hover_color="#242424", cursor='hand2', text_color="#e82930", width=90, command=Forget_function)
Forget_Button.place(relx=0.67, rely=0.687, anchor=CENTER)

Login_Button = CTkButton(master=Frame1, width=220, text="Login", command=Login_function, corner_radius=8,
        fg_color="#f6a823", text_color="white", hover_color="#956716")
Login_Button.place(relx=0.5, rely=0.78, anchor=CENTER)

Signup_Button = CTkButton(master=Frame1, width=60, text="Register", command=Register_function, corner_radius=8,
        fg_color="#242424", text_color="#f6a823", hover_color="#242424", font=("Arial", 14,"underline"))
Signup_Button.place(relx=0.672, rely=0.868, anchor=CENTER)

Open_eye_Button = CTkButton(master=root, text="",image=open_eye, fg_color="#343638", border_width=None,
        width=5, height=0, corner_radius=16, hover_color="#343638", cursor="hand2", command=Show_password_function)
Open_eye_Button.place(relx=0.638, rely=0.58, anchor=CENTER)

# -------------- Root - Start Main Loop --------------
root.mainloop()