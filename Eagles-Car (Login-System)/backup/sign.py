# -------------- Library used --------------
from tkinter import *
from tkinter.messagebox import *
from customtkinter import *
from PIL import ImageTk,Image
from mysql.connector import connect as con_db
import time

# -------------- Customize Tkinter --------------
set_appearance_mode("Dark")  # Modes: system (default), light, dark
set_default_color_theme("green")  # Themes: blue (default), dark-blue, green

# -------------- Root - Customize Window --------------
root_sign = CTk()
root_sign.title("Eagles Car (Sign Up - New Account)")
root_sign.geometry("500x480+620+190")
root_sign.resizable(False, False)
root_sign.focus_set()

# -------------- Define - Function --------------
global trial_no
trial_no = 0

def trial():
    global trial_no
    trial_no +=1
    print("Trial no is ", trial_no)
    if trial_no == 3:
        showwarning("Warning !", "You have tried more then limit required !!")
        root_sign.destroy()

def Signup_function():
    usernamee = Username_Entry_win.get()
    email = Email_Entry_win.get()
    passwordd = Password_Entry_win.get()
    con_passwordd = Confrim_Password_Entry_win.get()
    if usernamee != "" and email != "" and passwordd != "" and con_passwordd == passwordd:
        try:
            conn = con_db(host="localhost", user="root", password="", database="eagles-company")
            cur = conn.cursor()
            command = "insert into eagles_accounts values(0, %s, %s, %s)"
            cur.execute(command,(usernamee, passwordd, email))
            conn.commit()
            e = usernamee.capitalize()
            showinfo(title="Register Successfully !", message="The Register has been Successfully, Welcome " + e + " To Eagles Car !!")
            Username_Entry_win.delete(0, END)
            Email_Entry_win.delete(0, END)
            Password_Entry_win.delete(0, END)
            Confrim_Password_Entry_win.delete(0, END)
            Login()
        except:
            lb_error.configure(text="Unknown Error, Please Try Again Later..")
            Login_Button_win.place(relx=0.65, rely=0.96, anchor=CENTER)
            Login_LB_win.place(relx=0.45, rely=0.96, anchor=CENTER)
            Sign_Button.place(relx=0.5, rely=0.89, anchor=CENTER)
    else:
        lb_error.configure(text="Error,  Please Insert Data !")
        Login_Button_win.place(relx=0.65, rely=0.96, anchor=CENTER)
        Login_LB_win.place(relx=0.45, rely=0.96, anchor=CENTER)
        Sign_Button.place(relx=0.5, rely=0.89, anchor=CENTER)
        trial()

def Login():
    root_sign.destroy()
    time.sleep(0.1)
    import login

def Hide_password_function():
    Close_eye_Button.destroy()
    Password_Entry_win.configure(show="*")
    Open_eye_Button = CTkButton(master=root_sign, text="", image=open_eye, fg_color="#343638", bg_color="transparent",
            width=5, height=1, corner_radius=16, hover_color="#343638", cursor="hand2", command=Show_password_function)
    Open_eye_Button.place(relx=0.701, rely=0.62, anchor=CENTER)

def Show_password_function():
    Open_eye_Button.destroy()
    global Close_eye_Button
    Password_Entry_win.configure(show="")
    Close_eye_Button = CTkButton(master=root_sign, text="", image=close_eye, fg_color="#343638", bg_color="transparent",
            width=5, height=1, corner_radius=16, hover_color="#343638", cursor="hand2", command=Hide_password_function)
    Close_eye_Button.place(relx=0.701, rely=0.62, anchor=CENTER)

def Hide_password_function2():
    Close_eye_Button2.destroy()
    Confrim_Password_Entry_win.configure(show="*")
    Open_eye_Button2 = CTkButton(master=root_sign, text="", image=open_eye, fg_color="#343638", bg_color="transparent",
            width=5, height=1, corner_radius=16, hover_color="#343638", cursor="hand2", command=Show_password_function2)
    Open_eye_Button2.place(relx=0.701, rely=0.76, anchor=CENTER)

def Show_password_function2():
    Open_eye_Button2.destroy()
    global Close_eye_Button2
    Confrim_Password_Entry_win.configure(show="")
    Close_eye_Button2 = CTkButton(master=root_sign, text="", image=close_eye, fg_color="#343638", bg_color="transparent",
            width=5, height=1, corner_radius=16, hover_color="#343638", cursor="hand2", command=Hide_password_function2)
    Close_eye_Button2.place(relx=0.701, rely=0.76, anchor=CENTER)

# -------------- All - Tools --------------
img1 = ImageTk.PhotoImage(Image.open("assets/imgs/pattern.png"))
open_eye = ImageTk.PhotoImage(Image.open("assets/imgs/eye.png").resize((24,22)))
close_eye = ImageTk.PhotoImage(Image.open("assets/imgs/hidden.png").resize((22,22)))

background_logo = CTkLabel(master=root_sign,image=img1, text="")
background_logo.pack()

LB_Title_win = CTkLabel(master=root_sign, text="Welcome To Eagles Car, Again", fg_color="#f6a823", 
        text_color="white", width=500, height=50, font=('Cambria', 29, 'bold'))
LB_Title_win.place(relx=0.5, rely=0.05, anchor=CENTER)

lb_error = CTkLabel(master=root_sign, text="", 
corner_radius=0, fg_color="#242424", text_color="#ff402a", 
font=("Cambria", 14, "bold"))
lb_error.place(relx=0.5, rely=0.825, anchor=CENTER)

Create_acc_win = CTkLabel(master=root_sign, text="Create New Account :", font=('Cambria', 28, 'bold'))
Create_acc_win.place(relx=0.5, rely=0.17, anchor=CENTER)

Username_Label_win = CTkLabel(master=root_sign, text="Enter Username :", font=("Cambria", 17, 'bold'))
Username_Label_win.place(relx=0.21, rely=0.27, anchor=CENTER)
Username_Entry_win = CTkEntry(master=root_sign, width=235, height=31, placeholder_text='Username',
        font=("Cambria", 14, 'bold'))
Username_Entry_win.place(relx=0.5, rely=0.34, anchor=CENTER)

Email_Label_win = CTkLabel(master=root_sign, text="Enter Email :", font=("Cambria", 17, 'bold'))
Email_Label_win.place(relx=0.18, rely=0.41, anchor=CENTER)
Email_Entry_win = CTkEntry(master=root_sign, width=235, height=31, placeholder_text='Email@example.com',
        font=("Cambria", 14, 'bold'))
Email_Entry_win.place(relx=0.5, rely=0.48, anchor=CENTER)

Password_Label_win = CTkLabel(master=root_sign, text="Create New Password :", font=("Cambria", 17, 'bold'))
Password_Label_win.place(relx=0.22, rely=0.55, anchor=CENTER)
Password_Entry_win = CTkEntry(master=root_sign, width=235, height=31, placeholder_text='Create Strong Password', show="*",
        font=("Cambria", 14, 'bold'))
Password_Entry_win.place(relx=0.5, rely=0.62, anchor=CENTER)

Confirm_Password_Label_win = CTkLabel(master=root_sign, text="Confirm New Password :", font=("Cambria", 17, 'bold'))
Confirm_Password_Label_win.place(relx=0.23, rely=0.69, anchor=CENTER)
Confrim_Password_Entry_win = CTkEntry(master=root_sign, width=235, height=31, placeholder_text='Confrim Password',
        show="*", font=("Cambria", 14, 'bold'))
Confrim_Password_Entry_win.place(relx=0.5, rely=0.76, anchor=CENTER)

Open_eye_Button = CTkButton(master=root_sign, text="", image=open_eye, fg_color="#343638", bg_color="transparent",
        width=5, height=1, corner_radius=16, hover_color="#343638", cursor="hand2", command=Show_password_function)
Open_eye_Button.place(relx=0.701, rely=0.62, anchor=CENTER)

Open_eye_Button2 = CTkButton(master=root_sign, text="", image=open_eye, fg_color="#343638", bg_color="transparent",
        width=5, height=1, corner_radius=16, hover_color="#343638", cursor="hand2", command=Show_password_function2)
Open_eye_Button2.place(relx=0.701, rely=0.76, anchor=CENTER)

Sign_Button = CTkButton(master=root_sign, width=200, text="Register", command=Signup_function, corner_radius=8,
        fg_color="#f6a823", text_color="white", hover_color="#956716", font=("Cambria", 15))
Sign_Button.place(relx=0.5, rely=0.85, anchor=CENTER)

Login_LB_win = CTkLabel(master=root_sign, text="Do you Have Account ?", fg_color="#242424",
        text_color="white", font=("Cambria", 14.5))
Login_LB_win.place(relx=0.45, rely=0.92, anchor=CENTER)

Login_Button_win = CTkButton(master=root_sign, width=10, text="Login", corner_radius=8,
        fg_color="#242424", text_color="#f6a823", hover_color="#242424", font=("Cambria", 16), command=Login)
Login_Button_win.place(relx=0.65, rely=0.92, anchor=CENTER)

# -------------- Root-Sign - MainLoop --------------
root_sign.mainloop()