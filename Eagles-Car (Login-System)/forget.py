# -------------- Library used --------------
from tkinter import *
from tkinter.messagebox import *
from customtkinter import *
from PIL import ImageTk,Image
import mysql.connector

# -------------- Customize Tkinter --------------
set_appearance_mode("Dark")  # Modes: system (default), light, dark
set_default_color_theme("green")  # Themes: blue (default), dark-blue, green
# -------------- Root - Customize Window --------------
root_forget2 = CTk()
root_forget2.title("Eagles Car (Reset Password)")
root_forget2.geometry("470x400+900+450")
root_forget2.resizable(False, False)
root_forget2.focus_set()

def New_Pass_function():
    New_Pass = Forget_Password_Entry_Forget.get()
    Con_Pass = Confirm_New_Password_Entry_Forget.get()
    if New_Pass == "" and Con_Pass == "":
            lb_error.configure(text="Please Enter Password !!")
            New_Pass_Bt.place(relx=0.5, rely=0.85, anchor=CENTER)
    elif New_Pass != "" and Con_Pass != "" and Con_Pass == New_Pass:
            try:
                    conn2 = mysql.connector.connect(host="localhost", user="root", password="", database="eagles-company")
                    cur2 = conn2.cursor()
                    commandd = "update eagles_accounts set password=%s where mail=%s"
                    cur2.execute(commandd,(New_Pass))
                    conn2.commit()
                    Forget_Password_Entry_Forget.delete(0, END)
                    Confirm_New_Password_Entry_Forget.delete(0, END)
                    showinfo(title="Reset Password Successfully !", message="Congrats, Reset Password Has Been Successfully !")
                    root_forget2.destroy()
                    import login
            except:
                    lb_error.configure(text="Unknown Error, Please Try Again Later..")
                    New_Pass_Bt.place(relx=0.5, rely=0.85, anchor=CENTER)
    else:
            lb_error.configure(text="The Password is not Match !!")
            New_Pass_Bt.place(relx=0.5, rely=0.85, anchor=CENTER)

def Hide_password_function():
    Forget_Password_Entry_Forget.configure(show="*")
    Close_eye_Button.destroy()
    Open_eye_Button = CTkButton(master=root_forget2, text="",image=open_eye, fg_color="#343638", border_width=None,
            width=5, height=1, corner_radius=16, hover_color="#343638", cursor="hand2", command=Show_password_function)
    Open_eye_Button.place(relx=0.71, rely=0.48, anchor=CENTER)

def Hide_password_2_function():
    Confirm_New_Password_Entry_Forget.configure(show="*")
    Close_eye_Button2.destroy()
    Open_eye_Button2 = CTkButton(master=root_forget2, text="",image=open_eye, fg_color="#343638", border_width=None,
            width=5, height=1, corner_radius=16, hover_color="#343638", cursor="hand2", command=Show_password_2_function)
    Open_eye_Button2.place(relx=0.71, rely=0.69, anchor=CENTER)

def Show_password_function():
    global Close_eye_Button
    Forget_Password_Entry_Forget.configure(show="")
    Open_eye_Button.destroy()
    Close_eye_Button = CTkButton(master=root_forget2, text="",image=close_eye, fg_color="#343638", border_width=None,
            width=5, height=1, corner_radius=16, hover_color="#343638", cursor="hand2", command=Hide_password_function)
    Close_eye_Button.place(relx=0.71, rely=0.48, anchor=CENTER)

def Show_password_2_function():
    global Close_eye_Button2
    Confirm_New_Password_Entry_Forget.configure(show="")
    Open_eye_Button2.destroy()
    Close_eye_Button2 = CTkButton(master=root_forget2, text="",image=close_eye, fg_color="#343638", border_width=None,
            width=5, height=1, corner_radius=16, hover_color="#343638", cursor="hand2", command=Hide_password_2_function)
    Close_eye_Button2.place(relx=0.71, rely=0.69, anchor=CENTER)

# -------------- All - Tools --------------
imgg1 = ImageTk.PhotoImage(Image.open("assets/imgs/check.png"))
open_eye = CTkImage(Image.open("assets/imgs/eye-blue.png"), size=(18,18))
close_eye = CTkImage(Image.open("assets/imgs/hidden-blue.png"), size=((18,18)))

background_logo2 = CTkLabel(master=root_forget2, image=imgg1, text="")
background_logo2.pack()

lb_error = CTkLabel(master=root_forget2, text="", bg_color="#08092f",
        corner_radius=0, fg_color="#08092f", text_color="#ff402a", font=("Cambria", 14, "bold"))
lb_error.place(relx=0.5, rely=0.765, anchor=CENTER)

Lb_Title1 = CTkLabel(master=root_forget2, text="Welcome : Ahmed", fg_color="#08092f", text_color="white",
        width=500, height=70, font=('Cambria', 30, 'bold'))
Lb_Title1.place(relx=0.5, rely=0.06, anchor=CENTER)

Lb_Title2 = CTkLabel(master=root_forget2, text="Reset Your Password :",
        fg_color="#08092f", font=('Cambria', 30, 'bold'))
Lb_Title2.place(relx=0.5, rely=0.24, anchor=CENTER)

Forget_Password_Label_Forget = CTkLabel(master=root_forget2, text="Create New Password :",
        fg_color="#08092f", text_color="white", font=("Cambria", 18, 'bold'))
Forget_Password_Label_Forget.place(relx=0.28, rely=0.38, anchor=CENTER)
Forget_Password_Entry_Forget = CTkEntry(master=root_forget2, width=235, height=31,
        font=("Cambria", 15, 'bold'), placeholder_text='Create Strong Password', show="*")
Forget_Password_Entry_Forget.place(relx=0.5, rely=0.48, anchor=CENTER)

Confirm_New_Password_Label_Forget = CTkLabel(master=root_forget2, text="Confirm New Password : ",
        fg_color="#08092f", text_color="white", font=("Cambria", 18, 'bold'))
Confirm_New_Password_Label_Forget.place(relx=0.3, rely=0.59, anchor=CENTER)
Confirm_New_Password_Entry_Forget = CTkEntry(master=root_forget2, width=235, height=31,
        font=("Cambria", 15, 'bold'), placeholder_text='Confirm Password', show="*")
Confirm_New_Password_Entry_Forget.place(relx=0.5, rely=0.69, anchor=CENTER)

Open_eye_Button = CTkButton(master=root_forget2, text="",image=open_eye, fg_color="#343638", border_width=None,
    width=5, height=1, corner_radius=16, hover_color="#343638", cursor="hand2", command=Show_password_function)
Open_eye_Button.place(relx=0.71, rely=0.48, anchor=CENTER)

Open_eye_Button2 = CTkButton(master=root_forget2, text="",image=open_eye, fg_color="#343638", border_width=None,
    width=5, height=1, corner_radius=16, hover_color="#343638", cursor="hand2", command=Show_password_2_function)
Open_eye_Button2.place(relx=0.71, rely=0.69, anchor=CENTER)

New_Pass_Bt = CTkButton(master=root_forget2, text="Reset Password", corner_radius=12, width=180,
    fg_color="#1365ef", bg_color="#08092f", text_color="white", hover_color="#1348a2", command=New_Pass_function)
New_Pass_Bt.place(relx=0.5, rely=0.8, anchor=CENTER)
# -------------- Start - Mainloop --------------
root_forget2.mainloop()