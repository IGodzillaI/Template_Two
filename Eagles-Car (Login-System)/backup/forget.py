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
root_forget = CTk()
root_forget.title("Eagles Car (Forget Password)")
root_forget.geometry("490x440+630+200")
root_forget.resizable(False, False)
root_forget.focus_set()

# -------------- Define - Function --------------
def Forget_function():
        usern = Username_Entry_Forget.get()
        email = Email_Entry_Forget.get()
        if usern == "" and email == "":
                lb_errorr.configure(text="Please Insert Username and Email !")
                Signup_LB.place(relx=0.4, rely=0.86, anchor=CENTER)
                Remember.place(relx=0.68, rely=0.86, anchor=CENTER)
                Forget.place(relx=0.5, rely=0.79, anchor=CENTER)
        else:
                try:
                        conn = mysql.connector.connect(host="localhost", user="root", password="", database="eagles-company")
                        cur = conn.cursor()
                        command = "SELECT username FROM eagles_accounts WHERE username=%s and mail=%s"
                        cur.execute(command, (usern, email))
                        result = cur.fetchone()
                        name = ("Welcome : " + usern)
                        if result == None:
                                lb_errorr.configure(text="Invaild Username or Email !")
                                Signup_LB.place(relx=0.4, rely=0.86, anchor=CENTER)
                                Remember.place(relx=0.68, rely=0.86, anchor=CENTER)
                                Forget.place(relx=0.5, rely=0.79, anchor=CENTER)
                        else:
                                root_forget.destroy()
                                # -------------- Customize Tkinter --------------
                                set_appearance_mode("Dark")  # Modes: system (default), light, dark
                                set_default_color_theme("green")  # Themes: blue (default), dark-blue, green
                                # -------------- Root - Customize Window --------------
                                root_forget2 = CTk()
                                root_forget2.title("Eagles Car (Reset Password)")
                                root_forget2.geometry("470x400+630+220")
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
                                                        cur2.execute(commandd,(New_Pass, email))
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
                                imgg1 = ImageTk.PhotoImage(Image.open("assets/imgs/pattern.png"))
                                open_eye = ImageTk.PhotoImage(Image.open("assets/imgs/eye2.png").resize((20,20)))
                                close_eye = ImageTk.PhotoImage(Image.open("assets/imgs/hidden2.png").resize((24,20)))

                                background_logo2 = CTkLabel(master=root_forget2,image=imgg1,text="")
                                background_logo2.pack()

                                lb_error = CTkLabel(master=root_forget2, text="", 
                                corner_radius=0, fg_color="#242424", text_color="#ff402a", 
                                font=("Cambria", 14, "bold"))
                                lb_error.place(relx=0.5, rely=0.765, anchor=CENTER)

                                Lb_Title1 = CTkLabel(master=root_forget2, text=name, fg_color="#f6a823", text_color="white",
                                        width=500, height=70, font=('Cambria', 30, 'bold'))
                                Lb_Title1.place(relx=0.5, rely=0.06, anchor=CENTER)

                                Lb_Title2 = CTkLabel(master=root_forget2, text="Reset Password :",font=('Cambria', 30, 'bold'))
                                Lb_Title2.place(relx=0.5, rely=0.24, anchor=CENTER)

                                Forget_Password_Label_Forget = CTkLabel(master=root_forget2, text="Create New Password :", font=("Cambria", 18, 'bold'))
                                Forget_Password_Label_Forget.place(relx=0.28, rely=0.38, anchor=CENTER)
                                Forget_Password_Entry_Forget = CTkEntry(master=root_forget2, width=235, height=31,
                                        font=("Cambria", 15, 'bold'), placeholder_text='Create Strong Password', show="*")
                                Forget_Password_Entry_Forget.place(relx=0.5, rely=0.48, anchor=CENTER)

                                Confirm_New_Password_Label_Forget = CTkLabel(master=root_forget2, text="Confirm New Password : ", font=("Cambria", 18, 'bold'))
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
                                        fg_color="#f6a823", text_color="white", hover_color="#956716", command=New_Pass_function)
                                New_Pass_Bt.place(relx=0.5, rely=0.8, anchor=CENTER)
                                # -------------- Start - Mainloop --------------
                                root_forget2.mainloop()
                except:
                        lb_errorr.configure(text="Unknown Error, Please Try Again Later..")
                        Signup_LB.place(relx=0.4, rely=0.86, anchor=CENTER)
                        Remember.place(relx=0.68, rely=0.86, anchor=CENTER)
                        Forget.place(relx=0.5, rely=0.79, anchor=CENTER)

def Remember_function():
        root_forget.destroy()
        import login

# -------------- All - Tools --------------
img = ImageTk.PhotoImage(Image.open("assets/imgs/pattern.png"))

background_logo = CTkLabel(master=root_forget,image=img,text="")
background_logo.pack()

LB_Title = CTkLabel(master=root_forget, text="Welcome To Eagles Car, Again",
        font=('Cambria', 32, 'bold'), fg_color="#f6a823", width=500, height=50)
LB_Title.place(relx=0.5, rely=0.05, anchor=CENTER)

lb_errorr = CTkLabel(master=root_forget, text="", 
corner_radius=0, fg_color="#242424", text_color="#ff402a", 
font=("Cambria", 14, "bold"))
lb_errorr.place(relx=0.5, rely=0.71, anchor=CENTER)

LB = CTkLabel(master=root_forget, text="Forget Password :",font=('Cambria', 30, 'bold'))
LB.place(relx=0.5, rely=0.21, anchor=CENTER)

Signup_LB = CTkLabel(master=root_forget, text="No, I Remember The Password?", text_color="white",
        font=("Cambria", 13.5))
Signup_LB.place(relx=0.4, rely=0.82, anchor=CENTER)

Username_Label_Forget = CTkLabel(master=root_forget, text="Enter Username :", font=("Cambria", 18, 'bold'))
Username_Label_Forget.place(relx=0.3, rely=0.36, anchor=CENTER)
Username_Entry_Forget = CTkEntry(master=root_forget, width=230, height=30, text_color="white",
        placeholder_text='Username', font=("Arial", 13, "bold"))
Username_Entry_Forget.place(relx=0.5, rely=0.45, anchor=CENTER)

Email_Label_Forget = CTkLabel(master=root_forget, text="Enter Email :", font=("Cambria", 18, 'bold'))
Email_Label_Forget.place(relx=0.27, rely=0.55, anchor=CENTER)
Email_Entry_Forget = CTkEntry(master=root_forget, width=230, height=30,
        placeholder_text='Email@example.com', font=("Arial", 13, "bold"))
Email_Entry_Forget.place(relx=0.5, rely=0.64, anchor=CENTER)

Forget = CTkButton(master=root_forget, width=180, text="Forget Password", corner_radius=8,
        fg_color="#f6a823", text_color="white", hover_color="#956716", command=Forget_function)
Forget.place(relx=0.5, rely=0.74, anchor=CENTER)

Remember = CTkButton(master=root_forget, width=10, text="Remember", command=Remember_function, corner_radius=8,
        fg_color="transparent", text_color="#f6a823", hover_color="#242424", font=("Cambria", 14, "bold", "underline"))
Remember.place(relx=0.68, rely=0.82, anchor=CENTER)

# -------------- Root - Start Main Loop --------------
root_forget.mainloop()