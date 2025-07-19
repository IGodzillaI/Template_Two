# -------------- Library used --------------
from tkinter import *
from tkinter.messagebox import *
from customtkinter import *
from PIL import ImageTk,Image
import mysql.connector
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import random


# -------------- Customize Tkinter --------------
set_appearance_mode("Dark")  # Modes: system (default), light, dark
set_default_color_theme("green")  # Themes: blue (default), dark-blue, green

# -------------- Root - Customize Window --------------
root_forget = CTk()
root_forget.title("Eagles Car (Forget Password)")
root_forget.geometry("490x400+600+200")
root_forget.resizable(False, False)
root_forget.focus_set()

# -------------- Define - Function --------------
def Forget_function():
        usern = Username_Entry_Forget.get()
        email = Email_Entry_Forget.get()
        if usern == "" and email == "":
                LB_Status.configure(text="Please Insert Username and Email !", text_color="#ff402a")
                Signup_LB.place(relx=0.4, rely=0.88, anchor=CENTER)
                Remember.place(relx=0.68, rely=0.88, anchor=CENTER)
                Forget.place(relx=0.5, rely=0.79, anchor=CENTER)
                root_forget.focus_set()
        else:
                try:
                        conn = mysql.connector.connect(host="localhost", user="root", password="", database="eagles-company")
                        cur = conn.cursor()
                        command = "SELECT username FROM eagles_accounts WHERE username=%s and mail=%s"
                        cur.execute(command, (usern, email))
                        result = cur.fetchone()
                        name = ("Welcome : " + usern)
                        if result != None:
                                def Check_OTP():
                                        smtp_server = 'mail.meskaman.com'
                                        smtp_port = 465
                                        smtp_user = 'eagles@meskaman.com'
                                        smtp_password = "Sy9nlLEoSnBf"
                                        from_email = 'eagles@meskaman.com'
                                        to_email = email
                                        subject = 'Eagles Car Verification Code'
                                        otp = random.randint(100000,999999)
                                        body = str(otp)
                                        msg = MIMEMultipart()
                                        msg['From'] = from_email
                                        msg['To'] = to_email
                                        msg['Subject'] = subject
                                        msg.attach(MIMEText(body, 'plain'))
                                        try:
                                                server = smtplib.SMTP_SSL(smtp_server, smtp_port)
                                                server.login(smtp_user, smtp_password)

                                                # Send the email
                                                server.sendmail(from_email, to_email, msg.as_string())
                                                print('Email sent successfully!')
                                        except Exception as e:
                                                print(f'Error: {e}')
                                LB_Status.configure(text=f"The OTP Has Been Send For Email: \n{email}", text_color="green")
                                LB_Status.place(relx=0.5, rely=0.74, anchor=CENTER)
                                Forget.place(relx=0.5, rely=0.83, anchor=CENTER)
                                Signup_LB.place(relx=0.4, rely=0.92, anchor=CENTER)
                                Remember.place(relx=0.68, rely=0.92, anchor=CENTER)
                except:
                        showerror("Unknown Error !!", "Sorry, Unknown Error Please Try Again Later..")
                        root_forget.destroy()
def Remember_function():
        root_forget.destroy()
        import login

# -------------- All - Tools --------------
img = ImageTk.PhotoImage(Image.open("assets/imgs/check.png"))

background_logo = CTkLabel(master=root_forget,image=img,text="")
background_logo.pack()

LB_Title = CTkLabel(master=root_forget, text="Welcome To Eagles Car, Again",
        font=('Cambria', 32, 'bold'), fg_color="#08092f", bg_color="#08092f", width=500, height=70)
LB_Title.place(relx=0.5, rely=0.06, anchor=CENTER)

LB_Status = CTkLabel(master=root_forget, text="", width=280, corner_radius=0, fg_color="#08092f", text_color="#ff402a", 
        bg_color="#08092f", font=("Cambria", 14, "bold"))
LB_Status.place(relx=0.5, rely=0.71, anchor=CENTER)

LB = CTkLabel(master=root_forget, text="Forget Password : ",
        fg_color="#08092f", font=('Cambria', 30, 'bold'))
LB.place(relx=0.5, rely=0.21, anchor=CENTER)

Signup_LB = CTkLabel(master=root_forget, text="No, I Remember The Password?", text_color="white",
        fg_color="#08092f", bg_color="#08092f", font=("Cambria", 13.5))
Signup_LB.place(relx=0.4, rely=0.84, anchor=CENTER)

Username_Label_Forget = CTkLabel(master=root_forget, text="Enter Username : ", 
        fg_color="#08092f", bg_color="#08092f", font=("Cambria", 18, 'bold'))
Username_Label_Forget.place(relx=0.3, rely=0.36, anchor=CENTER)
Username_Entry_Forget = CTkEntry(master=root_forget, width=245, height=31, text_color="white",
        bg_color="#08092f", border_color="#1365ef", fg_color="#08092f", placeholder_text='Username', font=("Arial", 13, "bold"))
Username_Entry_Forget.place(relx=0.5, rely=0.45, anchor=CENTER)

Email_Label_Forget = CTkLabel(master=root_forget, text="Enter Email : ",
        fg_color="#08092f", bg_color="#08092f", font=("Cambria", 18, 'bold'))
Email_Label_Forget.place(relx=0.27, rely=0.55, anchor=CENTER)
Email_Entry_Forget = CTkEntry(master=root_forget, width=250, height=31,
        bg_color="#08092f", border_color="#1365ef", fg_color="#08092f", placeholder_text='Email@example.com', font=("Arial", 13, "bold"))
Email_Entry_Forget.place(relx=0.5, rely=0.64, anchor=CENTER)

Forget = CTkButton(master=root_forget, width=180, text="Forget Password", corner_radius=8,
        fg_color="#1365ef", bg_color="#08092f", text_color="white", hover_color="#1348a2", command=Forget_function)
Forget.place(relx=0.5, rely=0.75, anchor=CENTER)

Remember = CTkButton(master=root_forget, width=10, text="Remember", command=Remember_function, corner_radius=8,
        fg_color="#08092f", text_color="#1365ef", bg_color="#08092f", hover_color="#08092f",
        font=("Cambria", 14, "bold", "underline"))
Remember.place(relx=0.68, rely=0.84, anchor=CENTER)



# -------------- Root - Start Main Loop --------------
root_forget.mainloop()