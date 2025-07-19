from tkinter import *
from tkinter.messagebox import *
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import random

class otp_verify(Tk):
    def __init__(self):
        super().__init__()
        self.title("Verify OTP")
        self.geometry("600x550")
        self.resizable(False, False)

    def Labels(self):
        self.c = Canvas(self, bg="white", width=400, height=400)
        self.c.place(x=100, y=60)

        self.Login_Title = Label(self, text="OTP Verfication", font=("Arial", 20, "bold"), bg="white")
        self.Login_Title.place(x=210, y=90)

    def Entry(self):
        self.User_Name = Entry(self, bd=2, relief=SOLID, width=30)
        self.User_Name.place(x=220, y=160, height=25)

    def Buttons(self):
        self.send_otp = Button(self, text="Send OTP ?", border=0, width=40, command=self.sendOTP)
        self.send_otp.place(x=180, y=240)

        self.submit_Button = Button(self, text="Submit", border=0, width=20, command=self.checkOTP)
        self.submit_Button.place(x=250, y=210)

        self.resendOTP = Button(self, text="Resend OTP", border=0, command=self.resendOTPP)
        self.resendOTP.place(x=290, y=300)

    def sendOTP(self):
        global ver
        # Email configuration
        smtp_server = 'mail.meskaman.com'
        smtp_port = 465
        smtp_user = 'eagles@meskaman.com'
        smtp_password = "Sy9nlLEoSnBf"

        # Email content
        from_email = 'eagles@meskaman.com'
        to_email = 'ahmedessam200811@gmail.com'
        subject = 'Eagles Car Verification Code'
        otp = random.randint(100000,999999)
        body = str(otp)

        # Create the MIMEText object
        msg = MIMEMultipart()
        msg['From'] = from_email
        msg['To'] = to_email
        msg['Subject'] = subject

        # Attach the email body to the MIMEText object
        msg.attach(MIMEText(body, 'plain'))

        # Send the email
        try:
            # Establish connection to the SMTP server
            server = smtplib.SMTP_SSL(smtp_server, smtp_port)
            server.login(smtp_user, smtp_password)  # Login to the email account

            # Send the email
            server.sendmail(from_email, to_email, msg.as_string())
            print('Email sent successfully!')
            self.Login_Title.configure(text="The OTP Has Been Send For Email", fg="green")
            self.Login_Title.place(x=70, y=90)
        except Exception as e:
            print(f'Error: {e}')

    def checkOTP(self):
        self.user_input = str(self.User_Name.get())
        if self.user_input == ver:
                showerror()
                ver = "done"
        elif ver == "done":
                showinfo("showinfo", "The OTP Has Been Send For Email")
        else:
                showinfo("showinfo", "wrong OTP")
    def resendOTPP(self):
        otp = random.randint(100000,999999)
        # Email configuration
        smtp_server = 'mail.meskaman.com'
        smtp_port = 465  # Use 465 for SSL
        smtp_user = 'eagles@meskaman.com'
        smtp_password = "Sy9nlLEoSnBf"

        # Email content
        from_email = 'eagles@meskaman.com'
        to_email = 'ahmedessam010@inbox.ru'
        subject = 'Eagles Car Verification Code'
        body = str(otp)

        # Create the MIMEText object
        msg = MIMEMultipart()
        msg['From'] = from_email
        msg['To'] = to_email
        msg['Subject'] = subject

        # Attach the email body to the MIMEText object
        msg.attach(MIMEText(body, 'plain'))

        # Send the email
        try:
            # Establish connection to the SMTP server
            server = smtplib.SMTP_SSL(smtp_server, smtp_port)
            #server.starttls()  # Secure the connection
            server.login(smtp_user, smtp_password)  # Login to the email account

            # Send the email
            server.sendmail(from_email, to_email, msg.as_string())
            print('Email sent successfully!')
        except Exception as e:
            print(f'Error: {e}')
        finally:
            # Terminate the SMTP session
            server.quit()

if __name__ == "__main__":
    window = otp_verify()
    window.Labels()
    window.Entry()
    window.Buttons()
    window.mainloop()