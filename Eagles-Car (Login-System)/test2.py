import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import random

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