import os
import base64
import re
import datetime
import json
import email
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.message import MIMEMessage
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials

# Scopes for Gmail API
SCOPES = ['https://www.googleapis.com/auth/gmail.modify']

def authenticate_gmail():
    creds_info = json.loads(os.environ['GOOGLE_CREDENTIALS'])
    creds = Credentials.from_authorized_user_info(creds_info, SCOPES)
    service = build('gmail', 'v1', credentials=creds)
    return service

def analyze_email(service, message):
    msg = service.users().messages().get(userId='me', id=message['id'], format='full').execute()
    payload = msg['payload']
    headers = payload.get('headers', [])

    subject = ''
    from_email = ''
    for header in headers:
        if header['name'] == 'Subject':
            subject = header['value']
        if header['name'] == 'From':
            from_email = header['value']

    # Get the email body
    if 'parts' in payload:
        parts = payload['parts']
        data = parts[0]['body'].get('data', '')
    else:
        data = payload['body'].get('data', '')

    body = base64.urlsafe_b64decode(data.encode('ASCII')).decode('utf-8', errors='ignore')

    # Analyze content
    if re.search(r'password reset', body, re.IGNORECASE):
        return 'password_reset', from_email, subject
    elif re.search(r'refund', body, re.IGNORECASE):
        return 'refund_request', from_email, subject
    elif re.search(r'course extension', body, re.IGNORECASE):
        return 'course_extension', from_email, subject
    else:
        return 'other', from_email, subject

def create_message(to, subject, message_text):
    message = MIMEText(message_text)
    message['to'] = to
    message['subject'] = subject
    raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
    return {'raw': raw_message}

def send_message(service, message):
    sent_message = service.users().messages().send(userId='me', body=message).execute()
    return sent_message

def forward_email(service, message_id, to_email):
    # Fetch the original email in raw format
    original_msg = service.users().messages().get(userId='me', id=message_id, format='raw').execute()
    raw_message = original_msg['raw']

    # Decode the raw message
    msg_bytes = base64.urlsafe_b64decode(raw_message)
    mime_msg = email.message_from_bytes(msg_bytes)

    # Create a new email message to forward
    fwd = MIMEMultipart()
    fwd['To'] = to_email
    fwd['From'] = 'aiprojects345@gmail.com'
    fwd['Subject'] = 'FWD: ' + mime_msg['Subject']

    # Attach a message body
    body = MIMEText("Please see the forwarded message below.\n\n")
    fwd.attach(body)

    # Attach the original message
    attached_msg = MIMEMessage(mime_msg)
    attached_msg.add_header('Content-Disposition', 'attachment', filename='forwarded_message.eml')
    fwd.attach(attached_msg)

    # Encode the message and send
    raw_fwd = base64.urlsafe_b64encode(fwd.as_bytes()).decode()
    message = {'raw': raw_fwd}
    send_message(service, message)

def get_unread_messages(service, last_timestamp):
    # Use Gmail search query to filter emails after the last timestamp
    query = f'after:{last_timestamp}'
    results = service.users().messages().list(userId='me', q=query).execute()
    messages = results.get('messages', [])
    return messages

def main():
    service = authenticate_gmail()

    # Get the last processed timestamp from environment variable
    last_timestamp = os.environ.get('LAST_TIMESTAMP')
    if not last_timestamp:
        # If no timestamp, initialize with current time minus 10 minutes
        last_timestamp = str(int((datetime.datetime.utcnow() - datetime.timedelta(minutes=10)).timestamp()))
    
    # Get current timestamp
    current_timestamp = str(int(datetime.datetime.utcnow().timestamp()))

    messages = get_unread_messages(service, last_timestamp)

    if not messages:
        print("No new messages.")
    else:
        for message in messages:
            category, from_email, subject = analyze_email(service, message)
            response = None

            if category == 'password_reset':
                response_text = """Dear User,

To reset your password, please follow these steps:
1. Go to the login page.
2. Click on 'Forgot Password'.
3. Enter your registered email address.
4. Check your email for the reset link.

Best regards,
Support Team"""
                response = create_message(from_email, 'Password Reset Instructions', response_text)

            elif category == 'refund_request':
                response_text = """Dear User,

We have received your refund request. Please review our refund policy:
[Insert Refund Policy Here]

If you have any questions, feel free to reply to this email.

Best regards,
Support Team"""
                response = create_message(from_email, 'Refund Policy Information', response_text)

            elif category == 'course_extension':
                response_text = """Dear User,

Thank you for reaching out about extending your course access. Our extension policy is as follows:
[Insert Course Extension Policy Here]

Please let us know if you wish to proceed.

Best regards,
Support Team"""
                response = create_message(from_email, 'Course Extension Information', response_text)

            elif category == 'other':
                # Forward the email
                forward_email(service, message['id'], 'vanirudhsharma@gmail.com')
                # Notify the sender
                response_text = """Dear User,

Thank you for contacting us. Your message has been forwarded to our support team for further assistance.

Best regards,
Support Team"""
                response = create_message(from_email, 'Your Message Has Been Received', response_text)

            if response:
                send_message(service, response)
                print(f"Responded to email from {from_email} regarding {category.replace('_', ' ')}.")

            # Mark the message as read
            service.users().messages().modify(userId='me', id=message['id'], body={'removeLabelIds': ['UNREAD']}).execute()

    # Update the LAST_TIMESTAMP environment variable
    os.environ['LAST_TIMESTAMP'] = current_timestamp

    # Optionally, print the current timestamp for debugging
    print(f"Updated LAST_TIMESTAMP to {current_timestamp}")

if __name__ == '__main__':
    main()
