import os
import base64
import re
import datetime
import json
import email
from pymongo import MongoClient
from urllib.parse import quote_plus
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.message import MIMEMessage
# from dotenv import load_dotenv  # Importing load_dotenv

# # Load environment variables from .env file
# load_dotenv()


# Scopes for Gmail API
SCOPES = ['https://www.googleapis.com/auth/gmail.modify']

def authenticate_gmail():
    """Authenticate with the Gmail API using credentials from environment variable."""
    creds_info = json.loads(os.environ['GOOGLE_CREDENTIALS'])
    creds = Credentials.from_authorized_user_info(creds_info, SCOPES)
    service = build('gmail', 'v1', credentials=creds)
    return service

def get_mongo_client():
    """Connect to MongoDB Atlas using the username and password from environment variables."""
    mongo_username = os.environ.get('MONGO_USERNAME')
    mongo_password = os.environ.get('MONGO_PASSWORD')
    if not mongo_username or not mongo_password:
        raise ValueError("MONGO_USERNAME and MONGO_PASSWORD must be set in environment variables")

    encoded_username = quote_plus(mongo_username)
    encoded_password = quote_plus(mongo_password)

    mongo_uri = f"mongodb+srv://{encoded_username}:{encoded_password}@customertickerautomatio.bik3ced.mongodb.net/?retryWrites=true&w=majority&appName=customerTickerAutomation"
    client = MongoClient(mongo_uri)
    return client

def get_unread_messages(service, last_timestamp):
    """Retrieve unread messages received after the last timestamp."""
    query = f'after:{last_timestamp}'
    results = service.users().messages().list(userId='me', q=query).execute()
    messages = results.get('messages', [])
    return messages

from email.utils import parseaddr  # Add this import at the top

def analyze_email(service, message):
    """Analyze the email content and extract necessary information."""
    msg = service.users().messages().get(userId='me', id=message['id'], format='full').execute()
    payload = msg.get('payload', {})
    headers = payload.get('headers', [])

    subject = ''
    from_email = ''
    for header in headers:
        if header['name'] == 'Subject':
            subject = header['value']
        elif header['name'] == 'From':
            from_email_full = header['value']
            # Parse the email address from the 'From' header
            from_name, from_email = parseaddr(from_email_full)
            from_email = from_email.lower()  # Convert to lowercase for consistency

    # Get the email body
    body = ''
    if 'parts' in payload:
        parts = payload['parts']
        for part in parts:
            if part['mimeType'] == 'text/plain':
                data = part['body'].get('data', '')
                body += base64.urlsafe_b64decode(data.encode('ASCII')).decode('utf-8', errors='ignore')
    else:
        data = payload.get('body', {}).get('data', '')
        body = base64.urlsafe_b64decode(data.encode('ASCII')).decode('utf-8', errors='ignore')

    return from_email, subject, body


def categorize_email(body):
    """Categorize the email based on its content."""
    # Analyze content
    if re.search(r'password reset', body, re.IGNORECASE):
        return 'password_reset'
    elif re.search(r'refund', body, re.IGNORECASE):
        return 'refund_request'
    elif re.search(r'course extension', body, re.IGNORECASE):
        return 'course_extension'
    else:
        return 'other'

def create_message(to, subject, message_text):
    """Create a MIME message for sending."""
    message = MIMEText(message_text)
    message['to'] = to
    message['subject'] = subject
    raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
    return {'raw': raw_message}

def send_message(service, message):
    """Send an email message using the Gmail API."""
    sent_message = service.users().messages().send(userId='me', body=message).execute()
    return sent_message

def forward_email(service, message_id, to_email):
    """Forward an email to a specified email address."""
    # Fetch the original email in raw format
    original_msg = service.users().messages().get(
        userId='me', id=message_id, format='raw'
    ).execute()
    raw_message = original_msg['raw']

    # Decode the raw message
    msg_bytes = base64.urlsafe_b64decode(raw_message)
    mime_msg = email.message_from_bytes(msg_bytes)

    # Create a new email message to forward
    fwd = MIMEMultipart()
    fwd['To'] = to_email
    fwd['From'] = 'aiprojects345@gmail.com'  # Replace with your email if necessary
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

def main():
    """Main function to process emails."""
    service = authenticate_gmail()

    # Connect to MongoDB Atlas
    client = get_mongo_client()
    db = client['email_automation']  # Database name

    # Collections
    timestamps_collection = db['timestamps']
    customers_collection = db['customers']

    # Retrieve LAST_TIMESTAMP from MongoDB
    last_timestamp_doc = timestamps_collection.find_one({'_id': 'last_timestamp'})
    if last_timestamp_doc and 'timestamp' in last_timestamp_doc:
        last_timestamp = last_timestamp_doc['timestamp']
    else:
        # Initialize with current time minus 10 minutes
        last_timestamp = str(int((datetime.datetime.utcnow() - datetime.timedelta(minutes=10)).timestamp()))

    # Get current timestamp
    current_timestamp = str(int(datetime.datetime.utcnow().timestamp()))

    # Retrieve unread messages
    messages = get_unread_messages(service, last_timestamp)

    if not messages:
        print("No new messages.")
    else:
        for message in messages:
            from_email, subject, body = analyze_email(service, message)

            # Check if sender is a registered customer
            customer = customers_collection.find_one({'email': from_email.lower()})
            if not customer:
                print(f"Email from unregistered user {from_email}. Skipping.")
                continue  # Skip processing this email

            # Categorize the email
            category = categorize_email(body)

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
                forward_email(service, message['id'], 'vanirudhsharma@gmail.com')  # Replace with your email
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
            service.users().messages().modify(
                userId='me',
                id=message['id'],
                body={'removeLabelIds': ['UNREAD']}
            ).execute()

    # Update LAST_TIMESTAMP in MongoDB
    timestamps_collection.update_one(
        {'_id': 'last_timestamp'},
        {'$set': {'timestamp': current_timestamp}},
        upsert=True
    )

    # Close MongoDB connection
    client.close()

if __name__ == '__main__':
    main()
