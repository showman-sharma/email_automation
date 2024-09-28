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
import cohere
from cohere import ClassifyExample
from dotenv import load_dotenv  # Importing load_dotenv

# Load environment variables from .env file
load_dotenv()

# Initialize Cohere client
cohere_api_key = os.environ.get('COHERE_API_KEY')
co = cohere.Client(cohere_api_key)

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


examples = [
    # Password Reset Examples
    ClassifyExample(text="I forgot my password, can you help?", label="password_reset"),
    ClassifyExample(text="How can I reset my password?", label="password_reset"),
    ClassifyExample(text="I can't log in because I forgot my password.", label="password_reset"),
    ClassifyExample(text="Can you assist me with resetting my account password?", label="password_reset"),
    ClassifyExample(text="The system is asking me to reset my password, but I'm not sure how.", label="password_reset"),
    ClassifyExample(text="I need to change my password but don't know how.", label="password_reset"),
    ClassifyExample(text="Help! I lost my password and can't access my account.", label="password_reset"),
    ClassifyExample(text="What's the procedure for resetting my password?", label="password_reset"),
    ClassifyExample(text="I can't remember my password, can you guide me on resetting it?", label="password_reset"),
    ClassifyExample(text="Please help, I need to reset my password.", label="password_reset"),
    ClassifyExample(text="I want to reset my password, but I can't figure out how.", label="password_reset"),
    ClassifyExample(text="Is there a way to recover my password?", label="password_reset"),
    ClassifyExample(text="Can you send me instructions to reset my password?", label="password_reset"),
    ClassifyExample(text="My password isn't working, how can I reset it?", label="password_reset"),
    ClassifyExample(text="I forgot the password for my account, what should I do?", label="password_reset"),

    # Refund Request Examples
    ClassifyExample(text="I would like to get a refund for my purchase.", label="refund_request"),
    ClassifyExample(text="Can I get my money back for the course?", label="refund_request"),
    ClassifyExample(text="Please process a refund for my recent payment.", label="refund_request"),
    ClassifyExample(text="I'm not satisfied with the service and would like a refund.", label="refund_request"),
    ClassifyExample(text="How do I go about getting a refund?", label="refund_request"),
    ClassifyExample(text="I want a refund for the product I bought.", label="refund_request"),
    ClassifyExample(text="Is it possible to refund my money?", label="refund_request"),
    ClassifyExample(text="I need to cancel my purchase and get a refund.", label="refund_request"),
    ClassifyExample(text="Can I return the product and get a refund?", label="refund_request"),
    ClassifyExample(text="How can I request a refund?", label="refund_request"),
    ClassifyExample(text="I'm unhappy with the purchase and would like a refund.", label="refund_request"),
    ClassifyExample(text="Can you process a refund for the course?", label="refund_request"),
    ClassifyExample(text="I accidentally bought the wrong course, can I get a refund?", label="refund_request"),
    ClassifyExample(text="Please issue a refund for my recent order.", label="refund_request"),
    ClassifyExample(text="I would like to cancel my subscription and request a refund.", label="refund_request"),

    # Course Extension Examples
    ClassifyExample(text="Can I extend my course access?", label="course_extension"),
    ClassifyExample(text="I need more time to complete the course, can I get an extension?", label="course_extension"),
    ClassifyExample(text="Is it possible to extend my access to the course materials?", label="course_extension"),
    ClassifyExample(text="My course access is about to expire, can I extend it?", label="course_extension"),
    ClassifyExample(text="I'd like to request an extension for my course completion time.", label="course_extension"),
    ClassifyExample(text="Can I get more time to finish the course?", label="course_extension"),
    ClassifyExample(text="I'm unable to complete the course on time, can I get an extension?", label="course_extension"),
    ClassifyExample(text="Please extend my course access by a few weeks.", label="course_extension"),
    ClassifyExample(text="I need an extension to complete my coursework.", label="course_extension"),
    ClassifyExample(text="Is there a way to extend my course deadline?", label="course_extension"),
    ClassifyExample(text="Can my course access be extended?", label="course_extension"),
    ClassifyExample(text="I'm requesting an extension for my course due to personal reasons.", label="course_extension"),
    ClassifyExample(text="Could you please extend my course access period?", label="course_extension"),
    ClassifyExample(text="I require more time to finish the course, can I get an extension?", label="course_extension"),
    ClassifyExample(text="What are the steps to request an extension for my course?", label="course_extension"),

    # Other Examples
    ClassifyExample(text="I have a question about the course content.", label="other"),
    ClassifyExample(text="Can you explain this topic again?", label="other"),
    ClassifyExample(text="I need help with my account.", label="other"),
    ClassifyExample(text="What should I do next in the course?", label="other"),
    ClassifyExample(text="How can I contact support?", label="other"),
    ClassifyExample(text="I'm having trouble accessing my course materials.", label="other"),
    ClassifyExample(text="Can you provide more information on this subject?", label="other"),
    ClassifyExample(text="I don't understand this part of the lesson, can you clarify?", label="other"),
    ClassifyExample(text="Who can I reach out to for technical support?", label="other"),
    ClassifyExample(text="Is there additional reading material available?", label="other"),
    ClassifyExample(text="Where can I find more details about the course schedule?", label="other"),
    ClassifyExample(text="Can you help me with a different aspect of the course?", label="other"),
    ClassifyExample(text="How do I update my account information?", label="other"),
    ClassifyExample(text="I'm confused about the assignment requirements.", label="other"),
    ClassifyExample(text="Can you help me with the course registration process?", label="other"),
]


def categorize_email(body, threshold=0.3):
    """Categorize the email using Cohere API based on its content."""
    # Classify the email body
    response = co.classify(
        inputs=[body],
        examples=examples,
    )

    # Extract the top prediction and its confidence score
    classification = response.classifications[0]
    prediction = classification.prediction
    confidence = classification.confidence

    # If the confidence is below the threshold, classify as 'other'
    if confidence < threshold:
        return 'other'
    
    return prediction

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
    fwd['From'] = os.environ.get('SUPPORT_EMAIL_ID')
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
                forward_email(service, message['id'], os.environ.get('MANUAL_SUPPORT_EMAIL_ID'))  # Replace with your email
                
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
