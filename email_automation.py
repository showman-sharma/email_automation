import os
import base64
import re
from datetime import datetime, timedelta, timezone
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
from cohere import Client, ClassifyExample
from dotenv import load_dotenv
from email.utils import parseaddr

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

def get_classification_examples(db):
    """Retrieve classification examples from MongoDB and construct ClassifyExample objects."""
    examples_collection = db['classification_examples']  # Collection name
    documents = examples_collection.find()
    
    examples = []
    for doc in documents:
        text = doc.get('text')
        label = doc.get('label')
        if text and label:
            examples.append(ClassifyExample(text=text, label=label))
    return examples

def get_response_template(db, category):
    """Retrieve the email response template for a given category."""
    templates_collection = db['response_templates']  # Collection name
    template = templates_collection.find_one({'category': category})
    if template:
        return template.get('subject'), template.get('body')
    else:
        return None, None

def get_unread_messages(service, last_timestamp):
    """Retrieve unread messages received after the last timestamp."""
    query = f'after:{last_timestamp}'
    results = service.users().messages().list(userId='me', q=query).execute()
    messages = results.get('messages', [])
    return messages

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

def categorize_email(body, examples, threshold=0.3):
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
    if not to_email:
        raise ValueError("Recipient email address is missing. Please check the MANUAL_SUPPORT_EMAIL_ID environment variable.")
    
    print(f"Forwarding email to {to_email}")
    
    # Fetch the original email in raw format
    original_msg = service.users().messages().get(userId='me', id=message_id, format='raw').execute()
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
    
    # Retrieve classification examples from MongoDB
    examples = get_classification_examples(db)
    if not examples:
        print("No classification examples found in the database.")
        return  # Exit if no examples are found
    
    # Retrieve LAST_TIMESTAMP from MongoDB
    last_timestamp_doc = timestamps_collection.find_one({'_id': 'last_timestamp'})
    if last_timestamp_doc and 'timestamp' in last_timestamp_doc:
        last_timestamp = last_timestamp_doc['timestamp']
    else:
        # Initialize with current time minus 10 minutes
        last_timestamp = str(int((datetime.utcnow() - timedelta(minutes=10)).timestamp()))
    
    # Get current timestamp
    current_timestamp = str(int(datetime.now(timezone.utc).timestamp()))
    
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
    
            # Categorize the email using examples from MongoDB
            category = categorize_email(subject + " : " + body, examples)
    
            # Fetch the response template for the category
            response_subject, response_body_template = get_response_template(db, category)
    
            if not response_subject or not response_body_template:
                print(f"No response template found for category '{category}'.")
                continue  # Skip if no template is found
    
            # Personalize the response body
            user_name = customer.get('name', 'User')  # Default to 'User' if name not available
            response_body = response_body_template.format(user_name=user_name)
    
            response = create_message(from_email, response_subject, response_body)
    
            if category == 'other':
                # Forward the email to support team
                forward_email(service, message['id'], os.environ.get('MANUAL_SUPPORT_EMAIL_ID'))
                print(f"Forwarded email from {from_email} to support team.")
    
            # Send the response email
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
