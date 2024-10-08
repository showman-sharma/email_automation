import os
import base64
from datetime import datetime, timedelta, timezone
import json
from pymongo import MongoClient
from urllib.parse import quote_plus
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
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

def get_authenticated_email(service):
    """Retrieve the authenticated user's email address."""
    profile = service.users().getProfile(userId='me').execute()
    return profile['emailAddress']

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
    examples_collection = db['classification_examples']
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
    templates_collection = db['response_templates']
    template = templates_collection.find_one({'category': category})
    if template:
        return template.get('subject'), template.get('body')
    else:
        return None, None

def get_unread_messages(service, last_timestamp):
    """Retrieve unread messages received after the last timestamp."""
    query = f'after:{last_timestamp}'
    results = service.users().messages().list(userId='me', q=query, labelIds=['INBOX', 'UNREAD']).execute()
    messages = results.get('messages', [])
    return messages

def analyze_email(service, message):
    """Analyze the email content and extract necessary information."""
    msg = service.users().messages().get(userId='me', id=message['id'], format='full').execute()
    payload = msg.get('payload', {})
    headers = payload.get('headers', [])
    
    subject = ''
    from_email = ''
    message_id = ''
    for header in headers:
        header_name = header['name'].lower()
        if header_name == 'subject':
            subject = header['value']
        elif header_name == 'from':
            from_email_full = header['value']
            # Parse the email address from the 'From' header
            from_name, from_email = parseaddr(from_email_full)
            from_email = from_email.lower()
        elif header_name == 'message-id':
            message_id = header['value']
    
    # Get the email body
    body = ''
    if 'parts' in payload:
        body = get_email_body(payload)
    else:
        data = payload.get('body', {}).get('data', '')
        if data:
            body = base64.urlsafe_b64decode(data.encode('ASCII')).decode('utf-8', errors='ignore')
    
    thread_id = msg.get('threadId')
    
    return from_email, subject, body, thread_id, message_id

def get_email_body(payload):
    """Extract the email body from the payload."""
    body = ''
    if 'parts' in payload:
        for part in payload['parts']:
            if part['mimeType'] == 'text/plain':
                data = part['body'].get('data', '')
                if data:
                    body += base64.urlsafe_b64decode(data.encode('ASCII')).decode('utf-8', errors='ignore')
            elif part['mimeType'].startswith('multipart/'):
                body += get_email_body(part)
    else:
        data = payload.get('body', {}).get('data', '')
        if data:
            body += base64.urlsafe_b64decode(data.encode('ASCII')).decode('utf-8', errors='ignore')
    return body

def categorize_email(text, examples, threshold=0.3):
    """Categorize the email using Cohere API based on its content."""
    response = co.classify(
        inputs=[text],
        examples=examples,
    )
    classification = response.classifications[0]
    prediction = classification.prediction
    confidence = classification.confidence

    if confidence < threshold:
        return 'other'
    
    return prediction

def create_message(to, subject, message_text, from_email, in_reply_to=None, references=None, cc=None, original_body=None):
    """Create a MIME message for sending."""
    message = MIMEMultipart()
    message['To'] = to
    message['Subject'] = subject
    message['From'] = from_email

    if cc:
        message['Cc'] = cc
    if in_reply_to:
        message['In-Reply-To'] = f"<{in_reply_to.strip('<>')}>"
    if references:
        message['References'] = f"<{references.strip('<>')}>"

    # Attach the response body
    message.attach(MIMEText(message_text, 'plain'))

    # Include the original email content if provided
    if original_body:
        original_message = f"\n\n--- Original Message ---\n{original_body}"
        message.attach(MIMEText(original_message, 'plain'))

    raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
    return {'raw': raw_message}

def send_message(service, message, thread_id=None):
    """Send an email message using the Gmail API."""
    message_with_thread = {'raw': message['raw']}
    if thread_id:
        message_with_thread['threadId'] = thread_id
    sent_message = service.users().messages().send(userId='me', body=message_with_thread).execute()
    return sent_message

def main():
    """Main function to process emails."""
    service = authenticate_gmail()
    authenticated_email = get_authenticated_email(service)
    
    # Connect to MongoDB Atlas
    client = get_mongo_client()
    db = client['email_automation']
    
    # Collections
    timestamps_collection = db['timestamps']
    customers_collection = db['customers']
    
    # Retrieve classification examples from MongoDB
    examples = get_classification_examples(db)
    if not examples:
        print("No classification examples found in the database.")
        return
    
    # Retrieve LAST_TIMESTAMP from MongoDB
    last_timestamp_doc = timestamps_collection.find_one({'_id': 'last_timestamp'})
    if last_timestamp_doc and 'timestamp' in last_timestamp_doc:
        last_timestamp = last_timestamp_doc['timestamp']
    else:
        last_timestamp = str(int((datetime.utcnow() - timedelta(minutes=10)).timestamp()))
    
    # Get current timestamp
    current_timestamp = str(int(datetime.now(timezone.utc).timestamp()))
    
    # Retrieve unread messages
    messages = get_unread_messages(service, last_timestamp)
    
    if not messages:
        print("No new messages.")
    else:
        for message in messages:
            from_email, subject, body, thread_id, message_id = analyze_email(service, message)
    
            # Check if sender is a registered customer
            customer = customers_collection.find_one({'email': from_email.lower()})
            if not customer:
                print(f"Email from unregistered user {from_email}. Skipping.")
                continue
    
            # Categorize the email using examples from MongoDB
            email_text = f"{subject} : {body}"
            category = categorize_email(email_text, examples)
    
            # Fetch the response template for the category
            response_subject, response_body_template = get_response_template(db, category)
    
            if not response_subject or not response_body_template:
                print(f"No response template found for category '{category}'.")
                continue
    
            # Personalize the response body
            user_name = customer.get('name', 'User')
            response_body = response_body_template.format(user_name=user_name)
    
            # Prepare CC field and include original email if necessary
            cc_email = None
            original_email_body = None
            if category == 'other':
                cc_email = os.environ.get('MANUAL_SUPPORT_EMAIL_ID')
                if cc_email:
                    print(f"Adding {cc_email} to CC.")
                else:
                    print("MANUAL_SUPPORT_EMAIL_ID not set.")
                original_email_body = f"Subject: {subject}\nFrom: {from_email}\n\n{body}"
    
            # Create the reply message
            response = create_message(
                to=from_email,
                subject=response_subject,
                message_text=response_body,
                from_email=authenticated_email,
                in_reply_to=message_id,
                references=message_id,
                cc=cc_email,
                original_body=original_email_body
            )
    
            # Send the response email as a reply
            send_message(service, response, thread_id=thread_id)
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
