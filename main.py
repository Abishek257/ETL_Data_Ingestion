import os
import os.path
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import base64
from google.cloud import storage
import google.oauth2.service_account
from google.cloud import bigquery
import datetime
import requests 
from email.mime.text import MIMEText
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# --- User Configuration Parameters from .env ---
CREDENTIALS_PATH = os.getenv("CREDENTIALS_PATH")
CLIENT_SECRET_FILE = os.getenv("CLIENT_SECRET_FILE")
TOKEN_FILE = os.getenv("TOKEN_FILE")

SCOPES = os.getenv("SCOPES").split(",")
REDIRECT_URI = os.getenv("REDIRECT_URI")

NOTIFICATION_RECIPIENTS = os.getenv("NOTIFICATION_RECIPIENTS")
GMAIL_QUERY = os.getenv("GMAIL_QUERY")

GCS_UNPROCESSED_PATH = os.getenv("GCS_UNPROCESSED_PATH")

BIGQUERY_DATASET = os.getenv("BIGQUERY_DATASET")
BIGQUERY_TABLE = os.getenv("BIGQUERY_TABLE")

HTTP_REQUEST_TIMEOUT = int(os.getenv("HTTP_REQUEST_TIMEOUT", "900"))
BIGQUERY_BATCH_SIZE = int(os.getenv("BIGQUERY_BATCH_SIZE", "500"))
# --- End of Configuration ---


# Initialize Google Cloud Storage client using service account credentials
SERVICE_ACCOUNT_CREDENTIALS = google.oauth2.service_account.Credentials.from_service_account_file(
    CREDENTIALS_PATH)
STORAGE_CLIENT = storage.Client(credentials=SERVICE_ACCOUNT_CREDENTIALS)

# Global variable for Gmail credentials
GMAIL_CREDS = None


class CallbackHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        global GMAIL_CREDS
        parsed_url = urlparse(self.path)
        if parsed_url.path == '/callback':
            query_params = parse_qs(parsed_url.query)
            code = query_params.get('code', [None])[0]
            if code:
                session_for_flow = requests.Session()
                session_for_flow.timeout = HTTP_REQUEST_TIMEOUT # Apply timeout to this session as well

                flow = Flow.from_client_secrets_file(
                    CLIENT_SECRET_FILE, scopes=SCOPES, redirect_uri=REDIRECT_URI
                )
                try:
                    # Pass the requests.Session to Request directly
                    flow.fetch_token(code=code, request=Request(session=session_for_flow))
                    GMAIL_CREDS = flow.credentials
                    with open(TOKEN_FILE, 'w') as token:
                        token.write(GMAIL_CREDS.to_json())
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    self.wfile.write(
                        b"Authentication successful! You can close this window.")
                except Exception as e:
                    self.send_response(500)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    self.wfile.write(f"Authentication failed: {e}".encode())
                    print(f"Authentication failed: {e}")
            else:
                self.send_response(400)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(b"Authorization code not received.")
        else:
            self.send_response(404)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b"Not found.")


def get_gmail_service():
    """
    Authenticates with the Gmail API using the web application flow.
    """
    global GMAIL_CREDS

    # Create a requests.Session object with the desired timeout
    http_session = requests.Session()
    http_session.timeout = HTTP_REQUEST_TIMEOUT

    if os.path.exists(TOKEN_FILE):
        GMAIL_CREDS = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)

    if not GMAIL_CREDS or not GMAIL_CREDS.valid:
        if GMAIL_CREDS and GMAIL_CREDS.expired and GMAIL_CREDS.refresh_token:
            # Pass the http_session to the Request object's session.
            request_with_timeout = Request(session=http_session)
            try:
                GMAIL_CREDS.refresh(request_with_timeout)
            except Exception as e:
                print(f"Error refreshing credentials: {e}")
                # Consider deleting token_web.json here if refresh fails persistently
                # os.remove(TOKEN_FILE)
                return None
            with open(TOKEN_FILE, 'w') as token:
                token.write(GMAIL_CREDS.to_json())
        else:
            flow = Flow.from_client_secrets_file(
                CLIENT_SECRET_FILE, scopes=SCOPES, redirect_uri=REDIRECT_URI
            )
            auth_url, _ = flow.authorization_url(prompt='consent')
            print(
                'Please open the following URL in your browser and authorize'
                f' the application:\n{auth_url}'
            )
            webbrowser.open(auth_url)

            httpd = HTTPServer(('localhost', 8080), CallbackHandler)
            print('Waiting for authorization callback...')
            httpd.handle_request()

    if not GMAIL_CREDS:
        print("Authentication failed or was not completed.")
        return None

    # This is the crucial part for using requests with googleapiclient.discovery.build()
    # You don't pass `request=AuthorizedSession(...)` directly to `build`.
    # Instead, the `credentials` object itself should be prepared to use `requests`.
    # The `google-auth-requests` library handles this automatically when installed.
    # The `build` function typically expects an httplib2.Http object for the `http` argument,
    # or relies on `credentials` being correctly configured with the transport.

    # When using requests, `build` usually only needs the `credentials` object
    # to be initialized correctly (which happens via `Flow` or `from_authorized_user_file`
    # combined with `google-auth-requests`).
    # The `http_session` is used for the `Request` object during refresh and initial token fetching.
    # The `googleapiclient` library will use the HTTP transport configured within the `credentials` object.

    # So, the line should simply be:
    return build('gmail', 'v1', credentials=GMAIL_CREDS)


def list_messages(service, query=''):
    """
    Lists all messages in the user's mailbox matching the query.

    Args:
        service: Authorized Gmail API service instance.
        query: String used to filter messages returned.
            Eg.- 'from:user@some_domain.com' for messages from a user.

    Returns:
        List of messages that match the query.
    """
    try:
        response = service.users().messages().list(userId='me', q=query).execute()
        messages = response.get('messages', [])
        return messages
    except HttpError as error:
        print(f'An error occurred while listing messages: {error}')
        send_error_email(service, "Gmail Message Listing", error)
        return []


def get_message_detail(service, msg_id):
    """Get a Message by ID.

    Args:
        service: Authorized Gmail API service instance.
        msg_id: The ID of the Message to get.

    Returns:
        A Message.
    """
    try:
        message = service.users().messages().get(userId='me', id=msg_id,
                                                 format='full').execute()
        return message
    except HttpError as error:
        print(f'An error occurred while retrieving message {msg_id}: {error}')
        send_error_email(service, f"Retrieving Message {msg_id}", error)
        return None


def get_attachment(service, msg_id, attachment_id):
    """Get a specific attachment file.

    Args:
        service: Authorized Gmail API service instance.
        msg_id: The ID of the Message containing the attachment.
        attachment_id: The ID of the attachment to get.

    Returns:
        The attachment file data as bytes, or None if an error occurs.
    """
    try:
        attachment = service.users().messages().attachments().get(
            userId='me', messageId=msg_id, id=attachment_id).execute()
        file_data = base64.urlsafe_b64decode(attachment['data'].encode('UTF-8'))
        return file_data
    except HttpError as error:
        print(f'An error occurred while retrieving attachment {attachment_id} from message {msg_id}: {error}')
        send_error_email(service, f"Retrieving Attachment {attachment_id} from Message {msg_id}", error)
        return None


def upload_attachment_to_gcs(destination_bucket_path, file_data, filename):
    """Uploads attachment data to Google Cloud Storage using the
    service account key.

    Args:
        destination_bucket_path (str): The GCS path
            (gs://bucket-name/optional/path/prefix/).
        file_data (bytes): The content of the attachment file as bytes.
        filename (str): The name of the attachment file.
    """
    try:
        parts = destination_bucket_path.replace("gs://", "").split("/", 1)
        bucket_name = parts[0]
        path_prefix = parts[1] + "/" if len(parts) > 1 else ""
        destination_blob_name = path_prefix + filename
        bucket = STORAGE_CLIENT.bucket(bucket_name)
        blob = bucket.blob(destination_blob_name)
        blob.upload_from_string(file_data)
        print(
            f"Attachment {filename} uploaded to"
            f" gs://{bucket_name}/{destination_blob_name}"
        )
        return True
    except Exception as e:
        print(f"An error occurred during GCS upload of {filename}: {e}")
        return False


def move_blob(bucket_name, source_blob_name, destination_blob_name):
    """Moves a blob from one path to another within the same bucket."""
    try:
        bucket = STORAGE_CLIENT.bucket(bucket_name)
        source_blob = bucket.blob(source_blob_name)

        new_blob = bucket.rename_blob(source_blob, destination_blob_name)

        print(
            f"Blob '{source_blob_name}' moved to '{new_blob.name}' in bucket '{bucket_name}'.")
        return True
    except Exception as e:
        print(
            f"Error moving blob '{source_blob_name}' to '{destination_blob_name}': {e}")
        return False


def process_ctb_and_insert_to_bigquery(
    file_data, filename, bigquery_dataset, bigquery_table, bucket_name, original_blob_path, service
):
    """
    Processes the CTB file, extracts data, and inserts it into a
    BigQuery table in batches.

    Args:
        file_data (bytes): The content of the CTB file as bytes.
        filename (str): The name of the CTB file.
        bigquery_dataset (str): The BigQuery dataset ID.
        bigquery_table (str): The BigQuery table ID.
        bucket_name (str): The name of the GCS bucket where the file is stored.
        original_blob_path (str): The full path of the blob in GCS (e.g., 'CTB/Week_26_Unprocessed/CTB_file.txt').
        service: Authorized Gmail API service instance (for sending emails).

    Returns:
        tuple: (bool, int) - True if processing and BigQuery insertion were successful, False otherwise, and the number of rows inserted.
    """
    try:
        file_content = file_data.decode('utf-8')
        lines = file_content.strip().split('\n')
        if not lines or len(lines) < 2:
            error_message = f"CTB file '{filename}' is empty or has no data rows. Moving to Failed."
            print(error_message)
            send_error_email(service, filename, error_message)
            move_blob(bucket_name, original_blob_path,
                      original_blob_path.replace("Unprocessed", "Failed"))
            return False, 0

        header_raw = lines[0].split('\t')

        bq_schema_map = {
            'ORG CODE': 'ORG_CODE',
            'MASTER CUST NAME': 'MASTER_CUST_NAME',
            'CUSTOMER NUMBER': 'CUSTOMER_NUMBER',
            'ITEM NUMBER': 'ITEM_NUMBER',
            'CUST PART NUM': 'CUST_PART_NUM',
            'ITEM DESCRIPTION': 'ITEM_DESCRIPTION',
            'DEMAND DUE DATE': 'DEMAND_DUE_DATE',
            'DEMAND QTY': 'DEMAND_QTY',
            'Avail OnTime': 'ONTIME_QTY',
            'Avail Date': 'AVAILABLE_DATE',
            'SplitAvail Supply Source': 'SUPPLY_SOURCE',
            'SplitAvailDate': 'SUPPLY_AVAILABLE_DATE',
            'SplitAvail Qty': 'SUPPLY_AVA_QTY',
            'Days Late': 'DAYS_LATE',
            'Unique Short Qty Count': 'UNIQ_SHORT_QTY',
            'GATING Part': 'GATING_PART',
            'GATING M/B': 'MAKE_BUY',
            'GATING LT': 'LEAD_TIME',
            'GATING CUST PART': 'GATING_CUST_PART',
            'CUST PART DESCRIPTION': 'CUST_PART_DESCRIPTION',
            'SNAPSHOT_DATE': 'SNAPSHOT_DATE'
        }

        bq_schema_types = {
            'ORG_CODE': 'STRING',
            'MASTER_CUST_NAME': 'STRING',
            'CUSTOMER_NUMBER': 'STRING',
            'ITEM_NUMBER': 'STRING',
            'CUST_PART_NUM': 'STRING',
            'ITEM_DESCRIPTION': 'STRING',
            'DEMAND_DUE_DATE': 'DATE',
            'DEMAND_QTY': 'INTEGER',
            'ONTIME_QTY': 'INTEGER',
            'AVAILABLE_DATE': 'DATE',
            'SUPPLY_SOURCE': 'STRING',
            'SUPPLY_AVAILABLE_DATE': 'DATE',
            'SUPPLY_AVA_QTY': 'INTEGER',
            'DAYS_LATE': 'INTEGER',
            'UNIQ_SHORT_QTY': 'INTEGER',
            'GATING_PART': 'STRING',
            'MAKE_BUY': 'STRING',
            'LEAD_TIME': 'INTEGER',
            'GATING_CUST_PART': 'STRING',
            'CUST_PART_DESCRIPTION': 'STRING',
            'SNAPSHOT_DATE': 'DATE'
        }

        cleaned_headers = []
        for h_name_raw in header_raw:
            cleaned_name = h_name_raw.lstrip('\ufeff').strip().replace('\r', '').upper().replace(" ", "_")
            mapped_name = bq_schema_map.get(cleaned_name, cleaned_name)
            cleaned_headers.append(mapped_name)

        if not all(col in bq_schema_types for col in cleaned_headers):
            error_message = (
                f"Error: Some headers in '{filename}' do not match expected BigQuery schema after cleaning. "
                "Please review file headers and bq_schema_map.\n"
                f"File Headers (cleaned): {cleaned_headers}\n"
                f"Expected BQ Schema Keys: {list(bq_schema_types.keys())}"
            )
            print(error_message)
            send_error_email(service, filename, error_message)
            move_blob(bucket_name, original_blob_path,
                      original_blob_path.replace("Unprocessed", "Failed"))
            return False, 0

        records_to_insert = []
        row_level_errors = []

        for line_num, line in enumerate(lines[1:]):
            values = line.split('\t')

            if len(values) != len(header_raw):
                row_level_errors.append(
                    f"Malformed row at line {line_num + 2} in '{filename}': column count mismatch. "
                    f"Expected {len(header_raw)}, got {len(values)}. Row content: '{line}'"
                )
                continue

            row_dict = {}
            row_has_error = False
            for i, bq_col_name in enumerate(cleaned_headers):
                field_value = values[i].strip()

                if bq_col_name in bq_schema_types:
                    bq_type = bq_schema_types[bq_col_name]

                    if field_value == '':
                        row_dict[bq_col_name] = None
                    elif bq_type == 'INTEGER':
                        try:
                            cleaned_value = field_value.replace(',', '')
                            row_dict[bq_col_name] = int(cleaned_value)
                        except ValueError:
                            row_level_errors.append(
                                f"Value error for column '{bq_col_name}' at line {line_num + 2} in '{filename}': "
                                f"Could not convert '{field_value}' to INTEGER. Setting to None."
                            )
                            row_dict[bq_col_name] = None
                            row_has_error = True
                    elif bq_type == 'DATE':
                        try:
                            row_dict[bq_col_name] = datetime.datetime.strptime(
                                field_value, '%Y-%m-%d').date().isoformat()
                        except ValueError:
                            row_level_errors.append(
                                f"Value error for column '{bq_col_name}' at line {line_num + 2} in '{filename}': "
                                f"Could not convert '{field_value}' to DATE (expected %Y-%m-%d). Setting to None."
                            )
                            row_dict[bq_col_name] = None
                            row_has_error = True
                    else:  # STRING type
                        row_dict[bq_col_name] = field_value
            if not row_has_error:
                records_to_insert.append(row_dict)

        bq_client = bigquery.Client(credentials=SERVICE_ACCOUNT_CREDENTIALS)
        table_id = f"{bq_client.project}.{bigquery_dataset}.{bigquery_table}"

        try:
            bq_client.get_table(table_id)
        except Exception as e:
            error_message = (
                f"Error: BigQuery Table '{table_id}' does not exist or access denied: {e}. "
                "Please ensure the table is created and permissions are correct before running this code."
            )
            print(error_message)
            send_error_email(service, filename, error_message)
            move_blob(bucket_name, original_blob_path,
                      original_blob_path.replace("Unprocessed", "Failed"))
            return False, 0

        total_inserted_rows = 0
        total_bq_insertion_errors = []

        if not records_to_insert:
            final_status_message = (
                f"No valid data rows found in '{filename}' to insert into BigQuery after initial parsing. "
                "The file will be moved to the 'Failed' folder."
            )
            print(final_status_message)
            if row_level_errors:
                final_status_message += "\n\nRow-level errors encountered:\n" + "\n".join(row_level_errors)
            send_error_email(service, filename, final_status_message)
            move_blob(bucket_name, original_blob_path,
                      original_blob_path.replace("Unprocessed", "Failed"))
            return False, 0

        print(
            f"Attempting to insert {len(records_to_insert)} valid rows from '{filename}' into BigQuery table '{table_id}' in batches of {BIGQUERY_BATCH_SIZE}..."
        )

        # --- Explicit Batching Loop ---
        for i in range(0, len(records_to_insert), BIGQUERY_BATCH_SIZE):
            batch = records_to_insert[i : i + BIGQUERY_BATCH_SIZE]
            print(
                f"   Inserting batch {i // BIGQUERY_BATCH_SIZE + 1} (rows {i+1}-{min(i+BIGQUERY_BATCH_SIZE, len(records_to_insert))})..."
            )
            try:
                batch_errors = bq_client.insert_rows_json(table_id, batch)
                if not batch_errors:
                    total_inserted_rows += len(batch)
                else:
                    total_bq_insertion_errors.extend(batch_errors)
                    print(f"   Encountered errors in batch {i // BIGQUERY_BATCH_SIZE + 1}: {batch_errors}")
            except Exception as batch_e:
                print(f"   An unexpected error occurred during batch insertion {i // BIGQUERY_BATCH_SIZE + 1}: {batch_e}")
                total_bq_insertion_errors.append(f"Batch insertion failed: {batch_e}")
        # --- End of Explicit Batching Loop ---

        if total_inserted_rows > 0:
            # At least some rows were successfully inserted
            status_message = (
                f"Inserted {total_inserted_rows} valid rows from '{filename}' into {table_id}.\n"
            )

            if total_bq_insertion_errors:
                status_message += f"\n{len(total_bq_insertion_errors)} BigQuery insertion errors:\n"
                status_message += "\n".join(str(err) for err in total_bq_insertion_errors)

            if row_level_errors:
                status_message += f"\n{len(row_level_errors)} row-level errors:\n"
                status_message += "\n".join(row_level_errors)

            print(status_message)

            # Send success if clean, or error report if partial failures
            if not total_bq_insertion_errors and not row_level_errors:
                send_success_email(service, filename, total_inserted_rows)
            else:
                send_error_email(service, filename, status_message)

            # Mark file as Processed since we got valid rows
            move_blob(bucket_name, original_blob_path,
                    original_blob_path.replace("Unprocessed", "Processed"))
            return True, total_inserted_rows
        else:
            # No rows inserted at all → Fail the file
            final_status_message = (
                f"No valid rows from '{filename}' could be inserted into BigQuery. "
                "The file will be moved to 'Failed'."
            )
            if total_bq_insertion_errors:
                final_status_message += f"\nBigQuery errors:\n" + "\n".join(str(err) for err in total_bq_insertion_errors)
            if row_level_errors:
                final_status_message += "\nRow-level errors:\n" + "\n".join(row_level_errors)

            print(final_status_message)
            send_error_email(service, filename, final_status_message)
            move_blob(bucket_name, original_blob_path,
                    original_blob_path.replace("Unprocessed", "Failed"))
            return False, 0


def process_part(service, part, message_id, destination_bucket_path):
    """Recursively processes message parts to find and upload attachments
    starting with 'CTB'."""
    attachment_processed = False
    if (
        'filename' in part
        and part['filename'].startswith('CTB')
        and 'body' in part
        and 'attachmentId' in part['body']
    ):
        attachment_id = part['body']['attachmentId']
        attachment_file = get_attachment(service, message_id, attachment_id)
        if attachment_file:
            filename = part['filename']
            print("\n--- Attachment Found ---")
            print(f"   Message ID: {message_id}")
            print(f"   Filename: {filename}")

            parts = destination_bucket_path.replace(
                "gs://", "").split("/", 1)
            bucket_name = parts[0]
            unprocessed_prefix = parts[1] + "/" if len(parts) > 1 else ""
            original_blob_name = unprocessed_prefix + \
                filename

            upload_successful = upload_attachment_to_gcs(
                destination_bucket_path, attachment_file, filename)

            if upload_successful:
                print("Attachment uploaded to GCS successfully. Attempting BigQuery insertion.")
                bigquery_process_successful, inserted_rows = process_ctb_and_insert_to_bigquery(
                    attachment_file, filename, BIGQUERY_DATASET,
                    BIGQUERY_TABLE, bucket_name, original_blob_name,
                    service
                )
                if bigquery_process_successful:
                    attachment_processed = True
                else:
                    attachment_processed = False
            else:
                error_message = f"Failed to upload attachment '{filename}' to GCS. No further processing."
                print(error_message)
                send_error_email(service, filename, error_message)
                attachment_processed = False
        else:
            error_message = (
                f"Failed to retrieve attachment data for '{part['filename']}'"
                f" in Message ID: {message_id}. No further processing."
            )
            print(error_message)
            send_error_email(service, part['filename'], error_message)
            attachment_processed = False
    elif 'parts' in part:
        for sub_part in part['parts']:
            if process_part(service, sub_part, message_id,
                            destination_bucket_path):
                attachment_processed = True
                break
    return attachment_processed


def send_email(service, to, subject, body):
    """Sends an email using the Gmail API."""
    sender = "me"
    message = MIMEText(body)
    message['to'] = to
    message['from'] = sender
    message['subject'] = subject
    raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()

    try:
        sent_message = service.users().messages().send(userId=sender, body={'raw': raw_message}).execute()
        print(f"Successfully sent email with message ID: {sent_message['id']}")
    except HttpError as error:
        print(f"An error occurred while sending email: {error}")


def send_success_email(service, filename, inserted_rows):
    """Sends an email indicating successful processing and BigQuery insertion."""
    subject = f"SUCCESS: CTB File '{filename}' Processing Successful"
    body = (
        f"Successfully processed '{filename}' and inserted {inserted_rows} rows into BigQuery.\n\n"
        f"The file has been moved to the 'Processed' folder in GCS and the email has been unlabelled from Inbox."
    )
    send_email(service, NOTIFICATION_RECIPIENTS, subject, body)


def send_error_email(service, context, error_details):
    """Sends an email indicating an error during processing.
    Args:
        service: Authorized Gmail API service instance.
        context (str): A brief description of where the error occurred (e.g., "Gmail Message Listing", "Retrieving Attachment").
        error_details (str or Exception): The detailed error message or an Exception object.
    """
    subject = f"ERROR: CTB Processing Failed - {context}"

    # If error_details is an Exception object, convert it to a string
    if isinstance(error_details, Exception):
        error_details_str = str(error_details)
    else:
        error_details_str = error_details

    body = (
        f"An error occurred during CTB file processing.\n\nDetails:\n{error_details_str}\n\n"
        f"The problematic file (if any) should be in the 'Failed' folder in GCS."
    )
    send_email(service, NOTIFICATION_RECIPIENTS, subject, body)


def send_no_ctb_email(service, query):
    """Sends an email if no CTB documents are found."""
    subject = "INFO: No CTB Documents Found in Gmail"
    body = f"No CTB documents matching the query '{query}' were found in the Gmail inbox during this run."
    send_email(service, NOTIFICATION_RECIPIENTS, subject, body)


def remove_inbox_label(service, message_id):
    """Removes the 'INBOX' label from a Gmail message."""
    try:
        message = service.users().messages().modify(
            userId='me',
            id=message_id,
            body={
                'removeLabelIds': ['INBOX']
            }
        ).execute()
        print(f"Removed INBOX label from Message ID: {message_id}")
        return message
    except HttpError as error:
        print(f"An error occurred while removing INBOX label from Message ID {message_id}: {error}")
        send_error_email(service, f"Removing Inbox Label for Message {message_id}", error)
        return None


if __name__ == '__main__':
    gmail_service = get_gmail_service()
    if gmail_service:
        messages_found = list_messages(gmail_service, query=GMAIL_QUERY)
        print(
            f"Found {len(messages_found)} messages with subject 'Demand & CTB'"
            " and attachment 'CTB' in INBOX."
        )

        ctb_documents_processed_count = 0

        if messages_found:
            for message in messages_found:
                msg_id = message['id']
                try:
                    msg_detail = get_message_detail(gmail_service, msg_id)
                    if msg_detail and 'payload' in msg_detail and 'parts' in msg_detail['payload']:
                        if process_part(gmail_service, msg_detail['payload'], msg_id, GCS_UNPROCESSED_PATH):
                            ctb_documents_processed_count += 1
                            remove_inbox_label(gmail_service, msg_id)
                        else:
                            print(f"No CTB attachment processed in message {msg_id} or processing failed for it.")
                    else:
                        error_msg = f"Could not retrieve details or payload parts for Message ID: {msg_id}. Skipping."
                        print(error_msg)
                        send_error_email(gmail_service, f"Message Details {msg_id}", error_msg)
                except Exception as e:
                    error_msg = f"An unexpected error occurred while processing Message ID {msg_id}: {e}"
                    print(error_msg)
                    send_error_email(gmail_service, f"Overall Message Processing {msg_id}", error_msg)

            if ctb_documents_processed_count == 0:
                print("No CTB attachments were successfully processed from the found messages.")
                send_no_ctb_email(gmail_service, GMAIL_QUERY)

        else:
            print("No emails found with the specified subject and filename matching the query.")
            send_no_ctb_email(gmail_service, GMAIL_QUERY)
    else:
        print("Failed to authenticate with Gmail API. Cannot proceed with email processing.")