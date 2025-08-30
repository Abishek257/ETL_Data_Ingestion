**📩 Gmail → GCS → BigQuery ETL Pipeline**

This project implements an ETL (Extract, Transform, Load) pipeline that automates the ingestion of CTB (Customer Transaction/Booking) files received via Gmail. The pipeline extracts attachments from Gmail, uploads them to Google Cloud Storage (GCS), validates and transforms the file contents, and loads the cleaned data into BigQuery for analytics.

**🚀 Features**

**Extract**

(1) Connects to Gmail via OAuth2.

(2) Searches for emails with specific query filters.

(3) Downloads attachments starting with CTB.

**Transform**

(1) Validates CTB file structure.

(2) Cleans headers and maps them to BigQuery schema.

(3) Converts field types (dates, integers, strings).

(4) Handles malformed rows gracefully (logs + skips).

**Load**

(1) Uploads raw attachments to Google Cloud Storage.

(2) Inserts valid rows into BigQuery in batches.

(3) Moves processed files into Processed/ or Failed/ folders in GCS.

**Notifications**

(1) Sends success/failure email alerts via Gmail API.

(2) Notifies if no CTB documents were found.

**🛠️ Tech Stack**

**Python 3**

**Google APIs**

(1) Gmail API

(2) Google Cloud Storage

(3) Google BigQuery

**Libraries**

(1) google-auth, google-auth-oauthlib, google-api-python-client

(2) google-cloud-storage, google-cloud-bigquery

(3) requests

(4) python-dotenv

**📂 Project Structure**

├── main.py            # Main ETL pipeline script

├── requirements.txt   # Python dependencies

├── .env               # Environment configuration (not for public repo)

└── README.md          # Project documentation

**⚙️ Setup & Installation**

**Clone the repository**

git clone https://github.com/your-username/ctb-etl-pipeline.git

cd ctb-etl-pipeline

**Install dependencies**

pip install -r requirements.txt

**Configure environment variables**

Create a .env file in the project root:

CREDENTIALS_PATH=path/to/service_account.json

CLIENT_SECRET_FILE=path/to/client_secret.json

TOKEN_FILE=token.json

SCOPES=https://www.googleapis.com/auth/gmail.readonly,https://www.googleapis.com/auth/gmail.send

REDIRECT_URI=http://localhost:8080/callback

NOTIFICATION_RECIPIENTS=your_email@example.com

GMAIL_QUERY=subject:"Demand & CTB" filename:CTB

GCS_UNPROCESSED_PATH=gs://your-bucket/CTB/Week_Unprocessed

BIGQUERY_DATASET=your_dataset

BIGQUERY_TABLE=your_table

HTTP_REQUEST_TIMEOUT=900

BIGQUERY_BATCH_SIZE=500


**Run the ETL pipeline**

python main.py

**📊 Workflow**

(1) Extract → Fetch Gmail messages with CTB attachments.

(2) Transform → Parse CTB file, clean headers, validate row data.

(3) Load → Upload file to GCS & insert valid rows into BigQuery.

(4) Notify → Send email alerts on success, errors, or no files found.
