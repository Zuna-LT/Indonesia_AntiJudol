import json
import os
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from utils.constants import TOKEN_FILE, SCOPES

class AuthManager:
    def __init__(self):
        self.youtube = None
        
    def load_token(self):
        if os.path.exists(TOKEN_FILE):
            with open(TOKEN_FILE, 'r') as f:
                return json.load(f)
        return None

    def save_token(self, creds):
        with open(TOKEN_FILE, 'w') as f:
            json.dump(creds, f)

    def authenticate(self):
        flow = InstalledAppFlow.from_client_secrets_file('client_secrets.json', SCOPES)
        creds = flow.run_local_server(port=0)
        self.youtube = build('youtube', 'v3', credentials=creds)
        self.save_token(creds.__dict__)
        return self.youtube