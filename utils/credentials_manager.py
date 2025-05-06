import os
import json
import base64
import hashlib
import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Custom JSON encoder to handle datetime objects
class JSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime.datetime):
            return obj.isoformat()
        elif isinstance(obj, datetime.date):
            return obj.isoformat()
        elif isinstance(obj, datetime.timedelta):
            return str(obj)
        elif hasattr(obj, '__dict__'):
            # Convert objects to dict
            return obj.__dict__
        return super().default(obj)


class CredentialsManager:
    def __init__(self):
        self.app_data_dir = self.get_app_data_dir()
        self.encrypted_creds_path = os.path.join(self.app_data_dir, "app_credentials.enc")
        self.machine_id = self.get_machine_id()
        self._obfuscated_client_id = "NDY5MDUyNTA3OTkwLTloZjZsYm11NHZic2V2dXQyMmltMWFjM2wxM29oNWRxLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29t"
        self._obfuscated_client_secret = "R09DU1BYLTE5MTkzWXZoSlNQOV8xTnh6U2xhVkhia25qeDM="
        
    def get_app_data_dir(self):
        """Get the application data directory based on platform"""
        import sys
        if sys.platform == "win32":
            app_data = os.path.join(os.environ["APPDATA"], "JudolSlayer")
        elif sys.platform == "darwin":
            app_data = os.path.join(os.path.expanduser("~"), "Library", "Application Support", "JudolSlayer")
        else:  # Linux/Unix
            app_data = os.path.join(os.path.expanduser("~"), ".config", "judolslayer")
            
        # Create directory if it doesn't exist
        os.makedirs(app_data, exist_ok=True)
        return app_data
        
    def get_machine_id(self):
        """Generate a stable machine identifier"""
        import platform, uuid
        
        # Combine static and dynamic identifiers
        identifiers = [
            platform.node(),  # Hostname
            str(uuid.getnode()),  # MAC address hash
            "static_salt_judolslayer"  # Fixed salt
        ]
        
        # Create a SHA256 hash
        return hashlib.sha256("|".join(identifiers).encode()).hexdigest()
    
    def _generate_key(self):
        """Generate an encryption key based on machine ID"""
        # Use PBKDF2 to derive a key from the machine ID
        salt = b'judolslayer_salt'  # Fixed salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.machine_id.encode()))
        return key
    
    def _deobfuscate(self, obfuscated_string):
        """Convert from base64"""
        try:
            return base64.b64decode(obfuscated_string).decode('utf-8')
        except:
            return ""
            
    def get_client_credentials(self):
        """Get client credentials for OAuth2 flow"""
        # First, try to load from encrypted file
        if os.path.exists(self.encrypted_creds_path):
            try:
                # Decrypt the file
                key = self._generate_key()
                fernet = Fernet(key)
                
                with open(self.encrypted_creds_path, 'rb') as file:
                    encrypted_data = file.read()
                    
                decrypted_data = fernet.decrypt(encrypted_data)
                credentials = json.loads(decrypted_data.decode())
                
                #Debug
                print(f"[DEBUG] Machine ID: {self.machine_id}")  # Add this
                print(f"[DEBUG] Decrypted Credentials: {credentials}")  # Add this
                return credentials.get('client_id'), credentials.get('client_secret')

                return credentials.get('client_id'), credentials.get('client_secret')
            except:
                # If decryption fails, fall back to deobfuscated defaults
                pass
                
        # Fall back to deobfuscated default credentials
        client_id = self._deobfuscate(self._obfuscated_client_id)
        client_secret = self._deobfuscate(self._obfuscated_client_secret)
        
        # Store the credentials for future use
        self.store_client_credentials(client_id, client_secret)
        
        return client_id, client_secret
        
    def store_client_credentials(self, client_id, client_secret):
        """Encrypt and store client credentials"""
        # Skip if the credentials are empty
        if not client_id or not client_secret:
            return False
            
        try:
            # Prepare data for encryption
            credentials = {
                'client_id': client_id,
                'client_secret': client_secret
            }
            
            # Convert to JSON with custom encoder
            json_data = json.dumps(credentials, cls=JSONEncoder).encode()
            
            # Generate encryption key
            key = self._generate_key()
            fernet = Fernet(key)
            
            # Encrypt the data
            encrypted_data = fernet.encrypt(json_data)
            
            # Save to file
            with open(self.encrypted_creds_path, 'wb') as file:
                file.write(encrypted_data)
                
            return True
        except Exception as e:
            print(f"Failed to store credentials: {str(e)}")
            return False
    
    def create_client_secrets_file(self):
        client_id, client_secret = self.get_client_credentials()
        
        client_config = {
            "installed": {
                "client_id": client_id,
                "project_id": "indonesiantijudol",  # Updated project ID
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
                "client_secret": client_secret,
                "redirect_uris": ["http://localhost", "urn:ietf:wg:oauth:2.0:oob"]
            }
        }
        
        # Create a temporary client_secrets.json in the app data directory
        secrets_path = os.path.join(self.app_data_dir, "client_secrets.json")
        with open(secrets_path, "w") as f:
            json.dump(client_config, f)
            
        return secrets_path
