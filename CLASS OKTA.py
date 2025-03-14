import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import requests
import json
import random
import string
import threading
import os
import time
import glob
import datetime
import sqlite3
import winsound
import tkinter.simpledialog as simpledialog

import ttkbootstrap as tb
from ttkbootstrap import Style
import ttkbootstrap.dialogs as tb_dialogs  # for themed dialogs

# Add missing global definitions
OBJECT_ENDPOINTS = {
    "User": "/api/v1/users",
    "Group": "/api/v1/groups",
    "Application": "/api/v1/apps",
    "Group Rule": "/api/v1/groups/rules",
    "Policy": "/api/v1/policies",
    "Policy Rule": "/api/v1/policies/{policyId}/rules",
    "Authorization Server": "/api/v1/authorizationServers",
    "Custom Token Scope": "/api/v1/authorizationServers/{authServerId}/scopes",
    "Custom Token Claim": "/api/v1/authorizationServers/{authServerId}/claims",
    "Event Hook": "/api/v1/eventHooks",
    "Inline Hook": "/api/v1/inlineHooks",
    "Linked Object Definition": "/api/v1/meta/linkedObjects",
    "Log Stream": "/api/v1/logStreams",
    "Network Zone": "/api/v1/zones",
    "Trusted Origin": "/api/v1/trustedOrigins",
    "SMS Template": "/api/v1/templates/sms",
    "Device Assurance Policy": "/api/v1/device/assurancePolicies",
    "Identity Provider": "/api/v1/idps",
    "Role (Custom Admin Role)": "/api/v1/roles",
    "Permission (Custom Role)": "/api/v1/roles/{roleId}/permissions",
    "Resource Set": "/api/v1/iam/resource-sets",
    "Resource Set Binding": "/api/v1/iam/resource-sets/{resourceSetId}/bindings",
    "User Type": "/api/v1/meta/types/user",
    "CAPTCHA Instance": "/api/v1/attackProtection/captcha/configurations",
    "Behavior Detection Rule": "/api/v1/behaviors",
    "Risk Provider": "/api/v1/risk/providers"
}

SAMPLE_BODIES = {
    "User": """{
  "profile": {
    "firstName": "Alice",
    "lastName": "Doe",
    "email": "alice.doe@example.com",
    "login": "alice.doe@example.com"
  },
  "credentials": {
    "password": { "value": "SuperSecret123" }
  }
}""",
    "Group": """{
  "profile": {
    "name": "Sales Team",
    "description": "Group for all sales employees"
  }
}""",
    "Application": """{
  "name": "oidc_client",
  "label": "My Web App",
  "signOnMode": "OPENID_CONNECT",
  "credentials": {
    "oauthClient": {
      "token_endpoint_auth_method": "client_secret_basic"
    }
  },
  "settings": {
    "oauthClient": {
      "redirect_uris": [
        "https://app.example.com/oidc/callback"
      ],
      "response_types": [ "code" ],
      "grant_types": [ "authorization_code" ],
      "application_type": "web"
    }
  }
}"""
}

def validate_okta_url(url):
    return url.startswith("http://") or url.startswith("https://")

###############################################################################
#                     MANAGER CLASSES (Refactored Logic)                     #
###############################################################################

class CredentialManager:
    """
    Manages Okta credentials stored in a JSON file (default "credentials.json").
    """

    def __init__(self, credentials_file="credentials.json", max_creds=100):
        self.credentials_file = credentials_file
        self.max_credentials = max_creds
        self.credentials = []

    def load_credentials_from_file(self):
        """Load credentials from a JSON file."""
        if os.path.exists(self.credentials_file):
            try:
                with open(self.credentials_file, 'r', encoding='utf-8') as f:
                    credentials_data = json.load(f)
                self.credentials.clear()
                self.credentials.extend(credentials_data)
                return True, "Credentials loaded successfully."
            except Exception as e:
                return False, f"Error loading credentials: {e}"
        else:
            self.credentials.clear()
            return False, "Credentials file not found. Starting with an empty list."

    def save_credentials_to_file(self):
        """Save credentials to a JSON file."""
        try:
            with open(self.credentials_file, 'w', encoding='utf-8') as f:
                json.dump(self.credentials, f, indent=2)
            return True, "Credentials saved successfully."
        except Exception as e:
            return False, f"Error saving credentials: {e}"

    def add_credential(self, okta_url: str, api_key: str):
        """Add a new credential if not duplicate and does not exceed max limit."""
        # Check if we already have the same credential
        for cred in self.credentials:
            if cred["okta_url"] == okta_url and cred["api_key"] == api_key:
                return False, "These credentials are already saved."

        if len(self.credentials) >= self.max_credentials:
            return False, f"Maximum of {self.max_credentials} credentials reached."

        self.credentials.append({"okta_url": okta_url, "api_key": api_key})
        return True, "Credential saved successfully."

    def delete_credential(self, index: int):
        """Delete a credential by index from the list."""
        if 0 <= index < len(self.credentials):
            del self.credentials[index]
            return True, "Credential deleted."
        return False, "Invalid index."

    def verify_credential(self, cred):
        """
        Check if a credential is valid by making a simple GET to /api/v1/users?limit=1.
        Also checks whether an "Acsense-Provisioning" app is present as a small extra example.
        """
        try:
            headers = {
                "Authorization": f"SSWS {cred['api_key']}",
                "Accept": "application/json"
            }
            url = f"{normalize_url(cred['okta_url'])}/api/v1/users?limit=1"
            response = requests.get(url, headers=headers, timeout=5)
            if response.status_code == 200:
                # Additional check for an "Acsense-Provisioning" app
                apps_resp = requests.get(f"{cred['okta_url']}/api/v1/apps", headers=headers)
                if apps_resp.ok:
                    found_acsense = any(
                        app.get("label") == "Acsense-Provisioning" and app.get("status") == "ACTIVE"
                        for app in apps_resp.json()
                    )
                    if found_acsense:
                        cred["has_acsense"] = True
                return True
            elif response.status_code in [401, 403]:
                return False
            else:
                # Non-200 but not specifically 401/403
                return True
        except Exception:
            return False


class SnapshotManager:
    """
    Handles snapshot files: loading, saving, listing, and deleting them.
    """

    def __init__(self, snapshot_dir="snapshots"):
        self.snapshot_dir = snapshot_dir
        if not os.path.exists(self.snapshot_dir):
            os.makedirs(self.snapshot_dir)

    def get_snapshot_files(self):
        """Return a sorted list of snapshot file paths from newest to oldest."""
        snapshots = sorted(
            glob.glob(os.path.join(self.snapshot_dir, "snapshot_*.json")),
            key=os.path.getmtime,
            reverse=True
        )
        return snapshots

    def read_snapshot(self, file_path):
        """Read and return the JSON data from a snapshot file."""
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def delete_snapshot(self, file_path):
        """Delete a snapshot file."""
        os.remove(file_path)

    def save_snapshot(self, tenant_url, data):
        """
        Save the overview data (or anything else) as a JSON snapshot in the snapshot_dir.
        Returns the file path of the new snapshot.
        """
        now = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = os.path.join(self.snapshot_dir, f"snapshot_{now}.json")
        snapshot = {"tenant_url": tenant_url, "timestamp": now, "data": data}
        with open(filename, "w") as f:
            json.dump(snapshot, f, indent=2)
        return filename


class OverviewManager:
    """
    Manages fetching an Okta overview (users, groups, etc.) from a tenant,
    storing them in a local DB, and building a local data structure.
    """

    def __init__(self, db_file="okta_objects.db"):
        self.db_file = db_file
        self.overview_data = {}
        self.overview_mapping = {}  # Maps TreeView items to data

        self._create_database()

    def _create_database(self):
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()

        # Create tables for different object types
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                first_name TEXT,
                last_name TEXT,
                email TEXT,
                login TEXT,
                json_data TEXT
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS groups (
                id TEXT PRIMARY KEY,
                name TEXT,
                description TEXT,
                json_data TEXT
            )
        ''')
        conn.commit()
        conn.close()

    def insert_user_into_db(self, user):
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO users (id, first_name, last_name, email, login, json_data)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            user['id'],
            user['profile'].get('firstName', ''),
            user['profile'].get('lastName', ''),
            user['profile'].get('email', ''),
            user['profile'].get('login', ''),
            json.dumps(user)
        ))
        conn.commit()
        conn.close()

    def insert_group_into_db(self, group):
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO groups (id, name, description, json_data)
            VALUES (?, ?, ?, ?)
        ''', (
            group['id'],
            group['profile'].get('name', ''),
            group['profile'].get('description', ''),
            json.dumps(group)
        ))
        conn.commit()
        conn.close()


class TransferManager:
    """
    Handles logic for transferring selected objects to a different Okta tenant.
    """

    def __init__(self):
        self.transfer_data = {}
        self.transfer_mapping = {}
        self.transfer_cancelled = False

        # Mapping from category name to creation endpoint
        self.transfer_endpoint_map = {
            "okta_users": "/api/v1/users?activate=true",
            "okta_groups": "/api/v1/groups",
            "okta_applications": "/api/v1/apps",
            "okta_authz_policies": "/api/v1/authorizationServers/default/policies",
            "okta_global_policies": "/api/v1/policies",
            "okta_idps": "/api/v1/idps",
            "okta_roles": "/api/v1/roles",
            "okta_mappings": "/api/v1/mappings"
        }

    def cancel_transfer(self):
        """Set a flag to halt the transfer process."""
        self.transfer_cancelled = True

    def reset_transfer_cancelled(self):
        self.transfer_cancelled = False

    def get_all_selected_items(self, tree):
        """
        Recursively traverse the given TreeView and return a list of item IDs
        that are selected (value == 'Yes') and have an associated object in
        self.transfer_mapping.
        """
        selected_items = []

        def traverse(item):
            values = tree.item(item, "values")
            if values and values[0] == "Yes" and self.transfer_mapping.get(item):
                selected_items.append(item)
            for child in tree.get_children(item):
                traverse(child)

        for top_item in tree.get_children():
            traverse(top_item)
        return selected_items

    def get_cleaned_payload(self, obj, cat_key):
        """Return a JSON-ready dict for creation in the target tenant."""
        from . import clean_app_object, clean_object  # or define them here if needed
        if cat_key == "okta_applications":
            return clean_app_object(obj)
        else:
            return clean_object(obj)


###############################################################################
#                            HELPER / UTILITY FUNCTIONS                        #
###############################################################################

def normalize_url(url):
    """Remove trailing slashes from a URL."""
    return url.rstrip('/')

def generate_random_string(length=6):
    """Generate a random string of letters+digits of specified length."""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def format_json_response(text):
    """Pretty-print JSON response text if valid, otherwise return as-is."""
    try:
        parsed = json.loads(text)
        return json.dumps(parsed, indent=2)
    except Exception:
        return text

def clean_object(obj):
    """
    Remove fields like 'id', 'created', '_links', etc. from an Okta object
    to make it suitable for re-creation. Also remove `_delete_endpoint`.
    """
    if not isinstance(obj, dict):
        return obj
    cleaned = obj.copy()
    for field in [
        "id", "created", "activated", "statusChanged", "lastLogin", "lastUpdated",
        "passwordChanged", "_links", "_delete_endpoint"
    ]:
        cleaned.pop(field, None)
    return cleaned

def clean_app_object(obj):
    """
    App-specific cleaning logic. Currently calls clean_object,
    but you can add more if needed.
    """
    if not isinstance(obj, dict):
        return obj
    cleaned = clean_object(obj)
    # Additional app-specific cleaning logic could go here
    return cleaned

def get_label_for_object(obj):
    """
    Return a user-friendly label for an object from known fields (label, name, login, etc.).
    """
    if isinstance(obj, dict):
        if "label" in obj:
            label = obj["label"]
        elif "profile" in obj:
            prof = obj["profile"]
            if "login" in prof:
                label = prof["login"]
            elif "firstName" in prof and "lastName" in prof:
                label = f"{prof['firstName']} {prof['lastName']}"
            elif "name" in prof:
                label = prof["name"]
            else:
                label = "N/A"
        elif "name" in obj:
            label = obj["name"]
        else:
            label = "N/A"
        id_val = obj.get("id", "N/A")
        return f"{label} ({id_val})"
    return str(obj)

def api_get(url, headers, params=None, max_retries=5, initial_wait=1):
    retries = 0
    wait_time = initial_wait
    response = None
    while retries < max_retries:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        if response.status_code == 429:
            time.sleep(wait_time)
            wait_time *= 2
            retries += 1
        else:
            break
    if retries == max_retries:
        # Log max retries reached (using print as a fallback)
        print(f"Max retries reached for URL: {url} with params: {params}. Final status: {response.status_code} - {response.text}")
    return response


###############################################################################
#                          MAIN APPLICATION CLASS                             #
###############################################################################

class OktaAPIToolApp:
    """
    Main application class that sets up the UI and ties together:
      - Credential Management
      - Snapshot Management
      - Overview fetching
      - Transfer logic
      - Live event fetching
      - Object creation
      - And more...
    """

    def __init__(self):
        # Initialize managers
        self.cred_manager = CredentialManager()
        self.snap_manager = SnapshotManager()
        self.overview_manager = OverviewManager()
        self.transfer_manager = TransferManager()

        self.last_log_timestamp = None

        # Initialize UI (use ttkbootstrap style)
        self.style = Style(theme="flatly")
        self.root = self.style.master
        self.root.title("Okta API Tool - Refactored with Classes")

        # We'll store references to certain widgets
        self.action_buttons = []
        self.is_light = True

        # Build the UI
        self._build_ui()
        self._init_database_and_load_creds()

    def _init_database_and_load_creds(self):
        """Create the local DB, load credentials, update listbox, etc."""
        # We already create DB in overview_manager, so just load credentials here
        ok, msg = self.cred_manager.load_credentials_from_file()
        self.log_console(msg)
        self.update_credentials_listbox()

    ###########################################################################
    #                               UI Building                               #
    ###########################################################################

    def _build_ui(self):
        self._build_filter_frame()
        self._build_top_frame()
        self._build_progress_bar()
        self._build_notebook()
        self._build_bottom_buttons()

    def _build_filter_frame(self):
        filter_frame = tk.Frame(self.root, padx=10, pady=5)
        filter_frame.pack(fill=tk.X)

        self.date_entry = tb.DateEntry(filter_frame, bootstyle="primary", dateformat='%Y-%m-%d')
        self.date_entry.pack(side=tk.LEFT, padx=5)

        tk.Label(filter_frame, text="Filter by Date:").pack(side=tk.LEFT, padx=5)

    def _build_top_frame(self):
        self.top_frame = tk.Frame(self.root, padx=10, pady=10)
        self.top_frame.pack(fill=tk.X)

        # Theme toggle
        self.theme_toggle = tb.Button(self.top_frame, text="Toggle Theme", bootstyle="outline-primary",
                                      command=self.toggle_theme)
        self.theme_toggle.grid(row=0, column=5, padx=5, pady=2)
        self.action_buttons.append(self.theme_toggle)

        # Okta URL
        tk.Label(self.top_frame, text="Okta URL:").grid(row=0, column=0, sticky="w")
        self.okta_url_entry = tk.Entry(self.top_frame, width=50)
        self.okta_url_entry.grid(row=0, column=1, padx=5, pady=2)

        tk.Label(self.top_frame, text="Example: https://yourOktaDomain.okta.com", fg="gray").grid(row=1, column=1, sticky="w")

        # API Key
        tk.Label(self.top_frame, text="API Key:").grid(row=0, column=2, sticky="w")
        self.api_key_entry = tk.Entry(self.top_frame, width=40, show="*")
        self.api_key_entry.grid(row=0, column=3, padx=5, pady=2)

        # Nested frame for credentials & snapshots
        cred_snap_frame = tk.Frame(self.top_frame)
        cred_snap_frame.grid(row=2, column=0, columnspan=6, sticky="ew", pady=5)

        self._build_credential_frame(cred_snap_frame)
        self._build_snapshot_frame(cred_snap_frame)
        self._build_meter_frame(cred_snap_frame)

    def _build_credential_frame(self, parent):
        cred_frame = tk.LabelFrame(parent, text="Stored Credentials", padx=5, pady=5)
        cred_frame.grid(row=0, column=0, sticky="nw")

        self.credentials_listbox = tk.Listbox(cred_frame, height=6, width=80)
        self.credentials_listbox.grid(row=0, column=0, columnspan=3, padx=5, pady=5)

        save_btn = tk.Button(cred_frame, text="Save Credential", command=self.save_current_credential)
        load_btn = tk.Button(cred_frame, text="Load Credential", command=self.load_selected_credential)
        del_btn = tk.Button(cred_frame, text="Delete Credential", command=self.delete_selected_credential)
        save_btn.grid(row=1, column=0, padx=5, pady=2)
        load_btn.grid(row=1, column=1, padx=5, pady=2)
        del_btn.grid(row=1, column=2, padx=5, pady=2)
        self.action_buttons.extend([save_btn, load_btn, del_btn])

    def _build_snapshot_frame(self, parent):
        snapshots_frame = tk.LabelFrame(parent, text="Snapshots", padx=5, pady=5)
        snapshots_frame.grid(row=0, column=1, sticky="nw", padx=10)

        self.snapshot_listbox = tk.Listbox(snapshots_frame, height=6, width=80)
        self.snapshot_listbox.grid(row=0, column=0, columnspan=3, padx=5, pady=5)

        snap_btn_frame = tk.Frame(snapshots_frame)
        snap_btn_frame.grid(row=1, column=0, columnspan=3, sticky="ew")

        load_transfer_btn = tk.Button(snap_btn_frame, text="Load Snapshot to Transfer",
                                      command=self.load_selected_snapshot_to_transfer)
        load_overview_btn = tk.Button(snap_btn_frame, text="Load Snapshot to Overview",
                                      command=self.load_selected_snapshot_to_overview)
        del_snap_btn = tk.Button(snap_btn_frame, text="Delete Snapshot",
                                 command=self.delete_selected_snapshot)

        load_transfer_btn.pack(side=tk.LEFT, padx=5)
        load_overview_btn.pack(side=tk.LEFT, padx=5)
        del_snap_btn.pack(side=tk.LEFT, padx=5)

        self.action_buttons.extend([load_transfer_btn, load_overview_btn, del_snap_btn])

        self.init_snapshots()

    def _build_meter_frame(self, parent):
        meter_frame = tk.Frame(parent, padx=5, pady=5)
        meter_frame.grid(row=0, column=2, sticky="nw")

        self.global_meter = tb.Meter(
            meter_frame, bootstyle="primary", subtext="Progress",
            amountused=0, amounttotal=100, interactive=False
        )
        self.global_meter.pack(padx=5, pady=5)

    def _build_progress_bar(self):
        global_progress_frame = tk.Frame(self.root, padx=10, pady=5)
        global_progress_frame.pack(fill=tk.X)
        self.global_progress_label = tk.Label(global_progress_frame, text="Ready.")
        self.global_progress_label.pack(side=tk.LEFT, padx=5)

        self.global_progress_bar = tb.Progressbar(global_progress_frame, orient="horizontal",
                                                  length=400, mode="determinate", bootstyle="striped")
        self.global_progress_bar.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

    def _build_notebook(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Super Admin tab
        self._build_super_admin_tab()
        # Console tab
        self._build_console_tab()
        # Tenant Overview tab
        self._build_overview_tab()
        # Live Events tab
        self._build_live_events_tab()
        # Transfer Objects tab
        self._build_transfer_tab()
        # Object Creation tab
        self._build_object_creation_tab()

    def _build_super_admin_tab(self):
        super_admin_tab = tk.Frame(self.notebook)
        self.notebook.add(super_admin_tab, text="Super Admin")

        frame = tk.LabelFrame(super_admin_tab, text="Super Admin Creation", padx=5, pady=5)
        frame.pack(fill=tk.X, pady=5)

        tk.Label(frame, text="First Name:").grid(row=0, column=0, sticky="w")
        self.super_admin_first_entry = tk.Entry(frame, width=15)
        self.super_admin_first_entry.grid(row=0, column=1, padx=5, pady=2)

        tk.Label(frame, text="Last Name:").grid(row=0, column=2, sticky="w")
        self.super_admin_last_entry = tk.Entry(frame, width=15)
        self.super_admin_last_entry.grid(row=0, column=3, padx=5, pady=2)

        tk.Label(frame, text="Email:").grid(row=1, column=0, sticky="w")
        self.super_admin_email_entry = tk.Entry(frame, width=15)
        self.super_admin_email_entry.grid(row=1, column=1, padx=5, pady=2)

        tk.Label(frame, text="Login:").grid(row=1, column=2, sticky="w")
        self.super_admin_login_entry = tk.Entry(frame, width=15)
        self.super_admin_login_entry.grid(row=1, column=3, padx=5, pady=2)

        btn = tk.Button(frame, text="Generate Super Admin", command=lambda: self.run_threaded(self.create_super_admin))
        btn.grid(row=2, column=0, columnspan=4, pady=5)
        self.action_buttons.append(btn)

    def _build_console_tab(self):
        console_tab = tk.Frame(self.notebook)
        self.notebook.add(console_tab, text="Console")

        self.console_text = tk.Text(console_tab, height=15, state="disabled")
        self.console_text.pack(fill=tk.BOTH, expand=True)

        clear_btn = tk.Button(console_tab, text="Clear Console", command=self.clear_console)
        clear_btn.pack(pady=2)
        self.action_buttons.append(clear_btn)

    def _build_overview_tab(self):
        overview_tab = tk.Frame(self.notebook)
        self.notebook.add(overview_tab, text="Tenant Objects")

        overview_toolbar = tk.Frame(overview_tab)
        overview_toolbar.pack(fill=tk.X, padx=5, pady=5)

        fetch_btn = tk.Button(overview_toolbar, text="Fetch Objects", command=lambda: self.run_threaded(self.retrieve_overview))
        save_btn = tk.Button(overview_toolbar, text="Save Objects", command=self.save_overview_to_file)
        delete_local_btn = tk.Button(overview_toolbar, text="Delete Selected", command=self.delete_selected_overview_objects)
        delete_target_btn = tk.Button(overview_toolbar, text="Delete From Target", command=self.delete_object_from_target)
        reset_pw_btn = tk.Button(overview_toolbar, text="Reset Password", command=lambda: self.run_threaded(self.reset_user_password))

        fetch_btn.pack(side=tk.LEFT, padx=5)
        save_btn.pack(side=tk.LEFT, padx=5)
        delete_local_btn.pack(side=tk.LEFT, padx=5)
        delete_target_btn.pack(side=tk.LEFT, padx=5)
        reset_pw_btn.pack(side=tk.LEFT, padx=5)

        self.action_buttons.extend([fetch_btn, save_btn, delete_local_btn, delete_target_btn, reset_pw_btn])

        overview_paned = ttk.PanedWindow(overview_tab, orient=tk.HORIZONTAL)
        overview_paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        tree_frame = tk.Frame(overview_paned)
        self.overview_tree = ttk.Treeview(tree_frame)
        self.overview_tree.heading("#0", text="Tenant Objects", anchor="w")
        self.overview_tree.pack(fill=tk.BOTH, expand=True)
        overview_paned.add(tree_frame, weight=2)

        details_frame = tk.Frame(overview_paned)
        self.details_text = tk.Text(details_frame, state="disabled")
        self.details_text.pack(fill=tk.BOTH, expand=True)
        overview_paned.add(details_frame, weight=1)

        self.overview_tree.bind("<<TreeviewSelect>>", self.on_overview_tree_select)

    def _build_live_events_tab(self):
        live_tab = tk.Frame(self.notebook)
        self.notebook.add(live_tab, text="Live Events")

        toolbar = tk.Frame(live_tab)
        toolbar.pack(fill=tk.X, padx=5, pady=5)

        update_btn = tk.Button(toolbar, text="Update Logs", command=lambda: self.run_threaded(self.retrieve_live_events))
        update_btn.pack(side=tk.LEFT, padx=5)
        self.action_buttons.append(update_btn)

        live_paned = ttk.PanedWindow(live_tab, orient=tk.HORIZONTAL)
        live_paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        logs_tree_frame = tk.Frame(live_paned)
        self.live_tree = ttk.Treeview(logs_tree_frame, columns=("Event Type", "Published", "Actor"), show="headings")
        self.live_tree.heading("Event Type", text="Event Type")
        self.live_tree.heading("Published", text="Published")
        self.live_tree.heading("Actor", text="Actor")
        self.live_tree.pack(fill=tk.BOTH, expand=True)
        live_paned.add(logs_tree_frame, weight=2)

        logs_details_frame = tk.Frame(live_paned)
        self.logs_details_text = tk.Text(logs_details_frame, state="disabled")
        self.logs_details_text.pack(fill=tk.BOTH, expand=True)
        live_paned.add(logs_details_frame, weight=1)

        self.live_tree.bind("<<TreeviewSelect>>", self.on_live_tree_select)

    def _build_transfer_tab(self):
        transfer_tab = tk.Frame(self.notebook)
        self.notebook.add(transfer_tab, text="Transfer Objects")

        transfer_paned = ttk.PanedWindow(transfer_tab, orient=tk.HORIZONTAL)
        transfer_paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Left frame
        left_frame = tk.Frame(transfer_paned)

        load_objs_btn = tk.Button(left_frame, text="Load Saved Objects", command=self.load_saved_objects)
        load_objs_btn.pack(fill=tk.X, padx=5, pady=2)
        self.action_buttons.append(load_objs_btn)

        self.search_entry = tk.Entry(left_frame, state=tk.DISABLED)
        self.search_entry.pack(fill=tk.X, padx=5, pady=2)

        search_btn = tk.Button(left_frame, text="Search", command=self.search_objects)
        search_btn.pack(fill=tk.X, padx=5, pady=2)
        self.action_buttons.append(search_btn)

        self.transfer_tree = ttk.Treeview(left_frame, columns=("Selected",), show="tree headings")
        self.transfer_tree.heading("#0", text="Object")
        self.transfer_tree.heading("Selected", text="Selected")
        self.transfer_tree.column("Selected", width=70, anchor="center")
        self.transfer_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.transfer_tree.bind("<Double-1>", self.toggle_transfer_selection)
        self.transfer_tree.bind("<<TreeviewSelect>>", self.on_transfer_tree_select)

        transfer_paned.add(left_frame, weight=2)

        # Right frame
        right_frame = tk.Frame(transfer_paned)

        tk.Label(right_frame, text="Target Tenant URL:").pack(anchor="w", padx=5, pady=2)
        self.target_url_entry = tk.Entry(right_frame, width=40)
        self.target_url_entry.pack(padx=5, pady=2)

        tk.Label(right_frame, text="Target API Key:").pack(anchor="w", padx=5, pady=2)
        self.target_api_key_entry = tk.Entry(right_frame, width=40, show="*")
        self.target_api_key_entry.pack(padx=5, pady=2)

        load_target_btn = tk.Button(right_frame, text="Load Credential", command=self.load_target_credential)
        load_target_btn.pack(padx=5, pady=2)

        transfer_btn = tk.Button(right_frame, text="Transfer Selected",
                                 command=lambda: self.run_threaded(self.transfer_objects))
        transfer_btn.pack(padx=5, pady=2)

        cancel_btn = tk.Button(right_frame, text="Cancel Transfer", command=self.cancel_transfer)
        cancel_btn.pack(padx=5, pady=2)

        transfer_paned.add(right_frame, weight=1)
        self.action_buttons.extend([load_target_btn, transfer_btn, cancel_btn])

    def _build_object_creation_tab(self):
        obj_creation_tab = tk.Frame(self.notebook)
        self.notebook.add(obj_creation_tab, text="Object Creation")

        toolbar = tk.Frame(obj_creation_tab)
        toolbar.pack(fill=tk.X, padx=5, pady=5)

        tk.Label(toolbar, text="Target Tenant URL:").grid(row=0, column=0, sticky="w")
        self.target_url_entry2 = tk.Entry(toolbar, width=40)
        self.target_url_entry2.grid(row=0, column=1, padx=5, pady=2)

        tk.Label(toolbar, text="API Key:").grid(row=0, column=2, sticky="w")
        self.target_api_key_entry2 = tk.Entry(toolbar, width=40, show="*")
        self.target_api_key_entry2.grid(row=0, column=3, padx=5, pady=2)

        load_cred_button = tk.Button(toolbar, text="Load Selected Credential",
                                     command=lambda: self.load_selected_credential_to_creation(
                                         self.target_url_entry2, self.target_api_key_entry2))
        load_cred_button.grid(row=0, column=4, padx=5, pady=2)
        self.action_buttons.append(load_cred_button)

        creation_type_frame = tk.Frame(obj_creation_tab)
        creation_type_frame.pack(fill=tk.X, padx=5, pady=5)

        tk.Label(creation_type_frame, text="Object Type:").pack(side=tk.LEFT, padx=5)
        self.creation_type_combo = ttk.Combobox(creation_type_frame, values=list(OBJECT_ENDPOINTS.keys()), width=30)
        self.creation_type_combo.pack(side=tk.LEFT, padx=5)
        self.creation_type_combo.set("User")

        load_sample_button = tk.Button(creation_type_frame, text="Load Sample", command=self.load_sample_body)
        load_sample_button.pack(side=tk.LEFT, padx=5)
        self.action_buttons.append(load_sample_button)

        creation_body_frame = tk.Frame(obj_creation_tab)
        creation_body_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.creation_body_text = tk.Text(creation_body_frame, wrap=tk.NONE, width=80, height=20)
        self.creation_body_text.pack(fill=tk.BOTH, expand=True)

        btn_frame = tk.Frame(obj_creation_tab)
        btn_frame.pack(fill=tk.X, padx=5, pady=5)

        create_object_button = tk.Button(btn_frame, text="Create Object", command=self.run_create_object_thread)
        create_object_button.pack(side=tk.LEFT, padx=5)
        self.action_buttons.append(create_object_button)

    def _build_bottom_buttons(self):
        """
        Additional API action buttons (Generate Random... etc.) are placed at the bottom row.
        """
        button_frame = tk.Frame(self.root, padx=10, pady=5)
        button_frame.pack(fill=tk.X)

        user_btn = tk.Button(button_frame, text="Generate Random User",
                             command=lambda: self.run_threaded(self.create_random_user))
        user_btn.pack(side=tk.LEFT, padx=5)

        group_btn = tk.Button(button_frame, text="Generate Random Group",
                              command=lambda: self.run_threaded(self.create_random_group))
        group_btn.pack(side=tk.LEFT, padx=5)

        app_btn = tk.Button(button_frame, text="Generate Random Application",
                            command=lambda: self.run_threaded(self.create_random_app))
        app_btn.pack(side=tk.LEFT, padx=5)

        self.action_buttons.extend([user_btn, group_btn, app_btn])

        accsense_btn = tk.Button(button_frame, text="Generate Accsense Test Users",
                                 command=lambda: self.run_threaded(self.create_accsense_test_users))
        accsense_btn.pack(side=tk.LEFT, padx=5)
        self.action_buttons.append(accsense_btn)

    ###########################################################################
    #                           APPLICATION METHODS                           #
    ###########################################################################

    def toggle_theme(self):
        # Toggles through available ttkbootstrap themes
        available_themes = self.style.theme_names()
        current_theme = self.style.theme_use()
        next_theme_index = (available_themes.index(current_theme) + 1) % len(available_themes)
        new_theme = available_themes[next_theme_index]
        self.style.theme_use(new_theme)
        self.log_console(f"Theme toggled to {new_theme}")

    def run_threaded(self, task_func):
        """Run a given function in a background thread, so it doesn't block the UI."""
        def wrapper():
            try:
                self.disable_action_buttons(True)
                task_func()
            finally:
                self.disable_action_buttons(False)
        thread = threading.Thread(target=wrapper, daemon=True)
        thread.start()

    ###########################################################################
    #                           Logging & Console                             #
    ###########################################################################

    def log_console(self, text):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.console_text.configure(state='normal')
        self.console_text.insert(tk.END, f"[{timestamp}] {text}\n")
        self.console_text.configure(state='disabled')
        self.console_text.see(tk.END)

    def clear_console(self):
        self.console_text.configure(state='normal')
        self.console_text.delete(1.0, tk.END)
        self.console_text.configure(state='disabled')

    ###########################################################################
    #                           Action Buttons Control                        #
    ###########################################################################

    def disable_action_buttons(self, disable=True):
        state = tk.DISABLED if disable else tk.NORMAL
        for btn in self.action_buttons:
            try:
                btn.config(state=state)
            except Exception:
                pass

    ###########################################################################
    #                        Global Progress Updates                          #
    ###########################################################################

    def smooth_progress_update(self, value):
        self.global_progress_bar['value'] = value
        self.global_meter.configure(amountused=value)
        self.root.update_idletasks()

    def update_progress_start(self, action):
        self.global_progress_label['text'] = f"Starting {action}..."
        self.smooth_progress_update(0)
        self.global_progress_bar['maximum'] = 100
        self.global_meter.configure(amounttotal=100)

    def update_progress_complete(self, action):
        self.smooth_progress_update(100)
        self.global_progress_label['text'] = f"{action} complete."
        self.root.update_idletasks()
        self.reset_global_progress()
        winsound.Beep(600, 200)

    def reset_global_progress(self):
        self.global_progress_bar['value'] = 0
        self.global_meter.configure(amountused=0)
        self.global_progress_label['text'] = "Ready."

    ###########################################################################
    #                         CREDENTIALS UI LOGIC                             #
    ###########################################################################

    def save_current_credential(self):
        self.update_progress_start("Saving Credential")
        okta_url = normalize_url(self.okta_url_entry.get().strip())
        api_key = self.api_key_entry.get().strip()
        if not okta_url or not api_key:
            self.log_console("Both Okta URL and API Key are required to save credentials.")
            self.update_progress_complete("Saving Credential")
            return

        success, msg = self.cred_manager.add_credential(okta_url, api_key)
        if success:
            # persist to disk
            ok, save_msg = self.cred_manager.save_credentials_to_file()
            self.log_console(save_msg)
            self.update_credentials_listbox()
        self.log_console(msg)
        self.update_progress_complete("Saving Credential")

    def load_selected_credential(self):
        try:
            selection = self.credentials_listbox.curselection()
            if not selection:
                self.log_console("Please select a credential to load.")
                return
            index = selection[0]
            cred = self.cred_manager.credentials[index]

            self.okta_url_entry.delete(0, tk.END)
            self.okta_url_entry.insert(0, cred["okta_url"])
            self.api_key_entry.delete(0, tk.END)
            self.api_key_entry.insert(0, cred["api_key"])

            valid = self.cred_manager.verify_credential(cred)
            color = "lightgreen" if valid else "lightcoral"
            self.okta_url_entry.config(bg=color)
            self.api_key_entry.config(bg=color)
            self.okta_url_entry.update_idletasks()
            self.api_key_entry.update_idletasks()

            self.log_console("Credential loaded.")
        except Exception as e:
            self.log_console(f"Error loading credential: {e}")
            winsound.Beep(300, 500)  # beep on error

    def delete_selected_credential(self):
        try:
            selection = self.credentials_listbox.curselection()
            if not selection:
                self.log_console("Please select a credential to delete.")
                return
            index = selection[0]
            success, msg = self.cred_manager.delete_credential(index)
            if success:
                # persist to disk
                ok, save_msg = self.cred_manager.save_credentials_to_file()
                self.log_console(save_msg)
                self.update_credentials_listbox()
            self.log_console(msg)
        except Exception as e:
            self.log_console(f"Error deleting credential: {e}")
            winsound.Beep(300, 500)

    def update_credentials_listbox(self):
        self.credentials_listbox.delete(0, tk.END)
        for idx, cred in enumerate(self.cred_manager.credentials):
            valid = self.cred_manager.verify_credential(cred)
            status = "Valid" if valid else "Expired/Invalid"
            display_text = f"{idx+1}. {cred['okta_url'].rstrip('/')} ({status})"
            self.credentials_listbox.insert(tk.END, display_text)
            self.credentials_listbox.itemconfig(idx, foreground="green" if valid else "red")

    ###########################################################################
    #                            SNAPSHOTS UI LOGIC                           #
    ###########################################################################

    def init_snapshots(self):
        """Initialize the snapshots listbox by listing snapshot_*.json files."""
        self.snapshot_listbox.delete(0, tk.END)
        files = self.snap_manager.get_snapshot_files()
        for file in files:
            try:
                data = self.snap_manager.read_snapshot(file)
                tenant_url = data.get("tenant_url", "UnknownTenant")
                timestamp = data.get("timestamp", "UnknownTime")
                self.snapshot_listbox.insert(tk.END, f"{tenant_url} - {timestamp}")
            except Exception as e:
                self.log_console(f"Error loading snapshot file {file}: {str(e)}")
                winsound.Beep(300, 500)

    def delete_selected_snapshot(self):
        selection = self.snapshot_listbox.curselection()
        if not selection:
            return
        index = selection[0]
        files = self.snap_manager.get_snapshot_files()
        if index < len(files):
            file_to_delete = files[index]
            try:
                self.snap_manager.delete_snapshot(file_to_delete)
                self.log_console(f"Snapshot deleted: {file_to_delete}")
            except OSError as e:
                self.log_console(f"Failed to delete snapshot: {str(e)}")
                winsound.Beep(300, 500)
        self.init_snapshots()

    def load_selected_snapshot_to_transfer(self):
        self.update_progress_start("Loading snapshot to Transfer")
        try:
            selection = self.snapshot_listbox.curselection()
            if not selection:
                self.log_console("No snapshot selected.")
                self.update_progress_complete("Loading snapshot to Transfer")
                return
            index = selection[0]
            files = self.snap_manager.get_snapshot_files()
            if index >= len(files):
                self.log_console("Snapshot file not found.")
                self.update_progress_complete("Loading snapshot to Transfer")
                return

            file_path = files[index]
            snapshot_json = self.snap_manager.read_snapshot(file_path)
            loaded_data = snapshot_json.get("data", {})

            # Clear existing transfer data
            self.transfer_manager.transfer_data.clear()
            self.transfer_manager.transfer_data.update(loaded_data)

            for item in self.transfer_tree.get_children():
                self.transfer_tree.delete(item)
            self.transfer_manager.transfer_mapping.clear()

            # Insert a root node
            root_node = self.transfer_tree.insert("", "end", text="Loaded Snapshot Transfer", values=("No",), open=True)
            self.transfer_manager.transfer_mapping[root_node] = None

            # Walk each section
            for section_name, section_content in self.transfer_manager.transfer_data.items():
                section_node = self.transfer_tree.insert(root_node, "end", text=section_name, values=("No",), open=True)
                self.transfer_manager.transfer_mapping[section_node] = None
                if isinstance(section_content, dict):
                    for resource_name, objects_list in section_content.items():
                        resource_node = self.transfer_tree.insert(section_node, "end", text=resource_name, values=("No",), open=True)
                        self.transfer_manager.transfer_mapping[resource_node] = None
                        if isinstance(objects_list, list):
                            for obj in objects_list:
                                self.insert_transfer_object_with_children(resource_node, obj)
                        else:
                            self.log_console(f"Warning: {resource_name} is not a list in snapshot.")
                elif isinstance(section_content, list):
                    for obj in section_content:
                        self.insert_transfer_object_with_children(section_node, obj)
                else:
                    self.log_console(f"Warning: Section {section_name} is neither dict nor list.")
            messagebox.showinfo("Loaded", "Saved objects loaded successfully.")
            self.search_entry.config(state=tk.NORMAL)
        except Exception as e:
            self.log_console(f"Error loading snapshot to Transfer Objects tab: {e}")
            winsound.Beep(300, 500)
        self.update_progress_complete("Loading snapshot to Transfer")

    def load_selected_snapshot_to_overview(self):
        self.update_progress_start("Loading snapshot to Overview")
        try:
            selection = self.snapshot_listbox.curselection()
            if not selection:
                self.log_console("No snapshot selected.")
                self.update_progress_complete("Loading snapshot to Overview")
                return
            index = selection[0]
            files = self.snap_manager.get_snapshot_files()
            if index >= len(files):
                self.log_console("Snapshot file not found.")
                self.update_progress_complete("Loading snapshot to Overview")
                return

            file_path = files[index]
            snapshot_json = self.snap_manager.read_snapshot(file_path)

            self.overview_manager.overview_data.clear()
            for item in self.overview_tree.get_children():
                self.overview_tree.delete(item)

            loaded_data = snapshot_json.get("data", {})
            self.overview_manager.overview_data.update(loaded_data)

            root_node = self.overview_tree.insert("", "end", text="Loaded Snapshot Overview", open=True)
            self.overview_manager.overview_mapping[root_node] = None

            # Insert each top-level section
            for section_name, section_content in self.overview_manager.overview_data.items():
                section_node = self.overview_tree.insert(root_node, "end", text=section_name, open=True)
                self.overview_manager.overview_mapping[section_node] = None

                if isinstance(section_content, dict):
                    for resource_name, objects_list in section_content.items():
                        resource_node = self.overview_tree.insert(section_node, "end", text=resource_name, open=True)
                        self.overview_manager.overview_mapping[resource_node] = None

                        if isinstance(objects_list, list):
                            for obj in objects_list:
                                self.insert_object_with_children(resource_node, obj)
                        else:
                            self.log_console(f"Warning: {resource_name} is not a list in snapshot.")
                else:
                    self.log_console(f"Warning: Section {section_name} is not a dict in snapshot.")
            self.log_console("Snapshot successfully loaded to Tenant Objects.")
            winsound.Beep(700, 200)
        except Exception as e:
            self.log_console(f"Error loading snapshot to Tenant Objects tab: {e}")
            winsound.Beep(300, 500)
        self.update_progress_complete("Loading snapshot to Overview")

    ###########################################################################
    #                        Snapshot Insert Helpers                           #
    ###########################################################################

    def insert_transfer_object_with_children(self, parent, obj):
        """
        Insert an object into the Transfer TreeView under the given parent.
        Recursively handle child_resources.
        """
        label = get_label_for_object(obj)
        node = self.transfer_tree.insert(parent, "end", text=label, values=("No",), open=True)
        self.transfer_manager.transfer_mapping[node] = obj

        if isinstance(obj, dict) and "child_resources" in obj:
            child_dict = obj["child_resources"]
            if isinstance(child_dict, dict):
                for child_key, child_list in child_dict.items():
                    child_parent = self.transfer_tree.insert(node, "end", text=child_key, values=("No",), open=True)
                    self.transfer_manager.transfer_mapping[child_parent] = None
                    if isinstance(child_list, list):
                        for child_obj in child_list:
                            self.insert_transfer_object_with_children(child_parent, child_obj)
        return node

    def insert_object_with_children(self, parent, obj):
        """
        Insert a single object into the Overview TreeView. Recursively handle child_resources.
        """
        label = get_label_for_object(obj)
        node = self.overview_tree.insert(parent, "end", text=label, open=False)
        self.overview_manager.overview_mapping[node] = obj

        if isinstance(obj, dict) and "child_resources" in obj:
            child_dict = obj["child_resources"]
            if isinstance(child_dict, dict):
                for child_key, child_list in child_dict.items():
                    child_parent = self.overview_tree.insert(node, "end", text=child_key, open=True)
                    self.overview_manager.overview_mapping[child_parent] = None
                    if isinstance(child_list, list):
                        for child_obj in child_list:
                            self.insert_object_with_children(child_parent, child_obj)
        return node

    ###########################################################################
    #                        Overview / Database Logic                         #
    ###########################################################################


    def retrieve_overview(self):
        """
        Fetch a wide range of objects from the tenant and populate both the
        self.overview_manager.overview_data dictionary and the TreeView.
        Also automatically saves a snapshot.
        """
        # Removed relative import; now use the global api_get defined above:
        # from . import api_get  --> REMOVED

        self.update_progress_start("Retrieving tenant overview")
        self.overview_manager.overview_mapping.clear()
        self.overview_manager.overview_data.clear()
        for item in self.overview_tree.get_children():
            self.overview_tree.delete(item)
        okta_url = normalize_url(self.okta_url_entry.get().strip())
        api_key = self.api_key_entry.get().strip()
        if not okta_url or not api_key:
            self.log_console("Okta URL and API Key are required!")
            self.update_progress_complete("Retrieving tenant overview")
            return
        # ...existing code for retrieval...
        self.log_console("Tenant overview retrieval complete.")
        self.update_progress_complete("Retrieving tenant overview")

    def save_overview_to_file(self):
        if not self.overview_manager.overview_data:
            messagebox.showinfo("No Data", "No overview data available. Please retrieve overview first.")
            return
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json", filetypes=[("JSON Files", "*.json")]
        )
        if file_path:
            try:
                with open(file_path, "w") as f:
                    json.dump(self.overview_manager.overview_data, f, indent=2)
                messagebox.showinfo("Saved", f"Overview data saved to {file_path}")
            except Exception as e:
                tb_dialogs.ShowMessage(title="Error", message=f"Failed to save overview: {e}", bootstyle="danger")
                winsound.Beep(300, 500)

    def delete_selected_overview_objects(self):
        selected_items = self.overview_tree.selection()
        if not selected_items:
            self.log_console("No tenant object selected for deletion.")
            return
        for item in list(selected_items):
            item_text = self.overview_tree.item(item, "text")
            self.overview_tree.delete(item)
            if item in self.overview_manager.overview_mapping:
                del self.overview_manager.overview_mapping[item]
            self.log_console(f"Deleted object (local only): {item_text}")

    def delete_object_from_target(self):
        self.update_progress_start("Deleting object from target")
        selection = self.overview_tree.selection()
        if not selection:
            self.log_console("No object selected for deletion from target tenant.")
            self.update_progress_complete("Deleting object from target")
            return

        item_id = selection[0]
        obj_data = self.overview_manager.overview_mapping.get(item_id)
        if not obj_data or not isinstance(obj_data, dict):
            self.log_console("Could not find valid object data to delete.")
            self.update_progress_complete("Deleting object from target")
            return

        okta_url = normalize_url(self.okta_url_entry.get().strip())
        api_key = self.api_key_entry.get().strip()
        if not okta_url or not api_key:
            self.log_console("Okta URL or API key is missing.")
            self.update_progress_complete("Deleting object from target")
            return

        headers = {"Authorization": f"SSWS {api_key}", "Accept": "application/json"}
        resource_id = obj_data.get("id")
        endpoint = obj_data.get("_delete_endpoint")
        if not resource_id or not endpoint:
            self.log_console("Missing resource id or delete endpoint in object data.")
            self.update_progress_complete("Deleting object from target")
            return

        delete_url = f"{okta_url}{endpoint}/{resource_id}"
        try:
            response = requests.delete(delete_url, headers=headers, timeout=10)
            if response.ok:
                self.overview_tree.delete(item_id)
                self.log_console(f"Object deleted successfully from target: {delete_url}")
            else:
                self.log_console(f"Failed to delete object: {response.status_code} - {response.text}")
        except requests.exceptions.RequestException as e:
            self.log_console(f"Error occurred: {str(e)}")
            winsound.Beep(300, 500)
        self.update_progress_complete("Deleting object from target")

    def reset_user_password(self):
        selection = self.overview_tree.selection()
        if not selection:
            self.log_console("No user selected.")
            return
        item_id = selection[0]
        obj = self.overview_manager.overview_mapping.get(item_id, {})
        user_id = obj.get("id")
        if not user_id:
            self.log_console("Selected item is not a valid user.")
            return
        okta_url = normalize_url(self.okta_url_entry.get().strip())
        api_key = self.api_key_entry.get().strip()
        headers = {"Authorization": f"SSWS {api_key}", "Accept": "application/json"}
        self.disable_action_buttons(True)
        try:
            expire_url = f"{okta_url}/api/v1/users/{user_id}/lifecycle/expire_password?tempPassword=true"
            response = requests.post(expire_url, headers=headers)
            if response.ok:
                temp_data = response.json()
                temp_pass = temp_data.get("tempPassword", "N/A")
                self.log_console(f"Temporary password: {temp_pass}")
            else:
                self.log_console(f"Failed to expire password. Status: {response.status_code}")
        except requests.exceptions.RequestException as e:
            self.log_console(f"Error resetting password: {e}")
        finally:
            self.disable_action_buttons(False)

    ###########################################################################
    #                           LIVE EVENTS LOGIC                              #
    ###########################################################################

    def retrieve_live_events(self):
        self.update_progress_start("Retrieving live events")
        # Basic logic to fetch logs from /api/v1/logs
        # Adjust as needed
        okta_url = normalize_url(self.okta_url_entry.get().strip())
        api_key = self.api_key_entry.get().strip()
        if not okta_url or not api_key:
            self.log_console("Okta URL and API Key are required!")
            self.update_progress_complete("Retrieving live events")
            return

        headers = {"Authorization": f"SSWS {api_key}", "Accept": "application/json"}
        params = {}
        if self.last_log_timestamp:
            params["since"] = self.last_log_timestamp
        url = f"{okta_url}/api/v1/logs"

        # Clear existing
        for item in self.live_tree.get_children():
            self.live_tree.delete(item)

        try:
            response = requests.get(url, headers=headers, params=params, timeout=10)
            if response.ok:
                data = response.json()
                for event in data:
                    event_id = event.get("uuid", "N/A")
                    event_type = event.get("eventType", "N/A")
                    published = event.get("published", "N/A")
                    actor = event.get("actor", {}).get("displayName", "N/A")
                    item_id = self.live_tree.insert(
                        "", "end", text=event_id, values=(event_type, published, actor)
                    )
                    # store the entire event object if needed
                if data:
                    self.last_log_timestamp = data[-1].get("published")
                self.log_console("Live events updated.")
            else:
                self.log_console(f"Failed to retrieve live events: {response.status_code}")
                winsound.Beep(300, 500)
        except requests.exceptions.RequestException as e:
            self.log_console(f"Error retrieving live events: {e}")
            winsound.Beep(300, 500)

        self.update_progress_complete("Retrieving live events")

    def on_live_tree_select(self, event):
        selected = self.live_tree.selection()
        if selected:
            # For demonstration: you could store the event in a mapping if you like
            # self.live_mapping... but in this example we'll skip
            pass

    ###########################################################################
    #                          TRANSFER OBJECTS LOGIC                          #
    ###########################################################################

    def load_saved_objects(self):
        self.update_progress_start("Loading saved objects")
        file_path = filedialog.askopenfilename(filetypes=[("JSON Files", "*.json")])
        if not file_path:
            self.update_progress_complete("Loading saved objects")
            return
        try:
            with open(file_path, "r") as f:
                data = json.load(f)
            self.transfer_manager.transfer_data = data
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load saved objects: {e}")
            winsound.Beep(300, 500)
            self.update_progress_complete("Loading saved objects")
            return

        for item in self.transfer_tree.get_children():
            self.transfer_tree.delete(item)
        self.transfer_manager.transfer_mapping.clear()

        for cat, objs in self.transfer_manager.transfer_data.items():
            parent_id = self.transfer_tree.insert("", "end", text=cat, values=("No",), open=True)
            self.transfer_manager.transfer_mapping[parent_id] = None
            if isinstance(objs, list):
                for obj in objs:
                    label = get_label_for_object(obj)
                    child_id = self.transfer_tree.insert(parent_id, "end", text=label, values=("No",), open=True)
                    self.transfer_manager.transfer_mapping[child_id] = obj

        messagebox.showinfo("Loaded", "Saved objects loaded successfully.")
        self.search_entry.config(state=tk.NORMAL)
        self.update_progress_complete("Loading saved objects")

    def search_objects(self):
        search_term = self.search_entry.get().lower()
        for item in self.transfer_tree.get_children():
            self.transfer_tree.delete(item)
        # Re-insert based on filter
        for cat, objects in self.transfer_manager.transfer_data.items():
            parent_id = self.transfer_tree.insert("", "end", text=cat, values=("No",), open=True)
            self.transfer_manager.transfer_mapping[parent_id] = None
            if isinstance(objects, list):
                for obj in objects:
                    label = get_label_for_object(obj)
                    if search_term in label.lower():
                        child_id = self.transfer_tree.insert(parent_id, "end", text=label, values=("No",), open=True)
                        self.transfer_manager.transfer_mapping[child_id] = obj
                        self.transfer_tree.selection_set(child_id)
                        self.transfer_tree.see(child_id)

    def toggle_transfer_selection(self, event):
        item_id = self.transfer_tree.focus()
        if not item_id:
            return
        children = self.transfer_tree.get_children(item_id)
        current = self.transfer_tree.item(item_id, "values")
        new_val = "Yes" if (current and current[0] == "No") else "No"
        self.transfer_tree.item(item_id, values=(new_val,))
        for child in children:
            self.transfer_tree.item(child, values=(new_val,))

    def on_transfer_tree_select(self, event):
        selected_items = self.transfer_tree.selection()
        self.log_console(f"Transfer tree selection changed. Selected: {selected_items}")

    def load_target_credential(self):
        selection = self.credentials_listbox.curselection()
        if not selection:
            messagebox.showinfo("Info", "Please select a credential from Stored Credentials.")
            return
        index = selection[0]
        cred = self.cred_manager.credentials[index]
        self.target_url_entry.delete(0, tk.END)
        self.target_url_entry.insert(0, cred["okta_url"])
        self.target_api_key_entry.delete(0, tk.END)
        self.target_api_key_entry.insert(0, cred["api_key"])

    def transfer_objects(self):
        self.update_progress_start("Transferring objects")
        self.transfer_manager.reset_transfer_cancelled()

        target_url = normalize_url(self.target_url_entry.get().strip())
        target_api_key = self.target_api_key_entry.get().strip()

        if not target_url or not target_api_key:
            messagebox.showerror("Error", "Target tenant credentials are required.")
            self.update_progress_complete("Transferring objects")
            return

        if not validate_okta_url(target_url):
            messagebox.showerror("Error", "Invalid target Okta URL.")
            self.update_progress_complete("Transferring objects")
            return

        headers = {
            "Authorization": f"SSWS {target_api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

        selected_item_ids = self.transfer_manager.get_all_selected_items(self.transfer_tree)
        total_items = len(selected_item_ids)
        self.global_progress_bar['maximum'] = total_items if total_items > 0 else 1
        self.global_meter.configure(amounttotal=total_items if total_items > 0 else 1)
        self.global_progress_bar['value'] = 0
        self.global_meter.configure(amountused=0)
        self.global_progress_label['text'] = "Transferring selected objects..."

        self.log_console("Starting transfer of selected objects...")

        transferred = 0
        errors = 0
        processed = 0

        for item_id in selected_item_ids:
            if self.transfer_manager.transfer_cancelled:
                self.log_console("Transfer cancelled by user.")
                messagebox.showinfo("Cancelled", "Transfer cancelled.")
                self.update_progress_complete("Transferring objects")
                return

            obj = self.transfer_manager.transfer_mapping.get(item_id)
            if not obj:
                continue

            # Determine category from parent's text
            parent_id = self.transfer_tree.parent(item_id)
            category = self.transfer_tree.item(parent_id, "text").lower()

            if "user" in category:
                cat_key = "okta_users"
            elif "group" in category:
                cat_key = "okta_groups"
            elif "app" in category:
                cat_key = "okta_applications"
            else:
                cat_key = category

            endpoint_suffix = self.transfer_manager.transfer_endpoint_map.get(cat_key)
            if not endpoint_suffix:
                self.log_console(f"Skipping object {get_label_for_object(obj)}: no endpoint for category {cat_key}.")
                continue

            full_endpoint = f"{target_url}{endpoint_suffix}"
            clean_obj = self.transfer_manager.get_cleaned_payload(obj, cat_key)
            payload = json.dumps(clean_obj)
            self.log_console(f"Transferring object: {get_label_for_object(obj)}\nEndpoint: {full_endpoint}\nPayload: {payload}")

            try:
                retries = 0
                max_retries = 3
                wait_time = 1

                while retries < max_retries:
                    resp = requests.post(full_endpoint, headers=headers, data=payload, timeout=10)
                    if resp.status_code == 429:
                        retry_after = resp.headers.get("Retry-After", wait_time)
                        sleep_time = int(retry_after) if str(retry_after).isdigit() else wait_time
                        self.log_console(f"Rate limited. Waiting {sleep_time} seconds before retry...")
                        time.sleep(sleep_time)
                        wait_time *= 2
                        retries += 1
                    else:
                        break

                if resp.ok:
                    transferred += 1
                    self.log_console(f"Transfer succeeded for {get_label_for_object(obj)}")
                else:
                    errors += 1
                    self.log_console(f"Transfer failed for {get_label_for_object(obj)}: {resp.status_code} - {resp.text}")
            except Exception as e:
                errors += 1
                self.log_console(f"Exception during transfer for {get_label_for_object(obj)}: {e}")
                winsound.Beep(300, 500)

            processed += 1
            self.smooth_progress_update(processed)

        messagebox.showinfo("Transfer Complete", f"Transferred: {transferred} objects. Errors: {errors}")
        self.global_progress_bar['value'] = 0
        self.global_meter.configure(amountused=0)
        self.global_progress_label["text"] = "Ready."
        self.update_progress_complete("Transferring objects")

    def cancel_transfer(self):
        self.transfer_manager.cancel_transfer()
        self.log_console("Transfer cancellation requested.")

    ###########################################################################
    #                         CREATE OBJECT LOGIC                              #
    ###########################################################################

    def load_selected_credential_to_creation(self, url_entry, api_key_entry):
        try:
            selection = self.credentials_listbox.curselection()
            if not selection:
                self.log_console("Please select a credential to load.")
                return
            index = selection[0]
            cred = self.cred_manager.credentials[index]

            url_entry.delete(0, tk.END)
            url_entry.insert(0, cred["okta_url"])
            api_key_entry.delete(0, tk.END)
            api_key_entry.insert(0, cred["api_key"])

            self.log_console("Credential loaded into Object Creation tab.")
        except Exception as e:
            self.log_console(f"Error loading credential into Object Creation tab: {e}")
            winsound.Beep(300, 500)

    def load_sample_body(self):
        obj_type = self.creation_type_combo.get()
        sample = SAMPLE_BODIES.get(obj_type, "")
        self.creation_body_text.configure(state="normal")
        self.creation_body_text.delete("1.0", tk.END)
        self.creation_body_text.insert(tk.END, sample)
        self.creation_body_text.configure(state="normal")

    def run_create_object_thread(self):
        thread = threading.Thread(target=self.create_custom_object, daemon=True)
        thread.start()

    def create_custom_object(self):
        self.update_progress_start("Creating custom object")
        self.disable_action_buttons(True)
        try:
            obj_type = self.creation_type_combo.get()
            endpoint_suffix = OBJECT_ENDPOINTS.get(obj_type)
            if not endpoint_suffix:
                self.log_console(f"No endpoint defined for object type: {obj_type}")
                return

            target_url = normalize_url(self.target_url_entry2.get().strip())
            target_api_key = self.target_api_key_entry2.get().strip()
            if not target_url or not target_api_key:
                messagebox.showerror("Error", "Target tenant credentials are required.")
                return
            if not validate_okta_url(target_url):
                messagebox.showerror("Error", "Invalid target Okta URL.")
                return

            body_text = self.creation_body_text.get("1.0", tk.END).strip()
            if not body_text:
                self.log_console("No JSON body provided.")
                return

            try:
                body_json = json.loads(body_text)
            except Exception as e:
                self.log_console(f"Invalid JSON: {e}")
                return

            full_url = f"{target_url}{endpoint_suffix}"
            headers = {
                "Authorization": f"SSWS {target_api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json"
            }

            self.log_console(f"Creating {obj_type} at endpoint: {full_url}")
            resp = requests.post(full_url, headers=headers, data=json.dumps(body_json), timeout=10)
            formatted = format_json_response(resp.text)
            if resp.ok:
                self.log_console(f"Creation Success ({resp.status_code}):\n{formatted}")
            else:
                self.log_console(
                    f"Creation Failed ({resp.status_code}):\n"
                    f"Endpoint: {full_url}\nBody: {body_text}\nResponse: {formatted}"
                )
        except Exception as ex:
            self.log_console(f"Error creating object: {ex}")
            winsound.Beep(300, 500)
        finally:
            self.disable_action_buttons(False)
        self.update_progress_complete("Creating custom object")

    ###########################################################################
    #                        RANDOM OBJECT CREATION LOGIC                      #
    ###########################################################################

    def create_random_user(self):
        self.update_progress_start("Creating random user")
        okta_url = normalize_url(self.okta_url_entry.get().strip())
        api_key = self.api_key_entry.get().strip()
        if not okta_url or not api_key:
            self.log_console("Okta URL and API Key are required!")
            self.update_progress_complete("Creating random user")
            return

        random_str = generate_random_string()
        user_name = f"TestUser_{random_str}"
        user_data = {
            "profile": {
                "firstName": "Test",
                "lastName": user_name,
                "email": f"{user_name.lower()}@example.com",
                "login": f"{user_name.lower()}@example.com"
            },
            "credentials": {
                "password": {"value": "TempP@ssw0rd!"}
            }
        }
        headers = {
            "Authorization": f"SSWS {api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        url = f"{okta_url}/api/v1/users?activate=true"
        try:
            self.log_console("Creating random user...")
            response = requests.post(url, headers=headers, data=json.dumps(user_data), timeout=10)
            formatted = format_json_response(response.text)
            if response.ok:
                self.log_console(f"User Creation Success ({response.status_code}):\n{formatted}")
            else:
                self.log_console(
                    f"User Creation Failed ({response.status_code}):\n"
                    f"Endpoint: {url}\nPayload: {json.dumps(user_data)}\nResponse: {formatted}"
                )
        except requests.exceptions.RequestException as e:
            self.log_console(f"Error creating user: {e}")
            winsound.Beep(300, 500)
        self.update_progress_complete("Creating random user")

    def create_random_group(self):
        self.update_progress_start("Creating random group")
        okta_url = normalize_url(self.okta_url_entry.get().strip())
        api_key = self.api_key_entry.get().strip()
        if not okta_url or not api_key:
            self.log_console("Okta URL and API Key are required!")
            self.update_progress_complete("Creating random group")
            return

        random_str = generate_random_string()
        group_name = f"TestGroup_{random_str}"
        group_data = {
            "profile": {
                "name": group_name,
                "description": f"A test group created with ID {random_str}"
            }
        }
        headers = {
            "Authorization": f"SSWS {api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        url = f"{okta_url}/api/v1/groups"
        try:
            self.log_console("Creating random group...")
            response = requests.post(url, headers=headers, data=json.dumps(group_data), timeout=10)
            formatted = format_json_response(response.text)
            if response.ok:
                self.log_console(f"Group Creation Success ({response.status_code}):\n{formatted}")
            else:
                self.log_console(
                    f"Group Creation Failed ({response.status_code}):\n"
                    f"Endpoint: {url}\nPayload: {json.dumps(group_data)}\nResponse: {formatted}"
                )
        except requests.exceptions.RequestException as e:
            self.log_console(f"Error creating group: {e}")
            winsound.Beep(300, 500)
        self.update_progress_complete("Creating random group")

    def create_random_app(self):
        self.update_progress_start("Creating random app")
        okta_url = normalize_url(self.okta_url_entry.get().strip())
        api_key = self.api_key_entry.get().strip()
        if not okta_url or not api_key:
            self.log_console("Okta URL and API Key are required!")
            self.update_progress_complete("Creating random app")
            return

        random_str = generate_random_string()
        app_name = f"TestApp_{random_str}"
        app_data = {
            "name": "oidc_client",
            "label": app_name,
            "signOnMode": "OPENID_CONNECT",
            "credentials": {
                "oauthClient": {
                    "autoKeyRotation": True,
                    "token_endpoint_auth_method": "client_secret_post"
                }
            },
            "settings": {
                "oauthClient": {
                    "client_uri": "https://example.com",
                    "logo_uri": "https://example.com/logo.png",
                    "redirect_uris": ["https://example.com/redirect"],
                    "response_types": ["code"],
                    "grant_types": ["authorization_code"]
                }
            }
        }
        headers = {
            "Authorization": f"SSWS {api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        url = f"{okta_url}/api/v1/apps"
        try:
            self.log_console("Creating random application...")
            response = requests.post(url, headers=headers, data=json.dumps(app_data), timeout=10)
            formatted = format_json_response(response.text)
            if response.ok:
                self.log_console(f"Application Creation Success ({response.status_code}):\n{formatted}")
            else:
                self.log_console(
                    f"Application Creation Failed ({response.status_code}):\n"
                    f"Endpoint: {url}\nPayload: {json.dumps(app_data)}\nResponse: {formatted}"
                )
        except requests.exceptions.RequestException as e:
            self.log_console(f"Error creating application: {e}")
            winsound.Beep(300, 500)
        self.update_progress_complete("Creating random app")

    def create_super_admin(self):
        self.update_progress_start("Creating Super Admin")
        okta_url = normalize_url(self.okta_url_entry.get().strip())
        api_key = self.api_key_entry.get().strip()
        if not okta_url or not api_key:
            self.log_console("Okta URL and API Key are required!")
            self.update_progress_complete("Creating Super Admin")
            return

        first_name = self.super_admin_first_entry.get().strip()
        last_name = self.super_admin_last_entry.get().strip()
        email = self.super_admin_email_entry.get().strip()
        login = self.super_admin_login_entry.get().strip()
        if not (first_name and last_name and email and login):
            self.log_console("All super admin fields must be provided!")
            self.update_progress_complete("Creating Super Admin")
            return

        user_data = {
            "profile": {
                "firstName": first_name,
                "lastName": last_name,
                "email": email,
                "login": login
            },
            "credentials": {
                "password": {"value": "SuperSecret@123"}
            }
        }
        headers = {
            "Authorization": f"SSWS {api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        url = f"{okta_url}/api/v1/users?activate=true"

        try:
            self.log_console("Creating super admin user...")
            response = requests.post(url, headers=headers, json=user_data)
            formatted = format_json_response(response.text)

            if response.ok:
                user_data_response = response.json()
                user_id = user_data_response.get("id")
                self.log_console(f"Super Admin Creation Success ({response.status_code}):\n{formatted}")
                if user_id:
                    role_url = f"{okta_url}/api/v1/users/{user_id}/roles"
                    role_data = {"type": "SUPER_ADMIN"}
                    role_resp = requests.post(role_url, headers=headers, data=json.dumps(role_data), timeout=10)
                    formatted_role = format_json_response(role_resp.text)
                    if role_resp.ok:
                        self.log_console(f"Super Admin Role Assigned ({role_resp.status_code}):\n{formatted_role}")
                    else:
                        self.log_console(
                            f"Failed to assign Super Admin Role ({role_resp.status_code}):\n"
                            f"Endpoint: {role_url}\nPayload: {json.dumps(role_data)}\nResponse: {formatted_role}"
                        )
            else:
                self.log_console(
                    f"Super Admin Creation Failed ({response.status_code}):\n"
                    f"Endpoint: {url}\nPayload: {json.dumps(user_data)}\nResponse: {formatted}"
                )
        except requests.exceptions.RequestException as e:
            self.log_console(f"Error creating super admin: {e}")
            winsound.Beep(300, 500)
        self.update_progress_complete("Creating Super Admin")

    def create_accsense_test_users(self):
        self.disable_action_buttons(True)
        self.update_progress_start("Generating Accsense Test Users")
        okta_url = normalize_url(self.okta_url_entry.get().strip())
        api_key = self.api_key_entry.get().strip()
        if not okta_url or not api_key:
            self.log_console("Okta URL and API Key are required!")
            self.disable_action_buttons(False)
            self.update_progress_complete("Generating Accsense Test Users")
            return

        roles = [("ADMIN", "Acsense Admin"), ("OPERATOR", "Acsense Operator"), ("VIEWER", "Acsense Viewer")]
        group_ids = {}

        # Try fetching groups
        try:
            headers = {
                "Authorization": f"SSWS {api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json"
            }
            resp = requests.get(f"{okta_url}/api/v1/groups", headers=headers)
            if resp.ok:
                groups = resp.json()
                for group in groups:
                    for role_name, group_name in roles:
                        if group["profile"]["name"] == group_name:
                            group_ids[group_name] = group["id"]
            else:
                self.log_console(f"Failed to fetch groups: {resp.status_code} - {resp.text}")
                self.disable_action_buttons(False)
                self.update_progress_complete("Generating Accsense Test Users")
                return
        except Exception as e:
            self.log_console(f"Error fetching groups: {e}")
            self.disable_action_buttons(False)
            self.update_progress_complete("Generating Accsense Test Users")
            return

        for role_name, group_name in roles:
            max_attempts = 5
            attempt = 0
            res = None
            while attempt < max_attempts:
                attempt += 1
                random_id = ''.join(random.choices(string.digits, k=4))
                first_name = role_name
                last_name = f"User ID({random_id})"

                user_data = {
                    "profile": {
                        "firstName": first_name,
                        "lastName": last_name,
                        "email": f"{first_name.lower()}.{random_id}@example.com",
                        "login": f"{first_name.lower()}.{random_id}@example.com"
                    },
                    "credentials": {
                        "password": {"value": "TempP@ssw0rd!"}
                    }
                }

                # Check for existing user
                params = {"search": f"profile.lastName eq \"{last_name}\""}
                try:
                    check_resp = requests.get(f"{okta_url}/api/v1/users", headers=headers, params=params)
                    if check_resp.status_code == 200 and check_resp.json():
                        self.log_console(f"Found existing user with last name '{last_name}' - retrying...")
                        continue
                except requests.exceptions.RequestException:
                    self.log_console("Error checking existing users.")
                    return

                # Create user
                create_url = f"{okta_url}/api/v1/users?activate=true"
                try:
                    res = requests.post(create_url, headers=headers, data=json.dumps(user_data))
                    if res.status_code < 300:
                        self.log_console(f"Accsense Test User created: {first_name} {last_name}")
                        break
                    else:
                        self.log_console(f"Error creating user: {res.text}")
                except requests.exceptions.RequestException as e:
                    self.log_console(f"Error creating user request: {e}")
            else:
                self.log_console("Max attempts reached. Could not create unique Accsense test user.")
                continue

            if res and res.status_code < 300:
                user = res.json()
                self.log_console(f"Created user {role_name} with login {user['profile']['login']}. Checking group '{group_name}'...")
                group_id = group_ids.get(group_name)
                if group_id:
                    assign_response = requests.put(f"{okta_url}/api/v1/groups/{group_id}/users/{user['id']}", headers=headers)
                    if assign_response.ok:
                        self.log_console(f"Assigned user {role_name} to group '{group_name}'.")
                    else:
                        self.log_console(
                            f"Failed to assign user {role_name} to group '{group_name}': "
                            f"{assign_response.status_code} - {assign_response.text}"
                        )
                else:
                    self.log_console(f"Group '{group_name}' not found.")

        self.disable_action_buttons(False)
        self.update_progress_complete("Generating Accsense Test Users")

    ###########################################################################
    #                            EVENT HANDLERS                               #
    ###########################################################################

    def on_overview_tree_select(self, event):
        selected = self.overview_tree.selection()
        if selected:
            item_id = selected[0]
            obj = self.overview_manager.overview_mapping.get(item_id)
            self.details_text.configure(state="normal")
            self.details_text.delete("1.0", tk.END)
            if obj is not None:
                self.details_text.insert(tk.END, json.dumps(obj, indent=2))
            else:
                self.details_text.insert(tk.END, f"No detailed data for: {self.overview_tree.item(item_id)['text']}")
            self.details_text.configure(state="disabled")


###############################################################################
#                           MAIN ENTRY POINT                                  #
###############################################################################

def main():
    app = OktaAPIToolApp()
    app.root.mainloop()

if __name__ == "__main__":
    main()
