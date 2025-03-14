#Beta Version#
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

# ------------------ Global Constants and Variables ------------------ #
CREDENTIALS_FILE = "credentials.json"
MAX_CREDENTIALS = 10

credentials = []        # Stored Okta credentials
overview_data = {}      # Data retrieved from tenant overview
overview_mapping = {}   # Maps tree item IDs in Overview tab to full JSON objects
live_mapping = {}       # Maps tree item IDs in Live Events tab to full JSON objects
transfer_data = {}      # Loaded saved objects for transfer
transfer_mapping = {}   # Maps tree item IDs in Transfer tab to full JSON objects

last_log_timestamp = None   # For live events
transfer_cancelled = False  # Kill switch flag for transfer
action_buttons = []         # Global list of buttons

# Mapping from category name to creation endpoint (for Transfer)
transfer_endpoint_map = {
    "okta_users": "/api/v1/users?activate=true",
    "okta_groups": "/api/v1/groups",
    "okta_applications": "/api/v1/apps",
    "okta_authz_policies": "/api/v1/authorizationServers/default/policies",
    "okta_global_policies": "/api/v1/policies",  # We'll use query param type=OKTA_SIGN_ON
    "okta_idps": "/api/v1/idps",
    "okta_roles": "/api/v1/roles",
    "okta_mappings": "/api/v1/mappings"
}

snapshot_dir = "snapshots"  # Global snapshot directory


# ------------------ Helper Functions ------------------ #
def reset_global_progress():
    global_progress_bar['value'] = 0
    global_progress_label['text'] = "Ready."

# Add a global variable to track the current theme state for toggling
is_light = True

def toggle_theme():
    global is_light
    # Toggle between two themes; for example "flatly" (light) and "darkly" (dark)
    new_theme = "darkly" if is_light else "flatly"
    style.theme_use(new_theme)
    is_light = not is_light
    log_console(f"Theme toggled to {new_theme}")

# Smoother progress update helper using after
def smooth_progress_update(target, duration=500):
    pass

# Override update_progress_start and update_progress_complete to use smooth updating
def update_progress_start(action):
    global_progress_label['text'] = f"Starting {action}..."
    smooth_progress_update(0)
    global_progress_bar['maximum'] = 100

def update_progress_complete(action):
    smooth_progress_update(100)
    global_progress_label['text'] = f"{action} complete."
    root.update_idletasks()
    reset_global_progress()
    winsound.Beep(600, 200)

def load_credentials_from_file():
    update_progress_start("Loading credentials")
    if os.path.exists(CREDENTIALS_FILE):
        try:
            with open(CREDENTIALS_FILE, 'r', encoding='utf-8') as f:
                credentials_data = json.load(f)
            credentials.clear()
            credentials.extend(credentials_data)
            log_console("Credentials loaded successfully.")
        except Exception as e:
            log_console(f"Error loading credentials: {e}")
            winsound.Beep(300, 500)  # Beep on error
    else:
        credentials.clear()
        log_console("Credentials file not found. Starting with an empty list.")
    update_progress_complete("Loading credentials")

def save_credentials_to_file():
    update_progress_start("Saving credentials")
    try:
        with open(CREDENTIALS_FILE, 'w', encoding='utf-8') as f:
            json.dump(credentials, f, indent=2)
        log_console("Credentials saved successfully.")
    except Exception as e:
        log_console(f"Error saving credentials: {e}")
        winsound.Beep(300, 500)  # Beep on error
    update_progress_complete("Saving credentials")

def normalize_url(url):
    """Remove trailing slashes from a URL."""
    return url.rstrip('/')


def validate_okta_url(url):
    """Check if the URL starts with http:// or https://."""
    return url.startswith("http://") or url.startswith("https://")


def generate_random_string(length=6):
    """Generate a random string of the specified length (default 6)."""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))


def format_json_response(text):
    """Pretty-print JSON response text if valid, otherwise return as-is."""
    try:
        parsed = json.loads(text)
        return json.dumps(parsed, indent=2)
    except Exception:
        return text


def log_console(text):
    """Log messages to the console text widget with timestamps."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    console_text.configure(state='normal')
    console_text.insert(tk.END, f"[{timestamp}] {text}\n")
    console_text.configure(state='disabled')
    console_text.see(tk.END)


def clear_console():
    """Clear the console text widget."""
    console_text.configure(state='normal')
    console_text.delete(1.0, tk.END)
    console_text.configure(state='disabled')


def disable_action_buttons(disable=True):
    """Enable or disable all action buttons."""
    state = tk.DISABLED if disable else tk.NORMAL
    for btn in action_buttons:
        try:
            btn.config(state=state)
        except Exception:
            pass


def api_get(url, headers, params=None, max_retries=5, initial_wait=1):
    """
    Wrapper for GET requests that handles rate-limit (429) responses.
    Retries up to `max_retries` times, doubling wait time upon 429.
    """
    retries = 0
    wait_time = initial_wait
    response = None

    while retries < max_retries:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After")
            sleep_time = int(retry_after) if (retry_after and retry_after.isdigit()) else wait_time
            log_console(
                f"Rate limited for URL: {url} with params: {params}. "
                f"Waiting for {sleep_time} seconds... (Retry {retries + 1}/{max_retries})"
            )
            time.sleep(sleep_time)
            wait_time *= 2
            retries += 1
        else:
            return response

    # After max retries, log and return the last response
    if response:
        log_console(
            f"Max retries reached for URL: {url} with params: {params}. "
            f"Final status: {response.status_code} - {response.text}"
        )
    return response


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


def clean_object(obj):
    """
    Remove fields like 'id', 'created', '_links', etc. from an Okta object
    to make it suitable for re-creation.
    """
    if not isinstance(obj, dict):
        return obj
    cleaned = obj.copy()
    for field in [
        "id", "created", "activated", "statusChanged", "lastLogin", "lastUpdated",
        "passwordChanged", "_links"
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


snapshot_files = []  # Holds snapshot file paths for reference

def init_snapshots():
    """
    Initialize the snapshots listbox by loading all 'snapshot_*.json' files
    from the 'snapshots' directory. Displays their timestamp and associated tenant.
    """
    if not os.path.exists(snapshot_dir):
        os.makedirs(snapshot_dir)
    snapshots = sorted(
        glob.glob(os.path.join(snapshot_dir, "snapshot_*.json")),
        key=os.path.getmtime,
        reverse=True
    )

    snapshot_listbox.delete(0, tk.END)
    snapshot_files.clear()

    for file in snapshots:
        try:
            with open(file, "r") as f:
                data = json.load(f)
            tenant_url = data.get("tenant_url", "UnknownTenant")
            timestamp = data.get("timestamp", "UnknownTime")
            snapshot_listbox.insert(tk.END, f"{tenant_url} - {timestamp}")
            snapshot_files.append(file)
        except Exception as e:
            log_console(f"Error loading snapshot file {file}: {str(e)}")
            winsound.Beep(300, 500)  # Beep on error

def delete_selected_snapshot():
    selection = snapshot_listbox.curselection()
    if not selection:
        return
    index = selection[0]
    file_to_delete = snapshot_files[index]
    try:
        os.remove(file_to_delete)
        log_console(f"Snapshot deleted: {file_to_delete}")
    except OSError as e:
        log_console(f"Failed to delete snapshot: {str(e)}")
        winsound.Beep(300, 500)  # Beep on error
    init_snapshots()

def save_snapshot(tenant_url, data):
    """
    Save the retrieved overview data (or anything else) as a JSON snapshot
    in the 'snapshots' directory.
    """
    now = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(snapshot_dir, f"snapshot_{now}.json")
    snapshot = {"tenant_url": tenant_url, "timestamp": now, "data": data}

    try:
        with open(filename, "w") as f:
            json.dump(snapshot, f, indent=2)
        log_console(f"Snapshot saved: {filename}")
    except Exception as e:
        log_console(f"Error saving snapshot: {e}")
        winsound.Beep(300, 500)  # Beep on error

    init_snapshots()


def load_selected_snapshot_to_transfer():
    update_progress_start("Loading snapshot to Transfer")
    log_console("Attempting to load snapshot into Transfer Objects...")
    try:
        selection = snapshot_listbox.curselection()
        if not selection:
            log_console("No snapshot selected.")
            return
        filename = snapshot_files[selection[0]]
        snapshot_path = filename  # Use the full path from snapshot_files
        if not os.path.exists(snapshot_path):
            log_console(f"Snapshot file not found: {snapshot_path}")
            return
        transfer_data.clear()
        for item in transfer_tree.get_children():
            transfer_tree.delete(item)
        with open(snapshot_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        transfer_data.update(data.get("data", {}))
        root_node = transfer_tree.insert("", "end", text="Loaded Snapshot Transfer", open=True)
        transfer_mapping[root_node] = None

        def insert_items(parent, items):
            if isinstance(items, list):
                for obj in items:
                    label = get_label_for_object(obj)
                    child_node = transfer_tree.insert(parent, "end", text=label, open=True)
                    transfer_mapping[child_node] = obj
            elif isinstance(items, dict):
                for key, value in items.items():
                    sub_parent = transfer_tree.insert(parent, "end", text=key, open=True)
                    transfer_mapping[sub_parent] = None
                    insert_items(sub_parent, value)

        for section_name, items in transfer_data.items():
            section_node = transfer_tree.insert(root_node, "end", text=section_name, open=True)
            transfer_mapping[section_node] = None
            insert_items(section_node, items)

        log_console("Snapshot successfully loaded to Transfer Objects.")
        winsound.Beep(700, 200)  # Beep on objects loaded
    except Exception as e:
        log_console(f"Error loading snapshot to Transfer Objects tab: {e}")
        winsound.Beep(300, 500)  # Beep on error
    update_progress_complete("Loading snapshot to Transfer")


def load_selected_snapshot_to_overview():
    update_progress_start("Loading snapshot to Overview")
    log_console("Attempting to load snapshot into Tenant Objects...")
    try:
        selection = snapshot_listbox.curselection()
        if not selection:
            log_console("No snapshot selected.")
            return
        filename = snapshot_files[selection[0]]
        snapshot_path = filename  # Use the full path from snapshot_files
        if not os.path.exists(snapshot_path):
            log_console(f"Snapshot file not found: {snapshot_path}")
            return
        overview_data.clear()
        for item in overview_tree.get_children():
            overview_tree.delete(item)
        with open(snapshot_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        overview_data.update(data.get("data", {}))
        root_node = overview_tree.insert("", "end", text="Loaded Snapshot Overview", open=True)
        overview_mapping[root_node] = None

        def insert_items(parent, items):
            if isinstance(items, list):
                for obj in items:
                    label = get_label_for_object(obj)
                    child_node = overview_tree.insert(parent, "end", text=label, open=True)
                    overview_mapping[child_node] = obj
            elif isinstance(items, dict):
                for key, value in items.items():
                    sub_parent = overview_tree.insert(parent, "end", text=key, open=True)
                    overview_mapping[sub_parent] = None
                    insert_items(sub_parent, value)

        for section_name, items in overview_data.items():
            section_node = overview_tree.insert(root_node, "end", text=section_name, open=True)
            overview_mapping[section_node] = None
            insert_items(section_node, items)

        log_console("Snapshot successfully loaded to Tenant Objects.")
        winsound.Beep(700, 200)  # Beep on objects loaded
    except Exception as e:
        log_console(f"Error loading snapshot to Tenant Objects tab: {e}")
        winsound.Beep(300, 500)  # Beep on error
    update_progress_complete("Loading snapshot to Overview")

# ------------------ Credential Verification ------------------ #
def verify_credential(cred):
    """Check if a credential is valid by making a simple GET to /api/v1/users?limit=1."""
    try:
        headers = {
            "Authorization": f"SSWS {cred['api_key']}",
            "Accept": "application/json"
        }
        url = f"{normalize_url(cred['okta_url'])}/api/v1/users?limit=1"
        response = requests.get(url, headers=headers, timeout=5)
        log_console(f"Verifying credentials at {url}: Status Code {response.status_code}")
        if response.status_code == 200:
            # Additional check for Acsense-Provisioning
            apps_resp = requests.get(f"{cred['okta_url']}/api/v1/apps", headers=headers)
            if apps_resp.ok:
                found_acsense = any(
                    app.get("label") == "Acsense-Provisioning" and app.get("status") == "ACTIVE"
                    for app in apps_resp.json()
                )
                if found_acsense:
                    cred["has_acsense"] = True
                    log_console("Acsense provisioning detected.")
            return True
        elif response.status_code in [401, 403]:
            log_console(f"Verification failed: {response.status_code} - {response.text}")
            return False
        else:
            log_console(f"Non-200 response {response.status_code}, not marking credential as invalid.")
            return True
    except Exception as e:
        log_console(f"Verification error for {cred['okta_url']}: {e}")
        return False


def update_credentials_listbox():
    """Refresh the Stored Credentials listbox with the validity status."""
    credentials_listbox.delete(0, tk.END)
    for idx, cred in enumerate(credentials):
        valid = verify_credential(cred)
        status = "Valid" if valid else "Expired/Invalid"
        display_text = f"{idx+1}. {cred['okta_url'].rstrip('/')} ({status})"
        credentials_listbox.insert(tk.END, display_text)
        credentials_listbox.itemconfig(idx, foreground="green" if valid else "red")


# ------------------ Credentials Helper Functions ------------------ #
def save_current_credential():
    """Save the user-entered Okta URL and API key to the credential store."""
    okta_url = normalize_url(okta_url_entry.get().strip())
    api_key = api_key_entry.get().strip()
    if not okta_url or not api_key:
        log_console("Both Okta URL and API Key are required to save credentials.")
        return

    if not validate_okta_url(okta_url):
        log_console("Invalid Okta URL. It must start with http:// or https://")
        return

    for cred in credentials:
        if cred["okta_url"] == okta_url and cred["api_key"] == api_key:
            log_console("These credentials are already saved.")
            return

    if len(credentials) >= MAX_CREDENTIALS:
        log_console(f"Maximum of {MAX_CREDENTIALS} credentials reached. "
                    "Delete one before saving a new credential.")
        return

    credentials.append({"okta_url": okta_url, "api_key": api_key})
    save_credentials_to_file()
    update_credentials_listbox()
    log_console("Credential saved successfully.")


def load_selected_credential():
    """Load the selected credential from the listbox into the input fields."""
    try:
        selection = credentials_listbox.curselection()
        if not selection:
            log_console("Please select a credential to load.")
            return
        index = selection[0]
        cred = credentials[index]

        okta_url_entry.delete(0, tk.END)
        okta_url_entry.insert(0, cred["okta_url"])
        api_key_entry.delete(0, tk.END)
        api_key_entry.insert(0, cred["api_key"])

        valid = verify_credential(cred)
        color = "lightgreen" if valid else "lightcoral"
        okta_url_entry.config(bg=color)
        api_key_entry.config(bg=color)
        okta_url_entry.update_idletasks()
        api_key_entry.update_idletasks()

        log_console("Credential loaded.")
    except Exception as e:
        log_console(f"Error loading credential: {e}")
        winsound.Beep(300, 500)  # Beep on error


def delete_selected_credential():
    """Remove the selected credential from the listbox and credential store."""
    try:
        selection = credentials_listbox.curselection()
        if not selection:
            log_console("Please select a credential to delete.")
            return
        index = selection[0]
        del credentials[index]
        save_credentials_to_file()
        update_credentials_listbox()
        log_console("Credential deleted.")
    except Exception as e:
        log_console(f"Error deleting credential: {e}")
        winsound.Beep(300, 500)  # Beep on error


# ------------------ API Functions (User/Group/App/Super Admin) ------------------ #
def create_random_user():
    update_progress_start("Creating random user")
    """Create a random user in the currently specified tenant."""
    okta_url = normalize_url(okta_url_entry.get().strip())
    api_key = api_key_entry.get().strip()
    if not okta_url or not api_key:
        log_console("Okta URL and API Key are required!")
        disable_action_buttons(False)
        return

    if not validate_okta_url(okta_url):
        log_console("Invalid Okta URL.")
        disable_action_buttons(False)
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
        log_console("Creating random user...")
        response = requests.post(url, headers=headers, data=json.dumps(user_data), timeout=10)
        formatted = format_json_response(response.text)
        if response.ok:
            log_console(f"User Creation Success ({response.status_code}):\n{formatted}")
        else:
            log_console(
                f"User Creation Failed ({response.status_code}):\n"
                f"Endpoint: {url}\nPayload: {json.dumps(user_data)}\nResponse: {formatted}"
            )
    except requests.exceptions.RequestException as e:
        log_console(f"Error creating user: {e}")
        winsound.Beep(300, 500)  # Beep on error
    finally:
        disable_action_buttons(False)
    update_progress_complete("Creating random user")


def create_random_group():
    update_progress_start("Creating random group")
    """Create a random group in the currently specified tenant."""
    okta_url = normalize_url(okta_url_entry.get().strip())
    api_key = api_key_entry.get().strip()
    if not okta_url or not api_key:
        log_console("Okta URL and API Key are required!")
        disable_action_buttons(False)
        return

    if not validate_okta_url(okta_url):
        log_console("Invalid Okta URL.")
        disable_action_buttons(False)
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
        log_console("Creating random group...")
        response = requests.post(url, headers=headers, data=json.dumps(group_data), timeout=10)
        formatted = format_json_response(response.text)
        if response.ok:
            log_console(f"Group Creation Success ({response.status_code}):\n{formatted}")
        else:
            log_console(
                f"Group Creation Failed ({response.status_code}):\n"
                f"Endpoint: {url}\nPayload: {json.dumps(group_data)}\nResponse: {formatted}"
            )
    except requests.exceptions.RequestException as e:
        log_console(f"Error creating group: {e}")
        winsound.Beep(300, 500)  # Beep on error
    finally:
        disable_action_buttons(False)
    update_progress_complete("Creating random group")


def create_random_app():
    update_progress_start("Creating random app")
    """Create a random OIDC application in the currently specified tenant."""
    okta_url = normalize_url(okta_url_entry.get().strip())
    api_key = api_key_entry.get().strip()
    if not okta_url or not api_key:
        log_console("Okta URL and API Key are required!")
        disable_action_buttons(False)
        return

    if not validate_okta_url(okta_url):
        log_console("Invalid Okta URL.")
        disable_action_buttons(False)
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
        log_console("Creating random application...")
        response = requests.post(url, headers=headers, data=json.dumps(app_data), timeout=10)
        formatted = format_json_response(response.text)
        if response.ok:
            log_console(f"Application Creation Success ({response.status_code}):\n{formatted}")
        else:
            log_console(
                f"Application Creation Failed ({response.status_code}):\n"
                f"Endpoint: {url}\nPayload: {json.dumps(app_data)}\nResponse: {formatted}"
            )
    except requests.exceptions.RequestException as e:
        log_console(f"Error creating application: {e}")
        winsound.Beep(300, 500)  # Beep on error
    finally:
        disable_action_buttons(False)
    update_progress_complete("Creating random app")


def create_super_admin():
    update_progress_start("Creating Super Admin")
    """Create a user and assign the SUPER_ADMIN role to that user."""
    okta_url = normalize_url(okta_url_entry.get().strip())
    api_key = api_key_entry.get().strip()
    if not okta_url or not api_key:
        log_console("Okta URL and API Key are required!")
        disable_action_buttons(False)
        return

    if not validate_okta_url(okta_url):
        log_console("Invalid Okta URL.")
        disable_action_buttons(False)
        return

    first_name = super_admin_first_entry.get().strip()
    last_name = super_admin_last_entry.get().strip()
    email = super_admin_email_entry.get().strip()
    login = super_admin_login_entry.get().strip()
    if not (first_name and last_name and email and login):
        log_console("All super admin fields must be provided!")
        disable_action_buttons(False)
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
        log_console("Creating super admin user...")
        response = requests.post(url, headers=headers, json=user_data)
        formatted = format_json_response(response.text)

        if response.ok:
            user_data_response = response.json()
            user_id = user_data_response.get("id")
            log_console(f"Super Admin Creation Success ({response.status_code}):\n{formatted}")

            if user_id:
                role_url = f"{okta_url}/api/v1/users/{user_id}/roles"
                role_data = {"type": "SUPER_ADMIN"}
                role_resp = requests.post(role_url, headers=headers, data=json.dumps(role_data), timeout=10)
                formatted_role = format_json_response(role_resp.text)
                if role_resp.ok:
                    log_console(f"Super Admin Role Assigned ({role_resp.status_code}):\n{formatted_role}")
                else:
                    log_console(
                        f"Failed to assign Super Admin Role ({role_resp.status_code}):\n"
                        f"Endpoint: {role_url}\nPayload: {json.dumps(role_data)}\nResponse: {formatted_role}"
                    )
        else:
            log_console(
                f"Super Admin Creation Failed ({response.status_code}):\n"
                f"Endpoint: {url}\nPayload: {json.dumps(user_data)}\nResponse: {formatted}"
            )
    except requests.exceptions.RequestException as e:
        log_console(f"Error creating super admin: {e}")
        winsound.Beep(300, 500)  # Beep on error
    finally:
        disable_action_buttons(False)
    update_progress_complete("Creating Super Admin")


# ------------------ Tenant Overview Functions ------------------ #
def create_database():
    conn = sqlite3.connect('okta_objects.db')
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

    # Add more tables for other object types as needed

    conn.commit()
    conn.close()

def insert_user_into_db(user):
    conn = sqlite3.connect('okta_objects.db')
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

def insert_group_into_db(group):
    conn = sqlite3.connect('okta_objects.db')
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

def retrieve_overview():
    update_progress_start("Retrieving tenant overview")
    """
    Fetch a wide range of objects from the tenant and populate both the `overview_data`
    dictionary and the TreeView in the Overview tab. Also automatically saves a snapshot.
    """
    global overview_data, overview_mapping, last_log_timestamp

    disable_action_buttons(True)
    log_console("Starting tenant overview retrieval...")

    # Reset previous data
    overview_mapping = {}
    overview_data = {}
    for item in overview_tree.get_children():
        overview_tree.delete(item)

    okta_url = normalize_url(okta_url_entry.get().strip())
    api_key = api_key_entry.get().strip()

    if not okta_url or not api_key:
        log_console("Okta URL and API Key are required!")
        disable_action_buttons(False)
        return

    if not validate_okta_url(okta_url):
        log_console("Invalid Okta URL.")
        disable_action_buttons(False)
        return

    headers = {"Authorization": f"SSWS {api_key}", "Accept": "application/json"}

    # Define top-level sections with resource definitions and API endpoints
    sections = {
        "Directory": [
            {"name": "Users", "endpoint": "/api/v1/users"},
            {"name": "Groups", "endpoint": "/api/v1/groups", 
             "child_resources": [
                {"name": "Membership", "endpoint": "/api/v1/groups/{id}/users"}
            ]},
            {"name": "User Types", "endpoint": "/api/v1/meta/types/user"},
            {"name": "Group Rules", "endpoint": "/api/v1/groups/rules"},
            {"name": "Devices", "endpoint": "/api/v1/devices"}
        ],
        "Customizations": [
            {"name": "Brands", "endpoint": "/api/v1/brands"},
            {"name": "Email Templates", "endpoint": "/api/v1/brands/{brandId}/templates/email"},
            {"name": "Sign-in Page", "endpoint": "/api/v1/brands/{brandId}/pages/sign-in"},
            {"name": "SMS Templates", "endpoint": "/api/v1/templates/sms"},
            {"name": "Custom domains", "endpoint": "/api/v1/customDomains"},
            {"name": "Email Domains", "endpoint": "/api/v1/emailDomains"}
        ],
        "Applications": [
            {
                "name": "Applications",
                "endpoint": "/api/v1/apps",
                "child_resources": [
                    {"name": "Assigned Users", "endpoint": "/api/v1/apps/{id}/users"}
                ]
            },
            {"name": "Mappings", "endpoint": "/api/v1/mappings"}
        ],
        "Security": [
            {"name": "Authenticators", "endpoint": "/api/v1/authenticators"},
            {"name": "Identity Providers", "endpoint": "/api/v1/idps"},
            {"name": "User Roles", "endpoint": "/api/v1/iam/roles"},
            {"name": "Group Roles", "endpoint": "/api/v1/groups/{id}/roles"},
            {"name": "Network Zones", "endpoint": "/api/v1/zones"},
            {
                "name": "Policies",
                "endpoint": "/api/v1/policies",
                "policy_types": [
                    {"name": "Authenticator Enrollment", "type": "MFA_ENROLL"},
                    {"name": "Authentication", "type": "ACCESS_POLICY"},
                    {"name": "Entity Risk", "type": "ENTITY_RISK"},
                    {"name": "Global Session", "type": "OKTA_SIGN_ON"},
                    {"name": "IdP Discovery", "type": "IDP_DISCOVERY"},
                    {"name": "Password", "type": "PASSWORD"},
                    {"name": "Post Auth Session", "type": "POST_AUTH_SESSION"},
                    {"name": "User Profile", "type": "PROFILE_ENROLLMENT"}
                ],
                "child_resources": [
                    {"name": "Rules", "endpoint": "/api/v1/policies/{id}/rules"},
                    {"name": "Apps", "endpoint": "/api/v1/policies/{id}/app"}
                ]
            },
            {"name": "Device Assurance Policies", "endpoint": "/api/v1/device-assurancePolicies"},
            {"name": "User Lockout Settings", "endpoint": "/attack-protection/api/v1/user-lockout-settings"},
            {"name": "Behavior Rules", "endpoint": "/api/v1/behaviors"}
        ],
        "API": [
            {
                "name": "Authorization Servers",
                "endpoint": "/api/v1/authorizationServers",
                "child_resources": [
                    {"name": "Claims", "endpoint": "/api/v1/authorizationServers/{id}/claims"},
                    {"name": "Scopes", "endpoint": "/api/v1/authorizationServers/{id}/scopes"},
                    {"name": "Policies", "endpoint": "/api/v1/authorizationServers/{id}/policies"}
                ]
            },
            {"name": "Trusted Origins", "endpoint": "/api/v1/trustedOrigins"},
            {"name": "API Tokens", "endpoint": "/api/v1/api-tokens"}
        ],
        "Agent Pools": [
            {"name": "Agent Pools", "endpoint": "/api/v1/agentPools"},
            {"name": "Agent Pool Updates", "endpoint": "/api/v1/agentPools/{poolId}/updates"},
            {"name": "Agent Pool Update Settings", "endpoint": "/api/v1/agentPools/{poolId}/updates/settings"}
        ],
        "Workflows": [
            {"name": "Event Hooks", "endpoint": "/api/v1/eventHooks"},
            {"name": "Hook Keys", "endpoint": "/api/v1/hookKeys"},
            {"name": "Inline Hooks", "endpoint": "/api/v1/inlineHooks"}
        ],
        "CAPTCHAs": [
            {"name": "CAPTCHA Instances", "endpoint": "/api/v1/captchas"}
        ],
        "Custom Domains": [
            {"name": "Custom Domains", "endpoint": "/api/v1/domains"}
        ],
        "Email Domains": [
            {"name": "Email Domains", "endpoint": "/api/v1/email/domains"}
        ],
        "Event Hooks": [
            {"name": "Event Hooks", "endpoint": "/api/v1/eventHooks"}
        ],
        "Features": [
            {"name": "Org Features", "endpoint": "/api/v1/features"}
        ],
        "Hook Keys": [
            {"name": "Hook Keys", "endpoint": "/api/v1/hookKeys"}
        ],
        "Identity Sources": [
            {"name": "Identity Source Sessions", "endpoint": "/api/v1/identitySources/sessions"}
        ],
        "Inline Hooks": [
            {"name": "Inline Hooks", "endpoint": "/api/v1/inlineHooks"}
        ],
        "Linked Objects": [
            {"name": "Linked Object Definitions", "endpoint": "/api/v1/meta/linkedObjects"}
        ],
        "Log Streaming": [
            {"name": "Log Streams", "endpoint": "/api/v1/logStreams"}
        ],
        "Org Settings and Information": [
            {"name": "Org Metadata", "endpoint": "/.well-known/okta-organization"},
            {"name": "Org Settings", "endpoint": "/api/v1/org"},
            {"name": "Org Contact Types", "endpoint": "/api/v1/org/contacts"},
            {"name": "ThreatInsight Configuration", "endpoint": "/api/v1/threats/configuration"},
            {"name": "Features", "endpoint": "/api/v1/features"},
            {"name": "Principal Rate Limits", "endpoint": "/api/v1/rateLimits/principals"}
        ],
        "Principal Rate Limits": [
            {"name": "Principal Rate Limits", "endpoint": "/api/v1/rateLimits/principals"}
        ],
        "Push Providers": [
            {"name": "Push Providers", "endpoint": "/api/v1/pushProviders"}
        ],
        "Resource Sets": [
            {"name": "Resource Sets", "endpoint": "/api/v1/iam/resourceSets"}
        ],
        "Risk Providers": [
            {"name": "Risk Providers", "endpoint": "/api/v1/risk/providers"}
        ],
        "Roles (Custom Admin Roles)": [
            {"name": "Roles", "endpoint": "/api/v1/roles"}
        ],
        "Sessions": [
            {"name": "Session", "endpoint": "/api/v1/sessions/{sessionId}"}
        ]
    }

    total_resources = sum(len(resources) for resources in sections.values())

    # Create/Reset the progress bar for this overview retrieval
    global_progress_bar['maximum'] = total_resources
    global_progress_bar['value'] = 0
    global_progress_label["text"] = "Fetching tenant objects..."

    def process_child_resources(parent_node, parent_obj, resources, resource_name):
        """
        Process child resources for a given policy or object that has sub-endpoints (like rules).
        Attach them as children to the tree item.
        """
        for child_res in resources:
            child_endpoint = child_res["endpoint"].format(
                id=parent_obj["id"], brandId=parent_obj.get("id")
            )
            try:
                child_resp = api_get(f"{okta_url}{child_endpoint}", headers)
                if child_resp.ok:
                    child_data = child_resp.json()
                    if not isinstance(child_data, list):
                        child_data = [child_data]
                    if child_data:
                        child_parent = overview_tree.insert(parent_node, "end",
                                                             text=child_res["name"], open=True)
                        overview_mapping[child_parent] = None
                        for item in child_data:
                            item_id = overview_tree.insert(child_parent, "end",
                                                           text=get_label_for_object(item))
                            overview_mapping[item_id] = item
            except Exception as e:
                log_console(f"Error retrieving {child_res['name']} for {resource_name}: {e}")
                winsound.Beep(300, 500)  # Beep on error

    root_node = overview_tree.insert("", "end", text="Tenant Overview")
    overview_mapping[root_node] = None

    for section, resources in sections.items():
        section_node = overview_tree.insert(root_node, "end", text=section, open=True)
        overview_mapping[section_node] = None
        overview_data[section] = {}

        for res in resources:
            if not res.get("endpoint"):
                continue

            res_name = res["name"]
            resource_node = overview_tree.insert(section_node, "end", text=res_name, open=True)
            overview_mapping[resource_node] = None

            try:
                # Special handling for "Policies" with policy_types
                if res_name == "Policies" and "policy_types" in res:
                    for policy_type in res["policy_types"]:
                        pt_node = overview_tree.insert(resource_node, "end",
                                                       text=policy_type["name"], open=True)
                        overview_mapping[pt_node] = None
                        params = {"type": policy_type["type"]}
                        response = api_get(f"{okta_url}{res['endpoint']}", headers, params=params)

                        if response.ok:
                            policies = response.json()
                            if policies:
                                overview_data[section].setdefault(res_name, []).extend(policies)
                                for policy in policies:
                                    policy_node = overview_tree.insert(pt_node, "end",
                                                                       text=get_label_for_object(policy))
                                    overview_mapping[policy_node] = policy
                                    if "child_resources" in res:
                                        process_child_resources(policy_node, policy,
                                                                res["child_resources"], res_name)
                else:
                    # Normal retrieval for other resources
                    response = api_get(f"{okta_url}{res['endpoint']}", headers)
                    if response.ok:
                        data = response.json()
                        if not isinstance(data, list):
                            data = [data]

                        overview_data[section][res_name] = data

                        for obj in data:
                            obj['_delete_endpoint'] = res['endpoint']  # Add delete endpoint to object
                            obj_node = overview_tree.insert(resource_node, "end",
                                                            text=get_label_for_object(obj))
                            overview_mapping[obj_node] = obj

                            # Insert into database
                            if res_name == "Users":
                                insert_user_into_db(obj)
                            elif res_name == "Groups":
                                insert_group_into_db(obj)
                            # Add more conditions for other object types

                            if "child_resources" in res:
                                process_child_resources(obj_node, obj, res["child_resources"], res_name)
                    else:
                        log_console(f"Failed retrieving {res_name}: {response.status_code}")
            except Exception as e:
                log_console(f"Error processing {res_name}: {e}")
                winsound.Beep(300, 500)  # Beep on error
                continue

            global_progress_bar['value'] += 1
            root.update_idletasks()

    global_progress_bar['value'] = total_resources
    global_progress_label["text"] = "Tenant overview retrieval complete."
    disable_action_buttons(False)

    # Automatically save a snapshot after successful fetch
    save_snapshot(okta_url, overview_data)
    update_progress_complete("Retrieving tenant overview")

def save_overview_to_file():
    """Save the current overview data to a chosen JSON file."""
    if not overview_data:
        messagebox.showinfo("No Data", "No overview data available. Please retrieve overview first.")
        return
    file_path = filedialog.asksaveasfilename(
        defaultextension=".json", filetypes=[("JSON Files", "*.json")]
    )
    if file_path:
        try:
            with open(file_path, "w") as f:
                json.dump(overview_data, f, indent=2)
            messagebox.showinfo("Saved", f"Overview data saved to {file_path}")
        except Exception as e:
            tb_dialogs.ShowMessage(title="Error", message=f"Failed to save overview: {e}", bootstyle="danger")
            winsound.Beep(300, 500)  # Beep on error


def delete_selected_overview_objects():
    """
    Currently only removes the selected items from the Overview TreeView.
    (Does not delete them in Okta.)
    """
    selected_items = overview_tree.selection()
    if not selected_items:
        log_console("No tenant object selected for deletion.")
        return

    for item in list(selected_items):
        item_text = overview_tree.item(item, "text")
        overview_tree.delete(item)
        if item in overview_mapping:
            del overview_mapping[item]
        log_console(f"Deleted object (local only): {item_text}")


def delete_object_from_target():
    update_progress_start("Deleting object from target")
    """Delete the selected object in the overview tree from the target Okta tenant."""
    selection = overview_tree.selection()
    if not selection:
        log_console("No object selected for deletion from target tenant.")
        return

    item_id = selection[0]
    obj_data = overview_mapping.get(item_id)
    if not obj_data or not isinstance(obj_data, dict):
        log_console("Could not find valid object data to delete.")
        return

    okta_url = normalize_url(okta_url_entry.get().strip())
    api_key = api_key_entry.get().strip()
    if not okta_url or not api_key:
        log_console("Okta URL or API key is missing.")
        return

    headers = {"Authorization": f"SSWS {api_key}", "Accept": "application/json"}
    # For demonstration, we assume obj_data['id'] and obj_data['_delete_endpoint'] exist:
    resource_id = obj_data.get("id")
    endpoint = obj_data.get("_delete_endpoint")  # e.g., "/api/v1/users"
    if not resource_id or not endpoint:
        log_console("Missing resource id or delete endpoint in object data.")
        return

    delete_url = f"{okta_url}{endpoint}/{resource_id}"
    try:
        response = requests.delete(delete_url, headers=headers, timeout=10)
        if response.ok:
            overview_tree.delete(item_id)
            log_console(f"Object deleted successfully from target Okta tenant: {delete_url}")
        else:
            log_console(f"Failed to delete object from target tenant: {response.status_code} - {response.text}")
    except requests.exceptions.HTTPError as e:
        log_console(f"HTTP error occurred: {str(e)}")
        winsound.Beep(300, 500)  # Beep on error
    except requests.exceptions.RequestException as e:
        log_console(f"Network error occurred: {str(e)}")
        winsound.Beep(300, 500)  # Beep on error
    except Exception as e:
        log_console(f"General error occurred: {str(e)}")
        winsound.Beep(300, 500)  # Beep on error
    else:
        log_console("Object successfully deleted.")
    update_progress_complete("Deleting object from target")

def reset_user_password():
    selection = overview_tree.selection()
    if not selection:
        log_console("No user selected.")
        return
    item_id = selection[0]
    obj = overview_mapping.get(item_id, {})
    user_id = obj.get("id")
    if not user_id:
        log_console("Selected item is not a valid user.")
        return
    okta_url = normalize_url(okta_url_entry.get().strip())
    api_key = api_key_entry.get().strip()
    headers = {"Authorization": f"SSWS {api_key}", "Accept": "application/json"}
    disable_action_buttons(True)
    try:
        expire_url = f"{okta_url}/api/v1/users/{user_id}/lifecycle/expire_password?tempPassword=true"
        response = requests.post(expire_url, headers=headers)
        if response.ok:
            temp_data = response.json()
            temp_pass = temp_data.get("tempPassword", "N/A")
            log_console(f"Temporary password: {temp_pass}")
        else:
            log_console(f"Failed to expire password. Status: {response.status_code}")
    except requests.exceptions.RequestException as e:
        log_console(f"Error resetting password: {e}")
    finally:
        disable_action_buttons(False)


# ------------------ Live Events Functions ------------------ #
def retrieve_live_events():
    update_progress_start("Retrieving live events")
    """Fetch logs from /api/v1/logs, using since=last_log_timestamp if set."""
    global last_log_timestamp, live_mapping
    live_mapping = {}

    okta_url = normalize_url(okta_url_entry.get().strip())
    api_key = api_key_entry.get().strip()

    if not okta_url or not api_key:
        log_console("Okta URL and API Key are required!")
        disable_action_buttons(False)
        return

    if not validate_okta_url(okta_url):
        log_console("Invalid Okta URL.")
        disable_action_buttons(False)
        return

    headers = {"Authorization": f"SSWS {api_key}", "Accept": "application/json"}
    params = {}
    if last_log_timestamp:
        params["since"] = last_log_timestamp
    url = f"{okta_url}/api/v1/logs"

    log_console("Retrieving live events...")
    response = api_get(url, headers, params)

    for item in live_tree.get_children():
        live_tree.delete(item)

    if response.ok:
        data = response.json()
        for event in data:
            event_id = event.get("uuid", "N/A")
            event_type = event.get("eventType", "N/A")
            published = event.get("published", "N/A")
            actor = event.get("actor", {}).get("displayName", "N/A")
            item_id = live_tree.insert(
                "", "end", text=event_id, values=(event_type, published, actor)
            )
            live_mapping[item_id] = event

        if data:
            last_log_timestamp = data[-1].get("published")

        log_console("Live events updated.")
    else:
        log_console(
            f"Failed to retrieve live events:\n"
            f"Endpoint: {url}\nParams: {params}\nStatus: {response.status_code}\nResponse: {response.text}"
        )
        winsound.Beep(300, 500)  # Beep on error

    disable_action_buttons(False)
    update_progress_complete("Retrieving live events")


def on_live_tree_select(event):
    """Handle selection on the Live Events TreeView."""
    selected = live_tree.selection()
    if selected:
        item_id = selected[0]
        event_obj = live_mapping.get(item_id)
        logs_details_text.configure(state="normal")
        logs_details_text.delete("1.0", tk.END)
        if event_obj is not None:
            logs_details_text.insert(tk.END, json.dumps(event_obj, indent=2))
        else:
            logs_details_text.insert(tk.END, f"No detailed data for: {live_tree.item(item_id)['text']}")
        logs_details_text.configure(state="disabled")


# ------------------ Transfer Objects Functions ------------------ #
def load_saved_objects():
    update_progress_start("Loading saved objects")
    """Load saved objects (JSON) from a file into the Transfer tab."""
    global transfer_data, transfer_mapping
    file_path = filedialog.askopenfilename(filetypes=[("JSON Files", "*.json")])
    if not file_path:
        return

    try:
        with open(file_path, "r") as f:
            transfer_data = json.load(f)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to load saved objects: {e}")
        winsound.Beep(300, 500)  # Beep on error
        return

    for item in transfer_tree.get_children():
        transfer_tree.delete(item)
    transfer_mapping.clear()

    for cat, objs in transfer_data.items():
        parent_id = transfer_tree.insert("", "end", text=cat, values=("No",), open=True)
        transfer_mapping[parent_id] = None
        if isinstance(objs, list):
            for obj in objs:
                label = get_label_for_object(obj)
                child_id = transfer_tree.insert(parent_id, "end", text=label, values=("No",), open=True)
                transfer_mapping[child_id] = obj

    messagebox.showinfo("Loaded", "Saved objects loaded successfully.")
    search_entry.config(state=tk.NORMAL)
    update_progress_complete("Loading saved objects")


def search_objects():
    """Filter objects in the Transfer tab by a search term."""
    search_term = search_entry.get().lower()

    for item in transfer_tree.get_children():
        transfer_tree.delete(item)

    for cat, objects in transfer_data.items():
        parent_id = transfer_tree.insert("", "end", text=cat, values=("No",), open=True)
        transfer_mapping[parent_id] = None
        if isinstance(objects, list):
            for obj in objects:
                label = get_label_for_object(obj)
                if search_term in label.lower():
                    child_id = transfer_tree.insert(parent_id, "end", text=label, values=("No",), open=True)
                    transfer_mapping[child_id] = obj
                    transfer_tree.selection_set(child_id)
                    transfer_tree.see(child_id)


def toggle_transfer_selection(event):
    """Toggle the 'Selected' state of the clicked item (and all children) in the Transfer TreeView."""
    item_id = transfer_tree.focus()
    if not item_id:
        return
    children = transfer_tree.get_children(item_id)
    current = transfer_tree.item(item_id, "values")
    new_val = "Yes" if (current and current[0] == "No") else "No"
    transfer_tree.item(item_id, values=(new_val,))
    for child in children:
        transfer_tree.item(child, values=(new_val,))


def load_target_credential():
    """Load the selected credential from the Stored Credentials listbox into the Transfer tab's target fields."""
    selection = credentials_listbox.curselection()
    if not selection:
        messagebox.showinfo("Info", "Please select a credential from Stored Credentials.")
        return

    index = selection[0]
    cred = credentials[index]
    target_url_entry.delete(0, tk.END)
    target_url_entry.insert(0, cred["okta_url"])
    target_api_key_entry.delete(0, tk.END)
    target_api_key_entry.insert(0, cred["api_key"])


def transfer_objects():
    update_progress_start("Transferring objects")
    global transfer_cancelled
    transfer_cancelled = False
    target_url = normalize_url(target_url_entry.get().strip())
    target_api_key = target_api_key_entry.get().strip()

    if not target_url or not target_api_key:
        messagebox.showerror("Error", "Target tenant credentials are required.")
        return

    if not validate_okta_url(target_url):
        messagebox.showerror("Error", "Invalid target Okta URL.")
        return

    headers = {
        "Authorization": f"SSWS {target_api_key}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    transferred = 0
    errors = 0

    global_progress_bar['value'] = 0
    total_items = sum(
        1
        for parent in transfer_tree.get_children()
        for child in transfer_tree.get_children(parent)
        if transfer_tree.item(child, "values") and transfer_tree.item(child, "values")[0] == "Yes"
    )
    global_progress_bar['maximum'] = total_items if total_items > 0 else 1
    global_progress_bar['value'] = 0
    global_progress_label['text'] = "Transferring selected objects..."

    log_console("Starting transfer of selected objects...")

    transfer_order = [
        "okta_groups",
        "okta_users",
        "okta_idps",
        "okta_mappings",
        "okta_applications",
        "okta_authz_policies",
        "okta_global_policies"
    ]

    for category in transfer_order:
        parent_items = [
            item for item in transfer_tree.get_children()
            if transfer_tree.item(item, "text") == category
        ]
        if not parent_items:
            continue

        parent = parent_items[0]
        endpoint_suffix = transfer_endpoint_map.get(category)
        if not endpoint_suffix:
            log_console(f"Skipping category {category} (no transfer endpoint defined).")
            continue

        full_endpoint = f"{target_url}{endpoint_suffix}"
        log_console(f"Transferring objects for category {category} to endpoint {full_endpoint}")

        for child in transfer_tree.get_children(parent):
            if transfer_cancelled:
                log_console("Transfer cancelled by user.")
                messagebox.showinfo("Cancelled", "Transfer cancelled.")
                disable_action_buttons(False)
                return

            values = transfer_tree.item(child, "values")
            if not values or values[0] != "Yes":
                continue

            obj = transfer_mapping.get(child)
            if not obj:
                continue

            if category == "okta_applications":
                clean_obj = clean_app_object(obj)
            else:
                clean_obj = clean_object(obj)

            payload = json.dumps(clean_obj)
            log_console(
                f"Transferring object: {get_label_for_object(obj)}\n"
                f"Endpoint: {full_endpoint}\nPayload: {payload}"
            )

            try:
                retries = 0
                max_retries = 3
                wait_time = 1

                while retries < max_retries:
                    resp = requests.post(full_endpoint, headers=headers, data=payload, timeout=10)
                    if resp.status_code == 429:
                        retry_after = resp.headers.get("Retry-After", wait_time)
                        sleep_time = int(retry_after) if str(retry_after).isdigit() else wait_time
                        log_console(
                            f"Rate limited during transfer. "
                            f"Waiting {sleep_time} seconds before retry..."
                        )
                        time.sleep(sleep_time)
                        wait_time *= 2
                        retries += 1
                    else:
                        break

                if resp.ok:
                    transferred += 1
                    log_console(f"Transfer succeeded for {get_label_for_object(obj)}")
                else:
                    errors += 1
                    log_console(
                        f"Transfer failed for {get_label_for_object(obj)}: "
                        f"{resp.status_code} - {resp.text}"
                    )
            except Exception as e:
                errors += 1
                log_console(f"Exception during transfer for {get_label_for_object(obj)}: {e}")
                winsound.Beep(300, 500)  # Beep on error

            global_progress_bar['value'] += 1

    messagebox.showinfo("Transfer Complete", f"Transferred: {transferred} objects. Errors: {errors}")
    global_progress_bar['value'] = 0
    global_progress_label["text"] = "Ready."
    disable_action_buttons(False)
    update_progress_complete("Transferring objects")


def cancel_transfer():
    """Set the global transfer_cancelled flag to True."""
    global transfer_cancelled
    transfer_cancelled = True
    log_console("Transfer cancellation requested.")


# ------------------ Tree Selection Callbacks ------------------ #
def on_overview_tree_select(event):
    """Display the JSON details of the selected Overview tree item in the details panel."""
    selected = overview_tree.selection()
    if selected:
        item_id = selected[0]
        obj = overview_mapping.get(item_id)
        details_text.configure(state="normal")
        details_text.delete("1.0", tk.END)
        if obj is not None:
            details_text.insert(tk.END, json.dumps(obj, indent=2))
        else:
            details_text.insert(tk.END, f"No detailed data for: {overview_tree.item(item_id)['text']}")
        details_text.configure(state="disabled")


def on_transfer_tree_select(event):
    """(Optional) Callback for selection change in Transfer tree (here just logs to console)."""
    selected_items = transfer_tree.selection()
    log_console(f"Transfer tree selection changed. Selected: {selected_items}")


# ------------------ Thread Runner ------------------ #
def run_threaded(task_func):
    def wrapper():
        try:
            task_func()
        finally:
            disable_action_buttons(False)

    thread = threading.Thread(target=wrapper, daemon=True)
    thread.start()


# ------------------ UI Setup ------------------ #
style = Style(theme="flatly")
root = style.master
root.title("Okta API Tool")

# NEW: Add an extra container in top_frame for custom theme and date filter.
filter_frame = tk.Frame(root, padx=10, pady=5)
filter_frame.pack(fill=tk.X)
# NEW: Example DateEntry widget for filtering snapshots
date_entry = tb.DateEntry(filter_frame, bootstyle="primary", dateformat='%Y-%m-%d')
date_entry.pack(side=tk.LEFT, padx=5)
tk.Label(filter_frame, text="Filter by Date:").pack(side=tk.LEFT, padx=5)

top_frame = tk.Frame(root, padx=10, pady=10)
top_frame.pack(fill=tk.X)

# Remove old snapshot_panel usage; we will reorganize it below.

# Theme Change Button (stays at the top)
# Upgrade: Use a ttkbootstrap ToggleButton for theme toggle
theme_toggle = tb.Button(top_frame, text="Toggle Theme", bootstyle="outline-primary", command=toggle_theme)
theme_toggle.grid(row=0, column=5, padx=5, pady=2)

# Okta URL and API Key at top row
tk.Label(top_frame, text="Okta URL:").grid(row=0, column=0, sticky="w")
okta_url_entry = tk.Entry(top_frame, width=50)
okta_url_entry.grid(row=0, column=1, padx=5, pady=2)

tk.Label(top_frame, text="Example: https://yourOktaDomain.okta.com", fg="gray").grid(row=1, column=1, sticky="w")

tk.Label(top_frame, text="API Key:").grid(row=0, column=2, sticky="w")
api_key_entry = tk.Entry(top_frame, width=40, show="*")
api_key_entry.grid(row=0, column=3, padx=5, pady=2)

# Credentials & Snapshots side by side
cred_snap_frame = tk.Frame(top_frame)
cred_snap_frame.grid(row=2, column=0, columnspan=4, sticky="ew", pady=5)

cred_frame = tk.LabelFrame(cred_snap_frame, text="Stored Credentials", padx=5, pady=5)
cred_frame.grid(row=0, column=0, sticky="w")

credentials_listbox = tk.Listbox(cred_frame, height=6, width=80)
credentials_listbox.grid(row=0, column=0, columnspan=3, padx=5, pady=5)

save_cred_button = tk.Button(cred_frame, text="Save Credential", command=save_current_credential)
save_cred_button.grid(row=1, column=0, padx=5, pady=2)

load_cred_button = tk.Button(cred_frame, text="Load Credential", command=load_selected_credential)
load_cred_button.grid(row=1, column=1, padx=5, pady=2)

delete_cred_button = tk.Button(cred_frame, text="Delete Credential", command=delete_selected_credential)
delete_cred_button.grid(row=1, column=2, padx=5, pady=2)

action_buttons.extend([save_cred_button, load_cred_button, delete_cred_button])

snapshots_frame = tk.LabelFrame(cred_snap_frame, text="Snapshots", padx=5, pady=5)
snapshots_frame.grid(row=0, column=1, sticky="w", padx=10)

snapshot_listbox = tk.Listbox(snapshots_frame, height=6, width=80)
snapshot_listbox.grid(row=0, column=0, columnspan=3, padx=5, pady=5)

snap_btn_frame = tk.Frame(snapshots_frame)
snap_btn_frame.grid(row=1, column=0, columnspan=3, sticky="ew")

load_snapshot_button = tk.Button(snap_btn_frame, text="Load Snapshot to Transfer",
                                 command=load_selected_snapshot_to_transfer)
load_snapshot_button.pack(side=tk.LEFT, padx=5)

load_snapshot_overview_button = tk.Button(snap_btn_frame, text="Load Snapshot to Overview",
                                          command=load_selected_snapshot_to_overview)
load_snapshot_overview_button.pack(side=tk.LEFT, padx=5)

delete_snapshot_button = tk.Button(snap_btn_frame, text="Delete Snapshot", command=delete_selected_snapshot)
delete_snapshot_button.pack(side=tk.LEFT, padx=5)

init_snapshots()

# Global Progress Bar Frame
global_progress_frame = tk.Frame(root, padx=10, pady=5)
global_progress_frame.pack(fill=tk.X)
global_progress_label = tk.Label(global_progress_frame, text="Ready.")
global_progress_label.pack(side=tk.LEFT, padx=5)
# NEW: Create a Meter widget; you may use this together with the progress bar.
# global_meter = tb.Meter(global_progress_frame, bootstyle="primary", subtext="Progress", amount=0, interactive=False)
# global_meter.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
# Also keep the original progress bar for backward compatibility
global_progress_bar = tb.Progressbar(global_progress_frame, orient="horizontal", length=400, mode="determinate", bootstyle="striped")
global_progress_bar.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

# NEW: In the Global Progress Bar frame, add a Floodgauge widget for a “system load” indicator.
def create_floodgauge(parent):
    # Placeholder implementation for a system load indicator.
    # Customize this widget as needed.
    frame = tk.Frame(parent, bd=2, relief="sunken")
    label = tk.Label(frame, text="System Load: N/A", font=("Helvetica", 10))
    label.pack(padx=5, pady=5)
    return frame

ffloodgauge = create_floodgauge(global_progress_frame)  
# Notebook with Tabs
notebook = ttk.Notebook(root)
notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

# Create new tab for Super Admin
super_admin_tab = tk.Frame(notebook)
notebook.add(super_admin_tab, text="Super Admin")

super_admin_frame = tk.LabelFrame(super_admin_tab, text="Super Admin Creation", padx=5, pady=5)
super_admin_frame.pack(fill=tk.X, pady=5)

tk.Label(super_admin_frame, text="First Name:").grid(row=0, column=0, sticky="w")
super_admin_first_entry = tk.Entry(super_admin_frame, width=15)
super_admin_first_entry.grid(row=0, column=1, padx=5, pady=2)

tk.Label(super_admin_frame, text="Last Name:").grid(row=0, column=2, sticky="w")
super_admin_last_entry = tk.Entry(super_admin_frame, width=15)
super_admin_last_entry.grid(row=0, column=3, padx=5, pady=2)

tk.Label(super_admin_frame, text="Email:").grid(row=1, column=0, sticky="w")
super_admin_email_entry = tk.Entry(super_admin_frame, width=15)
super_admin_email_entry.grid(row=1, column=1, padx=5, pady=2)

tk.Label(super_admin_frame, text="Login:").grid(row=1, column=2, sticky="w")
super_admin_login_entry = tk.Entry(super_admin_frame, width=15)
super_admin_login_entry.grid(row=1, column=3, padx=5, pady=2)

super_admin_button = tk.Button(super_admin_frame, text="Generate Super Admin",
                               command=lambda: run_threaded(create_super_admin))
super_admin_button.grid(row=2, column=0, columnspan=4, pady=5)
action_buttons.append(super_admin_button)

# Tab 1: Console
console_frame = tk.Frame(notebook)
notebook.add(console_frame, text="Console")

console_text = tk.Text(console_frame, height=15, state="disabled")
console_text.pack(fill=tk.BOTH, expand=True)

clear_console_button = tk.Button(console_frame, text="Clear Console", command=clear_console)
clear_console_button.pack(pady=2)

action_buttons.append(clear_console_button)

# Tab 2: Tenant Overview (Tree on Left, Details on Right)
overview_frame = tk.Frame(notebook)
notebook.add(overview_frame, text="Tenant Objects")

overview_toolbar = tk.Frame(overview_frame)
overview_toolbar.pack(fill=tk.X, padx=5, pady=5)

refresh_overview_button = tk.Button(overview_toolbar, text="Fetch Objects",
                                    command=lambda: run_threaded(retrieve_overview))
refresh_overview_button.pack(side=tk.LEFT, padx=5)

save_overview_button = tk.Button(overview_toolbar, text="Save Objects", command=save_overview_to_file)
save_overview_button.pack(side=tk.LEFT, padx=5)

delete_overview_button = tk.Button(overview_toolbar, text="Delete Selected",
                                   command=delete_selected_overview_objects)
delete_overview_button.pack(side=tk.LEFT, padx=5)

delete_target_button = tk.Button(overview_toolbar, text="Delete From Target",
                                 command=delete_object_from_target)
delete_target_button.pack(side=tk.LEFT, padx=5)

reset_password_button = tk.Button(overview_toolbar, text="Reset Password", command=lambda: run_threaded(reset_user_password))
reset_password_button.pack(side=tk.LEFT, padx=5)
action_buttons.append(reset_password_button)

# Comment out the local progress bars in overview_toolbar and transfer_right_frame
# progress_bar = ttk.Progressbar(overview_toolbar, ...)  <-- commented out
# transfer_progress_bar = ttk.Progressbar(transfer_right_frame, ...)  <-- commented out

action_buttons.extend([refresh_overview_button, save_overview_button, delete_overview_button, delete_target_button])

overview_paned = ttk.PanedWindow(overview_frame, orient=tk.HORIZONTAL)
overview_paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

tree_frame = tk.Frame(overview_paned)
overview_tree = ttk.Treeview(tree_frame)
overview_tree.heading("#0", text="Tenant Objects", anchor="w")
overview_tree.pack(fill=tk.BOTH, expand=True)
overview_paned.add(tree_frame, weight=2)

details_frame = tk.Frame(overview_paned)
details_text = tk.Text(details_frame, state="disabled")
details_text.pack(fill=tk.BOTH, expand=True)
overview_paned.add(details_frame, weight=1)

overview_tree.bind("<<TreeviewSelect>>", on_overview_tree_select)

# Tab 3: Live Events (Tree on Left, Details on Right)
live_frame = tk.Frame(notebook)
notebook.add(live_frame, text="Live Events")

live_toolbar = tk.Frame(live_frame)
live_toolbar.pack(fill=tk.X, padx=5, pady=5)

update_logs_button = tk.Button(live_toolbar, text="Update Logs",
                               command=lambda: run_threaded(retrieve_live_events))
update_logs_button.pack(side=tk.LEFT, padx=5)
action_buttons.append(update_logs_button)

live_paned = ttk.PanedWindow(live_frame, orient=tk.HORIZONTAL)
live_paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

logs_tree_frame = tk.Frame(live_paned)
live_tree = ttk.Treeview(logs_tree_frame, columns=("Event Type", "Published", "Actor"), show="headings")
live_tree.heading("Event Type", text="Event Type")
live_tree.heading("Published", text="Published")
live_tree.heading("Actor", text="Actor")
live_tree.pack(fill=tk.BOTH, expand=True)
live_paned.add(logs_tree_frame, weight=2)

logs_details_frame = tk.Frame(live_paned)
logs_details_text = tk.Text(logs_details_frame, state="disabled")
logs_details_text.pack(fill=tk.BOTH, expand=True)
live_paned.add(logs_details_frame, weight=1)

live_tree.bind("<<TreeviewSelect>>", on_live_tree_select)

# Tab 4: Transfer Objects
transfer_frame = tk.Frame(notebook)
notebook.add(transfer_frame, text="Transfer Objects")

transfer_paned = ttk.PanedWindow(transfer_frame, orient=tk.HORIZONTAL)
transfer_paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

transfer_left_frame = tk.Frame(transfer_paned)

load_objects_button = tk.Button(transfer_left_frame, text="Load Saved Objects", command=load_saved_objects)
load_objects_button.pack(fill=tk.X, padx=5, pady=2)

search_entry = tk.Entry(transfer_left_frame, state=tk.DISABLED)
search_entry.pack(fill=tk.X, padx=5, pady=2)

search_button = tk.Button(transfer_left_frame, text="Search", command=search_objects)
search_button.pack(fill=tk.X, padx=5, pady=2)

transfer_tree = ttk.Treeview(transfer_left_frame, columns=("Selected",), show="tree headings")
transfer_tree.heading("#0", text="Object")
transfer_tree.heading("Selected", text="Selected")
transfer_tree.column("Selected", width=70, anchor="center")
transfer_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

transfer_tree.bind("<Double-1>", toggle_transfer_selection)
transfer_tree.bind("<<TreeviewSelect>>", on_transfer_tree_select)

transfer_paned.add(transfer_left_frame, weight=2)

transfer_right_frame = tk.Frame(transfer_paned)

tk.Label(transfer_right_frame, text="Target Tenant URL:").pack(anchor="w", padx=5, pady=2)
target_url_entry = tk.Entry(transfer_right_frame, width=40)
target_url_entry.pack(padx=5, pady=2)

tk.Label(transfer_right_frame, text="Target API Key:").pack(anchor="w", padx=5, pady=2)
target_api_key_entry = tk.Entry(transfer_right_frame, width=40, show="*")
target_api_key_entry.pack(padx=5, pady=2)

load_target_button = tk.Button(transfer_right_frame, text="Load Credential", command=load_target_credential)
load_target_button.pack(padx=5, pady=2)

transfer_button = tk.Button(transfer_right_frame, text="Transfer Selected",
                            command=lambda: run_threaded(transfer_objects))
transfer_button.pack(padx=5, pady=2)

cancel_transfer_button = tk.Button(transfer_right_frame, text="Cancel Transfer", command=cancel_transfer)
cancel_transfer_button.pack(padx=5, pady=2)

transfer_paned.add(transfer_right_frame, weight=1)

action_buttons.extend([
    load_objects_button, search_button, load_target_button, transfer_button, cancel_transfer_button
])

# Additional API Action Buttons (Generate Random... etc.)
button_frame = tk.Frame(root, padx=10, pady=5)
button_frame.pack(fill=tk.X)

user_button = tk.Button(button_frame, text="Generate Random User",
                        command=lambda: run_threaded(create_random_user))
user_button.pack(side=tk.LEFT, padx=5)

group_button = tk.Button(button_frame, text="Generate Random Group",
                         command=lambda: run_threaded(create_random_group))
group_button.pack(side=tk.LEFT, padx=5)

app_button = tk.Button(button_frame, text="Generate Random Application",
                       command=lambda: run_threaded(create_random_app))
app_button.pack(side=tk.LEFT, padx=5)

action_buttons.extend([user_button, group_button, app_button])

accsense_button = tk.Button(button_frame, text="Generate Accsense Test Users",
                            command=lambda: run_threaded(create_accsense_test_users))
accsense_button.pack(side=tk.LEFT, padx=5)
action_buttons.append(accsense_button)


def create_accsense_test_users():
    disable_action_buttons(True)
    update_progress_start("Generating Accsense Test Users")
    okta_url = normalize_url(okta_url_entry.get().strip())
    api_key = api_key_entry.get().strip()
    if not okta_url or not api_key:
        log_console("Okta URL and API Key are required!")
        disable_action_buttons(False)
        return

    if not validate_okta_url(okta_url):
        log_console("Invalid Okta URL.")
        disable_action_buttons(False)
        return

    headers = {
        "Authorization": f"SSWS {api_key}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    roles = [("ADMIN", "Acsense Admin"), ("OPERATOR", "Acsense Operator"), ("VIEWER", "Acsense Viewer")]
    group_ids = {}

    # Fetch existing groups
    try:
        response = requests.get(f"{okta_url}/api/v1/groups", headers=headers)
        if response.ok:
            groups = response.json()
            for group in groups:
                for role_name, group_name in roles:
                    if group["profile"]["name"] == group_name:
                        group_ids[group_name] = group["id"]
        else:
            log_console(f"Failed to fetch groups: {response.status_code} - {response.text}")
            disable_action_buttons(False)
            return
    except Exception as e:
        log_console(f"Error fetching groups: {e}")
        disable_action_buttons(False)
        return

    for role_name, group_name in roles:
        max_attempts = 5
        attempt = 0
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

            # Check if user with this last name already exists:
            check_url = f"{okta_url}/api/v1/users"
            # Simple approach: filter for lastName eq ...
            params = {"search": f"profile.lastName eq \"{last_name}\""}
            try:
                response = requests.get(check_url, headers=headers, params=params)
                if response.status_code == 200 and response.json():
                    log_console(f"Found existing user with last name '{last_name}' - retrying...")
                    continue  # generate a new ID
            except requests.exceptions.RequestException:
                log_console("Error checking existing users.")
                return

            # If no existing user found, create:
            create_url = f"{okta_url}/api/v1/users?activate=true"
            try:
                res = requests.post(create_url, headers=headers, data=json.dumps(user_data))
                if res.status_code < 300:
                    log_console(f"Accsense Test User created: {first_name} {last_name}")
                    break
                else:
                    log_console(f"Error creating user: {res.text}")
            except requests.exceptions.RequestException as e:
                log_console(f"Error creating user request: {e}")
        else:
            log_console("Max attempts reached. Could not create unique Accsense test user.")

        # Assign user to group if created successfully
        if res.status_code < 300:
            user = res.json()
            log_console(f"Created user {role_name} with login {user['profile']['login']}. Checking group '{group_name}'...")
            group_id = group_ids.get(group_name)
            if group_id:
                assign_response = requests.put(
                    f"{okta_url}/api/v1/groups/{group_id}/users/{user['id']}",
                    headers=headers
                )
                if assign_response.ok:
                    log_console(f"Assigned user {role_name} to group '{group_name}'.")
                else:
                    log_console(f"Failed to assign user {role_name} to group '{group_name}': {assign_response.status_code} - {assign_response.text}")
            else:
                log_console(f"Group '{group_name}' not found.")

    disable_action_buttons(False)
    update_progress_complete("Generating Accsense Test Users")

# ------------------ Object Creation Tab Setup ------------------ #
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
    # Add more sample bodies here if desired
}

object_creation_frame = tk.Frame(notebook)
notebook.add(object_creation_frame, text="Object Creation")

obj_creation_toolbar = tk.Frame(object_creation_frame)
obj_creation_toolbar.pack(fill=tk.X, padx=5, pady=5)

tk.Label(obj_creation_toolbar, text="Target Tenant URL:").grid(row=0, column=0, sticky="w")
target_url_entry2 = tk.Entry(obj_creation_toolbar, width=40)
target_url_entry2.grid(row=0, column=1, padx=5, pady=2)

tk.Label(obj_creation_toolbar, text="API Key:").grid(row=0, column=2, sticky="w")
target_api_key_entry2 = tk.Entry(obj_creation_toolbar, width=40, show="*")
target_api_key_entry2.grid(row=0, column=3, padx=5, pady=2)


def load_selected_credential_to_creation(url_entry, api_key_entry):
    """Load the chosen credential from the listbox into the object creation tab fields."""
    try:
        selection = credentials_listbox.curselection()
        if not selection:
            log_console("Please select a credential to load.")
            return
        index = selection[0]
        cred = credentials[index]

        url_entry.delete(0, tk.END)
        url_entry.insert(0, cred["okta_url"])

        api_key_entry.delete(0, tk.END)
        api_key_entry.insert(0, cred["api_key"])

        log_console("Credential loaded into Object Creation tab.")
    except Exception as e:
        log_console(f"Error loading credential into Object Creation tab: {e}")
        winsound.Beep(300, 500)  # Beep on error


load_selected_cred_button = tk.Button(
    obj_creation_toolbar,
    text="Load Selected Credential",
    command=lambda: load_selected_credential_to_creation(target_url_entry2, target_api_key_entry2)
)
load_selected_cred_button.grid(row=0, column=4, padx=5, pady=2)

creation_type_frame = tk.Frame(object_creation_frame)
creation_type_frame.pack(fill=tk.X, padx=5, pady=5)

tk.Label(creation_type_frame, text="Object Type:").pack(side=tk.LEFT, padx=5)
creation_type_combo = ttk.Combobox(creation_type_frame, values=list(OBJECT_ENDPOINTS.keys()), width=30)
creation_type_combo.pack(side=tk.LEFT, padx=5)
creation_type_combo.set("User")  # default


def load_sample_body():
    """Load a sample JSON body for the selected object type."""
    obj_type = creation_type_combo.get()
    sample = SAMPLE_BODIES.get(obj_type, "")
    creation_body_text.configure(state="normal")
    creation_body_text.delete("1.0", tk.END)
    creation_body_text.insert(tk.END, sample)
    creation_body_text.configure(state="normal")


load_sample_button = tk.Button(creation_type_frame, text="Load Sample", command=load_sample_body)
load_sample_button.pack(side=tk.LEFT, padx=5)

creation_body_frame = tk.Frame(object_creation_frame)
creation_body_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

creation_body_text = tk.Text(creation_body_frame, wrap=tk.NONE, width=80, height=20)
creation_body_text.pack(fill=tk.BOTH, expand=True)


def create_custom_object():
    update_progress_start("Creating custom object")
    """POST user-provided JSON to the selected object-type's endpoint."""
    disable_action_buttons(True)
    try:
        obj_type = creation_type_combo.get()
        if not obj_type:
            log_console("Please select an object type.")
            return

        endpoint_suffix = OBJECT_ENDPOINTS.get(obj_type)
        if not endpoint_suffix:
            log_console(f"No endpoint defined for object type: {obj_type}")
            return

        # Gather target tenant info from the creation tab
        target_url = normalize_url(target_url_entry2.get().strip())
        target_api_key = target_api_key_entry2.get().strip()

        if not target_url or not target_api_key:
            messagebox.showerror("Error", "Target tenant credentials are required.")
            return
        if not validate_okta_url(target_url):
            messagebox.showerror("Error", "Invalid target Okta URL.")
            return

        # Read JSON from text box
        body_text = creation_body_text.get("1.0", tk.END).strip()
        if not body_text:
            log_console("No JSON body provided.")
            return

        try:
            body_json = json.loads(body_text)
        except Exception as e:
            log_console(f"Invalid JSON: {e}")
            return

        full_url = f"{target_url}{endpoint_suffix}"
        headers = {
            "Authorization": f"SSWS {target_api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

        log_console(f"Creating {obj_type} at endpoint: {full_url}")
        resp = requests.post(full_url, headers=headers, data=json.dumps(body_json), timeout=10)
        formatted = format_json_response(resp.text)

        if resp.ok:
            log_console(f"Creation Success ({resp.status_code}):\n{formatted}")
        else:
            log_console(
                f"Creation Failed ({resp.status_code}):\n"
                f"Endpoint: {full_url}\nBody: {body_text}\nResponse: {formatted}"
            )
    except Exception as ex:
        log_console(f"Error creating object: {ex}")
        winsound.Beep(300, 500)  # Beep on error
    finally:
        disable_action_buttons(False)
    update_progress_complete("Creating custom object")


def run_create_object_thread():
    """Launch object creation in a separate thread."""
    thread = threading.Thread(target=create_custom_object)
    thread.daemon = True
    thread.start()


create_button_frame = tk.Frame(object_creation_frame)
create_button_frame.pack(fill=tk.X, padx=5, pady=5)

create_object_button = tk.Button(create_button_frame, text="Create Object", command=run_create_object_thread)
create_object_button.pack(side=tk.LEFT, padx=5)

action_buttons.extend([create_object_button, load_sample_button, load_selected_cred_button])

def query_users():
    conn = sqlite3.connect('okta_objects.db')
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM users')
    users = cursor.fetchall()

    conn.close()
    return users

def query_groups():
    conn = sqlite3.connect('okta_objects.db')
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM groups')
    groups = cursor.fetchall()

    conn.close()
    return groups

# Load credentials and update UI

create_database()
load_credentials_from_file()
update_credentials_listbox()

import importlib

def load_testcases():
    """
    Load available test case files (e.g., *.json) and display them in a listbox.
    """
    # ...existing code...
    # Example: populate 'testcases_listbox' with found *.json files
    # from a 'testcases' folder or similar directory.

def run_selected_testcase():
    """
    Call the 'okta tool test cases' file and execute the selected test case.
    """
    # ...existing code...
    # Example:
    # selected = testcases_listbox.curselection()
    # if not selected: return
    # test_file = testcases_listbox.get(selected[0])
    # testcases_module = importlib.import_module("okta tool test cases")
    # testcases_module.run_test_file(test_file, credentials)

# Add a new UI section for loading and running test cases:
testcase_frame = tk.LabelFrame(top_frame, text="Test Cases", padx=5, pady=5)
testcase_frame.grid(row=3, column=0, columnspan=4, sticky="ew", pady=5)

testcases_listbox = tk.Listbox(testcase_frame, height=6, width=80)
testcases_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

testcase_scrollbar = tk.Scrollbar(testcase_frame)
testcase_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
testcases_listbox.config(yscrollcommand=testcase_scrollbar.set)
testcase_scrollbar.config(command=testcases_listbox.yview)

load_testcases_btn = tk.Button(testcase_frame, text="Load Testcases", command=load_testcases)
load_testcases_btn.pack(side=tk.LEFT, padx=5)

run_testcases_btn = tk.Button(testcase_frame, text="Run Testcase", command=lambda: run_threaded(run_selected_testcase))
run_testcases_btn.pack(side=tk.LEFT, padx=5)

test_tool_tab = tk.Frame(notebook)
notebook.add(test_tool_tab, text="Okta Test Cases")

tk.Label(
    test_tool_tab,
    text="Use this tab to call and display the external 'okta tool test cases.py' script."
).pack(pady=5)

test_tool_output = tk.Text(test_tool_tab, wrap='word', height=10)
test_tool_output.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

def launch_test_tool():
    # Only call 'okta tool test cases.py' here; do not import
    import subprocess
    process = subprocess.Popen(
        ["python", r"c:\Users\Ovidiu.M\Desktop\OKTA API TOOL\okta tool test cases.py"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    out, err = process.communicate()

    test_tool_output.config(state='normal')
    if out:
        test_tool_output.insert(tk.END, f"Output:\n{out}\n")
    if err:
        test_tool_output.insert(tk.END, f"Errors:\n{err}\n")
    test_tool_output.config(state='disabled')

launch_test_tool_btn = tk.Button(test_tool_tab, text="Launch Test Tool", command=launch_test_tool)
launch_test_tool_btn.pack(pady=5)

root.mainloop()
