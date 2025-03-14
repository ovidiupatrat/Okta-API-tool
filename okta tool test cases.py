#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Okta Full Admin Tool - Common Actions
=====================================

A Tkinter-based GUI that automates typical Okta admin tasks:
 - User creation, update, deletion
 - Group creation, deletion
 - User-to-group assignment
 - Application creation, deletion, deactivation
 - User-to-app assignment, group-to-app assignment
 - Policy creation, assignment to app, removal
 - Policy rule creation, update

All actions are stored as "steps" with a sample JSON body that can be edited.
When "Run Test Case" is clicked, each step is executed via the relevant Okta API.

IMPORTANT: 
  - Fill in `OKTA_ORG_URL` and `OKTA_API_TOKEN` with your domain & admin token.
  - Expand or adapt sample JSON bodies for real usage.
  - Real usage should handle errors, rate limits, advanced configurations, etc.
"""

import json
import time
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import requests
import random
import string

# -----------------------------------------------------------------------------
# 1) Configure your Okta domain and API token here (or fetch from env variables)
# -----------------------------------------------------------------------------
OKTA_ORG_URL = "https://dev-123456.okta.com"  # <---- Change this to your Okta domain
OKTA_API_TOKEN = "your_api_token_here"        # <---- Insert your Okta API token (Admin privileges)


# -----------------------------------------------------------------------------
# 2) Handler functions for each "event" (action).
#    They parse `request_body`, call the relevant Okta Admin endpoint, etc.
# -----------------------------------------------------------------------------
def get_credentials():
    """
    Returns currently loaded credentials from the main Beta Version GUI.
    """
    # Implementation that each step can call to get org URL and API token.

def create_user(request_body):
    """
    user.create => POST /api/v1/users?activate=...
    Sample body:
      {
        "profile": {
          "firstName": "Alice",
          "lastName": "Doe",
          "email": "alice@example.com",
          "login": "alice@example.com"
        },
        "credentials": {
          "password": { "value": "TempPass123" }
        },
        "activate": true
      }
    """
    org_url, api_token = get_credentials()
    activate_flag = request_body.pop("activate", True)
    url = f"{org_url}/api/v1/users?activate={str(activate_flag).lower()}"
    headers = {
        "Authorization": f"SSWS {api_token}",
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    resp = requests.post(url, headers=headers, json=request_body)
    if resp.ok:
        return resp.json()
    raise Exception(f"user.create failed: {resp.status_code} {resp.text}")


def delete_user(request_body):
    """
    user.delete => Delete user from Okta
    - We may need to deactivate the user first, or use `?sendEmail=false`.
    Sample body:
      {
        "userId": "00u123abcXYZ"
      }
    """
    user_id = request_body.get("userId")
    if not user_id:
        raise ValueError("Missing 'userId' in request_body")

    # Deactivate
    deact_url = f"{OKTA_ORG_URL}/api/v1/users/{user_id}/lifecycle/deactivate"
    headers = {"Authorization": f"SSWS {OKTA_API_TOKEN}"}
    requests.post(deact_url, headers=headers)  # ignoring errors here for brevity

    # Now Delete
    delete_url = f"{OKTA_ORG_URL}/api/v1/users/{user_id}"
    resp = requests.delete(delete_url, headers=headers)
    if resp.ok or resp.status_code == 204:
        return {"status": "user deleted"}
    raise Exception(f"user.delete failed: {resp.status_code} {resp.text}")


def create_group(request_body):
    """
    group.create => POST /api/v1/groups
    Sample body:
      {
        "profile": {
          "name": "Test Group",
          "description": "My Test Group"
        }
      }
    """
    org_url, api_token = get_credentials()
    url = f"{org_url}/api/v1/groups"
    headers = {
        "Authorization": f"SSWS {api_token}",
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    resp = requests.post(url, headers=headers, json=request_body)
    if resp.ok:
        return resp.json()
    raise Exception(f"group.create failed: {resp.status_code} {resp.text}")


def delete_group(request_body):
    """
    group.delete => DELETE /api/v1/groups/{groupId}
    Sample body:
      { "groupId": "00g123abcXYZ" }
    """
    group_id = request_body.get("groupId")
    if not group_id:
        raise ValueError("Missing 'groupId' in request_body")

    url = f"{OKTA_ORG_URL}/api/v1/groups/{group_id}"
    headers = {"Authorization": f"SSWS {OKTA_API_TOKEN}"}
    resp = requests.delete(url, headers=headers)
    if resp.ok or resp.status_code == 204:
        return {"status": "group deleted"}
    raise Exception(f"group.delete failed: {resp.status_code} {resp.text}")


def assign_user_to_group(request_body):
    """
    group.assign_user => PUT /api/v1/groups/{groupId}/users/{userId}
    Sample body:
      {
        "groupId": "00g123abcXYZ",
        "userId": "00u123abcXYZ"
      }
    """
    group_id = request_body.get("groupId")
    user_id = request_body.get("userId")
    if not group_id or not user_id:
        raise ValueError("Missing 'groupId' or 'userId'")

    url = f"{OKTA_ORG_URL}/api/v1/groups/{group_id}/users/{user_id}"
    headers = {"Authorization": f"SSWS {OKTA_API_TOKEN}", "Accept": "application/json"}
    resp = requests.put(url, headers=headers)
    if resp.ok or resp.status_code == 204:
        return {"status": "user assigned to group"}
    raise Exception(f"group.assign_user failed: {resp.status_code} {resp.text}")


def create_app(request_body):
    """
    app.create => POST /api/v1/apps
    For example, an OIDC app or SAML app.
    Sample body (OIDC):
      {
        "name": "oidc_client",
        "label": "My Sample OIDC App",
        "signOnMode": "OPENID_CONNECT",
        "credentials": {...},
        "settings": {...}
      }
    """
    org_url, api_token = get_credentials()
    url = f"{org_url}/api/v1/apps"
    headers = {
        "Authorization": f"SSWS {api_token}",
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    resp = requests.post(url, headers=headers, json=request_body)
    if resp.ok:
        return resp.json()
    raise Exception(f"app.create failed: {resp.status_code} {resp.text}")


def deactivate_app(request_body):
    """
    app.deactivate => POST /api/v1/apps/{appId}/lifecycle/deactivate
    Sample body:
      { "appId": "0oab1234xyz" }
    """
    app_id = request_body.get("appId")
    if not app_id:
        raise ValueError("Missing 'appId'")

    url = f"{OKTA_ORG_URL}/api/v1/apps/{app_id}/lifecycle/deactivate"
    headers = {"Authorization": f"SSWS {OKTA_API_TOKEN}", "Accept": "application/json"}
    resp = requests.post(url, headers=headers)
    if resp.ok or resp.status_code == 204:
        return {"status": "app deactivated"}
    raise Exception(f"app.deactivate failed: {resp.status_code} {resp.text}")


def delete_app(request_body):
    """
    app.delete => DELETE /api/v1/apps/{appId}
    Sample body:
      { "appId": "0oab1234xyz" }
    Must often deactivate first, but let's try anyway.
    """
    app_id = request_body.get("appId")
    if not app_id:
        raise ValueError("Missing 'appId'")

    # Optionally, call /lifecycle/deactivate first
    headers = {"Authorization": f"SSWS {OKTA_API_TOKEN}", "Accept": "application/json"}
    requests.post(f"{OKTA_ORG_URL}/api/v1/apps/{app_id}/lifecycle/deactivate", headers=headers)

    url = f"{OKTA_ORG_URL}/api/v1/apps/{app_id}"
    resp = requests.delete(url, headers=headers)
    if resp.ok or resp.status_code == 204:
        return {"status": "app deleted"}
    raise Exception(f"app.delete failed: {resp.status_code} {resp.text}")


def assign_user_to_app(request_body):
    """
    app.assign_user => POST /api/v1/apps/{appId}/users
    Sample body:
      {
        "appId": "0oab1234xyz",
        "userId": "00u123abcXYZ",
        "credentials": { "userName": "bob@example.com" }   # optional
      }
    """
    app_id = request_body.get("appId")
    user_id = request_body.get("userId")
    if not app_id or not user_id:
        raise ValueError("Missing 'appId' or 'userId'")

    url = f"{OKTA_ORG_URL}/api/v1/apps/{app_id}/users"
    headers = {
        "Authorization": f"SSWS {OKTA_API_TOKEN}",
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    payload = {
        "id": user_id,
        # Optionally override credentials, profile, etc.
    }
    # If the request body includes "credentials" or "scope" etc, we merge them
    # For simplicity:
    if "credentials" in request_body:
        payload["credentials"] = request_body["credentials"]
    resp = requests.post(url, headers=headers, json=payload)
    if resp.ok:
        return resp.json()
    raise Exception(f"app.assign_user failed: {resp.status_code} {resp.text}")


def assign_group_to_app(request_body):
    """
    app.assign_group => POST /api/v1/apps/{appId}/groups
    Sample body:
      {
        "appId": "0oab1234xyz",
        "groupId": "00g123abcXYZ"
      }
    """
    app_id = request_body.get("appId")
    group_id = request_body.get("groupId")
    if not app_id or not group_id:
        raise ValueError("Missing 'appId' or 'groupId'")

    url = f"{OKTA_ORG_URL}/api/v1/apps/{app_id}/groups"
    headers = {
        "Authorization": f"SSWS {OKTA_API_TOKEN}",
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    payload = {"id": group_id}
    resp = requests.post(url, headers=headers, json=payload)
    if resp.ok:
        return resp.json()
    raise Exception(f"app.assign_group failed: {resp.status_code} {resp.text}")


def create_policy(request_body):
    """
    policy.create => POST /api/v1/policies
    Sample body:
      {
        "type": "OKTA_SIGN_ON",
        "name": "My Sign On Policy",
        "status": "ACTIVE",
        "description": "Example policy"
      }
    """
    url = f"{OKTA_ORG_URL}/api/v1/policies"
    headers = {
        "Authorization": f"SSWS {OKTA_API_TOKEN}",
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    resp = requests.post(url, headers=headers, json=request_body)
    if resp.ok:
        return resp.json()
    raise Exception(f"policy.create failed: {resp.status_code} {resp.text}")


def delete_policy(request_body):
    """
    policy.delete => DELETE /api/v1/policies/{policyId}
    Sample body:
      { "policyId": "abc123XYZ" }
    """
    policy_id = request_body.get("policyId")
    if not policy_id:
        raise ValueError("Missing 'policyId'")

    url = f"{OKTA_ORG_URL}/api/v1/policies/{policy_id}"
    headers = {"Authorization": f"SSWS {OKTA_API_TOKEN}"}
    resp = requests.delete(url, headers=headers)
    if resp.ok or resp.status_code == 204:
        return {"status": "policy deleted"}
    raise Exception(f"policy.delete failed: {resp.status_code} {resp.text}")


def assign_policy_to_app(request_body):
    """
    policy.assign_app => some policy endpoints vary by type, e.g. /api/v1/policies/{policyId}/apps/{appId}
    But Okta doesn't have a universal approach for all policy types.
    We'll do a sign-on policy example:
      => PUT /api/v1/policies/{policyId}/apps/{appId}
    Sample:
      {
        "policyId": "abc123XYZ",
        "appId": "0oab1234xyz"
      }
    """
    policy_id = request_body.get("policyId")
    app_id = request_body.get("appId")
    if not policy_id or not app_id:
        raise ValueError("Missing 'policyId' or 'appId'")

    url = f"{OKTA_ORG_URL}/api/v1/policies/{policy_id}/apps/{app_id}"
    headers = {"Authorization": f"SSWS {OKTA_API_TOKEN}", "Accept": "application/json"}
    resp = requests.put(url, headers=headers)
    if resp.ok or resp.status_code == 204:
        return {"status": "policy assigned to app"}
    raise Exception(f"policy.assign_app failed: {resp.status_code} {resp.text}")


def remove_policy_from_app(request_body):
    """
    policy.remove_app => DELETE /api/v1/policies/{policyId}/apps/{appId}
    Sample:
      {
        "policyId": "abc123XYZ",
        "appId": "0oab1234xyz"
      }
    """
    policy_id = request_body.get("policyId")
    app_id = request_body.get("appId")
    if not policy_id or not app_id:
        raise ValueError("Missing 'policyId' or 'appId'")

    url = f"{OKTA_ORG_URL}/api/v1/policies/{policy_id}/apps/{app_id}"
    headers = {"Authorization": f"SSWS {OKTA_API_TOKEN}"}
    resp = requests.delete(url, headers=headers)
    if resp.ok or resp.status_code == 204:
        return {"status": "policy removed from app"}
    raise Exception(f"policy.remove_app failed: {resp.status_code} {resp.text}")


def create_policy_rule(request_body):
    """
    policy.rule.create => POST /api/v1/policies/{policyId}/rules
    Sample:
      {
        "policyId": "abc123XYZ",
        "name": "My rule",
        "priority": 1,
        "conditions": {},
        "actions": {}
      }
    """
    policy_id = request_body.pop("policyId", None)
    if not policy_id:
        raise ValueError("Missing 'policyId' in request_body")

    url = f"{OKTA_ORG_URL}/api/v1/policies/{policy_id}/rules"
    headers = {
        "Authorization": f"SSWS {OKTA_API_TOKEN}",
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    resp = requests.post(url, headers=headers, json=request_body)
    if resp.ok:
        return resp.json()
    raise Exception(f"policy.rule.create failed: {resp.status_code} {resp.text}")


def update_policy_rule(request_body):
    """
    policy.rule.update => PUT /api/v1/policies/{policyId}/rules/{ruleId}
    Sample:
      {
        "policyId": "abc123XYZ",
        "ruleId": "rl123AbC",
        "name": "Updated rule name",
        "priority": 2,
        ...
      }
    """
    policy_id = request_body.pop("policyId", None)
    rule_id = request_body.pop("ruleId", None)
    if not policy_id or not rule_id:
        raise ValueError("Missing 'policyId' or 'ruleId'")

    url = f"{OKTA_ORG_URL}/api/v1/policies/{policy_id}/rules/{rule_id}"
    headers = {
        "Authorization": f"SSWS {OKTA_API_TOKEN}",
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    resp = requests.put(url, headers=headers, json=request_body)
    if resp.ok:
        return resp.json()
    raise Exception(f"policy.rule.update failed: {resp.status_code} {resp.text}")


def delay_step(request_body):
    """
    delay => wait for 'seconds'
    Sample body:
      { "seconds": 10 }
    """
    secs = request_body.get("seconds", 1)
    time.sleep(secs)
    return {"status": f"Waited {secs} seconds"}

def _resolve_references(data, step_results):
    if isinstance(data, dict):
        if "$ref" in data:
            # Example: {"$ref": {"step": 2, "jsonPath": "id"}}
            ref_info = data["$ref"]
            step_idx = ref_info.get("step")
            path = ref_info.get("jsonPath", "")
            prev_resp = step_results.get(step_idx, {})
            # Simple example: only handle top-level keys
            return prev_resp.get(path, None)
        else:
            return {k: _resolve_references(v, step_results) for k, v in data.items()}
    elif isinstance(data, list):
        return [_resolve_references(item, step_results) for item in data]
    else:
        return data

def _random_string(n=5):
    return ''.join(random.choices(string.ascii_lowercase, k=n))

def randomize_body(event_type, body):
    new_body = json.loads(json.dumps(body))  # shallow copy
    if event_type == "user.create":
        first = "User" + _random_string()
        last = "Last" + _random_string()
        email = f"{first.lower()}@example.com"
        new_body["profile"]["firstName"] = first
        new_body["profile"]["lastName"] = last
        new_body["profile"]["email"] = email
        new_body["profile"]["login"] = email
    elif event_type == "group.create":
        new_body["profile"]["name"] = "Group_" + _random_string()
        new_body["profile"]["description"] = "Desc_" + _random_string()
    # add more random fields as needed
    return new_body


# -----------------------------------------------------------------------------
# 3) Full dictionary: event_type => { description, sample_body, api_handler }
#    We can add more or adapt as needed.
# -----------------------------------------------------------------------------
EVENT_DEFINITIONS = {
    # ---- Users ----
    "user.create": {
        "description": "Create a new user",
        "sample_body": {
            "profile": {
                "firstName": "Alice",
                "lastName": "Doe",
                "email": "alice@example.com",
                "login": "alice@example.com"
            },
            "credentials": {
                "password": { "value": "TempPass123" }
            },
            "activate": True
        },
        "api_handler": create_user
    },
    "user.delete": {
        "description": "Delete an existing user (must be deactivated first)",
        "sample_body": {
            "userId": "00u123abcXYZ"
        },
        "api_handler": delete_user
    },

    # ---- Groups ----
    "group.create": {
        "description": "Create a new group",
        "sample_body": {
            "profile": {
                "name": "Test Group",
                "description": "My Test Group"
            }
        },
        "api_handler": create_group
    },
    "group.delete": {
        "description": "Delete a group",
        "sample_body": {
            "groupId": "00g123abcXYZ"
        },
        "api_handler": delete_group
    },
    "group.assign_user": {
        "description": "Assign a user to a group",
        "sample_body": {
            "groupId": "00g123abcXYZ",
            "userId": "00u123abcXYZ"
        },
        "api_handler": assign_user_to_group
    },

    # ---- Applications ----
    "app.create": {
        "description": "Create an Okta application (e.g. OIDC/SAML)",
        "sample_body": {
            "name": "oidc_client",
            "label": "My OIDC App",
            "signOnMode": "OPENID_CONNECT",
            "credentials": {
                "oauthClient": {
                    "token_endpoint_auth_method": "client_secret_post"
                }
            },
            "settings": {
                "oauthClient": {
                    "redirect_uris": [
                        "https://example.com/callback"
                    ],
                    "response_types": ["code"],
                    "grant_types": ["authorization_code"]
                }
            }
        },
        "api_handler": create_app
    },
    "app.deactivate": {
        "description": "Deactivate an app (before deleting)",
        "sample_body": {
            "appId": "0oab1234xyz"
        },
        "api_handler": deactivate_app
    },
    "app.delete": {
        "description": "Delete an Okta app (must be deactivated first)",
        "sample_body": {
            "appId": "0oab1234xyz"
        },
        "api_handler": delete_app
    },
    "app.assign_user": {
        "description": "Assign a user to an app",
        "sample_body": {
            "appId": "0oab1234xyz",
            "userId": "00u123abcXYZ",
            # optionally "credentials": { "userName": "bob@example.com" }
        },
        "api_handler": assign_user_to_app
    },
    "app.assign_group": {
        "description": "Assign a group to an app",
        "sample_body": {
            "appId": "0oab1234xyz",
            "groupId": "00g123abcXYZ"
        },
        "api_handler": assign_group_to_app
    },

    # ---- Policies ----
    "policy.create": {
        "description": "Create a new policy (e.g. sign-on policy)",
        "sample_body": {
            "type": "OKTA_SIGN_ON",
            "name": "My Sign On Policy",
            "status": "ACTIVE",
            "description": "Example policy"
        },
        "api_handler": create_policy
    },
    "policy.delete": {
        "description": "Delete an existing policy",
        "sample_body": {
            "policyId": "abc123XYZ"
        },
        "api_handler": delete_policy
    },
    "policy.assign_app": {
        "description": "Assign policy to an app (sign-on policy example)",
        "sample_body": {
            "policyId": "abc123XYZ",
            "appId": "0oab1234xyz"
        },
        "api_handler": assign_policy_to_app
    },
    "policy.remove_app": {
        "description": "Remove an app from a policy assignment",
        "sample_body": {
            "policyId": "abc123XYZ",
            "appId": "0oab1234xyz"
        },
        "api_handler": remove_policy_from_app
    },

    # ---- Policy Rules ----
    "policy.rule.create": {
        "description": "Create a rule in a policy",
        "sample_body": {
            "policyId": "abc123XYZ",
            "name": "My rule",
            "priority": 1,
            "conditions": {},
            "actions": {}
        },
        "api_handler": create_policy_rule
    },
    "policy.rule.update": {
        "description": "Update an existing policy rule",
        "sample_body": {
            "policyId": "abc123XYZ",
            "ruleId": "rl123AbC",
            "name": "Updated rule name",
            "priority": 2
        },
        "api_handler": update_policy_rule
    },
    "delay": {
        "description": "Wait for some seconds",
        "sample_body": {"seconds": 10},
        "api_handler": delay_step
    }
}

ALL_EVENT_KEYS = sorted(EVENT_DEFINITIONS.keys())


# -----------------------------------------------------------------------------
# StepDialog: A popup that lets the user pick an event_type & see/edit its JSON
# -----------------------------------------------------------------------------
class StepDialog:
    def __init__(self, parent, event_keys):
        self.parent = parent
        self.event_keys = event_keys
        self.result = None  # (event_type, request_body)
        
        self.top = tk.Toplevel(parent)
        self.top.title("Add Okta Action Step")
        self.top.protocol("WM_DELETE_WINDOW", self.on_cancel)
        self.top.resizable(True, True)

        tk.Label(self.top, text="Action Type:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.E)
        self.event_combo = ttk.Combobox(self.top, values=event_keys, state="readonly", width=50)
        self.event_combo.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        if event_keys:
            self.event_combo.current(0)
        self.event_combo.bind("<<ComboboxSelected>>", self.on_event_change)

        self.desc_label_var = tk.StringVar(value="")
        self.desc_label = tk.Label(
            self.top, textvariable=self.desc_label_var,
            fg="gray", wraplength=400, justify=tk.LEFT
        )
        self.desc_label.grid(row=1, column=0, columnspan=2, sticky=tk.W, padx=10)

        tk.Label(self.top, text="Request Body (JSON):").grid(
            row=2, column=0, padx=5, pady=5, sticky=tk.NE)
        self.body_text = tk.Text(self.top, width=60, height=12)
        self.body_text.grid(row=2, column=1, padx=5, pady=5, sticky=tk.W)

        # Buttons
        btn_frame = tk.Frame(self.top)
        btn_frame.grid(row=3, column=0, columnspan=2, pady=5)
        random_btn = tk.Button(btn_frame, text="Random", command=self.on_random)
        random_btn.pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="OK", width=10, command=self.on_ok).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Cancel", width=10, command=self.on_cancel).pack(side=tk.LEFT, padx=5)

        self.update_body_and_description()

        self.top.transient(parent)
        self.top.grab_set()
        self.top.wait_window()

    def on_event_change(self, event=None):
        self.update_body_and_description()

    def update_body_and_description(self):
        current_key = self.event_combo.get()
        info = EVENT_DEFINITIONS.get(current_key, {})
        sample_body = info.get("sample_body", {})
        desc = info.get("description", current_key)
        self.desc_label_var.set(desc)

        self.body_text.delete("1.0", tk.END)
        try:
            text = json.dumps(sample_body, indent=2)
        except:
            text = str(sample_body)
        self.body_text.insert(tk.END, text)

    def on_random(self):
        current_key = self.event_combo.get()
        if not current_key:
            return
        info = EVENT_DEFINITIONS.get(current_key, {})
        sample_body = info.get("sample_body", {})
        randomized = randomize_body(current_key, sample_body)
        self.body_text.delete("1.0", tk.END)
        self.body_text.insert(tk.END, json.dumps(randomized, indent=2))

    def on_ok(self):
        event_type = self.event_combo.get()
        raw_text = self.body_text.get("1.0", tk.END).strip()
        try:
            body_json = json.loads(raw_text)
        except json.JSONDecodeError:
            messagebox.showerror("Invalid JSON", "Please provide valid JSON in the body.")
            return
        self.result = (event_type, body_json)
        self.top.destroy()

    def on_cancel(self):
        self.result = None
        self.top.destroy()


# -----------------------------------------------------------------------------
# Main GUI: TestCaseBuilder
# -----------------------------------------------------------------------------
class TestCaseBuilder:
    def __init__(self, root):
        self.root = root
        self.root.title("Okta Admin Automation Tool - Common Actions")
        self.root.geometry("1000x700")
        self.step_data = {}
        self._build_ui()

    def _build_ui(self):
        # Top row of buttons
        top_frame = tk.Frame(self.root)
        top_frame.pack(fill=tk.X, padx=10, pady=5)

        tk.Button(top_frame, text="New Test Case", command=self.new_test_case).pack(side=tk.LEFT, padx=5)
        tk.Button(top_frame, text="Load Test Case", command=self.load_test_case).pack(side=tk.LEFT, padx=5)
        tk.Button(top_frame, text="Save Test Case", command=self.save_test_case).pack(side=tk.LEFT, padx=5)
        tk.Button(top_frame, text="Run Test Case", command=self.run_test_case).pack(side=tk.LEFT, padx=5)

        # Paned window: steps on left, console on right
        paned = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Left side: steps
        steps_frame = tk.Frame(paned)
        paned.add(steps_frame, weight=1)

        self.steps_tree = ttk.Treeview(steps_frame, columns=("Action", "Body"), show="headings")
        self.steps_tree.heading("Action", text="Okta Action")
        self.steps_tree.heading("Body", text="Body (JSON snippet)")
        self.steps_tree.column("Action", width=220)
        self.steps_tree.column("Body", width=400)
        self.steps_tree.pack(fill=tk.BOTH, expand=True, side=tk.TOP)

        step_btn_frame = tk.Frame(steps_frame)
        step_btn_frame.pack(fill=tk.X, pady=5)
        tk.Button(step_btn_frame, text="Add Step", command=self.add_step).pack(side=tk.LEFT, padx=5)
        tk.Button(step_btn_frame, text="Remove Step", command=self.remove_step).pack(side=tk.LEFT, padx=5)

        # Right side: console
        console_frame = tk.Frame(paned)
        paned.add(console_frame, weight=1)

        tk.Label(console_frame, text="Console Output:").pack(anchor="w")
        self.console_text = tk.Text(console_frame, state="disabled")
        self.console_text.pack(fill=tk.BOTH, expand=True)

        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = tk.Label(self.root, textvariable=self.status_var, bd=1, relief=tk.SUNKEN, anchor="w")
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def log(self, msg: str):
        self.console_text.config(state="normal")
        self.console_text.insert(tk.END, msg + "\n")
        self.console_text.config(state="disabled")
        self.console_text.see(tk.END)
        print(msg)

    def set_status(self, msg: str):
        self.status_var.set(msg)
        self.root.update_idletasks()

    # -------------------------------
    # Test case (steps) management
    # -------------------------------
    def new_test_case(self):
        for child in self.steps_tree.get_children():
            self.steps_tree.delete(child)
        self.log("Started a new test case.")
        self.set_status("New test case")

    def add_step(self):
        dialog = StepDialog(self.root, ALL_EVENT_KEYS)
        if dialog.result:
            event_type, body_json = dialog.result
            snippet = json.dumps(body_json)[:300]
            step_iid = self.steps_tree.insert("", "end", values=(event_type, snippet))
            self.step_data[step_iid] = body_json
            self.log(f"Added step: {event_type}")
            self.set_status("Step added")

    def remove_step(self):
        selection = self.steps_tree.selection()
        for sel in selection:
            self.steps_tree.delete(sel)
            if sel in self.step_data:
                del self.step_data[sel]
        self.log("Removed selected steps.")
        self.set_status("Steps removed")

    def save_test_case(self):
        steps = []
        for child in self.steps_tree.get_children():
            action, short_body = self.steps_tree.item(child, "values")
            steps.append({"event_type": action, "request_body": self.step_data.get(child, {})})

        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON Files","*.json")])
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(steps, f, indent=2)
            self.log(f"Saved test case to {path}")
            self.set_status(f"Saved {path}")
        except Exception as e:
            messagebox.showerror("Error", f"Could not save: {e}")

    def load_test_case(self):
        path = filedialog.askopenfilename(filetypes=[("JSON Files","*.json")])
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            messagebox.showerror("Error", f"Could not load: {e}")
            return

        for child in self.steps_tree.get_children():
            self.steps_tree.delete(child)

        for step in data:
            event_type = step.get("event_type", "")
            full_json = step.get("request_body", {})
            snippet = json.dumps(full_json)[:300]
            iid = self.steps_tree.insert("", "end", values=(event_type, snippet))
            self.step_data[iid] = full_json
        self.log(f"Loaded test case from {path}")
        self.set_status(f"Loaded {path}")

    def run_test_case(self):
        steps = []
        for child in self.steps_tree.get_children():
            action, snippet = self.steps_tree.item(child, "values")
            steps.append({"event_type": action, "body_str": snippet})

        self.set_status("Running test case...")
        thread = threading.Thread(target=self._execute_steps, args=(steps,), daemon=True)
        thread.start()

    # -------------------------------
    # Execution of steps
    # -------------------------------
    def _execute_steps(self, steps):
        self.log("=== Starting Test Execution ===")
        step_results = {}
        for i, step in enumerate(steps, start=1):
            event_type = step["event_type"]
            snippet = step["body_str"] or "{}"
            self.log(f"Step {i}: {event_type}")

            # Attempt to parse snippet
            try:
                raw_body = json.loads(snippet)
            except:
                self.log("  Invalid JSON in request_body, skipping step.")
                continue

            # Replace any references in the JSON
            req_body = _resolve_references(raw_body, step_results)

            definition = EVENT_DEFINITIONS.get(event_type)
            if not definition:
                self.log(f"  No definition found for event '{event_type}', skipping.")
                continue
            handler = definition.get("api_handler")
            if not callable(handler):
                self.log(f"  No API handler for '{event_type}', skipping.")
                continue

            try:
                max_retries = 3
                resp_data = None
                for attempt in range(max_retries):
                    resp_data = handler(req_body)
                    # For rate-limit example, if '429' is part of resp_data, etc.
                    if isinstance(resp_data, dict) and resp_data.get("status_code") == 429:
                        time.sleep(2)
                        continue
                    break
                step_results[i] = resp_data if isinstance(resp_data, dict) else {}
                self.log(f"  Success: {resp_data}")
            except Exception as ex:
                self.log(f"  Error: {ex}")
            time.sleep(1)

        self.log("=== Test Execution Finished ===")
        self.set_status("Ready")


# -----------------------------------------------------------------------------
# Entry point
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    root = tk.Tk()
    app = TestCaseBuilder(root)
    root.mainloop()
