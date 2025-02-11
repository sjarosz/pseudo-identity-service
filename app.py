import logging
from flask import Flask, request, jsonify
import json
import os
import uuid
import base64
import datetime
import bcrypt
import logging

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")

app = Flask(__name__)

# ------------------------------------------------------------------------------
# LOGGING CONFIGURATION
# ------------------------------------------------------------------------------
# Configure the logging module to write DEBUG (and above) messages to a file.
# Adjust filename, level, and format as you prefer.
logging.basicConfig(
    filename="/app/logs/app.log",  # Change path as needed
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

# Path to our JSON data file
DATA_FILE = 'data.json'

# We'll keep our data in memory in a global 'store'.
store = {}

def load_data():
    """
    Load the data from data.json or return an empty dict if the file doesn't
    exist or fails to parse.
    """

    password = "P@ssw0rd"
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    logging.debug("All users password is 'P@ssw0rd' and hashed value is: "+hashed_password.decode('utf-8'))


    if not os.path.exists(DATA_FILE):
        logging.debug("DATA_FILE does not exist, initializing empty store.")
        return {}

    with open(DATA_FILE, 'r', encoding='utf-8') as f:
        try:
            data = json.load(f)
            logging.debug("Loaded data from %s successfully.", DATA_FILE)
            return data
        except json.JSONDecodeError as e:
            logging.debug("Failed to decode JSON from %s: %s", DATA_FILE, e)
            return {}

def save_data(data):
    """
    Save the data dict back into data.json (overwrites file).
    """
    with open(DATA_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)
    logging.debug("Saved updated data to %s.", DATA_FILE)

# Load data into 'store' at import/startup time.
store = load_data()

def get_user_by_email(email):
    if isinstance(store, dict):
        for user in store.get("user", []):
            logging.debug("debug %s.", user)

            if user.get("email") == email:
                return user
      
    return None

def get_request_data():
    """
    Helper function:
    1. Attempts to parse JSON from request body (request.get_json(silent=True)).
    2. If that fails or is None, returns request.form instead.
    This allows endpoints to accept either JSON or form-encoded data.
    """
    data = request.get_json(silent=True)
    if data is None:
        data = request.form

    logging.debug("get_request_data() -> %s", data)
    return data


# ------------------------------------------------------------------------------
# 0) OAuth Token Endpoint
# ------------------------------------------------------------------------------


@app.route('/oauth/token', methods=['POST'])
def oauth_token():
    # Parse Authorization header
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Basic '):
        return jsonify({"error": "invalid_request", "error_description": "Missing or invalid Authorization header."}), 400

    # Decode Base64 credentials
    try:
        base64_credentials = auth_header.split(' ')[1]
        credentials = base64.b64decode(base64_credentials).decode('utf-8')
        client_id, client_secret = credentials.split(':')
    except Exception:
        return jsonify({"error": "invalid_request", "error_description": "Invalid Authorization header format."}), 400

    # Validate grant type and refresh token
    grant_type = request.form.get('grant_type')
    refresh_token = request.form.get('refresh_token')

    if grant_type != 'refresh_token' or not refresh_token:
        return jsonify({"error": "invalid_request", "error_description": "Invalid grant type or missing refresh token."}), 400

    # Validate user credentials
    user = get_user_by_email(client_id)
    if not user:
        return jsonify({"error": "invalid_client", "error_description": "User not found."}), 401

    hashed_password = user.get("password", {}).get("value", "")
    if not bcrypt.checkpw(client_secret.encode('utf-8'), hashed_password.encode('utf-8')):
        return jsonify({"error": "invalid_client", "error_description": "Invalid credentials."}), 401

    # Simulate token generation
    new_access_token = base64.b64encode(b"new_access_token").decode('utf-8')
    new_refresh_token = base64.b64encode(b"new_refresh_token").decode('utf-8')
    expires_in = 3600  # 1 hour

    response = {
        "access_token": new_access_token,
        "expires_in": expires_in,
        "refresh_token": new_refresh_token,
        "user": {
            "id": user.get("id"),
            "username": user.get("username"),
            "fullName": user.get("fullName"),
            "email": user.get("email")
        },
        "stat": "ok"
    }

    return jsonify(response)



# ------------------------------------------------------------------------------
# 1a) GET /entity
# ------------------------------------------------------------------------------
@app.route('/entity', methods=['GET'])
def get_entities():
    """
    GET /entity:
    - Returns all 'user' elements from the data file.
    - Wraps the response in {"result": <data>, "stat": "ok"}.
    """
    logging.debug("=== [GET /entity] Incoming request ===")
    
    # Extract all 'user' elements
    user_data = store.get('user', [])
    
    # Wrap the response
    response = {
        "result": user_data,
        "stat": "ok"
    }
    
    logging.debug("[GET /entity] Returning user data: %s", response)
    return jsonify(response), 200

# ------------------------------------------------------------------------------
# 1b) POST /entity
# ------------------------------------------------------------------------------
@app.route('/entity', methods=['POST'])
def entity():
    """
    POST /entity:
    1. Reads type_name, attributes, key_attribute, key_value from the request body.
    2. Searches for the first matching entity in store[type_name].
    3. Returns only the requested attributes in {"result": {...}, "stat": "ok"}.
    """
    logging.debug("=== [POST /entity] Incoming request ===")
    data = get_request_data()

    type_name   = data.get('type_name')
    attributes  = data.get('attributes')
    key_attr    = data.get('key_attribute')
    key_value   = data.get('key_value')

    logging.debug("Parsed fields -> type_name: %s, attributes: %s, key_attr: %s, key_value: %s",
                  type_name, attributes, key_attr, key_value)

    # Handle attributes which may be a JSON string or a Python list
    if isinstance(attributes, str):
        try:
            attributes = json.loads(attributes)
        except:
            attributes = []
    elif attributes is None:
        attributes = []

    # Strip quotes if key_value is wrapped in double quotes
    if isinstance(key_value, str) and key_value.startswith('"') and key_value.endswith('"'):
        key_value = key_value.strip('"')

    # Validate the existence of type_name in our store
    if not type_name or type_name not in store:
        logging.debug("[POST /entity] type_name missing or not found in store.")
        return jsonify({"result": {}, "stat": "ok"})

    matched_item = None
    for item in store[type_name]:
        if str(item.get(key_attr, '')) == str(key_value):
            matched_item = item
            break

    if not matched_item:
        logging.debug("[POST /entity] No matching item found.")
        return jsonify({"result": {}, "stat": "ok"})

    # Build a result dict with only the requested attributes
    result = {}
    for attr in attributes:
        result[attr] = matched_item.get(attr)

    logging.debug("[POST /entity] Returning attributes: %s", result)
    return jsonify({"result": result, "stat": "ok"})


# ------------------------------------------------------------------------------
# 2) POST /entity.find
# ------------------------------------------------------------------------------
@app.route('/entity.find', methods=['POST'])
def entity_find():
    """
    POST /entity.find:
    1. Reads type_name, filter, attributes, sort_on from the request body.
    2. Filters the data based on simple "and"-separated key=value pairs (naive approach).
    3. Returns the filtered records (only requested attributes) in sorted order.
    """
    logging.debug("=== [POST /entity.find] Incoming request ===")
    data = get_request_data()

    type_name   = data.get('type_name')
    filter_str  = data.get('filter', '')
    attributes  = data.get('attributes')
    sort_on     = data.get('sort_on')

    logging.debug("Parsed fields -> type_name: %s, filter: %s, attributes: %s, sort_on: %s",
                  type_name, filter_str, attributes, sort_on)

    # Convert attributes and sort_on which may be JSON strings or lists
    if isinstance(attributes, str):
        try:
            attributes = json.loads(attributes)
        except:
            attributes = []
    elif attributes is None:
        attributes = []

    if isinstance(sort_on, str):
        try:
            sort_on = json.loads(sort_on)
        except:
            sort_on = []
    elif sort_on is None:
        sort_on = []

    if not type_name or type_name not in store:
        logging.debug("[POST /entity.find] type_name missing or not found in store.")
        return jsonify({"result_count": 0, "results": [], "stat": "ok"})

    entities = store[type_name]

    # Parse the filter string (a naive approach splitting on " and ").
    criteria = []
    if filter_str:
        parts = filter_str.split(" and ")
        for part in parts:
            if "=" in part:
                left, right = part.split("=", 1)
                left = left.strip()
                right = right.strip().strip("'")
                criteria.append((left, right))

    logging.debug("Filter criteria parsed -> %s", criteria)

    def matches_filter(entity):
        """
        Checks if a single entity matches all (field_path, expected_value) pairs.
        Example of field_path might be "primaryAddress.company".
        """
        for (field_path, expected_value) in criteria:
            parts = field_path.split(".")
            tmp_val = entity
            for p in parts:
                if isinstance(tmp_val, dict) and p in tmp_val:
                    tmp_val = tmp_val[p]
                else:
                    return False
            if str(tmp_val) != expected_value:
                return False
        return True

    # Filter the entities
    filtered = [e for e in entities if matches_filter(e)]
    logging.debug("Filtered results (before sort): %s", filtered)

    # Sort results if sort_on list was provided
    for attr in reversed(sort_on):
        filtered.sort(key=lambda x: x.get(attr, ''))

    # Build the final results with only requested attributes
    results = []
    for item in filtered:
        result_item = {}
        for attr in attributes:
            result_item[attr] = item.get(attr)
        results.append(result_item)

    logging.debug("[POST /entity.find] Found %d results. Returning subset of attributes.", len(results))

    return jsonify({
        "result_count": len(results),
        "results": results,
        "stat": "ok"
    })


# ------------------------------------------------------------------------------
# 3) POST /entity.count
# ------------------------------------------------------------------------------
@app.route('/entity.count', methods=['POST'])
def entity_count():
    """
    POST /entity.count:
    - Simply counts the total number of entities across all types in 'store'.
    - Optionally, could accept a type_name if needed, but currently doesn't.
    - Returns {"total_count": N, "stat": "ok"}.
    """
    logging.debug("=== [POST /entity.count] Incoming request ===")
    data = get_request_data()  # Not used in this minimal example, but might be needed later

    total_count = sum(len(items) for items in store.values())
    logging.debug("[POST /entity.count] Total entity count: %d", total_count)

    return jsonify({
        "total_count": total_count,
        "stat": "ok"
    })


# ------------------------------------------------------------------------------
# 4) POST /entity.update
# ------------------------------------------------------------------------------
@app.route('/entity.update', methods=['POST'])
def entity_update():
    """
    POST /entity.update:
    - Reads type_name, key_attribute, key_value, updates from the request body.
    - Locates the first matching entity and applies the key-value pairs in 'updates'.
    - Returns {"stat": "ok"} whether it updates or not.
    """
    logging.debug("=== [POST /entity.update] Incoming request ===")
    data = get_request_data()

    type_name  = data.get('type_name')
    key_attr   = data.get('key_attribute')
    key_value  = data.get('key_value')
    updates    = data.get('updates')

    logging.debug("Parsed fields -> type_name: %s, key_attr: %s, key_value: %s, updates: %s",
                  type_name, key_attr, key_value, updates)

    # updates might be a JSON string or a dict
    if isinstance(updates, str):
        try:
            updates = json.loads(updates)
        except:
            updates = {}
    elif updates is None:
        updates = {}

    if not type_name or type_name not in store:
        logging.debug("[POST /entity.update] type_name missing or not in store: %s", type_name)
        return jsonify({"stat": "ok"})

    # Strip extra quotes from key_value if present
    if isinstance(key_value, str) and key_value.startswith('"') and key_value.endswith('"'):
        key_value = key_value.strip('"')

    updated = False
    for item in store[type_name]:
        if str(item.get(key_attr, '')) == str(key_value):
            logging.debug("Matching item found: %s, applying updates: %s", item, updates)
            for k, v in updates.items():
                if k == "password" and isinstance(v, str):
                    hashed_password = bcrypt.hashpw(v.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                    item[k] = {"value": hashed_password, "type": "password-bcrypt"}
                elif isinstance(v, dict) and isinstance(item.get(k), dict):
                    item[k].update(v)  # Merge nested dictionary updates
                else:
                    item[k] = v


            updated = True
            break

    if updated:
        save_data(store)
        logging.debug("[POST /entity.update] Data updated and saved.")
    else:
        logging.debug("[POST /entity.update] No matching item found, no update performed.")

    return jsonify({"stat": "ok"})


# ------------------------------------------------------------------------------
# 5) POST /entity.create
# ------------------------------------------------------------------------------
@app.route('/entity.create', methods=['POST'])
def entity_create():
    """
    POST /entity.create:
    1. Reads type_name, attributes.
    2. Generates a new ID (max+1 in the list) and a new UUID.
    3. Creates the new entity and saves it in store[type_name].
    4. Returns {"id": <new_id>, "stat": "ok", "uuid": <new_uuid>}.
    """
    logging.debug("=== [POST /entity.create] Incoming request ===")
    data = get_request_data()

    type_name  = data.get('type_name')
    attributes = data.get('attributes')

    logging.debug("Parsed fields -> type_name: %s, attributes: %s", type_name, attributes)

    # attributes might be a JSON string or a dict
    if isinstance(attributes, str):
        try:
            attributes = json.loads(attributes)
        except:
            attributes = {}
    elif attributes is None:
        attributes = {}

    if not type_name:
        logging.debug("[POST /entity.create] type_name missing, returning default response.")
        return jsonify({"id": None, "stat": "ok", "uuid": ""})

    if type_name not in store:
        store[type_name] = []

    existing_ids = [item.get('id', 0) for item in store[type_name]]
    max_id = max(existing_ids) if existing_ids else 0
    new_id = max_id + 1

    new_uuid = str(uuid.uuid4())

    new_entity = {
        "id": new_id,
        "uuid": new_uuid
    }
    new_entity.update(attributes)

    store[type_name].append(new_entity)
    save_data(store)

    logging.debug("[POST /entity.create] Created entity with id=%d, uuid=%s", new_id, new_uuid)

    return jsonify({
        "id": new_id,
        "stat": "ok",
        "uuid": new_uuid
    })


# ------------------------------------------------------------------------------
# 6) POST /entity.delete
# ------------------------------------------------------------------------------
@app.route('/entity.delete', methods=['POST'])
def entity_delete():
    """
    POST /entity.delete:
    1. Reads type_name, key_attribute, key_value from the request body.
    2. Deletes the *first* matching item in store[type_name].
    3. Saves the updated store to data.json if an item was deleted.
    4. Returns {"stat": "ok"} always.
    """
    logging.debug("=== [POST /entity.delete] Incoming request ===")
    data = get_request_data()
    logging.debug("DEBUG - Incoming data: %s", data)

    type_name = data.get('type_name')
    key_attr  = data.get('key_attribute')
    key_value = data.get('key_value')

    logging.debug("DEBUG - Checking for type: %s, key_attr: %s, key_value: %s",
                  type_name, key_attr, key_value)

    if not type_name or type_name not in store:
        logging.debug("DEBUG - type_name missing or not in store: %s", type_name)
        return jsonify({"stat": "ok"})

    if isinstance(key_value, str) and key_value.startswith('"') and key_value.endswith('"'):
        key_value = key_value.strip('"')

    new_list = []
    deleted = False

    for item in store[type_name]:
        logging.debug("DEBUG - Checking item: %s", item)
        if str(item.get(key_attr, '')) == str(key_value) and not deleted:
            logging.debug("DEBUG - Found match! Deleting: %s", item)
            deleted = True
            # Skip adding this to new_list (i.e., we "delete" it)
        else:
            new_list.append(item)

    store[type_name] = new_list

    if deleted:
        save_data(store)
        logging.debug("DEBUG - Deleted item and saved data.")
    else:
        logging.debug("DEBUG - No matching item found, nothing deleted.")

    return jsonify({"stat": "ok"})


# ------------------------------------------------------------------------------
# MAIN ENTRY POINT
# ------------------------------------------------------------------------------
if __name__ == '__main__':
    # Running Flask directly. Ensure the /app/logs folder exists for app.log if needed.
    os.makedirs('/app/logs', exist_ok=True)
    logging.debug("Starting Flask app on 0.0.0.0:5000.")
    app.run(host='0.0.0.0', port=5000, debug=True)
