from flask import Flask, request, redirect, render_template
import requests
import hmac
import hashlib
import json

app = Flask(__name__)

API_KEY = "cad8562e309056451cfabd7ec0db475f"
API_SECRET = "5b482566f1284d8e9fe8a5b4907dfd8d"
REDIRECT_URI = "https://5ff1022c.r15.cpolar.top/auth/callback"
SCOPES = "read_themes,write_themes"

access_token = None
shop_url = "harvey-teststore.myshopify.com"
js_injection_enabled = False
resources = []

@app.route('/auth')
def auth():
    shop = request.args.get('shop')
    if not shop:
        return "Missing shop parameter", 400

    global shop_url
    shop_url = shop

    state = "unique_nonce_value"

    auth_url = (
        f"https://{shop}/admin/oauth/authorize?"
        f"client_id={API_KEY}&scope={SCOPES}&redirect_uri={REDIRECT_URI}&state={state}"
    )

    return redirect(auth_url)

@app.route('/auth/callback')
def auth_callback():
    global access_token

    shop = request.args.get('shop')
    code = request.args.get('code')
    hmac_param = request.args.get('hmac')
    state = request.args.get('state')

    if not (shop and code and hmac_param and state):
        return "Missing parameters", 400

    if not validate_hmac(request.args, API_SECRET):
        return "Invalid HMAC validation", 403

    try:
        access_token = get_access_token(shop, code)
        if access_token:
            if js_injection_enabled:
                inject_js(shop)
    except Exception as e:
        return f"Failed to get access token: {e}", 500

    return redirect('/')

@app.route('/')
def home():
    if not access_token:
        return (
            "<h1>Welcome to your Shopify App</h1>"
            "<p>Please <a href='/auth?shop=harvey-teststore.myshopify.com'>authorize the app</a> to continue.</p>"
        )

    return render_template('admin.html', js_injection_enabled=js_injection_enabled, resources=resources)

@app.route('/toggle_js', methods=['POST'])
def toggle_js():
    global js_injection_enabled
    js_injection_enabled = request.form.get('toggle_js') == 'on'
    if access_token and shop_url:
        if js_injection_enabled:
            inject_js(shop_url)
        else:
            remove_js(shop_url)
    return redirect('/')

@app.route('/add_resource', methods=['POST'])
def add_resource():
    global resources
    resource_type = request.form.get('resource_type')
    resource_content = request.form.get('resource_content')

    if resource_type not in ['js', 'css']:
        return "Invalid resource type", 400

    resource_id = len(resources) + 1
    resources.append({"id": resource_id, "type": resource_type, "content": resource_content})
    if access_token and shop_url:
        inject_js(shop_url)
    return redirect('/')

@app.route('/remove_resource', methods=['POST'])
def remove_resource():
    global resources
    resource_id = int(request.form.get('resource_id'))

    resources = [res for res in resources if res['id'] != resource_id]
    if access_token and shop_url:
        inject_js(shop_url)
    return redirect('/')

def get_access_token(shop, code):
    url = f"https://{shop}/admin/oauth/access_token"
    payload = {
        "client_id": API_KEY,
        "client_secret": API_SECRET,
        "code": code
    }
    response = requests.post(url, json=payload, timeout=30)
    response.raise_for_status()

    data = response.json()
    return data.get("access_token")

def validate_hmac(query_params, secret):
    hmac_param = query_params.get('hmac')
    if not hmac_param:
        return False

    sorted_keys = sorted(k for k in query_params if k != 'hmac')
    message = '&'.join(f"{k}={query_params[k]}" for k in sorted_keys)
    
    expected_hmac = hmac.new(
        key=secret.encode('utf-8'),
        msg=message.encode('utf-8'),
        digestmod=hashlib.sha256
    ).hexdigest()

    return hmac_param == expected_hmac

def inject_js(shop):
    url = f"https://{shop}/admin/api/2024-07/themes.json"
    response = requests.get(url, headers={"X-Shopify-Access-Token": access_token})
    response.raise_for_status()

    themes = response.json().get("themes", [])
    for theme in themes:
        if theme.get("role") == "main":
            theme_id = theme["id"]
            add_resources_to_theme(shop, theme_id)

def remove_js(shop):
    url = f"https://{shop}/admin/api/2024-07/themes.json"
    response = requests.get(url, headers={"X-Shopify-Access-Token": access_token})
    response.raise_for_status()

    themes = response.json().get("themes", [])
    for theme in themes:
        if theme.get("role") == "main":
            theme_id = theme["id"]
            remove_resources_from_theme(shop, theme_id)

def add_resources_to_theme(shop, theme_id):
    asset_url = f"https://{shop}/admin/api/2024-07/themes/{theme_id}/assets.json"
    for resource in resources:
        if resource["type"] == "js":
            script_tag = f'<script>{resource["content"]}</script>'
        elif resource["type"] == "css":
            script_tag = f'<style>{resource["content"]}</style>'
        
        params = {
            "asset[key]": "layout/theme.liquid"
        }
        response = requests.get(asset_url, headers={"X-Shopify-Access-Token": access_token}, params=params)
        response.raise_for_status()

        asset = response.json().get("asset", {})
        existing_content = asset.get("value", "")
        new_content = existing_content.replace("</body>", f"{script_tag}</body>")

        payload = {
            "asset": {
                "key": "layout/theme.liquid",
                "value": new_content
            }
        }
        response = requests.put(asset_url, json=payload, headers={"X-Shopify-Access-Token": access_token})
        response.raise_for_status()

def remove_resources_from_theme(shop, theme_id):
    asset_url = f"https://{shop}/admin/api/2024-07/themes/{theme_id}/assets.json"
    params = {
        "asset[key]": "layout/theme.liquid"
    }
    response = requests.get(asset_url, headers={"X-Shopify-Access-Token": access_token}, params=params)
    response.raise_for_status()

    asset = response.json().get("asset", {})
    existing_content = asset.get("value", "")
    for resource in resources:
        if resource["type"] == "js":
            script_tag = f'<script>{resource["content"]}</script>'
        elif resource["type"] == "css":
            script_tag = f'<style>{resource["content"]}</style>'

        new_content = existing_content.replace(script_tag, "")
        payload = {
            "asset": {
                "key": "layout/theme.liquid",
                "value": new_content
            }
        }
        response = requests.put(asset_url, json=payload, headers={"X-Shopify-Access-Token": access_token})
        response.raise_for_status()

if __name__ == "__main__":
    app.run(port=8080)