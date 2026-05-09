import requests
import urllib3
import re
import json
import os
import js2py
from datetime import datetime
import socket
from structure import get_struct_report_file
import xml.etree.ElementTree as ET
from playwright.sync_api import sync_playwright
import random
from urllib.parse import urlparse, urlunparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

REPORT_DIR = "reports"
SUSPICIOUS_WORDS = ["test","123","2","teste","dev","old","anonymous","screen1","screen2"]
SUSPICIOUS_EXTENSIONS = {".xlsx",".xls",".doc",".docx",".aspx",".xml",".pdf",".exe",".txt",".zip",".ppt",".pts",".7z",".rar",".oml",".oap",".backup",".bkp","backup","bkp",".sql",".abk",".tmp",".bak",".tm",".csv",".ical",".ics",".bin",".yaml",".json"}
CONFIG = {}

def load_config():
    global CONFIG
    with open("config.json", "r") as f:
        CONFIG = json.load(f)
        return CONFIG
    
def save_config(data):
    with open("config.json", "w") as f:
        json.dump(data, f, indent=4)

def random_headers():

    user_agents = [
        # Desktop
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",

        # Mobile
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Mobile Safari/537.36",
    ]

    accept = [
        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "application/json, text/plain, */*",
        "*/*"
    ]

    accept_language = [
        "en-US,en;q=0.9",
        "pt-BR,pt;q=0.9,en-US;q=0.8",
        "es-ES,es;q=0.9,en;q=0.8",
        "fr-FR,fr;q=0.9,en;q=0.8"
    ]

    encodings = ["gzip, deflate, br", "gzip, deflate", "br"]

    sec_fetch_site = ["same-origin", "same-site", "cross-site", "none"]
    sec_fetch_mode = ["cors", "navigate", "no-cors", "same-origin"]
    sec_fetch_dest = ["empty", "document", "script", "style", "image"]

    optional_headers = {
        "Upgrade-Insecure-Requests": random.choice(["1", None]),
        "X-Requested-With": random.choice(["XMLHttpRequest", None]),
        "DNT": random.choice(["1", "0", None]),
        "Pragma": random.choice(["no-cache", None]),
        "Cache-Control": random.choice(["no-cache", "max-age=0", None]),
    }

    base_headers = {
        "User-Agent": random.choice(user_agents),
        "Accept": random.choice(accept),
        "Accept-Language": random.choice(accept_language),
        "Accept-Encoding": random.choice(encodings),
        "Connection": random.choice(["keep-alive", "close"]),
        "Sec-Fetch-Site": random.choice(sec_fetch_site),
        "Sec-Fetch-Mode": random.choice(sec_fetch_mode),
        "Sec-Fetch-Dest": random.choice(sec_fetch_dest),

        "X-TOOL": "OSANALYZER"
    }

    for k, v in optional_headers.items():
        if v:
            base_headers[k] = v

    items = list(base_headers.items())
    random.shuffle(items)

    return dict(items)

def build_headers(required: dict = None):
    
    if CONFIG.get("use_random_headers", True):
        headers = random_headers()
    else:
        
        headers = {
            "X-TOOL": "OSANALYZER"
        }

    if required:
        headers.update(required)

    return headers

def load_json(path: str):
    if CONFIG.get("debug_mode", True):
        print(f"Reading JSON from Structure.")
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def save_json(path: str, data: dict):
    if CONFIG.get("debug_mode", True):
        print(f"Saving JSON from the structure.")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=4)

def get_report_paths(accesskey: str):
    folder = os.path.join(REPORT_DIR, accesskey)
    data_file = os.path.join(folder, f"{accesskey}_map.json")
    report_file = os.path.join(folder, f"{accesskey}.json")
    return data_file, report_file

def build_url_application(subdomain: str, domain: str, modulename: str) -> str:
    if CONFIG.get("debug_mode", True):
        print(f"Building the application's URL.")
    subdomain_part = f"{subdomain}." if subdomain else ""
    environment = f"https://{subdomain_part}{domain}"

    url = f"{environment}/{modulename}/"
    return url

def finish_scan(accesskey: str) -> bool:
    if CONFIG.get("debug_mode", True):
        print(f"Finishing the application scan.")
    _, report_file = get_report_paths(accesskey)

    report = load_json(report_file)
    if report is None:
        print(f"Relatório não encontrado: {report_file}")
        return False
    
    if "metadata" not in report:
        report["metadata"] = {}

    report["metadata"]["status"] = "completed"
    report["metadata"]["finished_at"] = datetime.utcnow().isoformat()

    save_json(report_file, report)
    return True

def get_real_dns(accesskey: str) -> bool:

    _, report_file = get_report_paths(accesskey)
    report = load_json(report_file)

    if report is None:
        print(f"Report not found: {report_file}")
        return False

    subdomain = report["target"].get("subdomain", "")
    domain = report["target"].get("domain", "")
    modulename = report["target"].get("modulename", "")

    if not domain or not modulename:
        print("The report is missing 'domain' or 'modulename'.")
        return False

    subdomain_part = f"{subdomain}." if subdomain else ""
    environment = f"{subdomain_part}{domain}"

    url = f"{environment}/{modulename}/"

    try:
        host = socket.gethostbyname(url)
        ip_address = socket.gethostbyaddr(host)[0]
        real_dns = ip_address

    except socket.gaierror:
        real_dns = url

    if "target" not in report:
        report["target"] = {}

    report["target"]["real_dns"] = real_dns

    save_json(report_file, report)

    if CONFIG.get("debug_mode", True):
        print(f"Obtaining the actual DNS for the address:{real_dns}")

    return True

def create_empty_report_file(folder: str,accesskey: str, subdomain: str, domain: str, modulename: str) -> str | None:
    if CONFIG.get("debug_mode", True):
        print(f"Creating the report file structure.")
    try:
        empty_structure = get_struct_report_file()

        empty_structure["target"]["domain"] = domain
        empty_structure["target"]["subdomain"] = subdomain
        empty_structure["target"]["modulename"] = modulename
        empty_structure["target"]["full_url"] = f"https://{subdomain}.{domain}/{modulename}" if subdomain else domain

        if subdomain:
            empty_structure["target"]["full_url"] = f"https://{subdomain}.{domain}/{modulename}"
        else:
            empty_structure["target"]["full_url"] = f"https://{domain}/{modulename}"
        
        filename = f"{accesskey}.json"
        filepath = os.path.join(folder, filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(empty_structure, f, ensure_ascii=False, indent=4)
        if CONFIG.get("debug_mode", True):
            print(f"JSON file for the report created successfully: {filepath}")

        return True
    
    except Exception as e:
        print(f"Error creating the report's JSON file: {e}")
        return None

def http_get(url, headers=None):
    attempts = CONFIG.get("max_attempts", 3)
    timeout = CONFIG.get("request_timeout", 60)
    
    def toggle_www(target_url):
        parsed = urlparse(target_url)
        netloc = parsed.netloc
        if netloc.startswith("www."):
            new_netloc = netloc.replace("www.", "", 1)
        else:
            new_netloc = f"www.{netloc}"
        return urlunparse(parsed._replace(netloc=new_netloc))

    urls_to_try = [url, toggle_www(url)]
    
    for current_url in urls_to_try:
        if CONFIG.get("debug_mode", True):
            print(f"--- Testing Host: {urlparse(current_url).netloc} ---")
            
        for attempt in range(1, attempts + 1):
            try:
                response = requests.get(
                    current_url,
                    headers=headers,
                    verify=False,
                    timeout=timeout
                )

                response.raise_for_status()
                
                if CONFIG.get("debug_mode", True):
                    print(f"Success in URL: {current_url}")
                return response

            except requests.exceptions.ConnectionError as e:
                if CONFIG.get("debug_mode", True):
                    print(f"Connection/DNS erros on {current_url} (attempt {attempt}/{attempts})")
                
                if "NameResolutionError" in str(e) or "Failed to resolve" in str(e):
                    if CONFIG.get("debug_mode", True):
                        print("Resolution failure detected, switching hosts...")
                    break 
                
                if attempt == attempts:
                    break

            except requests.exceptions.HTTPError as e:
                print(f"HTTP error: {current_url}: {e}")
                if attempt == attempts:
                    break
                    
    return None

def http_post(url, data=None, json=None, headers=None):
    attempts = CONFIG.get("max_attempts", 3)
    timeout = CONFIG.get("request_timeout", 60)
    
    def toggle_www(target_url):
        parsed = urlparse(target_url)
        netloc = parsed.netloc
        if netloc.startswith("www."):
            new_netloc = netloc.replace("www.", "", 1)
        else:
            new_netloc = f"www.{netloc}"
        return urlunparse(parsed._replace(netloc=new_netloc))

    urls_to_try = [url, toggle_www(url)]
    
    for current_url in urls_to_try:
        if CONFIG.get("debug_mode", True):
            print(f"--- Trying to host: {urlparse(current_url).netloc} ---")
            
        for attempt in range(1, attempts + 1):
            try:
                response = requests.post(
                    current_url,
                    data=data,
                    json=json, 
                    headers=headers,
                    verify=False,
                    timeout=timeout
                )
                
                response.raise_for_status()
                
                if CONFIG.get("debug_mode", True):
                    print(f"Success in URL: {current_url}")
                return response

            except requests.exceptions.ConnectionError as e:
                if CONFIG.get("debug_mode", True):
                    print(f"Connection/DNS error on {current_url} (Attempt {attempt}/{attempts})")
                
                # Se o DNS falhou (NameResolutionError), pula para a próxima URL imediatamente
                if "NameResolutionError" in str(e) or "Failed to resolve" in str(e):
                    if CONFIG.get("debug_mode", True):
                        print("Resolution failure detected, switching hosts...")
                    break 
                
                if attempt == attempts:
                    break

            except requests.exceptions.HTTPError as e:
                print(f"HTTP error: {e}")
                if attempt == attempts:
                    break
                    
    return None

def get_moduleinfo_from_target(subdomain: str, domain: str, modulename: str, accesskey: str) -> bool | str:
    # 1. Definimos os domínios para tentar (Original e Alternativo com/sem www)
    domains_to_try = [domain]
    if domain.startswith("www."):
        domains_to_try.append(domain.replace("www.", "", 1))
    else:
        domains_to_try.append(f"www.{domain}")

    data = None
    final_domain = domain

    try:
        # 2. Loop de tentativas
        for current_domain in domains_to_try:
            url_moduleinfo = f"{build_url_application(subdomain, current_domain, modulename)}moduleservices/moduleinfo"
            headers = build_headers({"Content-Type": "application/json"})
            
            if CONFIG.get("debug_mode", True):
                print(f"Trying URL: {url_moduleinfo}")

            response = http_get(url_moduleinfo, headers)

            # Se a resposta falhar (None ou erro de conexão), tenta o próximo domínio
            if response is None or response.status_code != 200:
                if CONFIG.get("debug_mode", True):
                    print(f"Failed attempt with: {current_domain}")
                continue 
            
            # Se chegamos aqui, o status é 200. Sucesso na conexão!
            try:
                data = response.json()
                final_domain = current_domain # Guardamos qual funcionou
                break # Sai do loop de tentativas
            except ValueError:
                continue

        # 3. Validação após as tentativas
        if data is None:
            print(f"Could not resolve or connect to {domain} (tried with and without www).")
            return False

        # --- Lógica ODC Verify ---
        manifest = data.get("manifest", {})
        url_mappings = manifest.get("urlMappings", {})
        is_odc = any(key.endswith("_RedirectLogin") for key in url_mappings.keys())
        
        if is_odc:
            return "odc_environment"

        # --- Processamento de Arquivos ---
        folders = os.path.join(REPORT_DIR, accesskey, "pages_js")
        os.makedirs(folders, exist_ok=True)

        default_folder = os.path.join(REPORT_DIR, accesskey)
        folder_path = os.path.join(default_folder, f"{accesskey}_map.json")

        with open(folder_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=4)
        
        # Usamos o final_domain que realmente funcionou para o relatório
        report_path = create_empty_report_file(default_folder, accesskey, subdomain, final_domain, modulename)
        
        return True if report_path else False
    
    except Exception as e:
        print(f"An unexpected error occurred during analysis: {e}")
        return False

def get_app_definitions(accesskey: str) -> bool:
    data_file, report_file = get_report_paths(accesskey)

    report_map = load_json(data_file)
    report = load_json(report_file)
    if report is None:
        print(f"Report not found: {report_file}")
        return False

    subdomain = report["target"].get("subdomain", "")
    domain = report["target"].get("domain", "")
    modulename = report["target"].get("modulename", "")

    if not domain or not modulename:
        print("The report is missing 'domain' or 'modulename'.")
        return False

    sub = f"{subdomain}." if subdomain else ""
    base_url = f"https://{sub}{domain}"

    search_pattern = f"{modulename}.appDefinition"
    url_versions = report_map.get("manifest", {}).get("urlVersions", {})
    app_definitions = next(
        (path for path in url_versions.keys()
        if search_pattern in path),
        None
    )

    url = f"{base_url}{app_definitions}"

    headers = build_headers({
        "Accept": "*/*",
        "Sec-Fetch-Dest": "script"
    })

    try:
        response = http_get(url, headers)
        response.raise_for_status()
        js_content = response.text
    except Exception as e:
        print(f"Error downloading appDefinition.js: {e}")
        return False

    try:
        match = re.search(
            r'define\s*\([^,]+,\s*\[[^\]]*\],\s*(function\s*\([^\)]*\)\s*\{[\s\S]*?\})\s*\);',
            js_content
        )

        if not match:
            print("It was not possible to extract the function from define().")
            return False

        function_body = match.group(1)

        js_clean = f"""
            var OutSystems = {{ Internal: {{}} }};
            var __DEF__ = {function_body};
            var __RESULT__ = __DEF__(OutSystems);
        """

        context = js2py.EvalJs()
        context.execute(js_clean)

        data = context.__RESULT__.to_dict()

    except Exception as e:
        print(f"Error interpreting JavaScript: {e}")
        return False

    report["target"].update({
        "applicationName": data.get("applicationName", ""),
        "applicationKey": data.get("applicationKey", ""),
        "environmentName": data.get("environmentName", ""),
        "environmentKey": data.get("environmentKey", ""),
        "homeModuleName": data.get("homeModuleName", ""),
        "homeModuleKey": data.get("homeModuleKey", ""),
        "userTenantProvider": data.get("userProviderName", "")
    })

    if "metadata" not in report:
        report["metadata"] = {}

    report["metadata"]["status"] = "running"
    report["metadata"]["analysis_id"] = accesskey

    save_json(report_file, report)

    if CONFIG.get("debug_mode", True):
        print(f"Saving application settings in report JSON: {data}")
    return True

def get_app_screens(accesskey: str) -> bool:
    data_file, report_file = get_report_paths(accesskey)

    data_json = load_json(data_file)
    report = load_json(report_file)

    if data_json is None or report is None:
        return False

    try:
        url_mappings = data_json["manifest"]["urlMappings"]
    except KeyError:
        print("urlMappings not found within manifest.")
        return False

    keys = list(url_mappings.keys())
    if keys:
        keys = keys[:-1]  # remove a última URL técnica

    screens_list = []
    for path in keys:
        lower_path = path.lower()

        suspicious = any(p in lower_path for p in SUSPICIOUS_WORDS)

        screens_list.append({
            "path": path,
            "suspicious": suspicious
        })

    if "appscreens" not in report or not isinstance(report["appscreens"], list):
        report["appscreens"] = []

    report["appscreens"] = screens_list

    save_json(report_file, report)
    if CONFIG.get("debug_mode", True):
        print(f"Saving the list of available screens: {screens_list}")
    return True

def get_app_modules(accesskey: str) -> bool:
    data_file, report_file = get_report_paths(accesskey)

    data_json = load_json(data_file)
    report = load_json(report_file)

    if data_json is None or report is None:
        return False

    try:
        modules_dict = data_json["data"]["modules"]
    except KeyError:
        print("Modules not found within date.")
        return False

    module_items = list(modules_dict.values())

    if len(module_items) > 1:
        module_items = module_items[1:]
    else:
        module_items = []

    dependencies_list = [
        {"modulename": module["moduleName"]}
        for module in module_items
        if "moduleName" in module
    ]

    if "dependencies" not in report or not isinstance(report["dependencies"], list):
        report["dependencies"] = []

    report["dependencies"] = dependencies_list

    save_json(report_file, report)
    if CONFIG.get("debug_mode", True):
        print(f"Saving the list of associated modules: {dependencies_list}")
    return True

def get_app_resources(accesskey: str) -> bool:
    data_file, report_file = get_report_paths(accesskey)

    data_json = load_json(data_file)
    report = load_json(report_file)

    if data_json is None or report is None:
        return False

    try:
        url_versions = data_json["manifest"]["urlVersions"]
    except KeyError:
        print("urlVersions not found within manifest.")
        return False

    filtered_paths = [
        path for path in url_versions.keys()
        if path.count("/") == 2
    ]
    
    versions_list = []
    for path in filtered_paths:
        _, ext = os.path.splitext(path.lower())
        suspicious = ext in SUSPICIOUS_EXTENSIONS

        versions_list.append({
            "path": path,
            "suspicious": suspicious
        })

    report["resources"] = versions_list
    save_json(report_file, report)

    if CONFIG.get("debug_mode", True):
        print(f"Saving the resource list: {versions_list}")
    return True

def get_react_version(accesskey: str) -> bool:
    report_data, report_file = get_report_paths(accesskey)
    
    report_map = load_json(report_data)
    report = load_json(report_file)
    if report is None:
        print(f"Report not found: {report_file}")
        return False

    subdomain = report["target"].get("subdomain", "")
    domain = report["target"].get("domain", "")
    modulename = report["target"].get("modulename", "")

    if not domain or not modulename:
        print("The report is missing 'domain' or 'modulename'.")
        return False

    subdomain_part = f"{subdomain}." if subdomain else ""
    environment = f"https://{subdomain_part}{domain}"

    search_pattern = f"OutSystemsReactView"
    url_versions = report_map.get("manifest", {}).get("urlVersions", {})
    react_view = next(
        (path for path in url_versions.keys()
        if search_pattern in path),
        None
    )

    js_url = f"{environment}{react_view}"

    headers = build_headers({
        "Accept": "*/*",
        "Sec-Fetch-Dest": "script"
    })

    try:
        response = http_get(js_url, headers)
        response.raise_for_status()
        js_content = response.text
    except Exception as e:
        print(f"Error downloading JS: {e}")
        return False

    match = re.search(r'e\.version\s*=\s*"([^"]+)"', js_content)

    if not match:
        print("The react version could not be found.")
        return False

    version = match.group(1)

    if "target" not in report:
        report["target"] = {}

    report["target"]["react_version"] = version

    save_json(report_file, report)
    if CONFIG.get("debug_mode", True):
        print(f"Saving React version: {version}")
    return True

def get_references_health(accesskey: str) -> bool:

    report_data, report_file = get_report_paths(accesskey)
    report_map = load_json(report_data)
    report = load_json(report_file)

    if report is None:
        print(f"Report not found: {report_file}")
        return False

    subdomain = report["target"].get("subdomain", "")
    domain = report["target"].get("domain", "")
    modulename = report["target"].get("modulename", "")

    if not domain or not modulename:
        print("Missing 'domain' or 'modulename' in report.")
        return False

    subdomain_part = f"{subdomain}." if subdomain else ""
    environment = f"https://{subdomain_part}{domain}"

    search_pattern = f"{modulename}.referencesHealth"
    url_versions = report_map.get("manifest", {}).get("urlVersions", {})
    client_health = next(
        (path for path in url_versions.keys()
        if search_pattern in path),
        None
    )

    js_url = f"{environment}{client_health}"

    headers = build_headers({
        "Accept": "*/*",
        "Sec-Fetch-Dest": "script"
    })

    try:
        response = http_get(js_url, headers)
        response.raise_for_status()
        js_content = response.text
    except Exception as e:
        print(f"Error downloading referencesHealth JS: {e}")
        return False

    matches = re.findall(r"'([^']+)'", js_content)

    references = []
    for name in matches:
        pattern = fr"referencesHealth\$.*{re.escape(name)}"
        if re.search(pattern, js_content):
            references.append(name)

    references = list(dict.fromkeys(references))

    report["references_health"] = references
    save_json(report_file, report)
    if CONFIG.get("debug_mode", True):
        print(f"Checking the health of the references: {references}")
    return True

def get_client_variables(accesskey: str) -> bool:
    report_data, report_file = get_report_paths(accesskey)

    report_map = load_json(report_data)
    report = load_json(report_file)

    if report is None:
        print(f"Report not found: {report_file}")
        return False

    subdomain = report["target"].get("subdomain", "")
    domain = report["target"].get("domain", "")
    modulename = report["target"].get("modulename", "")

    if not domain or not modulename:
        print("Missing 'domain' or 'modulename' in report.")
        return False

    subdomain_part = f"{subdomain}." if subdomain else ""
    environment = f"https://{subdomain_part}{domain}"

    search_pattern = f"{modulename}.clientVariables"
    url_versions = report_map.get("manifest", {}).get("urlVersions", {})
    client_variables = next(
        (path for path in url_versions.keys()
        if search_pattern in path),
        None
    )

    js_url = f"{environment}{client_variables}"

    headers = build_headers({
        "Accept": "*/*",
        "Sec-Fetch-Dest": "script"
    })

    try:
        response = http_get(js_url, headers)
        response.raise_for_status()
        js_content = response.text
    except Exception as e:
        print(f"Error downloading clientVariables JS: {e}")
        return False

    pattern = r'getVariable\(\s*[\'"]([^\'"]+)[\'"]\s*,\s*[\'"]([^\'"]+)[\'"]\s*,\s*([A-Za-z0-9\._]+)(?:\s*,\s*[\'"]([^\'"]*)[\'"])?'

    matches = re.findall(pattern, js_content)

    client_vars = []
    for var_name, module_name, var_type, default_value in matches:
        short_type = var_type.split(".")[-1]

        client_vars.append({
            "name": var_name,
            "module": module_name,
            "type": short_type,
            "default_value": default_value or None
        })

    report["client_variables"] = client_vars
    save_json(report_file, report)

    if CONFIG.get("debug_mode", True):
        print(f"Saving client variables: {client_vars}")
    return True

def get_mobile_apps(accesskey: str) -> bool:
    _, report_file = get_report_paths(accesskey)
    report = load_json(report_file)

    if report is None:
        print(f"Report not found: {report_file}")
        return False

    subdomain = report["target"].get("subdomain", "")
    domain = report["target"].get("domain", "")
    modulename = report["target"].get("modulename", "")

    if not domain:
        print("Missing 'domain' in report.")
        return False

    subdomain_part = f"{subdomain}." if subdomain else ""
    environment = f"https://{subdomain_part}{domain}"
    json_url = f"{environment}/NativeAppBuilder/rest/NativeApps/GetNativeApps"

    headers = build_headers({
        "Content-Type": "application/json"
    })

    response = http_get(json_url, headers)

    if response is None:
        if CONFIG.get("debug_mode", True):
            print(f"The Mobile Apps endpoint in {domain} could not be reached.")
        return False

    try:
        response.raise_for_status()
        data = response.json()
    except Exception as e:
        if hasattr(response, 'status_code') and response.status_code == 403:
            print(f"Access denied (403) on {domain}. The server blocked the REST request.")
        else:
            print(f"Error processing JSON from mobile apps: {e}")
        return False

    if not isinstance(data, list):
        if CONFIG.get("debug_mode", True):
            print("Unexpected JSON format: a list was expected.")
        return False

    report["mobile_apps"] = data
    save_json(report_file, report)
    
    if CONFIG.get("debug_mode", True):
        print(f"Mobile apps saved successfully: {len(data)} found.")
        
    return True

def get_platform_info(accesskey: str) -> bool:
    _, report_file = get_report_paths(accesskey)
    report = load_json(report_file)

    if report is None:
        print(f"Report not found: {report_file}")
        return False

    subdomain = report["target"].get("subdomain", "")
    domain = report["target"].get("domain", "")

    if not domain:
        print("Missing 'domain' in report.")
        return False

    subdomain_part = f"{subdomain}." if subdomain else ""
    environment = f"https://{subdomain_part}{domain}"

    soap_url = f"{environment}/ServiceCenter/OutSystemsPlatform.asmx"

    soap_body = """<?xml version="1.0" encoding="utf-8"?>
                <soap12:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                xmlns:xsd="http://www.w3.org/2001/XMLSchema"
                                xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">
                <soap12:Body>
                    <GetPlatformInfo xmlns="http://www.outsystems.com" />
                </soap12:Body>
                </soap12:Envelope>"""

    headers = build_headers({
        "Content-Type": "application/soap+xml; charset=utf-8"
    })

    response = http_post(soap_url, data=soap_body, headers=headers)

    if response is None:
        if CONFIG.get("debug_mode", True):
            print(f"Connection error in {domain}: The host could not be resolved or is offline.")
        return False

    try:
        response.raise_for_status()
        xml_content = response.text
    except Exception as e:
        print(f"SOAP protocol error in {domain}: {e}")
        return False

    try:
        root = ET.fromstring(xml_content)

        ns = {
            "soap": "http://www.w3.org/2003/05/soap-envelope",
            "os": "http://www.outsystems.com"
        }

        response_node = root.find(".//os:GetPlatformInfoResponse", ns)
        if response_node is None:
            if CONFIG.get("debug_mode", True):
                print("The GetPlatformInfoResponse structure was not found in the XML.")
            return False

        platform_info = {}
        for child in response_node:
            tag_name = child.tag.split("}")[-1]
            platform_info[tag_name] = child.text

    except Exception as e:
        print(f"Error processing XML of {domain}: {e}")
        return False

    report["platform_info"] = platform_info
    save_json(report_file, report)

    if CONFIG.get("debug_mode", True):
        print(f"Platform information successfully saved for {domain}.")
    
    return True

def get_platform_capabilities(accesskey: str) -> bool:
    _, report_file = get_report_paths(accesskey)
    report = load_json(report_file)

    if report is None:
        print(f"Report not found: {report_file}")
        return False

    subdomain = report["target"].get("subdomain", "")
    domain = report["target"].get("domain", "")

    if not domain:
        print("Missing 'domain' in report.")
        return False

    subdomain_part = f"{subdomain}." if subdomain else ""
    environment = f"https://{subdomain_part}{domain}"

    soap_url = f"{environment}/ServiceCenter/PlatformServices_v8_0_0.asmx"

    soap_body = """<?xml version="1.0" encoding="utf-8"?>
                <soap12:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                xmlns:xsd="http://www.w3.org/2001/XMLSchema"
                xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">
                <soap12:Body>
                <Capabilities_Get xmlns="http://www.outsystems.com" />
                </soap12:Body>
                </soap12:Envelope>"""

    headers = build_headers({
        "Content-Type": "application/soap+xml; charset=utf-8"
    })

    response = http_post(soap_url, data=soap_body, json=None, headers=headers)

    if response is None:
        if CONFIG.get("debug_mode", True):
            print(f"Error: Could not reach the SOAP endpoint at {soap_url} (Connection/DNS failure).")
        return False

    try:
        response.raise_for_status()
        xml_content = response.text
    except Exception as e:
        print(f"Error calling Capabilities_Get SOAP endpoint: {e}")
        return False

    try:
        root = ET.fromstring(xml_content)

        ns = {
            "soap": "http://www.w3.org/2003/05/soap-envelope",
            "os": "http://www.outsystems.com"
        }

        capability_nodes = root.findall(".//os:Properties", ns)

        capabilities = []
        for node in capability_nodes:
            name_node = node.find("os:Name", ns)
            value_node = node.find("os:Value", ns)

            name = name_node.text if name_node is not None else None
            value = value_node.text if value_node is not None else None

            if name is not None:
                capabilities.append({
                    "name": name,
                    "value": value
                })

    except Exception as e:
        print(f"Error parsing Capabilities_Get SOAP XML: {e}")
        return False

    report["platform_capabilities"] = capabilities
    save_json(report_file, report)

    if CONFIG.get("debug_mode", True):
        print(f"Checking and saving capabilities configurations: {capabilities}")
    return True

def get_installation_info(accesskey: str) -> bool:
    _, report_file = get_report_paths(accesskey)
    report = load_json(report_file)

    if report is None:
        print(f"Report not found: {report_file}")
        return False

    subdomain = report["target"].get("subdomain", "")
    domain = report["target"].get("domain", "")

    if not domain:
        print("Missing 'domain' in report.")
        return False

    subdomain_part = f"{subdomain}." if subdomain else ""
    environment = f"https://{subdomain_part}{domain}"

    soap_url = f"{environment}/ServiceCenter/ServiceStudio.asmx"

    soap_body = """<?xml version="1.0" encoding="utf-8"?>
                <soap12:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                xmlns:xsd="http://www.w3.org/2001/XMLSchema"
                                xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">
                <soap12:Body>
                    <GetInstallationKind xmlns="http://www.outsystems.com" />
                </soap12:Body>
                </soap12:Envelope>"""

    headers = build_headers({
        "Content-Type": "application/soap+xml; charset=utf-8"
    })

    response = http_post(soap_url, data=soap_body, headers=headers)

    if response is None:
        if CONFIG.get("debug_mode", True):
            print(f"We were unable to reach the host {domain} to obtain InstallationInfo.")
        return False

    try:
        response.raise_for_status()
        xml_content = response.text
    except Exception as e:
        print(f"Connection/permission error at the Get Installation Kind endpoint: {e}")
        return False

    try:
        root = ET.fromstring(xml_content)

        ns = {
            "soap": "http://www.w3.org/2003/05/soap-envelope",
            "os": "http://www.outsystems.com"
        }

        # Busca pelo nó de resposta específico
        response_node = root.find(".//os:GetInstallationKindResponse", ns)
        if response_node is None:
            if CONFIG.get("debug_mode", True):
                print(f"Node GetInstallationKindResponse not found in XML of {domain}.")
            return False

        installation_info = {}
        for child in response_node:
            tag_name = child.tag.split("}")[-1]
            installation_info[tag_name] = child.text

    except Exception as e:
        print(f"Error processing InstallationKind XML: {e}")
        return False

    # 5. Atualização do relatório
    report["installation_info"] = installation_info
    save_json(report_file, report)

    if CONFIG.get("debug_mode", True):
        print(f"[+] Informações de instalação salvas para {domain}: {installation_info}")
        
    return True

def get_handshake_properties(accesskey: str) -> bool:
    _, report_file = get_report_paths(accesskey)
    report = load_json(report_file)

    if report is None:
        print(f"Report not found: {report_file}")
        return False

    subdomain = report["target"].get("subdomain", "")
    domain = report["target"].get("domain", "")

    if not domain:
        print("Missing 'domain' in report.")
        return False

    subdomain_part = f"{subdomain}." if subdomain else ""
    environment = f"https://{subdomain_part}{domain}"

    soap_url = f"{environment}/ServiceCenter/ServiceStudio.asmx"

    soap_body = """<?xml version="1.0" encoding="utf-8"?>
                <soap12:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                xmlns:xsd="http://www.w3.org/2001/XMLSchema"
                                xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">
                <soap12:Body>
                    <GetPropertiesForHandshake xmlns="http://www.outsystems.com" />
                </soap12:Body>
                </soap12:Envelope>"""

    headers = build_headers({
        "Content-Type": "application/soap+xml; charset=utf-8"
    })

    response = http_post(soap_url, data=soap_body, headers=headers)

    if response is None:
        if CONFIG.get("debug_mode", True):
            print(f"Failed to reach GetPropertiesForHandshake in {domain}")
        return False

    try:
        response.raise_for_status()
        xml_content = response.text
    except Exception as e:
        print(f"[-] Erro de protocolo SOAP no handshake: {e}")
        return False

    try:
        root = ET.fromstring(xml_content)

        ns = {
            "soap": "http://www.w3.org/2003/05/soap-envelope",
            "os": "http://www.outsystems.com"
        }

        response_node = root.find(".//os:GetPropertiesForHandshakeResponse", ns)
        if response_node is None:
            if CONFIG.get("debug_mode", True):
                print(f"GetPropertiesForHandshakeResponse not found in XML of {domain}.")
            return False

        properties_nodes = response_node.findall(".//os:Properties", ns)

        handshake_properties = []
        for node in properties_nodes:
            name_node = node.find("os:Name", ns)
            value_node = node.find("os:Value", ns)

            name = name_node.text if name_node is not None else None
            value = value_node.text if value_node is not None else None

            if name is not None:
                handshake_properties.append({
                    "name": name,
                    "value": value
                })

    except Exception as e:
        print(f"Error processing Handshake XML: {e}")
        return False

    report["handshake_properties"] = handshake_properties
    save_json(report_file, report)

    if CONFIG.get("debug_mode", True):
        print(f"Handshake properties saved for {domain}: {len(handshake_properties)} items found.")
        
    return True

def get_external_authentication_status(accesskey: str) -> bool:
    _, report_file = get_report_paths(accesskey)
    report = load_json(report_file)

    if report is None:
        print(f"Report not found: {report_file}")
        return False

    subdomain = report["target"].get("subdomain", "")
    domain = report["target"].get("domain", "")

    if not domain:
        print("Missing 'domain' in report.")
        return False

    subdomain_part = f"{subdomain}." if subdomain else ""
    environment = f"https://{subdomain_part}{domain}"

    soap_url = f"{environment}/ServiceCenter/PlatformServices_v8_0_0.asmx"

    soap_body = """<?xml version="1.0" encoding="utf-8"?>
                <soap12:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                xmlns:xsd="http://www.w3.org/2001/XMLSchema"
                                xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">
                <soap12:Body>
                    <ExternalAuthentication_IsActive xmlns="http://www.outsystems.com" />
                </soap12:Body>
                </soap12:Envelope>"""

    headers = build_headers({
        "Content-Type": "application/soap+xml; charset=utf-8"
    })

    response = http_post(soap_url, data=soap_body, headers=headers)

    if response is None:
        if CONFIG.get("debug_mode", True):
            print(f"The authentication endpoint could not be reached. {domain}.")
        return False

    try:
        response.raise_for_status()
        xml_content = response.text
    except Exception as e:
        print(f"Error calling ExternalAuthentication_IsActive: {e}")
        return False

    try:
        root = ET.fromstring(xml_content)

        ns = {
            "soap": "http://www.w3.org/2003/05/soap-envelope",
            "os": "http://www.outsystems.com"
        }

        response_node = root.find(".//os:ExternalAuthentication_IsActiveResponse", ns)
        if response_node is None:
            if CONFIG.get("debug_mode", True):
                print(f"Node ExternalAuthentication_IsActiveResponse not found in {domain}.")
            return False

        auth_key_node = response_node.find("os:AuthenticationProviderKey", ns)
        auth_key = auth_key_node.text if auth_key_node is not None else None

        external_auth_info = {
            "AuthenticationProviderKey": auth_key
        }

    except Exception as e:
        print(f"Error processing External Authentication XML: {e}")
        return False

    report["external_authentication"] = external_auth_info
    save_json(report_file, report)

    if CONFIG.get("debug_mode", True):
        print(f"External authentication status saved: {external_auth_info}")
        
    return True

def download_screen_js_files(accesskey: str) -> bool:
    map_file, report_file = get_report_paths(accesskey)
    report_dir = os.path.dirname(report_file)

    report = load_json(report_file)
    if report is None:
        print(f"Report not found: {report_file}")
        return False

    subdomain = report["target"].get("subdomain", "")
    domain = report["target"].get("domain", "")

    if not domain:
        print("Missing 'domain' in report.")
        return False

    subdomain_part = f"{subdomain}." if subdomain else ""
    environment = f"https://{subdomain_part}{domain}"

    if not os.path.exists(map_file):
        print(f"Map file not found: {map_file}")
        return False

    with open(map_file, "r", encoding="utf-8") as f:
        file_map = json.load(f)

    url_versions = file_map.get("manifest", {}).get("urlVersions", {})
    if not url_versions:
        print("urlVersions not found in map file")
        return False

    pages_dir = os.path.join(report_dir, "pages_js")

    for screen in report.get("appscreens", []):
        path = screen.get("path", "")
        if not path or path == "/":
            continue

        screen_name = path.rstrip("/").split("/")[-1]

        matched_url = None
        for url in url_versions.keys():
            if screen_name in url and url.endswith(".mvc.js"):
                matched_url = url
                break

        if not matched_url:
            continue

        full_url = f"{environment}{matched_url}"

        headers = build_headers({
            "Accept": "*/*",
            "Sec-Fetch-Dest": "script"
        })
        try:
            response = http_get(full_url, headers)
            response.raise_for_status()
            js_content = response.text
        except Exception as e:
            print(f"Error downloading JS for screen {screen_name}: {e}")
            continue

        filename = f"{screen_name}_mvc.js"
        file_path = os.path.join(pages_dir, filename)

        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(js_content)
                if CONFIG.get("debug_mode", True):
                    print(f"Saving the JS file from the screen: {file_path}")
        except Exception as e:
            print(f"Error saving JS file for screen {screen_name}: {e}")
            continue

    return True

def extract_rest_endpoints(accesskey: str) -> bool:
    _, report_file = get_report_paths(accesskey)
    report_dir = os.path.dirname(report_file)

    report = load_json(report_file)
    if report is None:
        print(f"Report not found: {report_file}")
        return False

    pages_dir = os.path.join(report_dir, "pages_js")
    if not os.path.exists(pages_dir):
        print(f"Pages directory not found: {pages_dir}")
        return False

    if CONFIG.get("debug_mode", True):
        print("Arquivos encontrados:", os.listdir(pages_dir))

    results = []

    endpoint_pattern = r'(screenservices\/[A-Za-z0-9_\/\-]+|services\/[A-Za-z0-9_\/\-]+|serveractions\/[A-Za-z0-9_\/\-]+|clientactions\/[A-Za-z0-9_\/\-]+|\/rest\/[A-Za-z0-9_\/\-]+)'

    for filename in os.listdir(pages_dir):
        if not filename.endswith("_mvc.js"):
            continue
        if CONFIG.get("debug_mode", True):
            print("Reading:", filename)

        screen_name = filename.replace("_mvc.js", "")
        file_path = os.path.join(pages_dir, filename)

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception as e:
            print(f"Error reading: {filename}: {e}")
            continue

        matches = re.findall(endpoint_pattern, content)

        if matches:
            if CONFIG.get("debug_mode", True):
                print(f"Found in {filename}: {matches}")

            matches = list(set(matches))

            results.append({
                "screen": screen_name,
                "rest": [{"endpoint": m} for m in matches]
            })

    report["endpoints"] = results
    save_json(report_file, report)

    if CONFIG.get("debug_mode", True):
        print(f"Saving endpoints: {results}")
    return True

def extract_screen_variables(accesskey: str) -> bool:
    _, report_file = get_report_paths(accesskey)
    report_dir = os.path.dirname(report_file)
    report = load_json(report_file)
    if report is None:
        print(f"Report not found: {report_file}")
        return False

    pages_dir = os.path.join(report_dir, "pages_js")
    if not os.path.exists(pages_dir):
        print(f"Pages directory not found: {pages_dir}")
        return False

    screens_detail = []

    def split_args(arg_str: str):
        args = []
        current = []
        depth_paren = 0
        depth_brace = 0
        in_string = False
        string_char = None

        for ch in arg_str:
            if in_string:
                current.append(ch)
                if ch == string_char:
                    in_string = False
                continue

            if ch in ['"', "'"]:
                in_string = True
                string_char = ch
                current.append(ch)
                continue

            if ch == '(':
                depth_paren += 1
                current.append(ch)
                continue
            if ch == ')':
                depth_paren -= 1
                current.append(ch)
                continue
            if ch == '{':
                depth_brace += 1
                current.append(ch)
                continue
            if ch == '}':
                depth_brace -= 1
                current.append(ch)
                continue

            if ch == ',' and depth_paren == 0 and depth_brace == 0:
                arg = ''.join(current).strip()
                if arg:
                    args.append(arg)
                current = []
            else:
                current.append(ch)

        if current:
            arg = ''.join(current).strip()
            if arg:
                args.append(arg)

        return args

    attr_block_pattern = re.compile(
        r'this\.attr\(\s*([\s\S]*?)\s*\)',
        re.MULTILINE
    )

    for filename in os.listdir(pages_dir):
        if not filename.endswith("_mvc.js"):
            continue

        file_path = os.path.join(pages_dir, filename)

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception as e:
            print(f"Error reading {filename}: {e}")
            continue

        base = filename.replace("_mvc.js", "")
        parts = base.split(".")

        if len(parts) == 1:
            screen_name = parts[0]
        elif len(parts) == 2:
            screen_name = parts[1]
        else:
            screen_name = parts[-1]

        path = f"/{screen_name}"

        suspicious = any(word in screen_name.lower() for word in SUSPICIOUS_WORDS)

        variables = []

        for match in attr_block_pattern.finditer(content):
            inner = match.group(1)
            args = split_args(inner)

            if len(args) < 7:
                continue

            name = args[0].strip('"').strip("'")
            internal_name = args[1].strip('"').strip("'")
            type_arg = args[5]
            default_arg = args[6]

            type_match = re.search(r'OS\.(?:Types|DataTypes\.DataTypes)\.(\w+)', type_arg)
            type_out = type_match.group(1) if type_match else "Unknown"

            default_match = re.search(r'return\s*([\s\S]*?)\s*;', default_arg)
            if default_match:
                dr = default_match.group(1).strip()
            else:
                dr = ""

            if dr in ['""', "''"]:
                default_value = ""
            elif dr.lower() in ["true", "false", "0", "1"]:
                default_value = dr.lower()
            else:
                default_value = ""

            in_lower = internal_name.lower()
            is_input = in_lower.endswith("in")
            is_local = in_lower.endswith("var")
            is_aggregate = in_lower.endswith("out")

            variables.append({
                "name": name,
                "internal_name": internal_name,
                "type": type_out,
                "is_input": is_input,
                "is_local": is_local,
                "is_aggregate": is_aggregate,
                "default_value": default_value
            })

        screens_detail.append({
            "path": path,
            "suspicious": suspicious,
            "variables": variables
        })

    report["screens_detail"] = screens_detail
    save_json(report_file, report)

    if CONFIG.get("debug_mode", True):
        print(f"Extracting and saving screen variables: {screens_detail}")
    return True

def capture_all_screens_xhr(accesskey: str) -> bool:
    def toggle_www(target_url):
        parsed = urlparse(target_url)
        netloc = parsed.netloc
        if netloc.startswith("www."):
            new_netloc = netloc.replace("www.", "", 1)
        else:
            new_netloc = f"www.{netloc}"
        return urlunparse(parsed._replace(netloc=new_netloc))

    _, report_file = get_report_paths(accesskey)
    report = load_json(report_file)

    if report is None:
        print("Report not found.")
        return False

    target = report.get("target", {})
    domain = target.get("domain", "")
    subdomain = target.get("subdomain", "")
    
    if not domain:
        print("Missing 'domain' in report.")
        return False

    subdomain_part = f"{subdomain}." if subdomain else ""
    base_url = f"https://{subdomain_part}{domain}".rstrip("/")

    appscreens_requests = []

    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
    ]

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)

        for screen in report.get("appscreens", []):
            path = screen.get("path", "")
            if not path: continue

            full_url_original = base_url + path
            urls_to_try = [full_url_original, toggle_www(full_url_original)]
            
            xhr_results = []
            success_capture = False

            for current_url in urls_to_try:
                
                context = browser.new_context(user_agent=random.choice(USER_AGENTS))
                page = context.new_page()

                def handle_request(request):
                    if request.resource_type == "xhr":
                        url = request.url.lower()
                        if not any(ignore in url for ignore in ["moduleversioninfo", "moduleinfo"]):
                            xhr_results.append({
                                "url": request.url,
                                "method": request.method,
                                "post_data": request.post_data,
                                "response": None
                            })

                def handle_response(response):
                    if response.request.resource_type == "xhr":
                        for entry in xhr_results:
                            if entry["url"] == response.url and entry["response"] is None:
                                try:
                                    entry["response"] = {
                                        "status": response.status,
                                        "body": response.text()
                                    }
                                except Exception:
                                    entry["response"] = {"status": response.status, "body": "[Sem corpo]"}
                                break

                page.on("request", handle_request)
                page.on("response", handle_response)

                try:
                    if CONFIG.get("debug_mode", True):
                        print(f"[*] Tentando: {current_url}")

                    page.goto(current_url, wait_until="load", timeout=30000)
                    
                    page.wait_for_timeout(5000) 

                    if len(xhr_results) > 0:
                        success_capture = True
                        if CONFIG.get("debug_mode", True):
                            print(f"Captured {len(xhr_results)} XHR requests.")
                    
                    page.close()
                    context.close()
                    
                    if success_capture:
                        break 

                except Exception as e:
                    if CONFIG.get("debug_mode", True):
                        print(f"Error: {current_url}: {str(e)}")
                    page.close()
                    context.close()
                    continue

            appscreens_requests.append({
                "path": path,
                "requests": list(xhr_results)
            })

        browser.close()

    report["appscreensRequests"] = appscreens_requests
    save_json(report_file, report)
    return True

def get_roles(accesskey: str) -> bool:
    report_data, report_file = get_report_paths(accesskey)
    report_map = load_json(report_data)
    report = load_json(report_file)

    if report is None:
        print(f"Report not found: {report_file}")
        return False

    subdomain = report["target"].get("subdomain", "")
    domain = report["target"].get("domain", "")
    modulename = report["target"].get("modulename", "")

    if not domain or not modulename:
        print("Missing 'domain' or 'modulename' in report.")
        return False

    subdomain_part = f"{subdomain}." if subdomain else ""
    environment = f"https://{subdomain_part}{domain}"

    search_pattern = f"{modulename}.controller"
    url_versions = report_map.get("manifest", {}).get("urlVersions", {})
    client_controller = next(
        (path for path in url_versions.keys()
        if search_pattern in path),
        None
    )

    js_url = f"{environment}{client_controller}"

    headers = build_headers({
        "Accept": "*/*",
        "Sec-Fetch-Dest": "script"
    })

    try:
        response = http_get(js_url, headers)
        response.raise_for_status()
        js_content = response.text
    except Exception as e:
        print(f"Error downloading controller JS: {e}")
        report["roles"] = []
        save_json(report_file, report)
        return False

    block_match = re.search(
        r'Controller\.prototype\.roles\s*=\s*\{(.*?)\};',
        js_content,
        re.DOTALL
    )

    if not block_match:
        print("No roles block found.")
        report["roles"] = []
        save_json(report_file, report)
        return False

    block = block_match.group(1)

    pattern = r'(\w+)\s*:\s*\{\s*roleKey\s*:\s*"([^"]+)"'
    matches = re.findall(pattern, block)

    roles = []
    for name, rolekey in matches:
        roles.append({
            "name": name,
            "rolekey": rolekey
        })

    report["roles"] = roles
    save_json(report_file, report)

    if CONFIG.get("debug_mode", True):
        print(f"Checking and saving roles: {roles}")
    return True

def get_cloudconnet_version(accesskey: str) -> bool:
    _, report_file = get_report_paths(accesskey)
    report = load_json(report_file)

    if report is None:
        print(f"Report not found: {report_file}")
        return False

    subdomain = report["target"].get("subdomain", "")
    domain = report["target"].get("domain", "")

    if not domain:
        print("Missing 'domain' in report.")
        return False

    subdomain_part = f"{subdomain}." if subdomain else ""
    environment = f"https://{subdomain_part}{domain}"

    soap_url = f"{environment}/CloudConnectAgent/CloudConnect.asmx"

    soap_body = """<?xml version="1.0" encoding="utf-8"?>
        <soap12:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                         xmlns:xsd="http://www.w3.org/2001/XMLSchema"
                         xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">
            <soap12:Body>
                <GetVersion xmlns="http://www.outsystems.com" />
            </soap12:Body>
        </soap12:Envelope>"""

    headers = build_headers({
        "Content-Type": "application/soap+xml; charset=utf-8"
    })

    response = http_post(soap_url, data=soap_body, headers=headers)

    if response is None:
        if CONFIG.get("debug_mode", True):
            print(f"CloudConnect is inaccessible on {domain} (Connection/DNS failure).")
        return False

    try:
        response.raise_for_status()
        xml_content = response.text
    except Exception as e:
        print(f"Error calling SOAP CloudConnect: {e}")
        return False

    try:
        root = ET.fromstring(xml_content)

        ns = {
            "soap": "http://www.w3.org/2003/05/soap-envelope",
            "os": "http://www.outsystems.com"
        }

        response_node = root.find(".//os:GetVersionResponse", ns)
        if response_node is None:
            print("GetVersionResponse not found in XML.")
            return False

        version_node = response_node.find("os:Version", ns)
        version_value = version_node.text if version_node is not None else "Unknown"

    except Exception as e:
        print(f"Error processing CloudConnect XML: {e}")
        return False

    report["target"]["cloudconnect_version"] = version_value
    save_json(report_file, report)

    if CONFIG.get("debug_mode", True):
        print(f"Cloud Connect version saved: {version_value}")
    
    return True



if __name__ == '__main__':
    extract_screen_variables("b0cd9a38-b762-4756-871a-4c05c796c610")