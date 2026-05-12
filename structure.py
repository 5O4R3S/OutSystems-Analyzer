from datetime import datetime, timezone

def get_struct_report_file() -> dict:
    empty_structure = {
        "metadata": {
        "analysis_id": "",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "finished_at": None,
        "status": "pending"
        },
        "target": {
        "domain": "",
        "subdomain": "",
        "modulename": "",
        "full_url": "",
        "module_version_hash": "",
        "real_dns":"",
        "applicationName": "",
        "applicationKey": "",
        "environmentName": "",
        "environmentKey": "",
        "homeModuleName": "",
        "homeModuleKey": "",
        "userTenantProvider": "",
        "react_version":"",
        "cloudconnect_version":""
        },
        "security_headers": {},
        "appscreens":[],
        "dependencies":[],
        "resources":[],
        "references_health":[],
        "client_variables":[],
        "mobile_apps":[],
        "platform_info":{},
        "platform_capabilities":[],
        "installation_info":{},
        "handshake_properties":[],
        "external_authentication":{},
        "endpoints":[],
        "screens_detail":[],
        "appscreensRequests":[],
        "roles":[],
        "interaction_xhr_analysis":[],
        "vulnerabilities": []
    }
    return empty_structure