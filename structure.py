from datetime import datetime

def get_struct_report_file() -> dict:
    empty_structure = {
        "metadata": {
        "analysis_id": "",
        "started_at": datetime.utcnow().isoformat(),
        "finished_at": None,
        "status": "pending"
        },
        "target": {
        "domain": "",
        "subdomain": "",
        "modulename": "",
        "full_url": "",
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
        "appscreensRequests":[]
    }
    return empty_structure