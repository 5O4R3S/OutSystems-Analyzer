from flask import Flask, render_template, request, redirect, url_for, flash, stream_with_context, Response, jsonify
from database import init_db, get_scanhistory_items, delete_scanhistory_item, clear_all_scanhistory, ai_clear_cache, db_insert_targetinformations
from handleurl import resolve_url
from dotenv import load_dotenv, set_key
import os
import uuid
import functions
from datetime import datetime
import shutil
import generative
import io
from xhtml2pdf import pisa

load_dotenv(override=True)
init_db()

app = Flask(__name__)
app.secret_key = os.urandom(24).hex()

@app.context_processor
def inject_config():
    return {"config": functions.load_config()}

@app.template_filter('datetimeformat') # Modificado para aceitar um argumento de formato
def datetimeformat(value, format="%d/%m/%Y %H:%M:%S"):
    dt = datetime.fromisoformat(value)
    return dt.strftime(format)

@app.route('/', methods=['GET'])
def homePage():
    return render_template('index.html')

@app.route('/config', methods=['GET', 'POST'])
def configPage():
    if request.method == 'POST':
        current_config = functions.load_config()

        current_config["request_timeout"] = int(request.form.get("request_timeout", 30))
        current_config["max_attempts"] = int(request.form.get("max_attempts", 3))
        
        current_config["quick_mode"] = "quick_mode" in request.form
        current_config["use_random_headers"] = "use_random_headers" in request.form
        current_config["debug_mode"] = "debug_mode" in request.form

        functions.save_config(current_config)

        # 2. NOVA LÓGICA: Salvar a API Key no .env
        gemini_key = request.form.get("gemini_api_key")
        if gemini_key:
            # set_key(caminho_do_arquivo, nome_da_chave, valor)
            # Isso cria o arquivo se não existir ou atualiza se já existir
            set_key(".env", "GEMINI_API_KEY", gemini_key)
        
        return redirect(url_for('configPage'))
    
    # Para o GET, vamos carregar a chave atual para mostrar no input (opcional)
    current_key = os.getenv("GEMINI_API_KEY", "")
    
    return render_template("config.html", gemini_api_key=current_key)

@app.route('/target', methods=['POST'])
def verifyTarget():
    urlTarget = request.form.get('urlToScan')
    
    if not urlTarget:
        flash("The URL was not provided; please fill in the field to continue.", "error")
        return redirect(url_for('homePage'))
    
    urlSplited = resolve_url(urlTarget)
    if urlSplited is None:
        flash("The URL is invalid or unrecognized.", "error")
        return redirect(url_for("homePage"))
    
    domain = urlSplited.get('domain', '')
    subdomain = urlSplited.get('subdomain', '')
    modulename = urlSplited.get('modulename', '')

    accesskey = str(uuid.uuid4())
    parent_key = request.form.get('parentAccessKey')

    create_pre_files = functions.get_moduleinfo_from_target(subdomain, domain, modulename, accesskey, parent_key)

    if create_pre_files == "odc_environment":
        flash("Cannot scan ODC environments.", "error")
        return redirect(url_for("homePage"))

    if create_pre_files is False:
        flash("The target is unavailable, blocked our access, or a connection error occurred.", "error")
        return redirect(url_for("homePage"))

    if db_insert_targetinformations(domain, subdomain, modulename, accesskey):
        return redirect(url_for("scanningPage", accesskey=accesskey))

    flash("There was an error while saving target information to the database.", "error")
    return redirect(url_for("homePage"))

@app.route('/scanning', methods=['GET'])
def scanningPage():
    guid = request.args.get('accesskey')
    if not guid:
        flash("Access key not provided.", "error")
        return redirect(url_for('homePage'))
    
    data_file, report_file = functions.get_report_paths(guid)
    report_full = functions.load_json(report_file)
    
    return render_template('scanning.html', accesskey=guid,report=report_full)

@app.route('/scanningstream')
def scanningStream():
    accesskey = request.args.get('accesskey')
    if not accesskey:
        flash("Access key not provided.", "error")
        return redirect(url_for('homePage'))
    
    config = functions.load_config()

    def generate():
        yield "data: Obtaining information from the target application...\n\n"
        functions.get_app_definitions(accesskey)

        yield "data: Looking for screens in the application...\n\n"
        functions.get_app_screens(accesskey)

        yield "data: Looking for dependencies in the application...\n\n"
        functions.get_app_modules(accesskey)

        yield "data: Looking real DNS (Enterprise Only)...\n\n"
        functions.get_real_dns(accesskey)

        yield "data: Looking for resources...\n\n"
        functions.get_app_resources(accesskey)
    
        yield "data: Looking for ReactView version...\n\n"
        functions.get_react_version(accesskey)

        yield "data: Checking OutSystems Global Version...\n\n"
        functions.get_os_global_version(accesskey)

        yield "data: Checking Security Headers...\n\n"
        functions.get_security_info(accesskey)

        yield "data: Looking for Clients Variables...\n\n"
        functions.get_client_variables(accesskey)

        if not config.get("quick_mode", False):
            yield "data: Looking for Mobile Apps...\n\n"
            functions.get_mobile_apps(accesskey)
        else:
            yield "data: Skipping Mobile Apps [QUICK MODE ENABLED]\n\n"

        yield "data: Looking for Platform Informations...\n\n"
        functions.get_platform_info(accesskey)

        yield "data: Looking for Platform Capabilities...\n\n"
        functions.get_platform_capabilities(accesskey)

        yield "data: Looking for Installation Informations...\n\n"
        functions.get_installation_info(accesskey)

        yield "data: Looking for Handshake Properties...\n\n"
        functions.get_handshake_properties(accesskey)

        yield "data: Looking for external authentication status...\n\n"
        functions.get_external_authentication_status(accesskey)

        yield "data: Retrieving data from the screens to use in the following steps...\n\n"
        functions.download_screen_js_files(accesskey)

        yield "data: Retrieving some endpoints from screens...\n\n"
        functions.extract_rest_endpoints(accesskey)

        yield "data: Checking screen variables...\n\n"
        functions.extract_screen_variables(accesskey)

        if not config.get("quick_mode", False):
            yield "data: Checking the XHR requests for each page takes a while, so grab a coffee...\n\n"
            functions.capture_all_screens_xhr(accesskey)
        else:
            yield "data: Skipping Checking each XHR [QUICK MODE ENABLED]\n\n"
            
        yield "data: Checking References Health...\n\n"
        functions.get_references_health(accesskey)

        yield "data: Validating CKEditor CVE-2022-24728...\n\n"
        functions.check_ckeditor_vulnerability(accesskey)

        yield "data: Testing CKEditor Unrestricted File Upload...\n\n"
        functions.check_ckeditor_upload_vulnerability(accesskey)

        yield "data: Validating Froala Editor CVE-2023-41592...\n\n"
        functions.check_froala_vulnerability(accesskey)

        yield "data: Validating PDFTron vulnerabilities...\n\n"
        functions.check_pdftron_vulnerability(accesskey)

        yield "data: Checking Clickjacking vulnerability...\n\n"
        functions.check_clickjacking_vulnerability(accesskey)

        yield "data: Checking PRSSI/RPO vulnerability...\n\n"
        functions.check_rpo_vulnerability(accesskey)

        yield "data: Checking Debugger Headers exposure...\n\n"
        functions.check_debugger_vulnerability(accesskey)

        if not config.get("quick_mode", False):
            yield "data: Performing deep secret scan on all JS files (it may take time)...\n\n"
            functions.extract_secrets_from_js(accesskey)
        else:
            yield "data: Skipping Deep Secret Scan [QUICK MODE ENABLED]\n\n"

        yield "data: Inspecting Custom JavaScript Blocks (Option 2)...\n\n"
        functions.extract_custom_js_blocks(accesskey)

        yield "data: Analyzing Client Runtime (CSRF, Native, Internal APIs)...\n\n"
        functions.analyze_outsystems_runtime(accesskey)

        yield "data: Checking Roles...\n\n"
        functions.get_roles(accesskey)

        yield "data: Looking for Cloud Connect version...\n\n"
        functions.get_cloudconnet_version(accesskey)
        
        yield "data: Finishing scan...\n\n"
        functions.finish_scan(accesskey)
        
        yield "data: done\n\n"

    return Response(stream_with_context(generate()), mimetype='text/event-stream')

@app.route('/detail', methods=['GET'])
def reportDetailPage():
    guid = request.args.get('accesskey')
    if not guid:
        flash("Access key not provided.", "error")
        return redirect(url_for('homePage'))
    
    data_file, report_file = functions.get_report_paths(guid)
    report_full = functions.load_json(report_file)

    if report_full is None:
        flash("Report not found for this access key.","error")
        return redirect(url_for('homePage'))

    return render_template('detail.html', accesskey=guid,report=report_full)

@app.route('/export_pdf/<accesskey>')
def export_pdf(accesskey):
    data_file, report_file = functions.get_report_paths(accesskey)
    report = functions.load_json(report_file)

    if not report:
        flash("Report not found.", "error")
        return redirect(url_for('homePage'))

    # 1. Renderiza o template HTML com os dados do relatório
    html_content = render_template('pdf_report.html', report=report)
    
    # 2. Prepara o buffer para o PDF
    buffer = io.BytesIO()
    
    # 3. Converte o HTML em PDF usando xhtml2pdf
    pisa_status = pisa.CreatePDF(html_content, dest=buffer)
    
    if pisa_status.err:
        flash("Error generating PDF from template.", "error")
        return redirect(url_for('reportDetailPage', accesskey=accesskey))

    buffer.seek(0)

    modulename = report['target'].get('modulename', 'Report')
    return Response(
        buffer,
        mimetype="application/pdf",
        headers={"Content-Disposition": f"attachment;filename=Report_{modulename}_{accesskey[:8]}.pdf"}
    )

@app.route('/get_scanhistory_items', methods=['GET'])
def get_items():
    items = get_scanhistory_items()
    items_dict = [dict(row) for row in items]
    return jsonify(items_dict)

@app.route('/delete_scan/<accesskey>', methods=['POST'])
def delete_scan(accesskey):
    if delete_scanhistory_item(accesskey):
        data_file, report_file = functions.get_report_paths(accesskey)
        
        try:
            if os.path.exists(report_file):
                os.remove(report_file)
            if os.path.exists(data_file):
                os.remove(data_file)
            flash("Scan deleted successfully.", "success")
        except Exception as e:
            print(f"Error removing file: {e}")
            flash("Record deleted, but there was an error removing the report file.", "warning")
    else:
        flash("Error deleting scan from database.", "error")
    
    return redirect(url_for('homePage'))

@app.route('/clear_all_history', methods=['POST'])
def clear_all_history():
    if clear_all_scanhistory():
        report_dir = 'reports'
        try:
            if os.path.exists(report_dir):
                for filename in os.listdir(report_dir):
                    file_path = os.path.join(report_dir, filename)
                    
                    if filename.startswith('.'):
                        continue

                    if os.path.isdir(file_path):
                        shutil.rmtree(file_path)
                    elif os.path.isfile(file_path):
                        os.remove(file_path)
            
            return "History Cleared", 200
        except Exception as e:
            return f"Error cleaning files: {e}", 500
    else:
        return "Failed to clear database", 500

@app.route('/get-ai-advice', methods=['POST'])
def ai_advice():
    data = request.get_json()
    problema = data.get('problem')
    
    # Chama a função que acabamos de ajustar
    resposta_ia = generative.gemini_generative(problema)
    
    return jsonify({"advice": resposta_ia})

@app.route('/clear-ai-cache', methods=['POST'])
def clear_ai_cache():
    if ai_clear_cache():
        return jsonify({"status": "success", "message": "The AI cache has been successfully cleared."})
    else:
        return jsonify({"status": "error", "message": "Failed to clear AI cache."}), 500

print(f"Running on http://127.0.0.1:5000")

if __name__ == '__main__':
    app.run(debug=False,port=5000)