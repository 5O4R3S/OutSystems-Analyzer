import os
from google import genai
from dotenv import load_dotenv
import hashlib
from database import ai_get_cached_response, ai_save_cache

load_dotenv()

init_prompt = """Act as a Senior OutSystems Security Architect. 
                Briefly explain the security risk of this technical problem, and suggest possible fixes for the Studio, Service Center, LifeTime or the OT ecosystem.
                """

def gemini_generative(problem_text):
    gemini_key = os.getenv("GEMINI_API_KEY")
    problem_key = hashlib.sha256(problem_text.encode()).hexdigest()
    cached_data = ai_get_cached_response(problem_key)
    if cached_data:
        return f"ai_cache:\n\n {cached_data}"

    if not gemini_key:
        return "Error: Gemini api key not found, please check the .env"

    try:

        client = genai.Client(api_key=gemini_key)

        # LISTAR MODELOS DISPONÍVEIS
        modelos_disponiveis = [m.name for m in client.models.list()]

        modelo_alvo = "gemini-1.5-flash" 
        
        # Se o modelo padrão não estiver na lista, pegamos o primeiro da lista que seja Gemini
        if not any(modelo_alvo in m for m in modelos_disponiveis):
            modelo_alvo = modelos_disponiveis[0] if modelos_disponiveis else None

        if not modelo_alvo:
            return "Error: Gemini models not available with this api key."
        
        prompt = f"{init_prompt} \n\nAnalyze the following technical problem encountered in an application: {problem_text}"

        response = client.models.generate_content(
            model=modelo_alvo,
            contents=prompt
        )

        ai_save_cache(problem_key, response.text)
        return response.text

    except Exception as e:
        error_msg = str(e).lower()
        if "503" in error_msg or "unavailable" in error_msg:
            return "High demand, please call back in a few seconds."
        
        return f"Error AI: {str(e)}"