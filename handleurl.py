from urllib.parse import urlparse

def resolve_url(url: str) -> dict | None:
    """
    Extrai de forma simples:
    - domain: últimos 2 níveis do hostname
    - subdomain: o que vem antes (mas vazio se for apenas 'www' ou começar com 'www.')
    - app: primeiro segmento do path após o domínio
    
    Exemplos:
        www.domain.com/MyApp     → domain='domain.com', subdomain='', app='MyApp'
        luuuucas.outsystemscloud.com/MyApp → domain='outsystemscloud.com', subdomain='luuuucas', app='MyApp'
    """
    url = url.strip()
    if not url:
        return None

    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url.lstrip('/')

    try:
        parsed = urlparse(url)
    except:
        return None

    if not parsed.netloc or not parsed.path:
        return None

    hostname = parsed.netloc.lower()

    if ':' in hostname:
        hostname = hostname.split(':', 1)[0]

    parts = hostname.split('.')

    if len(parts) >= 2:
        domain = '.'.join(parts[-2:])
        subdomain_raw = '.'.join(parts[:-2]) if len(parts) > 2 else ''
    else:
        domain = hostname
        subdomain_raw = ''

    if subdomain_raw == 'www' or subdomain_raw.startswith('www.'):
        subdomain = subdomain_raw[4:] if subdomain_raw.startswith('www.') else ''
    else:
        subdomain = subdomain_raw

    path = parsed.path.rstrip('/')
    if not path or path == '/':
        return None

    app_parts = [p for p in path.split('/') if p]
    if not app_parts:
        return None

    modulename = app_parts[0]

    return {
        'domain': domain,
        'subdomain': subdomain,
        'modulename': modulename,
    }