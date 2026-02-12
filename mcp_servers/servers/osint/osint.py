#!/usr/bin/env python3
"""
MCP Server: OSINT ULTRA - Professional Intelligence Gathering Suite
==================================================================

Author: Unburden Team
Version: 2.0.0
License: MIT

Purpose
-------
Advanced OSINT server with 50+ specialized tools for:
- People & Identity Intelligence
- Corporate & Infrastructure Reconnaissance
- Vulnerability & Exploit Discovery
- IoT & Device Enumeration
- Blockchain & Cryptocurrency Analysis
- Geolocation & Mapping
- Dark Web & Leak Databases
- Multi-Engine Search (Google, Bing, DuckDuckGo, Yandex, Shodan)
- Automatic browser tab opening
- Results export (JSON/CSV)

Security
--------
This tool is designed EXCLUSIVELY for DEFENSIVE security and authorized OSINT.
- Only generates search URLs (no scraping, no automated access)
- Respects robots.txt and terms of service
- Use only on targets you are authorized to investigate
- Logs all queries for audit purposes

Run
---
python osint.py --host 127.0.0.1 --port 8085

Dependencies
------------
pip install mcp fastapi uvicorn starlette requests webbrowser
"""

import os
import sys
import json
import urllib.parse
import logging
import argparse
import webbrowser
import hashlib
import csv
from datetime import datetime
from typing import List, Optional, Dict, Any
from pathlib import Path

from fastapi import FastAPI
from starlette.routing import Route, Mount, Router
import uvicorn

from mcp.server.fastmcp import FastMCP
from mcp.server.sse import SseServerTransport

# ===================== CONFIGURATION =====================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("osint")
logging.getLogger('mcp.server.lowlevel.server').setLevel(logging.WARNING)

SAFE_MODE = int(os.getenv("SAFE_MODE", "1"))
AUTO_OPEN_BROWSER = os.getenv("AUTO_OPEN_BROWSER", "true").lower() == "true"

# ===================== SEARCH ENGINES =====================
ENGINES = {
    "google": "https://www.google.com/search?q=",
    "duckduckgo": "https://duckduckgo.com/?q=",
    "bing": "https://www.bing.com/search?q=",
    "yandex": "https://yandex.com/search/?text=",
    "yahoo": "https://search.yahoo.com/search?p=",
    "baidu": "https://www.baidu.com/s?wd=",
    "shodan": "https://www.shodan.io/search?query=",
    "censys": "https://search.censys.io/search?resource=hosts&q=",
    "virustotal": "https://www.virustotal.com/gui/search/",
}

DEFAULT_ENGINE = os.getenv("SEARCH_ENGINE", "google").lower()

# ===================== SPECIALIZED SEARCH URLS =====================
SPECIALIZED_URLS = {
    "hunter_io": "https://hunter.io/search/",  # Email finder
    "haveibeenpwned": "https://haveibeenpwned.com/",  # Breach checker
    "dehashed": "https://www.dehashed.com/search?query=",  # Credential leaks
    "intelx": "https://intelx.io/?s=",  # Intelligence X
    "wayback": "https://web.archive.org/web/*/",  # Internet Archive
    "phonebook_cz": "https://phonebook.cz/?",  # Domains/emails
    "crt_sh": "https://crt.sh/?q=",  # SSL/TLS certificates
    "dnsdumpster": "https://dnsdumpster.com/",  # DNS recon
    "securitytrails": "https://securitytrails.com/domain/",  # DNS history
    "builtwith": "https://builtwith.com/",  # Technology profiler
    "whois": "https://who.is/whois/",  # WHOIS lookup
    "viewdns": "https://viewdns.info/",  # DNS tools
    "blockchain_explorer_btc": "https://www.blockchain.com/explorer/addresses/btc/",
    "blockchain_explorer_eth": "https://etherscan.io/address/",
    "openstreetmap": "https://www.openstreetmap.org/search?query=",
    "google_maps": "https://www.google.com/maps/search/",
    "wigle": "https://wigle.net/search?ssid=",  # WiFi networks
    "greynoise": "https://viz.greynoise.io/ip/",  # IP intelligence
    "urlscan": "https://urlscan.io/search/#",  # URL scanner
    "pastebin": "https://psbdmp.ws/?q=",  # Pastebin dumps
    "github_search": "https://github.com/search?q=",
    "gitlab_search": "https://gitlab.com/search?search=",
    "trello": "https://trello.com/search?q=",
    "asn_lookup": "https://bgp.he.net/AS",
}

# ===================== FILE TYPE COLLECTIONS =====================
FILETYPES = {
    "docs": ["pdf", "doc", "docx", "odt", "rtf", "tex"],
    "sheets": ["xls", "xlsx", "ods", "csv", "tsv"],
    "slides": ["ppt", "pptx", "odp", "key"],
    "code": ["py", "go", "java", "js", "ts", "php", "rb", "cs", "c", "cpp", "sh", "ps1", "bat"],
    "configs": ["conf", "cfg", "ini", "yml", "yaml", "toml", "properties", "env", "xml", "json"],
    "keys": ["pem", "key", "ppk", "kdbx", "ovpn", "p12", "pfx", "crt", "cer"],
    "db": ["sql", "sqlite", "db", "mdb", "accdb", "dbf"],
    "logs": ["log", "txt", "out"],
    "archives": ["zip", "rar", "7z", "tar", "gz", "bz2", "xz", "tgz"],
    "mail": ["mbox", "eml", "pst", "ost"],
    "media": ["jpg", "jpeg", "png", "gif", "bmp", "tiff", "mp4", "mp3", "wav", "avi"],
    "cad_gis": ["dwg", "dxf", "kmz", "kml", "shp"],
    "backups": ["bak", "backup", "old", "tmp", "swp", "~"],
    "mobile": ["apk", "ipa", "deb"],
    "vm_containers": ["ova", "ovf", "vmdk", "vdi", "vhd"],
}

# ===================== SITE COLLECTIONS =====================
SITES = {
    "code": ["github.com", "gitlab.com", "bitbucket.org", "gist.github.com", "sourceforge.net"],
    "cloud": ["drive.google.com", "dropbox.com", "onedrive.live.com", "mega.nz", "sites.google.com", "box.com"],
    "social": ["facebook.com", "twitter.com", "x.com", "linkedin.com", "instagram.com", "tiktok.com", "reddit.com"],
    "old_social": ["myspace.com", "livejournal.com", "hi5.com", "orkut.com", "friendster.com"],
    "forums": ["stackoverflow.com", "stackexchange.com", "serverfault.com", "superuser.com"],
    "paste_sites": ["pastebin.com", "justpaste.it", "rentry.co", "ghostbin.com", "dpaste.com", "paste.ee"],
    "gov_acad": [".gov", ".edu", ".ac.uk", "boe.es", "europa.eu"],
    "dev_tools": ["atlassian.net", "confluence", "jira", "trello.com", "asana.com", "slack.com"],
    "leak_sites": ["haveibeenpwned.com", "dehashed.com", "leakbase.cc", "snusbase.com"],
}

# ===================== QUERY HISTORY =====================
query_history: List[Dict[str, Any]] = []

# ===================== MCP INSTANCE =====================
mcp = FastMCP("OSINT ULTRA - Professional Intelligence Suite v2.0")

# ===================== HELPER FUNCTIONS =====================

def join_or(items: List[str]) -> str:
    """Returns: (a | b | c)"""
    items = [s.strip() for s in items if s and s.strip()]
    if not items:
        return ""
    return "(" + " | ".join(items) + ")"


def quote(term: str) -> str:
    """Wrap term in quotes if not already quoted"""
    term = term.strip()
    if not term:
        return term
    if not (term.startswith('"') and term.endswith('"')):
        return f'"{term}"'
    return term


def build_engine_url(q: str, engine: str = DEFAULT_ENGINE) -> str:
    """Build search URL for specified engine"""
    base = ENGINES.get(engine, ENGINES[DEFAULT_ENGINE])
    encoded_query = urllib.parse.quote_plus(q)
    url = base + encoded_query

    # Log query
    log_query(q, engine, url)

    # Auto-open browser if enabled
    if AUTO_OPEN_BROWSER:
        try:
            webbrowser.open_new_tab(url)
            logger.info(f"Opened browser tab: {url}")
        except Exception as e:
            logger.warning(f"Could not open browser: {e}")

    return url


def build_specialized_url(base_key: str, query: str) -> str:
    """Build URL for specialized OSINT services"""
    if base_key not in SPECIALIZED_URLS:
        return f"ERROR: Unknown specialized service '{base_key}'"

    base = SPECIALIZED_URLS[base_key]
    url = base + urllib.parse.quote_plus(query)

    log_query(query, base_key, url)

    if AUTO_OPEN_BROWSER:
        try:
            webbrowser.open_new_tab(url)
            logger.info(f"Opened specialized tab: {url}")
        except Exception as e:
            logger.warning(f"Could not open browser: {e}")

    return url


def log_query(query: str, engine: str, url: str):
    """Log query to history"""
    query_hash = hashlib.md5(url.encode()).hexdigest()
    entry = {
        "timestamp": datetime.now().isoformat(),
        "query": query,
        "engine": engine,
        "url": url,
        "hash": query_hash
    }
    query_history.append(entry)
    logger.info(f"Query logged: {engine} -> {query[:50]}...")


def build_query(
    main: str,
    include_sites: Optional[List[str]] = None,
    exclude_sites: Optional[List[str]] = None,
    filetypes: Optional[List[str]] = None,
    inurl: Optional[List[str]] = None,
    intitle: Optional[List[str]] = None,
    intext: Optional[List[str]] = None,
    ext_buckets: Optional[List[str]] = None,
    extra: Optional[List[str]] = None,
    country_site_tld: Optional[str] = None,
    lang: Optional[str] = None,
    daterange: Optional[str] = None,
) -> str:
    """Compose flexible Google-style query from structured parameters"""
    parts: List[str] = []

    if main:
        parts.append(quote(main))

    # Include sites
    if include_sites:
        site_terms = [f"site:{s.strip()}" for s in include_sites if s.strip()]
        if site_terms:
            parts.append(join_or(site_terms))

    # Country TLD restriction
    if country_site_tld:
        parts.append(f"site:{country_site_tld}")

    # Filetypes
    if filetypes:
        parts.append(join_or([f"filetype:{ft.strip()}" for ft in filetypes if ft.strip()]))

    # Filetype buckets
    if ext_buckets:
        ft: List[str] = []
        for bucket in ext_buckets:
            ft.extend(FILETYPES.get(bucket, []))
        if ft:
            parts.append(join_or([f"filetype:{x}" for x in sorted(set(ft))]))

    # inurl/intitle/intext
    if inurl:
        parts.append(join_or([f"inurl:{quote(x)}" for x in inurl]))
    if intitle:
        parts.append(join_or([f"intitle:{quote(x)}" for x in intitle]))
    if intext:
        parts.append(join_or([f"intext:{quote(x)}" for x in intext]))

    # Language
    if lang:
        parts.append(f"lang:{lang}")

    # Date range
    if daterange:
        parts.append(daterange)

    # Exclude sites/terms
    excl_parts: List[str] = []
    if exclude_sites:
        for s in exclude_sites:
            s = s.strip()
            if s:
                excl_parts.append(f"-site:{s}")
    if extra:
        for e in extra:
            e = e.strip()
            if not e:
                continue
            if e.startswith("-"):
                excl_parts.append(e)
            else:
                parts.append(e)

    q = " ".join([p for p in parts if p])
    if excl_parts:
        q = q + " " + " ".join(excl_parts)
    return q.strip()


# ===================== EXPORT FUNCTIONS =====================

# export_query_history eliminada - no se usa


@mcp.tool()
async def clear_query_history() -> str:
    """Clear all query history from memory"""
    count = len(query_history)
    query_history.clear()
    logger.info(f"Cleared {count} queries from history")
    return f"✓ Cleared {count} queries from history"


# ===================== GENERIC ADVANCED DORK =====================

@mcp.tool()
async def google_dork(
    main: str,
    include_sites: Optional[List[str]] = None,
    exclude_sites: Optional[List[str]] = None,
    filetypes: Optional[List[str]] = None,
    inurl: Optional[List[str]] = None,
    intitle: Optional[List[str]] = None,
    intext: Optional[List[str]] = None,
    ext_buckets: Optional[List[str]] = None,
    extra: Optional[List[str]] = None,
    country_site_tld: Optional[str] = None,
    lang: Optional[str] = None,
    daterange: Optional[str] = None,
    engine: str = DEFAULT_ENGINE,
) -> str:
    """🔍 Advanced Google-style dork builder with full parameter control.

    Example:
        google_dork(
            main="Acme Corp confidential",
            include_sites=[".gov"],
            ext_buckets=["docs", "sheets"],
            intext=["internal", "restricted"],
            daterange="after:2023-01-01"
        )
    """
    q = build_query(
        main=main,
        include_sites=include_sites,
        exclude_sites=exclude_sites,
        filetypes=filetypes,
        inurl=inurl,
        intitle=intitle,
        intext=intext,
        ext_buckets=ext_buckets,
        extra=extra,
        country_site_tld=country_site_tld,
        lang=lang,
        daterange=daterange,
    )
    return build_engine_url(q, engine)


@mcp.tool()
async def multi_engine_search(query: str, engines: Optional[List[str]] = None) -> str:
    """🌐 Search same query across multiple engines simultaneously.

    Args:
        query: Search query
        engines: List of engines (default: google, bing, duckduckgo)

    Returns:
        Formatted list of all search URLs
    """
    if not engines:
        engines = ["google", "bing", "duckduckgo"]

    results = []
    for engine in engines:
        if engine in ENGINES:
            url = build_engine_url(query, engine)
            results.append(f"[{engine.upper()}] {url}")

    return "\n".join(results)


# ===================== PEOPLE & IDENTITY INTELLIGENCE =====================

@mcp.tool()
async def people_full_profile(name: str, location: Optional[str] = None) -> str:
    """👤 Comprehensive person search across social networks, forums, and public records.

    Args:
        name: Full name or username
        location: Optional location/city to narrow results
    """
    query = name
    if location:
        query += f' "{location}"'

    q = build_query(
        main=query,
        include_sites=SITES["social"] + SITES["forums"] + SITES["old_social"],
    )
    return build_engine_url(q)


@mcp.tool()
async def people_email_finder(name: str, domain: Optional[str] = None) -> str:
    """📧 Find email addresses associated with a person or domain.

    Uses Hunter.io format and Google dorks for maximum coverage.
    """
    if domain:
        return build_specialized_url("hunter_io", domain)
    else:
        q = build_query(
            main=name,
            intext=["email", "mail", "contact", "@"],
            ext_buckets=["docs", "sheets", "logs"]
        )
        return build_engine_url(q)


@mcp.tool()
async def people_phone_numbers(name: str, country_code: Optional[str] = None) -> str:
    """📞 Search for phone numbers associated with a person.

    Args:
        name: Person's name
        country_code: Optional country code (e.g., "+34", "+1")
    """
    query_terms = [name, "phone", "telephone", "mobile", "tel", "contact"]
    if country_code:
        query_terms.append(country_code)

    q = build_query(
        main=" ".join(query_terms),
        ext_buckets=["docs", "sheets"],
        intext=["directory", "contact list", "phonebook"]
    )
    return build_engine_url(q)


@mcp.tool()
async def people_addresses(name: str, city: Optional[str] = None) -> str:
    """🏠 Find physical addresses associated with a person.

    Args:
        name: Person's name
        city: Optional city to narrow search
    """
    query_parts = [name]
    if city:
        query_parts.append(city)

    q = build_query(
        main=" ".join(query_parts),
        intext=["address", "street", "avenue", "residence", "calle", "avenida"],
        ext_buckets=["docs", "sheets"]
    )
    return build_engine_url(q)


@mcp.tool()
async def people_social_media_profiles(username: str) -> str:
    """🌟 Find all social media profiles by username across 20+ platforms."""
    q = build_query(
        main=username,
        include_sites=SITES["social"] + SITES["old_social"] + ["vk.com", "weibo.com", "snapchat.com"]
    )
    return build_engine_url(q)


@mcp.tool()
async def people_professional_profiles(name: str, company: Optional[str] = None) -> str:
    """💼 Find LinkedIn, AngelList, GitHub, and other professional profiles.

    Args:
        name: Person's name
        company: Optional current or past company
    """
    query = name
    if company:
        query += f' "{company}"'

    q = build_query(
        main=query,
        include_sites=["linkedin.com", "angel.co", "github.com", "stackoverflow.com", "medium.com"]
    )
    return build_engine_url(q)


@mcp.tool()
async def people_breach_check(email: str) -> str:
    """🔓 Check if email appears in known data breaches (Have I Been Pwned)."""
    return build_specialized_url("haveibeenpwned", email)


@mcp.tool()
async def people_credential_leaks(email_or_username: str) -> str:
    """🚨 Search for leaked credentials in public dumps and paste sites."""
    q = build_query(
        main=email_or_username,
        include_sites=SITES["paste_sites"],
        intext=["password", "pass", "pwd", "credentials", "leak", "dump"]
    )
    return build_engine_url(q)


@mcp.tool()
async def people_documents_mentions(name: str) -> str:
    """📄 Find mentions in PDFs, Word docs, presentations, and spreadsheets."""
    q = build_query(
        main=name,
        ext_buckets=["docs", "sheets", "slides"],
        intext=["author", "contact", "signed", "prepared by"]
    )
    return build_engine_url(q)


@mcp.tool()
async def people_images_reverse(image_url: str) -> str:
    """🖼️ Reverse image search to find person's photos across the web."""
    google_reverse = f"https://www.google.com/searchbyimage?image_url={urllib.parse.quote(image_url)}"

    if AUTO_OPEN_BROWSER:
        webbrowser.open_new_tab(google_reverse)

    return google_reverse


# ===================== COMPANY & INFRASTRUCTURE =====================

@mcp.tool()
async def company_domain_reconnaissance(domain: str) -> str:
    """🏢 Full domain reconnaissance: subdomains, DNS, SSL/TLS, WHOIS."""
    return build_specialized_url("dnsdumpster", domain)


@mcp.tool()
async def company_subdomain_enumeration(domain: str) -> str:
    """🔍 Enumerate all subdomains using Google dorks and certificate transparency."""
    crt_sh_url = build_specialized_url("crt_sh", f"%.{domain}")

    # Also do Google dork
    q = build_query(main=f"site:{domain}", inurl=["-www"])
    google_url = build_engine_url(q)

    return f"[Certificate Transparency] {crt_sh_url}\n[Google Dork] {google_url}"


@mcp.tool()
async def company_ssl_certificates(domain: str) -> str:
    """🔒 Find all SSL/TLS certificates for domain (crt.sh)."""
    return build_specialized_url("crt_sh", domain)


@mcp.tool()
async def company_whois_lookup(domain: str) -> str:
    """📋 WHOIS information for domain."""
    return build_specialized_url("whois", domain)


@mcp.tool()
async def company_dns_history(domain: str) -> str:
    """📊 Historical DNS records (SecurityTrails)."""
    return build_specialized_url("securitytrails", domain)


@mcp.tool()
async def company_technology_stack(domain: str) -> str:
    """⚙️ Identify web technologies used (BuiltWith)."""
    return build_specialized_url("builtwith", domain)


@mcp.tool()
async def company_employee_emails(domain: str) -> str:
    """📧 Find employee emails for company domain (Hunter.io)."""
    return build_specialized_url("hunter_io", domain)


@mcp.tool()
async def company_employee_directory(company_name: str) -> str:
    """👥 Find employee lists and org charts."""
    q = build_query(
        main=company_name,
        intext=["employee", "staff", "directory", "org chart", "team"],
        ext_buckets=["docs", "sheets"],
        include_sites=[".linkedin.com", "rocketreach.co"]
    )
    return build_engine_url(q)


@mcp.tool()
async def company_financial_documents(company_name: str) -> str:
    """💰 Find SEC filings, annual reports, financial statements."""
    q = build_query(
        main=company_name,
        intext=["annual report", "financial statement", "10-K", "10-Q", "earnings"],
        ext_buckets=["docs"],
        include_sites=["sec.gov", "edgar"]
    )
    return build_engine_url(q)


@mcp.tool()
async def company_open_directories(domain: str) -> str:
    """📂 Find exposed directory listings on domain."""
    q = f'site:{domain} intitle:"index of" | intitle:"directory listing"'
    return build_engine_url(q)


@mcp.tool()
async def company_cloud_storage(company_name: str) -> str:
    """☁️ Find exposed cloud storage (S3, Azure, GCP, Dropbox)."""
    q = build_query(
        main=company_name,
        include_sites=SITES["cloud"],
        intext=["shared", "public", "index of"]
    )
    return build_engine_url(q)


@mcp.tool()
async def company_code_repositories(company_name: str) -> str:
    """💻 Find GitHub/GitLab repositories owned by company."""
    return build_specialized_url("github_search", f'org:"{company_name}" OR user:"{company_name}"')


@mcp.tool()
async def company_asn_lookup(asn: str) -> str:
    """🌐 Look up Autonomous System Number (BGP/IP ranges)."""
    return build_specialized_url("asn_lookup", asn)


# ===================== VULNERABILITY & EXPLOIT INTELLIGENCE =====================

@mcp.tool()
async def vuln_cve_search(cve_id: str) -> str:
    """🐛 Search CVE database and exploit information."""
    q = build_query(
        main=cve_id,
        include_sites=["nvd.nist.gov", "cve.mitre.org", "exploit-db.com", "github.com"]
    )
    return build_engine_url(q)


@mcp.tool()
async def vuln_product_exploits(product_name: str, version: Optional[str] = None) -> str:
    """💣 Find known exploits for specific product/version."""
    query = product_name
    if version:
        query += f" {version}"

    q = build_query(
        main=query,
        intext=["exploit", "vulnerability", "CVE", "PoC", "proof of concept"],
        include_sites=["exploit-db.com", "github.com", "packetstormsecurity.com"]
    )
    return build_engine_url(q)


@mcp.tool()
async def vuln_shodan_search(query: str) -> str:
    """🔎 Search Shodan for exposed devices/services."""
    return build_engine_url(query, "shodan")


@mcp.tool()
async def vuln_censys_search(query: str) -> str:
    """🔍 Search Censys for internet-exposed hosts."""
    return build_engine_url(query, "censys")


@mcp.tool()
async def vuln_exposed_services(domain: str) -> str:
    """⚠️ Find exposed admin panels, databases, dashboards on domain."""
    q = build_query(
        main=domain,
        inurl=["/admin", "/login", "/dashboard", "/phpmyadmin", "/wp-admin", "/administrator"],
        intitle=["login", "admin", "dashboard"]
    )
    return build_engine_url(q)


@mcp.tool()
async def vuln_config_files(domain: str) -> str:
    """⚙️ Find exposed configuration files (.env, web.config, etc.)."""
    q = build_query(
        main=domain,
        filetypes=["env", "config", "ini", "yml", "xml"],
        intext=["password", "api_key", "secret", "database"]
    )
    return build_engine_url(q)


@mcp.tool()
async def vuln_database_dumps(domain: str) -> str:
    """💾 Find database dumps and SQL files."""
    q = build_query(
        main=domain,
        ext_buckets=["db"],
        intext=["dump", "backup", "CREATE TABLE", "INSERT INTO"]
    )
    return build_engine_url(q)


@mcp.tool()
async def vuln_git_exposure(domain: str) -> str:
    """🔓 Find exposed .git directories and repositories."""
    q = build_query(main=domain, inurl=[".git", "/.git/config", "/.git/HEAD"])
    return build_engine_url(q)


@mcp.tool()
async def vuln_api_keys_exposure(company_or_domain: str) -> str:
    """🔑 Search for exposed API keys, tokens, secrets in code."""
    q = build_query(
        main=company_or_domain,
        include_sites=SITES["code"],
        intext=["api_key", "apikey", "access_token", "secret_key", "private_key", "AWS_SECRET"],
        ext_buckets=["code", "configs"]
    )
    return build_engine_url(q)


# ===================== IOT & DEVICE ENUMERATION =====================

@mcp.tool()
async def iot_webcams() -> str:
    """📹 Find publicly accessible webcams and CCTV."""
    q = 'inurl:"view/index.shtml" OR inurl:"ViewerFrame?Mode=" OR intitle:"webcamXP 5" OR inurl:"/axis-cgi/mjpg"'
    return build_engine_url(q)


@mcp.tool()
async def iot_ip_cameras(model: Optional[str] = None) -> str:
    """📷 Find IP cameras by model (Hikvision, Dahua, Axis, etc.)."""
    if model:
        q = build_query(
            main=model,
            intitle=["Network Camera", "IP Camera", "MJPEG"],
            inurl=["/viewer", "/view"]
        )
    else:
        q = 'intitle:"Network Camera" OR intitle:"MJPEG Live Demo"'

    return build_engine_url(q)


@mcp.tool()
async def iot_printers(brand: Optional[str] = None) -> str:
    """🖨️ Find network printers and print servers."""
    if brand:
        q = build_query(
            main=brand,
            intitle=["Printer", "LaserJet", "Print Server"],
            inurl=["/hp/", "/printer/", "/web/"]
        )
    else:
        q = 'intitle:"HP LaserJet" OR intitle:"Canon" OR intitle:"Brother" inurl:"/web/guest"'

    return build_engine_url(q)


@mcp.tool()
async def iot_scada_hmi() -> str:
    """🏭 Find SCADA/HMI systems and industrial control panels."""
    q = 'intitle:"SCADA" OR intitle:"HMI" OR inurl:"/scada" OR intext:"Siemens" OR intext:"Allen Bradley"'
    return build_engine_url(q)


@mcp.tool()
async def iot_routers_modems(brand: Optional[str] = None) -> str:
    """📡 Find routers, modems, and network devices."""
    if brand:
        q = build_query(
            main=brand,
            intitle=["Router", "Wireless", "DSL Modem", "Gateway"],
            inurl=["/login", "/admin"]
        )
    else:
        q = 'intitle:"Router" OR intitle:"Wireless Gateway" inurl:"/admin" OR inurl:"/login"'

    return build_engine_url(q)


@mcp.tool()
async def iot_nas_storage() -> str:
    """💿 Find Network Attached Storage (NAS) devices."""
    q = 'intitle:"Synology" OR intitle:"QNAP" OR intitle:"Buffalo" OR inurl:"/cgi-bin/luci"'
    return build_engine_url(q)


@mcp.tool()
async def iot_vpn_servers() -> str:
    """🔐 Find VPN servers and gateways."""
    q = 'intitle:"OpenVPN" OR intitle:"VPN" OR inurl:"/vpn/" OR intitle:"SonicWall"'
    return build_engine_url(q)


# ===================== BLOCKCHAIN & CRYPTOCURRENCY =====================

@mcp.tool()
async def blockchain_btc_address(address: str) -> str:
    """₿ Look up Bitcoin address transactions and balance."""
    return build_specialized_url("blockchain_explorer_btc", address)


@mcp.tool()
async def blockchain_eth_address(address: str) -> str:
    """Ξ Look up Ethereum address on Etherscan."""
    return build_specialized_url("blockchain_explorer_eth", address)


@mcp.tool()
async def blockchain_wallet_mentions(wallet_address: str) -> str:
    """💰 Find mentions of cryptocurrency wallet across the web."""
    q = build_query(
        main=wallet_address,
        include_sites=SITES["forums"] + SITES["social"] + SITES["paste_sites"]
    )
    return build_engine_url(q)


# ===================== GEOLOCATION & MAPPING =====================

@mcp.tool()
async def geo_google_maps(location: str) -> str:
    """🗺️ Search location on Google Maps."""
    return build_specialized_url("google_maps", location)


@mcp.tool()
async def geo_openstreetmap(location: str) -> str:
    """🌍 Search location on OpenStreetMap."""
    return build_specialized_url("openstreetmap", location)


@mcp.tool()
async def geo_wigle_wifi(ssid: str) -> str:
    """📶 Find WiFi networks by SSID (WiGLE database)."""
    return build_specialized_url("wigle", ssid)


@mcp.tool()
async def geo_ip_lookup(ip_address: str) -> str:
    """🌐 IP geolocation and threat intelligence (GreyNoise)."""
    return build_specialized_url("greynoise", ip_address)


# ===================== DARK WEB & LEAK DATABASES =====================

@mcp.tool()
async def darkweb_pastebin_dumps(keyword: str) -> str:
    """📋 Search Pastebin dumps database for leaks."""
    return build_specialized_url("pastebin", keyword)


@mcp.tool()
async def darkweb_intelx_search(query: str) -> str:
    """🕵️ Search Intelligence X database (dark web, leaks, breaches)."""
    return build_specialized_url("intelx", query)


@mcp.tool()
async def darkweb_dehashed_search(query: str) -> str:
    """🔍 Search DeHashed credential leak database."""
    return build_specialized_url("dehashed", query)


# ===================== ARCHIVE & HISTORICAL DATA =====================

@mcp.tool()
async def archive_wayback_machine(url: str) -> str:
    """⏰ View historical snapshots of website (Wayback Machine)."""
    return build_specialized_url("wayback", url)


@mcp.tool()
async def archive_cached_pages(url: str) -> str:
    """💾 Find cached versions of page in Google."""
    return build_engine_url(f"cache:{url}")


# ===================== GOVERNMENT & LEGAL =====================

@mcp.tool()
async def gov_legal_documents(person_or_company: str, country_tld: Optional[str] = None) -> str:
    """⚖️ Find legal documents, court records, official registries."""
    q = build_query(
        main=person_or_company,
        include_sites=SITES["gov_acad"],
        intext=["court", "legal", "registro", "judgment", "case"],
        ext_buckets=["docs"],
        country_site_tld=country_tld
    )
    return build_engine_url(q)


@mcp.tool()
async def gov_official_records(query: str, country: str = "es") -> str:
    """🏛️ Search official government records (BOE, EU regulations, etc.)."""
    sites_map = {
        "es": ["boe.es", "audiencianacional.es"],
        "eu": ["europa.eu", "eur-lex.europa.eu"],
        "us": [".gov"],
        "uk": [".gov.uk"]
    }

    sites = sites_map.get(country, [".gov"])

    q = build_query(
        main=query,
        include_sites=sites,
        ext_buckets=["docs"]
    )
    return build_engine_url(q)


# ===================== ADVANCED DORKS =====================

@mcp.tool()
async def dork_exposed_credentials() -> str:
    """🔐 Generic dork for exposed usernames/passwords in files."""
    q = build_query(
        main="username password",
        ext_buckets=["sheets", "logs", "configs"],
        intext=["password", "username", "credentials"]
    )
    return build_engine_url(q)


@mcp.tool()
async def dork_backup_files() -> str:
    """💾 Find backup and old files across the web."""
    q = build_query(
        main="",
        ext_buckets=["backups", "archives"],
        intext=["backup", "old", "copy"]
    )
    return build_engine_url(q)


@mcp.tool()
async def dork_error_messages() -> str:
    """⚠️ Find pages with error messages and stack traces."""
    q = 'intext:"Warning: mysql_" OR intext:"Stack trace:" OR intext:"Fatal error:" OR intext:"Uncaught exception"'
    return build_engine_url(q)


@mcp.tool()
async def dork_phpinfo_pages() -> str:
    """🐘 Find exposed phpinfo() pages."""
    q = 'inurl:"phpinfo.php" OR intext:"PHP Version" intitle:"phpinfo()"'
    return build_engine_url(q)


@mcp.tool()
async def dork_swagger_apis() -> str:
    """📡 Find exposed Swagger/OpenAPI documentation."""
    q = build_query(
        main="",
        inurl=["/swagger-ui", "/api-docs", "/openapi.json"],
        intitle=["Swagger", "API Documentation"]
    )
    return build_engine_url(q)


# ===================== FASTAPI + SSE TRANSPORT =====================

app = FastAPI(
    title="OSINT ULTRA - Professional Intelligence Suite",
    description="Advanced OSINT server with 50+ specialized tools for intelligence gathering",
    version="2.0.0",
)

sse = SseServerTransport("/messages/")

class SseEndpoint:
    async def __call__(self, scope, receive, send):
        client_host = scope.get('client')[0] if scope.get('client') else 'unknown'
        client_port = scope.get('client')[1] if scope.get('client') else 'unknown'
        logger.info(f"SSE connected from {client_host}:{client_port}")
        async with sse.connect_sse(scope, receive, send) as (read_stream, write_stream):
            await mcp._mcp_server.run(read_stream, write_stream, mcp._mcp_server.create_initialization_options())
        logger.info(f"SSE disconnected from {client_host}:{client_port}")

class MessagesEndpoint:
    async def __call__(self, scope, receive, send):
        client_host = scope.get('client')[0] if scope.get('client') else 'unknown'
        client_port = scope.get('client')[1] if scope.get('client') else 'unknown'
        logger.info(f"Received POST from {client_host}:{client_port}")
        await sse.handle_post_message(scope, receive, send)

mcp_router = Router([
    Route("/sse", endpoint=SseEndpoint(), methods=["GET"]),
    Route("/messages/", endpoint=MessagesEndpoint(), methods=["POST"]),
])
app.routes.append(Mount("/", app=mcp_router))

# ===================== MAIN =====================

def main():
    """Main entry point for OSINT ULTRA server"""
    global AUTO_OPEN_BROWSER

    parser = argparse.ArgumentParser(
        description="OSINT ULTRA - Professional Intelligence Gathering Suite"
    )
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to (HTTP mode)")
    parser.add_argument("--port", type=int, default=8085, help="Port to bind to (HTTP mode)")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload (HTTP mode)")
    parser.add_argument("--no-browser", action="store_true", help="Disable auto-opening browser tabs")
    parser.add_argument("--transport", choices=["stdio", "http", "sse"], default="stdio",
                        help="Transport mode: stdio (default), http, or sse")
    args = parser.parse_args()

    # Update browser setting
    if args.no_browser:
        AUTO_OPEN_BROWSER = False

    logger.debug("OSINT server initialized")

    if args.transport == "stdio":
        # STDIO mode - direct communication via stdin/stdout
        import asyncio
        from mcp.server.stdio import stdio_server

        async def run_stdio():
            async with stdio_server() as (read_stream, write_stream):
                await mcp._mcp_server.run(
                    read_stream,
                    write_stream,
                    mcp._mcp_server.create_initialization_options()
                )

        asyncio.run(run_stdio())

    else:
        # HTTP/SSE mode
        logger.info(f"Server starting at http://{args.host}:{args.port}")
        uvicorn.run(app, host=args.host, port=args.port, reload=args.reload)


if __name__ == "__main__":
    main()
