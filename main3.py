import typer
import requests
import re
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt
from rich.markdown import Markdown
from random import choice
from bs4 import BeautifulSoup

app = typer.Typer()

def fetch_cve_data(cve_id):
    """Fetch CVE data from the NVD API."""
    nvd_response = requests.get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}")
    nvd_response.raise_for_status()
    return nvd_response.json()


def fetch_epss_data(cve_id):
    """Fetch EPSS percentile by scraping CVE Details."""
    url = f"https://www.cvedetails.com/?cve/cve={cve_id}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'html.parser')

        epss_percentile_tag = soup.find('div', id='cvssscorestable')
        if epss_percentile_tag:
            epss_percentile_text = epss_percentile_tag.text.strip()
            match = re.search(r"(\d+\.?\d*) percentile", epss_percentile_text)
            if match:
                return float(match.group(1))
    except requests.exceptions.RequestException as e:
        print(f"[bold red]Error fetching EPSS data: {e}[/bold red]")
    return None

def fetch_kev_data():
    """Fetch known exploited vulnerabilities data from CISA."""
    kev_response = requests.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
    kev_response.raise_for_status()
    return kev_response.json()

def get_impact_analysis(vulnerability):
    """Analyze the impact of the vulnerability based on CVSS metrics."""
    cvss_v3_metrics = vulnerability.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {})
    cvss_v2_metrics = vulnerability.get("metrics", {}).get("cvssMetricV2", [{}])[0].get("cvssData", {})

    impact_analysis = {
        "Confidentiality Impact": cvss_v3_metrics.get("confidentialityImpact", "N/A"),
        "Integrity Impact": cvss_v3_metrics.get("integrityImpact", "N/A"),
        "Availability Impact": cvss_v3_metrics.get("availabilityImpact", "N/A"),
        "Access Vector": cvss_v2_metrics.get("accessVector", "N/A"),
        "Access Complexity": cvss_v2_metrics.get("accessComplexity", "N/A"),
        "Authentication": cvss_v2_metrics.get("authentication", "N/A")
    }
    
    return impact_analysis

@app.command()
def greet():
    """Fetches and displays CVE information from the NVD and KEV catalogs, including exploitability status."""

    console = Console()
    
    # Display a fun ASCII art banner
    with open("banner.txt", "r") as f:
        banner = f.read()
    console.print(Panel(banner, style="bold magenta"))

    # Prompt the user for a CVE ID with a fun message
    fun_messages = [
        "Enter a CVE ID to unleash the power of vulnerability analysis! (e.g., CVE-2019-1010218)",
        "Gimme a CVE ID, and I'll show you its secrets! (e.g., CVE-2019-1010218)",
        "Feed me a CVE ID, and I'll feed you vulnerability intel! (e.g., CVE-2019-1010218)"
    ]
    cve_id = Prompt.ask(choice(fun_messages))

    if not re.match(r"^CVE-\d{4}-\d{4,}$", cve_id):
        console.print("[bold red]Error: Invalid CVE ID format.[/bold red]")
        return

    try:
        # Fetch CVE data from the NVD API
        nvd_data = fetch_cve_data(cve_id)
        vulnerabilities = nvd_data.get("vulnerabilities", [])
        if not vulnerabilities:
            console.print(f"[bold red]Error: CVE {cve_id} not found in the NVD database.[/bold red]")
            return

        vulnerability = vulnerabilities[0]["cve"]
        vulnerability_name = vulnerability.get("descriptions", [{}])[0].get("value", "N/A")

        # Fetch EPSS score from FIRST API
        epss_data = fetch_epss_data(cve_id)
        epss_message = f"EPSS Percentile: {epss_percentile}" if epss_percentile is not None else "EPSS score not available for this CVE."
        cvss_v3_score = vulnerability.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore", "N/A")
        cvss_v2_score = vulnerability.get("metrics", {}).get("cvssMetricV2", [{}])[0].get("cvssData", {}).get("baseScore", "N/A")
        cpes = [cpe["criteria"].split(":")[3] for cpe in vulnerability.get("configurations", [{}])[0].get("nodes", [{}])[0].get("cpeMatch", [])]
        cwes = [cwe["description"][0]["value"] for cwe in vulnerability.get("weaknesses", [])]
        epss_score = epss_data.get("epss", {}).get(cve_id, {}).get("percentile", None) if epss_data else None
        epss_message = f"EPSS Percentile: {epss_score}" if epss_score is not None else "EPSS score not available for this CVE."

        kev_data = fetch_kev_data()
        exploitable = any(vuln["cveID"] == cve_id for vuln in kev_data["vulnerabilities"])  
        exploitability_message = "Exploit Known" if exploitable else "Exploit Unknown"

        published_date = vulnerability.get("published", "N/A")
        last_modified_date = vulnerability.get("lastModified", "N/A")

        # Get impact analysis
        impact_analysis = get_impact_analysis(vulnerability)

        table = Table(title=f"CVE Information for {cve_id}", style="bold cyan")
        table.add_column("Field", style="dim")
        table.add_column("Value")
        table.add_row("Vulnerability Name", vulnerability_name)
        
        cvss_v3_score_value = cvss_v3_score
        cvss_v3_score_style = ""
        if isinstance(cvss_v3_score, (int, float)):
            cvss_v3_score_style = "bold red" if cvss_v3_score >= 7.0 else ""
        table.add_row("CVSS v3.1 Score", str(cvss_v3_score_value), style=cvss_v3_score_style)
        
        table.add_row("CVSS v2.0 Score", str(cvss_v2_score))
        table.add_row("CPEs", ", ".join(cpes))
        table.add_row("CWEs", ", ".join(cwes))
        table.add_row("EPSS Percentile", epss_message)
        table.add_row("Exploitable?", exploitability_message, style="bold green" if exploitable else "bold red")
        table.add_row("Published Date", str(published_date))
        table.add_row("Last Modified Date", str(last_modified_date))
        
        # Add impact analysis to the table
        table.add_row("Confidentiality Impact", impact_analysis["Confidentiality Impact"])
        table.add_row("Integrity Impact", impact_analysis["Integrity Impact"])
        table.add_row("Availability Impact", impact_analysis["Availability Impact"])
        table.add_row("Access Vector", impact_analysis["Access Vector"])
        table.add_row("Access Complexity", impact_analysis["Access Complexity"])
        table.add_row("Authentication", impact_analysis["Authentication"])

        console.print(table)

        descriptions = vulnerability.get("descriptions", [])
        if descriptions:
            console.print("\n[bold green]Descriptions:[/bold green]")
            for description in descriptions:
                console.print(Markdown(f"- {description['value']} ({description['lang']})"))

    except requests.exceptions.RequestException as e:
        console.print(f"[bold red]Error: {e}[/bold red]")

if __name__ == "__main__":
    app()