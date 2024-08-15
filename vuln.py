import requests
import os
from datetime import datetime, timedelta

def get_vulnerabilities(service_name):

    api_key = os.getenv('API_KEY')
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    pub_start_date = (datetime.now() - timedelta(days=90)).strftime("%Y-%m-%dT%H:%MZ")

    pub_end_date = datetime.now().strftime("%Y-%m-%dT%H:%MZ")

    params = {
        'keywordSearch': service_name,
        'startIndex': 0,
        'resultsPerPage': 4,  # Adjust the number as needed
        'pubStartDate': pub_start_date,
        'pubEndDate': pub_end_date
    }
    headers = {
        'Accept': 'application/json',
        'Authorization': f'Bearer {api_key}'
    }
    
    try:
        response = requests.get(base_url, headers=headers, params=params)
        response.raise_for_status()  # Raise an HTTPError for bad responses

        # Parse JSON response
        data = response.json()

        # Return the vulnerability information
        vulnerabilities = data.get('vulnerabilities', [])

        return vulnerabilities

    except requests.RequestException as e:
        print(f"Error: Unable to fetch data (Exception: {e})")
        return None