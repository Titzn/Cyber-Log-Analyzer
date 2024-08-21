import requests
import logging

def geolocate_ip(ip):
    """Get geographical location of the IP address."""
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        response.raise_for_status()
        data = response.json()
        return f"{data.get('city', 'Unknown City')}, {data.get('country', 'Unknown Country')}"
    except requests.RequestException as e:
        logging.error(f"Failed to geolocate IP {ip}: {e}")
        return "Unknown Location"
