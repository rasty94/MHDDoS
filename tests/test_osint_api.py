import pytest
from unittest.mock import patch, MagicMock

from utils.osint.shodan_client import ShodanAdapter
from utils.osint.theharvester_wrapper import TheHarvesterAdapter
from utils.osint.mrholmes_wrapper import MrHolmesAdapter

def test_shodan_adapter_no_key():
    adapter = ShodanAdapter(api_key="")
    result = adapter.lookup_ip("8.8.8.8")
    assert result is None
    
    search_result = adapter.search("apache")
    assert search_result.hosts == []

@patch("shodan.Shodan")
def test_shodan_adapter_lookup(mock_shodan_class):
    mock_instance = MagicMock()
    mock_shodan_class.return_value = mock_instance
    
    # Mocking the host method response
    mock_instance.host.return_value = {
        "ip_str": "1.1.1.1",
        "hostnames": ["one.one.one.one"],
        "org": "Cloudflare",
        "vulns": ["CVE-2020-0001"],
        "data": [
            {
                "port": 80,
                "transport": "tcp",
                "_shodan": {"module": "http"},
                "data": "HTTP/1.1 200 OK"
            }
        ],
        "country_code": "US",
        "country_name": "United States"
    }

    adapter = ShodanAdapter(api_key="mock_key")
    result = adapter.lookup_ip("1.1.1.1")
    
    assert result.ip == "1.1.1.1"
    assert "one.one.one.one" in result.hostnames
    assert result.organization == "Cloudflare"
    assert "CVE-2020-0001" in result.vulnerabilities
    assert len(result.ports) == 1
    assert result.ports[0].port == 80
    assert result.ports[0].banner == "HTTP/1.1 200 OK"


@patch("subprocess.run")
def test_theharvester_adapter(mock_subprocess_run, tmp_path):
    adapter = TheHarvesterAdapter(executable_path="theHarvester")
    
    # In the try block of the wrapper, it creates a temp file. 
    # We will mock subprocess run to just write a fake JSON to the path that it tells us
    def side_effect_run(cmd, *args, **kwargs):
        # find the -f argument
        f_idx = cmd.index("-f")
        temp_path = cmd[f_idx + 1]
        
        # Write dummy output
        with open(temp_path + ".json", 'w') as f:
            f.write('{"hosts": ["api.test.com:1.2.3.4"], "emails": ["admin@test.com"], "ips": ["1.2.3.4", "5.6.7.8"]}')
        
        mock_result = MagicMock()
        mock_result.returncode = 0
        return mock_result

    mock_subprocess_run.side_effect = side_effect_run
    
    result = adapter.search_domain("test.com")
    
    assert len(result.domains) == 1
    domain_info = result.domains[0]
    assert domain_info.name == "test.com"
    assert "api.test.com" in domain_info.subdomains
    assert "1.2.3.4" in domain_info.ips
    assert "5.6.7.8" in domain_info.ips
    
    assert len(result.emails) == 1
    assert result.emails[0].address == "admin@test.com"


def test_mrholmes_adapter_placeholder():
    adapter = MrHolmesAdapter(mrholmes_dir="/tmp/fake")
    result = adapter.run_basic_lookup("test")
    
    assert result.metadata.source == "mrholmes"
    assert result.raw_data is not None
    assert "Not fully implemented" in result.raw_data.get("status", "")
