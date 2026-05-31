from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field

class OSINTMetadata(BaseModel):
    run_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    source: str
    query: str

class PortInfo(BaseModel):
    port: int
    protocol: str = "tcp"
    service: Optional[str] = None
    banner: Optional[str] = None

class HostInfo(BaseModel):
    ip: str
    hostnames: List[str] = []
    ports: List[PortInfo] = []
    geo_location: Optional[Dict[str, Any]] = None
    organization: Optional[str] = None
    vulnerabilities: List[str] = []

class EmailInfo(BaseModel):
    address: str
    sources: List[str] = []
    breach_info: Optional[Dict[str, Any]] = None

class DomainInfo(BaseModel):
    name: str
    subdomains: List[str] = []
    ips: List[str] = []
    whois_data: Optional[Dict[str, Any]] = None

class OSINTUnifiedResult(BaseModel):
    metadata: OSINTMetadata
    domains: List[DomainInfo] = []
    hosts: List[HostInfo] = []
    emails: List[EmailInfo] = []
    raw_data: Optional[Dict[str, Any]] = None
