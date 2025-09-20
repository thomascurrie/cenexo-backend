"""
Celery tasks for security scanning operations.
This module contains the background tasks for NMAP scanning.
"""

import nmap
import time
import logging
import subprocess
from typing import Dict, List, Any
from datetime import datetime, timezone
from celery import current_task
from celery.exceptions import MaxRetriesExceededError

from ..celery_app import celery_app
from ..models import ScanResult, ScanTarget, PortInfo

logger = logging.getLogger(__name__)


@celery_app.task(
    bind=True,
    max_retries=3,
    retry_backoff=True,
    autoretry_for=(Exception,),
    retry_kwargs={'max_retries': 3}
)
def perform_security_scan(
    self,
    scan_request_data: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Celery task to perform NMAP security scan.

    Args:
        scan_request_data: Dictionary containing scan parameters

    Returns:
        Dictionary with scan results and metadata
    """
    task_id = self.request.id
    logger.info(f"Starting security scan task {task_id}")

    try:
        # Update task state to STARTED
        self.update_state(state='STARTED', meta={'status': 'Initializing NMAP scanner'})

        # Initialize NMAP scanner
        nm = nmap.PortScanner()

        # Extract scan parameters
        targets = scan_request_data['targets']
        scan_type = scan_request_data['scan_type']
        ports = scan_request_data['ports']
        timeout = scan_request_data['timeout']

        # Update task state
        self.update_state(state='STARTED', meta={'status': 'Configuring scan parameters'})

        # Configure scan arguments securely
        scan_args = _get_scan_arguments(scan_type, ports, timeout)

        # Update task state
        self.update_state(state='STARTED', meta={'status': 'Executing NMAP scan'})

        # Perform the scan
        start_time = time.time()
        scan_result = _run_nmap_scan(targets, scan_args)
        duration = time.time() - start_time

        # Update task state
        self.update_state(state='STARTED', meta={'status': 'Processing scan results'})

        # Process results
        results = {}
        for target in targets:
            if target in scan_result['scan']:
                host_data = scan_result['scan'][target]
                scan_target = _parse_nmap_results(host_data)
                results[target] = scan_target
            else:
                # Target not found or unreachable
                results[target] = ScanTarget(
                    target=target,
                    ports=[]
                )

        # Create scan result object
        scan_result_obj = ScanResult(
            scan_id=task_id,
            targets=targets,
            results=results,
            duration=duration,
            status="completed"
        )

        # Update task state to SUCCESS
        self.update_state(state='SUCCESS', meta={'status': 'Scan completed successfully'})

        logger.info(f"Security scan task {task_id} completed in {duration:.2f} seconds")

        return {
            'scan_id': task_id,
            'targets': targets,
            'results': {k: v.dict() for k, v in results.items()},
            'duration': duration,
            'status': 'completed',
            'timestamp': datetime.now(timezone.utc).isoformat()
        }

    except Exception as exc:
        logger.error(f"Security scan task {task_id} failed: {str(exc)}")

        # Update task state to FAILURE
        self.update_state(state='FAILURE', meta={'error': str(exc)})

        # Retry logic is handled by the decorator
        raise self.retry(exc=exc, countdown=60)  # Retry after 60 seconds


def _get_scan_arguments(scan_type: str, ports: str, timeout: int) -> List[str]:
    """
    Get NMAP arguments based on scan type using secure argument list.

    Args:
        scan_type: Type of scan
        ports: Port specification
        timeout: Scan timeout

    Returns:
        List of NMAP arguments for subprocess
    """
    # Validate and sanitize inputs
    validated_ports = _validate_ports(ports)
    validated_scan_type = _validate_scan_type(scan_type)
    validated_timeout = _validate_timeout(timeout)

    # Build argument list securely
    base_args = ["nmap", "-T3", f"--host-timeout={validated_timeout}s"]

    # Add XML output to stdout for parsing
    base_args.extend(["-oX", "-"])

    # Add scan type specific arguments
    if validated_scan_type == "basic":
        base_args.extend(["-sS", f"-p={validated_ports}"])
    elif validated_scan_type == "comprehensive":
        base_args.extend(["-sS", "-sV", f"-p={validated_ports}", "--script=banner"])
    elif validated_scan_type == "custom":
        base_args.extend(["-sS", "-sV", f"-p={validated_ports}"])
    else:
        base_args.extend(["-sS", f"-p={validated_ports}"])

    return base_args


def _validate_scan_type(scan_type: str) -> str:
    """
    Validate scan type parameter.

    Args:
        scan_type: Type of scan to validate

    Returns:
        Validated scan type

    Raises:
        ValueError: If scan type is invalid
    """
    if not scan_type or not isinstance(scan_type, str):
        raise ValueError("Scan type must be a non-empty string")

    valid_types = ["basic", "comprehensive", "custom"]
    if scan_type not in valid_types:
        raise ValueError(f"Invalid scan type '{scan_type}'. Must be one of: {valid_types}")

    return scan_type


def _validate_timeout(timeout: int) -> int:
    """
    Validate timeout parameter.

    Args:
        timeout: Timeout value to validate

    Returns:
        Validated timeout

    Raises:
        ValueError: If timeout is invalid
    """
    if not isinstance(timeout, int):
        raise ValueError("Timeout must be an integer")

    if timeout < 30 or timeout > 3600:
        raise ValueError("Timeout must be between 30 and 3600 seconds")

    return timeout


def _validate_ports(ports: str) -> str:
    """
    Validate ports parameter securely.

    Args:
        ports: Port specification string

    Returns:
        Validated ports string

    Raises:
        ValueError: If ports specification is invalid
    """
    if not ports or not ports.strip():
        raise ValueError("Ports specification cannot be empty")

    ports = ports.strip()

    # Only allow specific characters: digits, commas, hyphens, and "all"
    allowed_chars = set("0123456789,- all")
    if not all(c in allowed_chars for c in ports):
        raise ValueError("Ports specification contains invalid characters")

    # Validate port ranges and individual ports
    if ports == "all":
        return ports

    # Split by comma for individual ports or ranges
    port_specs = ports.split(',')

    for spec in port_specs:
        spec = spec.strip()
        if not spec:
            continue

        # Check for range notation (e.g., "1-1024")
        if '-' in spec:
            try:
                start, end = spec.split('-', 1)
                start_port = int(start.strip())
                end_port = int(end.strip())

                if start_port < 1 or start_port > 65535:
                    raise ValueError(f"Invalid start port: {start_port}")
                if end_port < 1 or end_port > 65535:
                    raise ValueError(f"Invalid end port: {end_port}")
                if start_port > end_port:
                    raise ValueError(f"Start port {start_port} > end port {end_port}")
            except ValueError as e:
                raise ValueError(f"Invalid port range '{spec}': {str(e)}")
        else:
            # Single port
            try:
                port_num = int(spec)
                if port_num < 1 or port_num > 65535:
                    raise ValueError(f"Port out of range: {port_num}")
            except ValueError:
                raise ValueError(f"Invalid port number '{spec}'")

    return ports


def _run_nmap_scan(targets: List[str], arguments: List[str]) -> Dict[str, Any]:
    """
    Run NMAP scan securely using subprocess.

    Args:
        targets: List of targets to scan
        arguments: List of NMAP arguments

    Returns:
        NMAP scan results

    Raises:
        Exception: If NMAP scan fails
    """
    try:
        # Build the complete command
        cmd = arguments + targets

        logger.info(f"Executing secure NMAP scan: {' '.join(cmd)}")

        # Run NMAP using subprocess with shell=False for security
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=1800,  # 30 minute timeout
            check=False  # Don't raise exception on non-zero exit codes
        )

        if result.returncode != 0:
            logger.error(f"NMAP scan failed with return code {result.returncode}: {result.stderr}")
            raise Exception(f"NMAP scan failed: {result.stderr}")

        # Parse the XML output
        import xml.etree.ElementTree as ET

        # Find the XML output in the result
        xml_start = result.stdout.find('<?xml')
        if xml_start == -1:
            logger.error("No XML output found in NMAP results")
            raise Exception("No XML output found in NMAP results")

        xml_output = result.stdout[xml_start:]

        # Parse XML to get structured results
        try:
            root = ET.fromstring(xml_output)
            return _parse_nmap_xml_results(root)
        except ET.ParseError as e:
            logger.error(f"Failed to parse NMAP XML output: {e}")
            raise Exception(f"Failed to parse NMAP XML output: {e}")

    except subprocess.TimeoutExpired:
        logger.error("NMAP scan timed out")
        raise Exception("NMAP scan timed out")
    except Exception as e:
        logger.error(f"NMAP scan failed: {str(e)}")
        raise Exception(f"NMAP scan failed: {str(e)}")


def _parse_nmap_xml_results(xml_root) -> Dict[str, Any]:
    """
    Parse NMAP XML results into structured data.

    Args:
        xml_root: XML root element from NMAP output

    Returns:
        Dictionary with scan results
    """
    results = {}

    # Parse each host
    for host in xml_root.findall('host'):
        addresses = host.find('address')
        if addresses is None:
            continue

        # Get IP address
        ip_addr = 'unknown'
        if addresses.get('addrtype') == 'ipv4':
            ip_addr = addresses.get('addr', 'unknown')

        # Parse ports
        ports = []
        ports_element = host.find('ports')
        if ports_element is not None:
            for port in ports_element.findall('port'):
                portid = port.get('portid')
                protocol = port.get('protocol', 'tcp')

                if portid and protocol == 'tcp':
                    state_element = port.find('state')
                    if state_element is not None and state_element.get('state') == 'open':
                        service_element = port.find('service')
                        service_name = 'unknown'
                        service_version = ''

                        if service_element is not None:
                            service_name = service_element.get('name', 'unknown')
                            service_version = service_element.get('version', '')

                        ports.append({
                            'port': int(portid),
                            'state': 'open',
                            'service': service_name,
                            'version': service_version,
                            'protocol': 'tcp'
                        })

        results[ip_addr] = {
            'target': ip_addr,
            'ports': ports
        }

    return results


def _parse_nmap_results(host_data: Dict[str, Any]) -> ScanTarget:
    """
    Parse NMAP results into ScanTarget object.

    Args:
        host_data: NMAP host data

    Returns:
        ScanTarget object
    """
    ports = []

    if 'tcp' in host_data:
        for port, port_data in host_data['tcp'].items():
            if port_data['state'] == 'open':
                ports.append(PortInfo(
                    port=int(port),
                    state=port_data['state'],
                    service=port_data.get('name', 'unknown'),
                    version=port_data.get('version', ''),
                    protocol='tcp'
                ))

    return ScanTarget(
        target=host_data.get('addresses', {}).get('ipv4', 'unknown'),
        ports=ports
    )