"""
Celery tasks for security scanning operations.
This module contains the background tasks for NMAP scanning.
"""

import nmap
import time
import logging
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

        # Configure scan arguments
        scan_args = _get_scan_arguments(scan_type, ports, timeout)

        # Update task state
        self.update_state(state='STARTED', meta={'status': 'Executing NMAP scan'})

        # Perform the scan
        start_time = time.time()
        scan_result = _run_nmap_scan(nm, targets, scan_args)
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

        logger.info(f"Security scan task {task_id} completed in {duration".2f"} seconds")

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


def _get_scan_arguments(scan_type: str, ports: str, timeout: int) -> str:
    """
    Get NMAP arguments based on scan type.

    Args:
        scan_type: Type of scan
        ports: Port specification
        timeout: Scan timeout

    Returns:
        NMAP arguments string
    """
    # Validate ports first
    validated_ports = _validate_ports(ports)

    base_args = f"-T3 --host-timeout {timeout}s"

    if scan_type == "basic":
        return f"{base_args} -sS -p {validated_ports}"
    elif scan_type == "comprehensive":
        return f"{base_args} -sS -sV -p {validated_ports} --script banner"
    elif scan_type == "custom":
        return f"{base_args} -sS -sV -p {validated_ports}"

    return f"{base_args} -sS -p {validated_ports}"


def _validate_ports(ports: str) -> str:
    """
    Validate and sanitize ports parameter to prevent command injection.

    Args:
        ports: Port specification string

    Returns:
        Sanitized ports string

    Raises:
        ValueError: If ports specification is invalid
    """
    if not ports or not ports.strip():
        raise ValueError("Ports specification cannot be empty")

    # Remove any potentially dangerous characters
    ports = ports.strip()

    # Check for shell metacharacters and other dangerous patterns
    dangerous_patterns = [';', '&', '|', '$', '(', ')', '`', '\n', '\r', '\t']
    for pattern in dangerous_patterns:
        if pattern in ports:
            raise ValueError(f"Invalid character '{pattern}' in ports specification")

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


def _run_nmap_scan(nm: nmap.PortScanner, targets: List[str], arguments: str) -> Dict[str, Any]:
    """
    Run NMAP scan synchronously.

    Args:
        nm: NMAP scanner instance
        targets: List of targets to scan
        arguments: NMAP arguments

    Returns:
        NMAP scan results
    """
    try:
        # Join targets with spaces for NMAP
        target_string = " ".join(targets)

        # Perform the scan
        nm.scan(target_string, arguments=arguments)

        # Use public API instead of private attribute
        return dict(nm.get_nmap_last_output())
    except Exception as e:
        logger.error(f"NMAP scan failed: {str(e)}")
        raise Exception(f"NMAP scan failed: {str(e)}")


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