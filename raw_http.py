import socket
import ssl
import tempfile
import zlib
import gzip
from socket import timeout as SocketTimeout
from cryptography.hazmat.primitives.serialization import pkcs12, Encoding, PrivateFormat, NoEncryption  # pip install cryptography
import dns.resolver  # pip install dnspython
from typing import Tuple, List, Union
import logging
from dataclasses import dataclass
from contextlib import contextmanager
import socks  # pip install PySocks
import os

logger = logging.getLogger(__name__)

# Constants
CHUNK_SIZE = 4096
DEFAULT_TIMEOUT = 10.0
SHORT_TIMEOUT = 1.0

@dataclass
class ProxyConfig:
    """Configuration for proxy settings."""
    host: str
    port: int
    type: str  # 'http' or 'socks5'
    username: Union[str, None] = None
    password: Union[str, None] = None

class RawHTTPClient:
    """A client for sending raw HTTP/HTTPS requests."""

    DEFAULT_GET_REQUEST = "GET / HTTP/1.1\nHost: example.com:80\nAccept-Encoding: gzip, deflate\nUser-Agent: rawhttp/0.0.1\nConnection: close\n\n"

    @staticmethod
    def format_as_hex(data: Union[bytes, str]) -> str:
        """
        Format data as hexadecimal and ASCII representation.

        This method takes either bytes or string input and formats it into
        a hexadecimal dump with corresponding ASCII representation.

        Args:
            data (Union[bytes, str]): The data to format.

        Returns:
            str: Formatted hexadecimal and ASCII representation.
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        result = ''
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_part = ' '.join(f'{byte:02x}' for byte in chunk)
            ascii_part = ''.join(chr(byte) if 32 <= byte < 127 else '.' for byte in chunk)
            result += f"{hex_part:<48}  {ascii_part}\n"
        return result

    @staticmethod
    def send(
        host: str,
        port: int,
        request: Union[str, bytes],
        path: Union[str, None] = None,
        update_host_header: bool = True,
        update_content_length_header: bool = True,
        use_tls: Union[bool, None] = None,
        p12_file: Union[str, None] = None,
        p12_password: Union[str, None] = None,
        local_ip: Union[str, None] = None,
        dns_server: Union[str, None] = None,
        timeout: Union[float, None] = 10.0,
        proxy: Union[ProxyConfig, None] = None,
        verify_ssl: bool = True
    ) -> Tuple[Union[bytes, None], Union[bytes, None]]:
        """
        Send a raw HTTP/HTTPS request.

        This method handles the entire process of sending a request, including:
        - Preparing the request
        - Resolving the hostname (if a DNS server is specified)
        - Creating a connection (with or without a proxy)
        - Setting up TLS if needed
        - Sending the request and receiving the response

        Args:
            host (str): The target host.
            port (int): The target port.
            request (Union[str, bytes]): The raw HTTP request.
            path (Union[str, None]): The path to update in the request. If None, the original path in the request is kept.
            update_host_header (bool): Whether to update the Host header.
            update_content_length_header (bool): Whether to update the Content-Length header.
            use_tls (Union[bool, None]): Whether to use TLS. If None, it's auto-detected based on the port.
            p12_file (Union[str, None]): Path to the .p12 file for client certificate authentication.
            p12_password (Union[str, None]): Password for the .p12 file.
            local_ip (Union[str, None]): The local IP to bind to.
            dns_server (Union[str, None]): The DNS server to use for hostname resolution.
            timeout (Union[float, None]): The timeout for the connection in seconds.
            proxy (Union[ProxyConfig, None]): The proxy configuration to use.
            verify_ssl (bool): Whether to verify SSL certificates.

        Returns:
            Tuple[Union[bytes, None], Union[bytes, None]]: The response headers and body.

        Raises:
            RuntimeError: If there's an error during the request or response processing.
        """
        headers, body = RawHTTPClient._prepare_request(request, host, port, path, update_host_header, update_content_length_header)

        logger.debug("Request to send:\n%s", RawHTTPClient.format_as_hex(headers + b'\r\n\r\n' + body))

        try:
            # Resolve hostname if DNS server is provided
            ip_address = RawHTTPClient._resolve_hostname(host, dns_server) if dns_server else host
            
            # Create connection (with or without proxy)
            with RawHTTPClient._create_connection(ip_address, port, timeout, local_ip, proxy) as sock:
                # Determine if TLS should be used
                use_tls = use_tls if use_tls is not None else port not in (80, 8080)

                if use_tls:
                    # Set up TLS context and wrap socket
                    with RawHTTPClient._create_ssl_context(p12_file, p12_password, verify_ssl) as context:
                        with context.wrap_socket(sock, server_hostname=host) as wrapped_socket:
                            return RawHTTPClient._send_and_receive(wrapped_socket, headers, body, host, port)
                else:
                    # Send request without TLS
                    return RawHTTPClient._send_and_receive(sock, headers, body, host, port)
        except (SocketTimeout, ConnectionRefusedError, socket.gaierror) as e:
            raise RuntimeError(f"Connection error to {host}:{port}: {e}")

    @staticmethod
    def _prepare_request(request: Union[str, bytes], host: str, port: int, path: Union[str, None], update_host: bool, update_content_length: bool) -> Tuple[bytes, bytes]:
        """
        Prepare the HTTP request by updating headers if necessary.

        This method handles:
        - Converting string requests to bytes
        - Splitting headers and body
        - Updating the request path, host header, and content-length header as needed

        Args:
            request (Union[str, bytes]): The raw HTTP request.
            host (str): The target host.
            port (int): The target port.
            path (Union[str, None]): The new path to set in the request.
            update_host (bool): Whether to update the Host header.
            update_content_length (bool): Whether to update the Content-Length header.

        Returns:
            Tuple[bytes, bytes]: The prepared headers and body.

        Raises:
            RuntimeError: If the request format is invalid.
        """
        if isinstance(request, str):
            request = request.encode('utf-8')

        # Split headers and body
        if b'\r\n\r\n' in request:
            headers, body = request.split(b'\r\n\r\n', 1)
            headers_array = headers.split(b'\r\n')
        elif b'\n\n' in request:
            headers, body = request.split(b'\n\n', 1)
            headers_array = headers.split(b'\n')
        elif b'\r\r' in request:
            headers, body = request.split(b'\r\r', 1)
            headers_array = headers.split(b'\r')
        else:
            raise RuntimeError("Missing header-body delimiter in request")

        # Update headers as needed
        if path:
            headers_array = RawHTTPClient._update_request_path(headers_array, path)
        if update_host:
            headers_array = RawHTTPClient._update_host_header(headers_array, host, port)
        if update_content_length:
            headers_array = RawHTTPClient._update_content_length_header(headers_array, len(body))

        return b'\r\n'.join(headers_array), body

    @staticmethod
    def _update_request_path(headers_array: List[bytes], path: str) -> List[bytes]:
        """
        Update the request path in the first line (request line) of the HTTP headers.

        Args:
            headers_array (List[bytes]): The list of header lines.
            path (str): The new path to set.

        Returns:
            List[bytes]: The updated list of header lines.
        """
        if headers_array:
            parts = headers_array[0].split(b' ')
            if len(parts) >= 2:
                parts[1] = path.encode('utf-8')
                headers_array[0] = b' '.join(parts)
        else:
            headers_array.append(b'GET ' + path.encode('utf-8') + b' HTTP/1.1')
        return headers_array

    @staticmethod
    def _update_host_header(headers_array: List[bytes], host: str, port: int) -> List[bytes]:
        """
        Update or add the Host header in the HTTP headers.

        Args:
            headers_array (List[bytes]): The list of header lines.
            host (str): The host to set in the Host header.
            port (int): The port to set in the Host header.

        Returns:
            List[bytes]: The updated list of header lines.
        """
        host_header = f"Host: {host}".encode('utf-8') if port in (80, 443) else f"Host: {host}:{port}".encode('utf-8')
        for i, line in enumerate(headers_array):
            if line.lower().startswith(b"host:"):
                headers_array[i] = host_header
                break
        else:
            headers_array.append(host_header)
        return headers_array

    @staticmethod
    def _update_content_length_header(headers_array: List[bytes], content_length: int) -> List[bytes]:
        """
        Update or add the Content-Length header in the HTTP headers.

        Args:
            headers_array (List[bytes]): The list of header lines.
            content_length (int): The content length to set.

        Returns:
            List[bytes]: The updated list of header lines.
        """
        content_length_header = f"Content-Length: {content_length}".encode('utf-8')
        for i, line in enumerate(headers_array):
            if line.lower().startswith(b"content-length:"):
                headers_array[i] = content_length_header
                break
        else:
            if content_length > 0:
                headers_array.append(content_length_header)
        return headers_array

    @staticmethod
    def _resolve_hostname(hostname: str, dns_server: str) -> str:
        """
        Resolve a hostname using a specific DNS server.

        Args:
            hostname (str): The hostname to resolve.
            dns_server (str): The DNS server to use for resolution.

        Returns:
            str: The resolved IP address.

        Raises:
            RuntimeError: If DNS resolution fails.
        """
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [dns_server]
        try:
            return resolver.resolve(hostname)[0].address
        except dns.exception.DNSException as e:
            raise RuntimeError(f"DNS resolution error for {hostname}: {e}")

    @staticmethod
    def _create_connection(ip_address: str, port: int, timeout: float, local_ip: Union[str, None], proxy: Union[ProxyConfig, None]) -> socket.socket:
        """
        Create a socket connection, either directly or through a proxy.

        Args:
            ip_address (str): The IP address to connect to.
            port (int): The port to connect to.
            timeout (float): The connection timeout.
            local_ip (Union[str, None]): The local IP to bind to.
            proxy (Union[ProxyConfig, None]): The proxy configuration to use.

        Returns:
            socket.socket: The connected socket.
        """
        if proxy:
            return socks.create_connection(
                (ip_address, port),
                timeout,
                source_address=(local_ip, 0) if local_ip else None,
                proxy_type=socks.PROXY_TYPE_HTTP if proxy.type == 'http' else socks.PROXY_TYPE_SOCKS5,
                proxy_addr=proxy.host,
                proxy_port=proxy.port,
                proxy_username=proxy.username,
                proxy_password=proxy.password
            )
        else:
            return socket.create_connection(
                (ip_address, port),
                timeout,
                source_address=(local_ip, 0) if local_ip else None
            )

    @contextmanager
    @staticmethod
    def _create_ssl_context(p12_file: Union[str, None], p12_password: Union[str, None], verify_ssl: bool = True) -> ssl.SSLContext:
        """
        Create an SSL context, optionally using a .p12 file for client authentication.

        This context manager handles the creation and cleanup of temporary files
        used for SSL context creation.

        Args:
            p12_file (Union[str, None]): Path to the .p12 file.
            p12_password (Union[str, None]): Password for the .p12 file.
            verify_ssl (bool): Whether to verify SSL certificates.

        Yields:
            ssl.SSLContext: The created SSL context.

        Raises:
            RuntimeError: If there's an error creating the SSL context.
        """
        if not p12_file:
            context = ssl.create_default_context()
            if not verify_ssl:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            yield context
            return

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        try:
            cert, key, ca_certs = RawHTTPClient._convert_p12_to_pem(p12_file, p12_password)
            with tempfile.NamedTemporaryFile(delete=False) as cert_file, \
                tempfile.NamedTemporaryFile(delete=False) as key_file, \
                tempfile.NamedTemporaryFile(delete=False) as ca_file:
                
                cert_file.write(cert)
                key_file.write(key)
                ca_file.write(ca_certs)
                
                cert_file.flush()
                key_file.flush()
                ca_file.flush()

                context.load_cert_chain(certfile=cert_file.name, keyfile=key_file.name)
                if ca_certs:
                    context.load_verify_locations(cafile=ca_file.name)

            if verify_ssl:
                context.verify_mode = ssl.CERT_REQUIRED
            else:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

            yield context
        except Exception as e:
            raise RuntimeError(f"Failed to create SSL context: {e}")
        finally:
            for file in [cert_file.name, key_file.name, ca_file.name]:
                try:
                    os.remove(file)
                except OSError:
                    pass

    @staticmethod
    def _convert_p12_to_pem(p12_file: str, p12_password: Union[str, None]) -> Tuple[bytes, bytes, bytes]:
        """
        Convert a .p12 file to PEM format.

        Args:
            p12_file (str): Path to the .p12 file.
            p12_password (Union[str, None]): Password for the .p12 file.

        Returns:
            Tuple[bytes, bytes, bytes]: The certificate, private key, and CA certificates in PEM format.

        Raises:
            FileNotFoundError: If the .p12 file is not found.
            RuntimeError: If there's an error loading the .p12 file.
        """
        try:
            with open(p12_file, 'rb') as f:
                p12_data = f.read()

            private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(p12_data, p12_password.encode() if p12_password else None)

            cert = certificate.public_bytes(Encoding.PEM)
            key = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
            ca_certs = b"".join(ca.public_bytes(Encoding.PEM) for ca in additional_certificates or [])
            
            return cert, key, ca_certs
        except FileNotFoundError:
            raise FileNotFoundError(f"File not found: {p12_file}")
        except Exception as e:
            raise RuntimeError(f"Error loading .p12 file: {e}")

    @staticmethod
    def _send_and_receive(sock: socket.socket, headers: bytes, body: bytes, host: str, port: int) -> Tuple[Union[bytes, None], Union[bytes, None]]:
        """
        Send the HTTP request and receive the response.

        Args:
            sock (socket.socket): The connected socket.
            headers (bytes): The HTTP headers to send.
            body (bytes): The HTTP body to send.
            host (str): The target host (for logging purposes).
            port (int): The target port (for logging purposes).

        Returns:
            Tuple[Union[bytes, None], Union[bytes, None]]: The response headers and body.

        Raises:
            RuntimeError: If there's an error receiving the response.
        """
        sock.sendall(headers + b'\r\n\r\n' + body)
        logger.debug(f"Request sent successfully to {host}:{port}")
        return RawHTTPClient._receive_response(sock)

    @staticmethod
    def _receive_response(sock: socket.socket) -> Tuple[bytes, bytes]:
        """
        Receive and process the HTTP response.

        This method handles different types of responses, including:
        - Responses with Content-Length
        - Chunked responses
        - Responses that close the connection
        - Keep-alive connections

        It also handles decompression if the response is compressed.

        Args:
            sock (socket.socket): The connected socket.

        Returns:
            Tuple[bytes, bytes]: The response headers and body.

        Raises:
            RuntimeError: If there's an error receiving or processing the response.
        """
        response = bytearray()
        while True:
            part = sock.recv(CHUNK_SIZE)
            if not part:
                break
            response += part
            if b'\r\n\r\n' in response:
                headers, body = response.split(b'\r\n\r\n', 1)
                content_length, content_encoding, transfer_encoding, connection = RawHTTPClient._parse_headers(headers)
                
                if content_length:
                    # Known content length, read exact number of bytes
                    while len(body) < content_length:
                        body += sock.recv(CHUNK_SIZE)
                elif transfer_encoding == 'chunked':
                    # Chunked encoding, use special method to receive
                    body = RawHTTPClient._receive_chunked_body(sock, body)
                elif connection == 'close':
                    # Read until connection is closed
                    while True:
                        chunk = sock.recv(CHUNK_SIZE)
                        if not chunk:
                            break
                        body += chunk
                else:
                    # Keep-alive connection without proper content length
                    # or transfer encoding chunked header.
                    # The server will not close the connection and recv() will
                    # therefore not return if the server has no more data.
                    # Read with a short timeout and then stop
                    timeout = sock.timeout
                    sock.settimeout(SHORT_TIMEOUT)
                    try:
                        while True:
                            chunk = sock.recv(CHUNK_SIZE)
                            if not chunk:
                                break
                            body += chunk
                    except socket.timeout:
                        pass  # Expected behavior, we've likely read all available data
                    finally:
                        sock.settimeout(timeout)  # Reset the timeout

                if content_encoding:
                    body = RawHTTPClient._decompress_response(body, content_encoding)

                logger.debug("Received response:\n%s", RawHTTPClient.format_as_hex(headers + b"\r\n\r\n" + body))
                return headers, body

        raise RuntimeError("Failed to receive complete response")

    @staticmethod
    def _receive_chunked_body(sock: socket.socket, initial_body: bytes) -> bytes:
        """
        Receive and process a chunked HTTP response body.

        This method handles the complexities of chunked transfer encoding, including:
        - Reading chunk sizes
        - Handling variable-length chunks
        - Detecting the end of the chunked body

        Args:
            sock (socket.socket): The connected socket.
            initial_body (bytes): Any initial body data already received.

        Returns:
            bytes: The complete, unchunked response body.

        Raises:
            RuntimeError: If there's an error processing the chunked body.
        """
        buffer = bytearray(initial_body)
        decoded_body = bytearray()

        while True:
            if len(buffer) < 5:  # 5 Bytes must be there in chunked encoding: 0\r\n\r\n
                new_data = sock.recv(CHUNK_SIZE)
                if not new_data:
                    raise RuntimeError("Connection closed while reading chunked body")
                buffer += new_data
            
            if b'\r\n' not in buffer:
                raise RuntimeError("Invalid chunk size: missing CRLF")

            try:
                chunk_size, buffer = buffer.split(b'\r\n', 1)
                chunk_size = int(chunk_size, 16)
                if chunk_size == 0:
                    # End of chunked body
                    if len(buffer) < 2 or buffer[:2] != b'\r\n':
                        raise RuntimeError("Invalid end of chunked body")
                    remaining = buffer[2:]  # Any data after the last chunk
                    break

                total_required = chunk_size + 2  # +2 for trailing \r\n
                while len(buffer) < total_required:
                    to_read = max(total_required - len(buffer), CHUNK_SIZE)
                    new_data = sock.recv(to_read)
                    if not new_data:
                        raise RuntimeError("Connection closed while reading chunk")
                    buffer += new_data

                decoded_body += buffer[:chunk_size]
                buffer = buffer[total_required:]  # Remove chunk and trailing \r\n

            except ValueError as e:
                raise RuntimeError(f"Error decoding chunk: {e}")

        if remaining:
            logger.debug("Remaining content after chunked encoded response:\n%s", RawHTTPClient.format_as_hex(remaining))

        return bytes(decoded_body)

    @staticmethod
    def _parse_headers(headers: bytes) -> Tuple[Union[int, None], Union[str, None], Union[str, None], str]:
        """
        Parse HTTP response headers to extract key information.

        This method extracts:
        - Content-Length
        - Content-Encoding
        - Transfer-Encoding
        - Connection type
        - HTTP version

        Args:
            headers (bytes): The raw HTTP headers.

        Returns:
            Tuple[Union[int, None], Union[str, None], Union[str, None], str]: 
            Content-Length, Content-Encoding, Transfer-Encoding, and Connection type.
        """
        content_length = None
        content_encoding = None
        transfer_encoding = None
        connection = None
        http_version = 'HTTP/0.9'

        for header in headers.split(b'\r\n'):
            lower_header = header.lower()
            if lower_header.startswith(b'content-length:'):
                content_length = int(header.split(b':', 1)[1].strip())
            elif lower_header.startswith(b'content-encoding:'):
                content_encoding = header.split(b':', 1)[1].strip().decode('utf-8')
            elif lower_header.startswith(b'transfer-encoding:'):
                transfer_encoding = header.split(b':', 1)[1].strip().decode('utf-8')
            elif lower_header.startswith(b'connection:'):
                connection = 'keep-alive' if 'keep-alive' in header.split(b':', 1)[1].strip().decode('utf-8').split(',') else 'close'
            elif lower_header.startswith(b'http/'):
                http_version = header.split(b' ', 1)[0].decode('utf-8').upper()

        if connection is None:
            connection = 'close' if http_version in ('HTTP/0.9', 'HTTP/1.0') else 'keep-alive'

        return content_length, content_encoding, transfer_encoding, connection

    @staticmethod
    def _decompress_response(response: bytes, encoding: str) -> bytes:
        """
        Decompress the HTTP response body if it's compressed.

        Supports gzip and deflate encoding.

        Args:
            response (bytes): The compressed response body.
            encoding (str): The encoding type ('gzip' or 'deflate').

        Returns:
            bytes: The decompressed response body.

        Raises:
            RuntimeError: If there's an error during decompression.
        """
        try:
            if encoding.lower() == 'gzip':
                return gzip.decompress(response)
            elif encoding.lower() == 'deflate':
                return zlib.decompress(response)
            return response
        except Exception as e:
            raise RuntimeError(f"Decompression error: {e}")
