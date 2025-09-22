#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Proxy HTTP Universal - Compatible con múltiples códigos de respuesta
Autor: @JuanitoProSniff
Versión: 2.0 - Ubuntu 18-25 Compatible
Fecha: 2025

Características:
- Soporte universal para códigos HTTP (200, 101, 404, 500)
- Detección automática del tipo de solicitud
- Compatible con WebSocket y conexiones HTTP normales
- Optimizado para Ubuntu 18-25
- Mejor manejo de errores y logs en español
"""

import socket, threading, select, signal, sys, time, getopt
import re
import logging
from datetime import datetime

# Configuración de escucha
LISTENING_ADDR = '0.0.0.0'
if sys.argv[1:]:
    LISTENING_PORT = int(sys.argv[1])
else:
    LISTENING_PORT = 80

# Configuración
PASS = ''
BUFLEN = 4096 * 4
TIMEOUT = 60
DEFAULT_HOST = '127.0.0.1:22'

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/proxy_universal.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class UniversalHTTPResponse:
    """Clase para manejar respuestas HTTP universales"""
    
    @staticmethod
    def get_response(request_data, custom_message="Proxy Activo"):
        """
        Detecta el tipo de solicitud y devuelve la respuesta HTTP apropiada
        """
        try:
            request_str = request_data.decode('utf-8', errors='ignore')
        except:
            request_str = str(request_data)
        
        # Normalizar a minúsculas para comparación
        request_lower = request_str.lower()
        
        # Detectar WebSocket upgrade
        if 'upgrade: websocket' in request_lower and 'connection: upgrade' in request_lower:
            return UniversalHTTPResponse._websocket_response()
        
        # Detectar método CONNECT (para tunneling)
        if request_str.startswith('CONNECT'):
            return UniversalHTTPResponse._connect_response(custom_message)
        
        # Detectar solicitudes que requieren 404
        if any(pattern in request_lower for pattern in ['/favicon.ico', '/.well-known', '/robots.txt']):
            return UniversalHTTPResponse._not_found_response()
        
        # Detectar user agents que funcionan mejor con ciertos códigos
        user_agent = UniversalHTTPResponse._extract_header(request_str, 'user-agent')
        
        # Respuesta por defecto optimizada
        return UniversalHTTPResponse._default_response(custom_message)
    
    @staticmethod
    def _websocket_response():
        """Respuesta para WebSocket upgrade (101)"""
        return (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"
        )
    
    @staticmethod
    def _connect_response(custom_message):
        """Respuesta para método CONNECT (200)"""
        return (
            f"HTTP/1.1 200 {custom_message}\r\n"
            "Content-Length: 0\r\n"
            "Connection: keep-alive\r\n"
            "Proxy-Agent: Universal-Proxy/2.0\r\n\r\n"
            "HTTP/1.1 200 Connection established\r\n\r\n"
        )
    
    @staticmethod
    def _not_found_response():
        """Respuesta 404 que funciona como túnel"""
        return (
            "HTTP/1.1 404 Not Found\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n\r\n"
            "HTTP/1.1 200 Connection established\r\n\r\n"
        )
    
    @staticmethod
    def _server_error_response():
        """Respuesta 500 que funciona como túnel"""
        return (
            "HTTP/1.1 500 Internal Server Error\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n\r\n"
            "HTTP/1.1 200 Connection established\r\n\r\n"
        )
    
    @staticmethod
    def _default_response(custom_message):
        """Respuesta por defecto (200) optimizada"""
        return (
            f"HTTP/1.1 200 {custom_message}\r\n"
            "Content-Type: text/html; charset=UTF-8\r\n"
            "Content-Length: 0\r\n"
            "Connection: keep-alive\r\n"
            "Cache-Control: no-cache\r\n"
            "Pragma: no-cache\r\n"
            "Server: Universal-Proxy/2.0\r\n\r\n"
            "HTTP/1.1 200 Connection established\r\n\r\n"
        )
    
    @staticmethod
    def _extract_header(request, header_name):
        """Extrae un header específico de la solicitud HTTP"""
        try:
            pattern = rf"{header_name}:\s*([^\r\n]*)"
            match = re.search(pattern, request, re.IGNORECASE)
            return match.group(1).strip() if match else ""
        except:
            return ""


class ProxyServer(threading.Thread):
    """Servidor proxy principal"""
    
    def __init__(self, host, port):
        threading.Thread.__init__(self)
        self.daemon = True
        self.running = False
        self.host = host
        self.port = port
        self.threads = []
        self.threadsLock = threading.Lock()
        self.stats = {
            'connections': 0,
            'active_connections': 0,
            'errors': 0,
            'start_time': time.time()
        }

    def run(self):
        """Ejecuta el servidor proxy"""
        try:
            self.soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            self.soc.settimeout(2)
            self.soc.bind((self.host, int(self.port)))
            self.soc.listen(100)  # Aumentar backlog para mejor rendimiento
            self.running = True
            
            logger.info(f"Servidor proxy iniciado en {self.host}:{self.port}")
            logger.info("Soporte universal: HTTP 200, 101, 404, 500, WebSocket")

            while self.running:
                try:
                    client_socket, addr = self.soc.accept()
                    client_socket.settimeout(30)
                    
                    self.stats['connections'] += 1
                    self.stats['active_connections'] += 1
                    
                    conn = ConnectionHandler(client_socket, self, addr)
                    conn.start()
                    self.addConn(conn)
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        logger.error(f"Error aceptando conexión: {str(e)}")
                        self.stats['errors'] += 1
                        
        except Exception as e:
            logger.error(f"Error crítico del servidor: {str(e)}")
        finally:
            self.cleanup()

    def addConn(self, conn):
        """Añade una conexión a la lista de hilos activos"""
        with self.threadsLock:
            if self.running:
                self.threads.append(conn)

    def removeConn(self, conn):
        """Remueve una conexión de la lista de hilos activos"""
        with self.threadsLock:
            try:
                self.threads.remove(conn)
                self.stats['active_connections'] -= 1
            except ValueError:
                pass

    def cleanup(self):
        """Limpia recursos y cierra conexiones"""
        self.running = False
        
        with self.threadsLock:
            threads = list(self.threads)
            for conn in threads:
                conn.close()
        
        if hasattr(self, 'soc'):
            try:
                self.soc.close()
            except:
                pass
        
        logger.info("Servidor proxy detenido correctamente")

    def get_stats(self):
        """Devuelve estadísticas del servidor"""
        uptime = time.time() - self.stats['start_time']
        return {
            **self.stats,
            'uptime': uptime,
            'connections_per_minute': self.stats['connections'] / (uptime / 60) if uptime > 0 else 0
        }


class ConnectionHandler(threading.Thread):
    """Manejador de conexiones individuales"""
    
    def __init__(self, client_socket, server, addr):
        threading.Thread.__init__(self)
        self.daemon = True
        self.client = client_socket
        self.server = server
        self.addr = addr
        self.target = None
        self.clientClosed = False
        self.targetClosed = True
        self.log_prefix = f"[{addr[0]}:{addr[1]}]"

    def run(self):
        """Maneja la conexión del cliente"""
        try:
            # Recibir solicitud inicial del cliente
            client_data = self.client.recv(BUFLEN)
            if not client_data:
                logger.debug(f"{self.log_prefix} Conexión vacía recibida")
                return

            # Procesar headers
            host_port = self._find_header(client_data, 'X-Real-Host') or DEFAULT_HOST
            password = self._find_header(client_data, 'X-Pass')
            split_data = self._find_header(client_data, 'X-Split')

            # Manejar X-Split si existe
            if split_data:
                try:
                    self.client.recv(BUFLEN)
                except:
                    pass

            # Validar autorización
            if not self._is_authorized(password, host_port):
                return

            # Establecer conexión con el destino
            if self._connect_to_target(host_port):
                # Enviar respuesta HTTP apropiada
                response = UniversalHTTPResponse.get_response(client_data, "Conectado - @JuanitoProSniff")
                self.client.send(response.encode('utf-8'))
                
                logger.info(f"{self.log_prefix} Túnel establecido a {host_port}")
                
                # Iniciar túnel bidireccional
                self._start_tunnel()
            else:
                error_response = "HTTP/1.1 503 Service Unavailable\r\n\r\n"
                self.client.send(error_response.encode('utf-8'))

        except Exception as e:
            logger.error(f"{self.log_prefix} Error en conexión: {str(e)}")
        finally:
            self.close()
            self.server.removeConn(self)

    def _find_header(self, data, header_name):
        """Busca un header específico en los datos HTTP"""
        try:
            data_str = data.decode('utf-8', errors='ignore')
            pattern = rf"{header_name}:\s*([^\r\n]*)"
            match = re.search(pattern, data_str, re.IGNORECASE)
            return match.group(1).strip() if match else None
        except:
            return None

    def _is_authorized(self, password, host_port):
        """Verifica si la conexión está autorizada"""
        if PASS and password != PASS:
            logger.warning(f"{self.log_prefix} Contraseña incorrecta")
            self.client.send(b'HTTP/1.1 401 Unauthorized\r\n\r\n')
            return False
        
        if not (host_port.startswith('127.0.0.1') or host_port.startswith('localhost')):
            logger.warning(f"{self.log_prefix} Host no autorizado: {host_port}")
            self.client.send(b'HTTP/1.1 403 Forbidden\r\n\r\n')
            return False
        
        return True

    def _connect_to_target(self, host_port):
        """Establece conexión con el servidor de destino"""
        try:
            if ':' in host_port:
                host, port = host_port.rsplit(':', 1)
                port = int(port)
            else:
                host = host_port
                port = 22  # Puerto por defecto

            self.target = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.target.settimeout(10)
            self.target.connect((host, port))
            self.targetClosed = False
            
            logger.debug(f"{self.log_prefix} Conectado a {host}:{port}")
            return True
            
        except Exception as e:
            logger.error(f"{self.log_prefix} Error conectando a {host_port}: {str(e)}")
            return False

    def _start_tunnel(self):
        """Inicia el túnel bidireccional entre cliente y destino"""
        sockets = [self.client, self.target]
        timeout_count = 0
        
        while timeout_count < TIMEOUT:
            try:
                ready_sockets, _, error_sockets = select.select(sockets, [], sockets, 1)
                
                if error_sockets:
                    logger.debug(f"{self.log_prefix} Error en sockets")
                    break
                
                if ready_sockets:
                    timeout_count = 0  # Resetear contador si hay actividad
                    
                    for sock in ready_sockets:
                        try:
                            data = sock.recv(BUFLEN)
                            if not data:
                                logger.debug(f"{self.log_prefix} Conexión cerrada por peer")
                                return
                            
                            # Reenviar datos
                            if sock is self.client:
                                self.target.send(data)
                            else:
                                self.client.send(data)
                                
                        except Exception as e:
                            logger.debug(f"{self.log_prefix} Error en túnel: {str(e)}")
                            return
                else:
                    timeout_count += 1
                    
            except Exception as e:
                logger.error(f"{self.log_prefix} Error en select: {str(e)}")
                break

    def close(self):
        """Cierra todas las conexiones"""
        for sock, closed_flag in [(self.client, 'clientClosed'), (self.target, 'targetClosed')]:
            if sock and not getattr(self, closed_flag):
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                    sock.close()
                except:
                    pass
                finally:
                    setattr(self, closed_flag, True)


def signal_handler(signum, frame):
    """Manejador de señales para cierre limpio"""
    logger.info("Recibida señal de interrupción. Cerrando servidor...")
    global server
    if 'server' in globals():
        server.cleanup()
    sys.exit(0)


def print_usage():
    """Muestra información de uso"""
    print("Uso: python3 PDirect.py [puerto]")
    print("Ejemplo: python3 PDirect.py 8080")
    print()
    print("Características:")
    print("- Soporte universal HTTP (200, 101, 404, 500)")
    print("- Compatible con WebSocket")
    print("- Detección automática del tipo de solicitud")
    print("- Optimizado para Ubuntu 18-25")
    print()
    print("Autor: @JuanitoProSniff")


def main():
    """Función principal"""
    global server
    
    # Configurar manejador de señales
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Procesar argumentos
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
            if port < 1 or port > 65535:
                raise ValueError("Puerto fuera del rango válido")
            LISTENING_PORT = port
        except ValueError as e:
            print(f"Error: {e}")
            print_usage()
            sys.exit(1)
    else:
        port = LISTENING_PORT

    # Mostrar información de inicio
    print("\n" + "="*60)
    print("    PROXY HTTP UNIVERSAL - VERSIÓN 2.0")
    print("    Compatible con Ubuntu 18-25")
    print("    Autor: @JuanitoProSniff")
    print("="*60)
    print(f"Dirección de escucha: {LISTENING_ADDR}")
    print(f"Puerto de escucha: {port}")
    print(f"Destino por defecto: {DEFAULT_HOST}")
    print(f"Buffer size: {BUFLEN} bytes")
    print(f"Timeout: {TIMEOUT} segundos")
    print()
    print("Códigos HTTP soportados:")
    print("  ✓ 200 OK (conexiones normales)")
    print("  ✓ 101 Switching Protocols (WebSocket)")
    print("  ✓ 404 Not Found (modo stealth)")
    print("  ✓ 500 Internal Server Error (modo error)")
    print()
    print("Características avanzadas:")
    print("  ✓ Detección automática del tipo de solicitud")
    print("  ✓ Manejo inteligente de WebSocket")
    print("  ✓ Logging detallado")
    print("  ✓ Estadísticas en tiempo real")
    print("  ✓ Manejo robusto de errores")
    print("="*60)
    print()

    # Iniciar servidor
    try:
        server = ProxyServer(LISTENING_ADDR, port)
        server.start()
        
        # Mostrar estadísticas periódicamente
        last_stats_time = time.time()
        
        while True:
            time.sleep(5)
            current_time = time.time()
            
            # Mostrar estadísticas cada 60 segundos
            if current_time - last_stats_time >= 60:
                stats = server.get_stats()
                logger.info(f"Estadísticas - Conexiones: {stats['connections']}, "
                          f"Activas: {stats['active_connections']}, "
                          f"Errores: {stats['errors']}, "
                          f"Uptime: {stats['uptime']:.1f}s")
                last_stats_time = current_time
            
    except KeyboardInterrupt:
        logger.info("Interrupción por teclado recibida")
    except Exception as e:
        logger.error(f"Error crítico: {str(e)}")
    finally:
        if 'server' in locals():
            server.cleanup()
        print("\n¡Proxy detenido correctamente!")


if __name__ == '__main__':
    main()