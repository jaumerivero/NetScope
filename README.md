# NetScope

NetScope una herramienta de línea de comandos diseñada para realizar escaneos de red eficientes y detallados. Con capacidad para realizar escaneos ARP, ICMP, SYN y ACK, así como detección de servicios a través de la técnica de banner grabbing, esta herramienta es esencial para profesionales de la seguridad informática y entusiastas del networking.
Características

- **Escaneo ARP**: Descubre hosts activos y sus direcciones MAC en una subred especificada.

- **Escaneo ICMP**: Realiza escaneos de ping para identificar hosts activos.

- **Escaneo SYN**: Utiliza paquetes TCP SYN para identificar puertos abiertos sin completar la conexión TCP.

- **Escaneo ACK**: Ayuda a mapear reglas de firewall, identificando puertos filtrados.

- **Detección de Servicios**: Realiza banner grabbing en puertos abiertos para identificar servicios y versiones.

- **Soporte para Diversos Tipos de Ping**: Admite ping ICMP, TCP y UDP para una mayor flexibilidad en el mapeo de la red.

# Requisitos


# Instalación

Clona este repositorio y navega al directorio clonado:

```
git clone https://github.com/username/NetScope
cd NetScope
```
# Instala las dependencias necesarias:
```
pip install -r requirements.txt
```
# Uso

Para utilizar el Advanced Network Scanner, ejecuta el script network_scanner.py con los parámetros deseados. Aquí tienes algunos ejemplos de cómo utilizar la herramienta:

## Escaneo ARP

```
sudo ./net_scope.py -t 192.168.1.0/24 --arp
```

## Escaneo ICMP
```
./net_scope.py -t 192.168.1.1-100 --ping
```
## Escaneo SYN
```
sudo ./net_scope.py -t 192.168.1.1 -p 1-1000 -sY
```
## Detección de Servicios
```
./net_scope.py -t 192.168.1.1 -s
```
Consulta ./net_scope.py -h para más información sobre las opciones disponibles.
