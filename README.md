# NetScope

NetScope una herramienta de línea de comandos diseñada para realizar escaneos de red eficientes y detallados. Con capacidad para realizar escaneos ARP, ICMP, SYN y ACK, así como detección de servicios a través de la técnica de banner grabbing, análisis de cabeceras HTTP y otras más.

Características

- **Escaneo ARP**: Descubre hosts activos y sus direcciones MAC en una subred especificada.

- **Escaneo ICMP**: Realiza escaneos de ping para identificar hosts activos.

- **Escaneo SYN**: Utiliza paquetes TCP SYN para identificar puertos abiertos sin completar la conexión TCP.

- **Escaneo ACK**: Ayuda a mapear reglas de firewall, identificando puertos filtrados.

- **Detección de Servicios**: Realiza banner grabbing en puertos abiertos para identificar servicios y versiones.

- **Soporte para Diversos Tipos de Ping**: Admite ping ICMP, TCP y UDP para una mayor flexibilidad en el mapeo de la red.

# Instalación

Clona este repositorio y navega al directorio clonado:

```
git clone https://github.com/username/NetScope
cd NetScope
```

## Dependencias

- requests: 2.29.0
- beautifulsoup4: 4.12.3
- termcolor: 1.1.0
- scapy: 2.5.0

Se pueden instalar las dependencias a través del archivo requirements.txt con el siguiente comando:

```
pip install -r requirements.txt
```
# Uso

Para utilizar NetScope, ejecuta el script net_scope.py con los parámetros deseados. Aquí tienes algunos ejemplos de cómo utilizar la herramienta:

## Escaneo ARP

```
sudo ./net_scope.py -t 192.168.1.0/24 --arp
```

## Escaneo ICMP
```
./net_scope.py -t 192.168.1.1-100 --ping icmp
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
