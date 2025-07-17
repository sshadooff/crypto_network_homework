from scapy.all import IP, TCP, sr1

targets_ip = ["192.168.0.18", "192.168.0.14", "127.0.0.1"]
port_range = [22, 53, 80, 443, 8000]

for ip in targets_ip:
    print(f"Start scanning IP: {ip}")

    for port in port_range:
        # Создаем TCP пакет с флагом SYN для сканирования порта
        ip_packet = IP(dst=ip)
        tcp_packet = TCP(dport=port, flags="S")

        # Отправляем пакет и получаем ответ
        response = sr1(ip_packet / tcp_packet, timeout=0.5, verbose=0)

        # Обрабатываем полученный ответ
        if response:
            if response.haslayer(TCP) and response[TCP].flags == 18:  # TCP SYN-ACK
                print(f"{port} open")
