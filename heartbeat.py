from dataclasses import dataclass

TARGET_HOST = "vulnerable.example.com"
TARGET_PORT = 443


@dataclass
class HeartbeatPacket:
    record_type: str
    real_payload_len: int
    claimed_payload_len: int

    def describe(self) -> str:
        return (
            f"Тип записи: {self.record_type}\n"
            f"Фактическая длина payload: {self.real_payload_len} байт\n"
            f"Заявленная длина payload (в заголовке): {self.claimed_payload_len} байт\n"
        )


def build_malicious_heartbeat(claimed_len: int = 16384) -> HeartbeatPacket:
    real_payload_len = 1
    claimed_payload_len = claimed_len

    packet = HeartbeatPacket(
        record_type="heartbeat_request",
        real_payload_len=real_payload_len,
        claimed_payload_len=claimed_payload_len,
    )

    return packet


def simulate_heartbleed_attack():
    print("[*] Эмуляция атаки CVE-2014-0160 (Heartbleed)")
    print(f"[*] Цель: {TARGET_HOST}:{TARGET_PORT}")
    print()
    packet = build_malicious_heartbeat()

    print("[*] Сформирован псевдо heartbeat-пакет:")
    print(packet.describe())
    print("[*] Отправка пакета на сервер ОПУЩЕНА (это только эмуляция).")
    print()
    print("[!] При наличии уязвимости сервер мог бы вернуть до 64 КБ "
          "лишних данных из памяти процесса.")
    print("[!] Эти данные могли бы содержать пароли, cookie, приватные ключи и др.")
    print()
    print("[*] Эмуляция завершена.")


if __name__ == "__main__":
    simulate_heartbleed_attack()
