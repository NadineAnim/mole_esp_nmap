#include <WiFi.h>
#include <WiFiUdp.h>
#include <map>
#include <vector>
#include <mbedtls/sha256.h>
#include <lwip/etharp.h>
#include <BluetoothSerial.h>

BluetoothSerial SerialBT;

// --- WiFi Settings ---
const char* ssid = "TP-Link_D06B";
const char* password = "123456789";

// Прогрес кожного студента
struct StudentProgress {
  bool part1 = false;
  bool part2 = false;
  bool part3 = false;
};

// Дозволені ідентифікатори (MAC або IP)
std::vector<String> allowedIds = {
  "C0:35:32:2E:D4:19" // реальний MAC
};

std::map<String, StudentProgress> progress;

// Сервери
WiFiServer ftpServer(21);
WiFiServer sshServer(22);
WiFiServer httpServer(8080);
WiFiServer infoServer(80);
WiFiServer flagServer(88);

// -------------------- MAC визначення --------------------
String getMacFromIP(String ip) {
  ip4_addr_t addr;
  if (!ip4addr_aton(ip.c_str(), &addr)) return "";

  struct netif* netif = netif_default;
  if (!netif) return "";

  err_t result = etharp_request(netif, &addr);
  if (result != ERR_OK) return "";

  delay(200); // більше часу на ARP

  struct eth_addr* eth_ret = NULL;
  ip4_addr_t* ip_ret = NULL;
  if (etharp_find_addr(netif, &addr, &eth_ret, (const ip4_addr_t**)&ip_ret) == -1 || eth_ret == NULL) {
    return "";
  }

  char macStr[18];
  sprintf(macStr, "%02X:%02X:%02X:%02X:%02X:%02X",
          eth_ret->addr[0], eth_ret->addr[1], eth_ret->addr[2],
          eth_ret->addr[3], eth_ret->addr[4], eth_ret->addr[5]);
  return String(macStr);
}

// Function to generate a unique flag based on MAC address
String generateFlag(String macAddress) {
    uint8_t hash[32];
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    
    // Add "rabbit" modifier to the input string
    String modifiedInput = macAddress + "mole";
    mbedtls_sha256_update(&ctx, (const unsigned char*)modifiedInput.c_str(), modifiedInput.length());
    mbedtls_sha256_finish(&ctx, hash);
    mbedtls_sha256_free(&ctx);

    String flagResult = "FLAG{";
    for (int i = 0; i < 5; i++) {
        char hex[3];
        sprintf(hex, "%02x", hash[i]);
        flagResult += hex;
    }
    flagResult += "}";

    Serial.printf("[FLAG] Generated flag for MAC %s \n", macAddress.c_str());
    return flagResult;
}

// -------------------- Допоміжні функції --------------------
String getClientID(String ip) {
  String mac = getMacFromIP(ip);
  return mac != "" ? mac : ip;
}

String generateKeyPart(String id, int index) {
  uint8_t hash[32];
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts(&ctx, 0);
  String input = id + String(index);
  mbedtls_sha256_update(&ctx, (const unsigned char*)input.c_str(), input.length());
  mbedtls_sha256_finish(&ctx, hash);
  mbedtls_sha256_free(&ctx);

  char part[7];
  snprintf(part, sizeof(part), "%02X%02X%02X", hash[0], hash[1], hash[2]);
  String keyPart = String("KEY_PART_") + String(index) + ": " + part;

  // Logging info about key creation
  String mac = (id.indexOf(':') != -1) ? id : getMacFromIP(id);
  String ip = (id.indexOf(':') == -1) ? id : "";
  Serial.println("[KEYGEN] MAC: " + mac + " | IP: " + ip + " | Issued key: " + keyPart);

  return keyPart;
}

// -------------------- FTP-сервер (порт 21) --------------------
void handleFTPClient() {
  WiFiClient client = ftpServer.available();
  if (!client) return;

  String ip = client.remoteIP().toString();
  String id = getClientID(ip);

  client.println("220 ESP FTP Ready");
  delay(100);

  String cmd = "";
  unsigned long timeout = millis() + 3000;

  while (millis() < timeout && client.connected()) {
    if (client.available()) {
      cmd += (char)client.read();
      if (cmd.endsWith("\r\n")) {
        cmd.trim();
        if (cmd.startsWith("USER anonymous")) {
          client.println("230 Login successful.");
          client.println(generateKeyPart(id, 1));
          break;
        } else {
          client.println("530 Login incorrect.");
          break;
        }
      }
    }
  }

  client.stop();
}

// -------------------- SSH-сервер (порт 22) --------------------
void handleSSHClient() {
  WiFiClient client = sshServer.available();
  if (!client) return;

  String ip = client.remoteIP().toString();
  String id = getClientID(ip);
  
  // Initially don't send anything - wait for client to send something first
  unsigned long timeout = millis() + 1000;
  String clientData = "";
  bool clientSentData = false;
  
  while (millis() < timeout && client.connected()) {
    if (client.available()) {
      char c = client.read();
      clientData += c;
      clientSentData = true;
      if (clientData.endsWith("\r\n")) break;
    }
  }
  

  if (!clientSentData) {
    // This is likely an automated scan like Nmap
    String banner = "SSH-2.0-ESP_CTF_Server KEY:" + generateKeyPart(id, 2) + "\r\n";
    client.print(banner);
    Serial.println("Sent banner with key to automated client");
  } else {
    // This is likely an interactive client like netcat
    client.print("SSH-2.0-ESP_CTF_Server\r\n");
    Serial.println("Sent banner without key to interactive client");
  }
  
  // Continue listening for a bit to properly handle SSH protocol
  timeout = millis() + 1500;
  while (millis() < timeout && client.connected()) {
    if (client.available()) {
      char c = client.read();
      clientData += c;
    }
    delay(10);
  }
  
  delay(500);
  client.stop();
}

// -------------------- HTTP  --------------------
void handleHTTPClient() {
  WiFiClient client = httpServer.available();
  if (!client) return;

  String ip = client.remoteIP().toString();
  String id = getClientID(ip);

  // Читання запиту
  unsigned long timeout = millis() + 2000;
  String req = "";
  while (millis() < timeout && client.connected()) {
    if (client.available()) {
      char c = client.read();
      req += c;
      if (req.endsWith("\r\n\r\n")) break;
    }
  }

  req.trim();
  Serial.println("HTTP Request: " + req);

  // Дозволяємо тільки User-Agent: Nmap Scripting Engine
  if (req.indexOf("User-Agent:") != -1 && req.indexOf("Nmap Scripting Engine") != -1) {
    String key = generateKeyPart(id, 3);
    // Створюємо правильну HTML-відповідь з тегом title
    String body = "<!DOCTYPE html>\n<html>\n<head>\n<title>" + key + "</title>\n</head>\n";
    body += "<body>\n<h1>Welcome to CTF server</h1>\n</body>\n</html>";
    
    client.println("HTTP/1.1 200 OK");
    client.println("Content-Type: text/html");
    client.println("Connection: close");
    client.println("Content-Length: " + String(body.length()));
    client.println();
    client.print(body);
  } else {
    client.println("HTTP/1.1 403 Forbidden");
    client.println("Content-Type: text/html");
    client.println("Connection: close");
    client.println("Content-Length: 36");
    client.println();
    client.print("<html><body>403 Forbidden</body></html>");
  }
  
  delay(50);
  client.stop();
}

// -------------------- Інформаційна сторінка на порт 80 --------------------
void handleInfoClient() {
  WiFiClient client = infoServer.available();
  if (!client) return;

  String body = "<html><head><title>CTF Info</title></head><body>";
  body += "<h1>CTF ESP32 Services</h1>";
  body += "<ul>";
  body += "<li>FTP (порт 21): отримай частину ключа через USER anonymous</li>";
  body += "<li>SSH (порт 22): отримай частину ключа через nmap</li>";
  body += "<li>HTTP (порт 8080): отримай частину ключа через nmap --script=http-title</li>";
  body += "<li>Прапор доступний через nc на порт 88 (введіть усі три ключі)</li>";
  body += "</ul></body></html>";

  client.println("HTTP/1.1 200 OK");
  client.println("Content-Type: text/html");
  client.println("Connection: close");
  client.println("Content-Length: " + String(body.length()));
  client.println();
  client.print(body);
  delay(50);
  client.stop();
}

// -------------------- Сервер прапора на порт 88 --------------------
void handleFlagClient() {
  WiFiClient client = flagServer.available();
  if (!client) return;

  String ip = client.remoteIP().toString();
  String mac = getMacFromIP(ip); 
  String id = getClientID(ip);

  client.println("Введіть три ключі в один рядок через пробіл:");

  String input = "";
  unsigned long timeout = millis() + 20000;
  while (millis() < timeout && client.connected()) {
    if (client.available()) {
      char c = client.read();
      if (c == '\n' || c == '\r') break;
      input += c;
    }
  }
  input.trim();

  // Розбиваємо рядок на ключі
  String keys[3];
  int idx = 0, last = 0;
  for (int i = 0; i < 3; ++i) {
    int spaceIdx = input.indexOf(' ', last);
    if (spaceIdx == -1 && i < 2) { keys[i] = ""; break; }
    if (spaceIdx == -1) spaceIdx = input.length();
    keys[i] = input.substring(last, spaceIdx);
    last = spaceIdx + 1;
  }

  // Логи для перевірки
  Serial.println("[FLAG] Введено:");
  for (int i = 0; i < 3; ++i) {
    Serial.println("key" + String(i+1) + ": '" + keys[i] + "'");
  }
  Serial.println("[FLAG] Очікується:");
  for (int i = 1; i <= 3; ++i) {
    String expected = generateKeyPart(id, i);
    int colonIdx = expected.indexOf(':');
    String expectedHex = expected.substring(colonIdx + 2);
    Serial.println("key" + String(i) + ": '" + expectedHex + "'");
  }

  // Перевірка ключів (тільки HEX-частина)
  bool ok = true;
  for (int i = 1; i <= 3; ++i) {
    String expected = generateKeyPart(id, i);
    int colonIdx = expected.indexOf(':');
    String expectedHex = expected.substring(colonIdx + 2);
    if (keys[i-1] != expectedHex) ok = false;
  }

  if (ok) {
    // Прапор через generateFlag (MAC якщо є, інакше IP)
    String flag = generateFlag(mac != "" ? mac : ip);
    client.println("\nВітаємо! Ваш прапор:");
    client.println(flag);
    Serial.println("[FLAG] Прапор видано: " + flag);
  } else {
    client.println("\nНевірні ключі. Спробуйте ще раз.");
    Serial.println("[FLAG] Невірні ключі.");
  }
  delay(500);
  client.stop();
}

// -------------------- SETUP --------------------
void setup() {
  Serial.begin(115200);
  SerialBT.begin("ESP_CTF_BT");

  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\nConnected. IP: " + WiFi.localIP().toString());

  ftpServer.begin();
  sshServer.begin();
  httpServer.begin();
  infoServer.begin();
  flagServer.begin();
  Serial.println("FTP, SSH, HTTP, INFO, FLAG servers started.");
}

// -------------------- LOOP --------------------
void loop() {
  handleFTPClient();
  handleSSHClient();
  handleHTTPClient();
  handleInfoClient();
  handleFlagClient();
  delay(10);
}
