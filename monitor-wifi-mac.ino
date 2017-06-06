// Monitor WiFi networks for presence of a specified MAC Address and light up the on-board LED to show that the MAC address has been detected (edit mac_addr variable)
// WiFi sniffer developped for the WEMOS D1 Mini using the Arduino platform
// Credits: A fork of ESP8266 mini-sniff by Ray Burnette https://www.hackster.io/rayburne/esp8266-mini-sniff-f6b93a

#include <ESP8266WiFi.h>
#include "./structures.h"
// Expose Espressif SDK functionality
extern "C" {
#include "user_interface.h"
  typedef void (*freedom_outside_cb_t)(uint8 status);
  int  wifi_register_send_pkt_freedom_cb(freedom_outside_cb_t cb);
  void wifi_unregister_send_pkt_freedom_cb(void);
  int  wifi_send_pkt_freedom(uint8 *buf, int len, bool sys_seq);
}

#define disable 0
#define enable  1
// uint8_t channel = 1;
unsigned int channel = 1;
unsigned long previousMillis = 0; // last time update
long interval = 60000; // interval at which you should forget the client was nearby (ms)
String mac_addr = "06952630fc35"; // mac address we are looking for

void setup() {
  Serial.begin(115200);

  wifi_set_opmode(STATION_MODE);            // Promiscuous works only with station mode
  wifi_set_channel(channel);
  wifi_promiscuous_enable(disable);
  wifi_set_promiscuous_rx_cb(promisc_cb);   // Set up promiscuous callback
  wifi_promiscuous_enable(enable);
  pinMode(LED_BUILTIN, OUTPUT);
  digitalWrite(LED_BUILTIN, HIGH); // turn led OFF
}

void loop() {
  unsigned long currentMillis = millis();
  channel = 1;
  wifi_set_channel(channel);
  if(currentMillis - previousMillis > interval) {
     previousMillis = currentMillis;
      Serial.println("\n-------MAC WAS NOT SEED BEFORE INTERVAL EXPIRED-------\n");
      digitalWrite(LED_BUILTIN, HIGH);
  }
  while (true) {
    channel++;
    if (channel == 15) break;             // Only scan channels 1 to 14
    wifi_set_channel(channel);
    delay(1);  // critical processing timeslice for NONOS SDK! No delay(0) yield()
  }
}

int find_mac(clientinfo ci, String mac) {
  if (ci.err != 0) {
    // nothing
  } else {
    String new_mac = "";
    for (int i = 0; i < 6; i++) {
      if (String(ci.station[i], HEX).length() == 1) { new_mac += 0;}  //pad "0" to one-digit hex numbers
      new_mac += String(ci.station[i], HEX);  // Convert decimal to hexadecimal...
    }

    Serial.println("Seeing: " + new_mac);

    unsigned long currentMillis = millis();

    if (mac == new_mac) {
      Serial.println("\n-------FOUND " + mac_addr + " (Client within WiFi range)-------\n");
      digitalWrite(LED_BUILTIN, LOW);
      previousMillis = currentMillis;
    }
  }
}

void promisc_cb(uint8_t *buf, uint16_t len) {
  uint16_t seq_n_new = 0;
  if (len == 12) {
    struct RxControl *sniffer = (struct RxControl*) buf;
  } else if (len == 128) {
    struct sniffer_buf2 *sniffer = (struct sniffer_buf2*) buf;
    struct beaconinfo beacon = parse_beacon(sniffer->buf, 112, sniffer->rx_ctrl.rssi);
  } else {
    struct sniffer_buf *sniffer = (struct sniffer_buf*) buf;
    //Is data or QOS?
    if ((sniffer->buf[0] == 0x08) || (sniffer->buf[0] == 0x88)) {
      struct clientinfo ci = parse_data(sniffer->buf, 36, sniffer->rx_ctrl.rssi, sniffer->rx_ctrl.channel);
      if (memcmp(ci.bssid, ci.station, ETH_MAC_LEN)) {
        find_mac(ci, "202d07a8a322");
      }
    }
  }
}

