#include <SPI.h>
#include <MFRC522.h> //13.56 MHz
#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <ESP8266WiFiMulti.h>
#include <ESP8266HTTPClient.h>
#include <WiFiClient.h>
#include <WiFiClientSecureBearSSL.h>

const uint8_t fingerprint[32] = {
    0xe6, 0xfe, 0x22, 0xbf, 0x45, 0xe4, 0xf0, 0xd3,
    0xb8, 0x5c, 0x59, 0xe0, 0x2c, 0x0f, 0x49, 0x54,
    0x18, 0xe1, 0xeb, 0x8d, 0x32, 0x10, 0xf7, 0x88,
    0xd4, 0x8c, 0xd5, 0xe1, 0xcb, 0x54, 0x7c, 0xd4
};

#define RST_PIN  D3     // Configurable, see typical pin layout above
#define SS_PIN   D4     // Configurable, see typical pin layout above
#define BUZZER   D2     // Configurable, see typical pin layout above

MFRC522 mfrc522(SS_PIN, RST_PIN);  // Instance of the class
MFRC522::MIFARE_Key key;  
ESP8266WiFiMulti WiFiMulti;
MFRC522::StatusCode status;      

/* Be aware of Sector Trailer Blocks */
int blockNum = 2;  

/* Create another array to read data from Block */
/* Legthn of buffer should be 2 Bytes more than the size of Block (16 Bytes) */
byte bufferLen = 18;
byte readBlockData[18];

String data2;
/* Google sheet url  */
const String data1 = "https://script.google.com/macros/s/AKfycbxg6HDKFOdpCC4dI2NKVRUILt7NjmY4_SYMAI5tSmpRVaiJHohyXYasNMIBFD1Bosgziw/exec?name=";

void setup() 
{
  /* Initialize serial communications with the PC */
  Serial.begin(9600);
  // Serial.setDebugOutput(true);

  Serial.println();
  Serial.println();
  Serial.println();

  for (uint8_t t = 4; t > 0; t--) 
  {
    Serial.printf("[SETUP] WAIT %d...\n", t);
    Serial.flush();
    delay(1000);
  }

  WiFi.mode(WIFI_STA);
  
  /* Put your WIFI Name and Password here */
  Serial.printf("ready to connet\n");
/* wifi creds */
  WiFiMulti.addAP("DESKTOP-FL39STV 8383", "abc@12345");
  Serial.printf("Conneceted to TEST");

  /* Set BUZZER as OUTPUT */
  pinMode(BUZZER, OUTPUT);
  /* Initialize SPI bus */
  SPI.begin();
}

void loop()
{  
  mfrc522.PCD_Init();
  
  if (!mfrc522.PICC_IsNewCardPresent()) {
    return;
  }

  if (!mfrc522.PICC_ReadCardSerial()) {
    return;
  }

  Serial.println(F("Reading last data from RFID..."));
  ReadDataFromBlock(blockNum, readBlockData);

  Serial.print(F("Last data in RFID:"));
  for (int j = 0; j < 16; j++) {
    Serial.write(readBlockData[j]);
  }
  
  digitalWrite(BUZZER, HIGH);
  delay(200);
  digitalWrite(BUZZER, LOW);
  
  if (WiFiMulti.run() == WL_CONNECTED) {
    std::unique_ptr<BearSSL::WiFiClientSecure> client(new BearSSL::WiFiClientSecure);
    client->setInsecure(); // Ignore SSL certificate validation

    data2 = data1 + String((char*)readBlockData);
    data2.trim();
    
    HTTPClient https;
    Serial.print(F("[HTTPS] begin...\n"));
    
    if (https.begin(*client, data2)) {
      Serial.print(F("[HTTPS] GET...\n"));
      int httpCode = https.GET();
      
      if (httpCode > 0) {
        Serial.printf("[HTTPS] GET... code: %d\n", httpCode);
      } else {
        Serial.printf("[HTTPS] GET... failed, error: %s\n", https.errorToString(httpCode).c_str());
      }
      
      https.end();
    } else {
      Serial.printf("[HTTPS] Unable to connect\n");
    }
    
    delay(1000);
  } else {
    Serial.println("WiFi not connected");
  }

}

void ReadDataFromBlock(int blockNum, byte readBlockData[]) 
{ 
  /* Prepare the ksy for authentication */
  /* All keys are set to FFFFFFFFFFFFh at chip delivery from the factory */
  for (byte i = 0; i < 6; i++)
  {
    key.keyByte[i] = 0xFF;
  }
  /* Authenticating the desired data block for Read access using Key A */
  status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, blockNum, &key, &(mfrc522.uid));

  if (status != MFRC522::STATUS_OK)
  {
     Serial.print("Authentication failed for Read: ");
     Serial.println(mfrc522.GetStatusCodeName(status));
     return;
  }
  else
  {
    Serial.println("Authentication success");
  }

  /* Reading data from the Block */
  status = mfrc522.MIFARE_Read(blockNum, readBlockData, &bufferLen);
  if (status != MFRC522::STATUS_OK)
  {
    Serial.print("Reading failed: ");
    Serial.println(mfrc522.GetStatusCodeName(status));
    return;
  }
  else
  {
    Serial.println("Block was read successfully");  
  }
}
