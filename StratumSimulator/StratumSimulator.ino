/*

  StratumSimulator.ino

  This project offers a convenient way to test SHA256-based cryptocurrency miners. 
  It enables developers or users to connect to a simulated Stratum server and mine 
  virtual blocks at a customizable difficulty level. It is meant to be compiled
  through the Arduino IDE and deployed on ESP32 devices.

*/

#include <Arduino.h>
#include <ArduinoJson.h>
#include <WiFi.h>
#include <mbedtls/sha256.h>
#include <nvs.h>
#include "esp_random.h"


// Defines you can change to your liking
#define WIFI_SSID ""                      // If SSID is not specified here, it can be set via serial command
#define WIFI_PASSWORD ""                  // If WiFi password is not specified here, it can be set via serial command
#define STRATUM_LISTEN_PORT 3333          // Port our server will listen on
#define JOB_CHANGE_FREQUENCY 600          // Seconds between job changes
#define MAX_CLIENTS 10                    // Number of concurrent clients
#define POOL_DIFFICULTY 0.001             // Starting difficulty for our pool
#define BLOCK_DIFFICULTY 1.0              // The difficulty for our fake blocks - MUST BE AT LEAST 1.0
#define ALLOW_DIFFICULTY_SUGGESTION true  // true|false - If true, client difficulty suggestions will be honored
#define BLOCK_TIME 0x6797e794             // Value of block time at start (UNIX timestamp)
#define BLOCK_VERSION 2                   // Block version put into hash block
#define STATS_REFRESH_FREQUENCY_MS 10000  // Statistics refresh time in milliseconds, 0 for no updates
#define WIFI_CONNECT_WAIT_TIME_MS 20000   // How long to wait for a WiFi connection in milliseconds
#define SERIAL_BAUD_RATE 115200           // Baud rate of serial port

// Defines you don't really need to change
#define DEFAULT_NBITS 0x1D00FFFF          // Any calculation errors will result in the default difficulty value of 1


#define EXTRA_NONCE2_SIZE 4               
#define MERKLE_BRANCHES 4

#define PREV_HASH  "4d16b6f85af6e2198f44ae2a6de67f78487ae5611b77c6c0440b921e00000000"
#define COINBASE_1 "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff1d03bf770d041083956700"
#define COINBASE_2 "0a4d696e696e67636f72650000000001e72fa312000000001976a9144b06af76a993d1bc008070b2b5b074578bc2966788ac00000000"

#define NVS_SSID_KEY "ssid"
#define NVS_SSID_PW_KEY "password"
#define NVS_STORAGE_NS "storage"

// Defines that you don't change
#define ERR_NONE 0
#define ERR_JOB_NOT_FOUND 21
#define ERR_LOW_DIFFICULTY 23

#define LOG_LEVEL_NONE 0
#define LOG_LEVEL_DEBUG 10

#define MAX_SSID_LENGTH 32
#define MAX_PASSWORD_LENGTH 64

#define BYTESWAP32(z) ((uint32_t)((z&0xFF)<<24|((z>>8)&0xFF)<<16|((z>>16)&0xFF)<<8|((z>>24)&0xFF)))

// Structures
typedef struct {
  WiFiClient  client;
  uint32_t    sessionId;
  uint32_t    lastId;
  uint32_t    connectTime;
  double      difficulty;
  char        extraNonce1[10];
  char        userAgent[120];
  char        wallet[120];
  uint32_t    extraNonce2Size;
  bool        subscribed;
  bool        authorized;
  bool        sendJob;
  bool        sendDifficulty;
} StratumClient;

typedef struct {
  uint32_t version;
  uint8_t prev_hash[32];
  uint8_t merkle_root[32];
  uint32_t timestamp;
  uint32_t difficulty;
  uint32_t nonce;
} HashBlock;

typedef struct {
  uint32_t  blockTemplates;
  uint32_t  poolSolutions;
  uint32_t  blockSolutions;
  uint32_t  rejectedShares;
  double    bestDifficulty;
} Stats;


// Variables
WiFiServer server(STRATUM_LISTEN_PORT);
StratumClient stratumClients[MAX_CLIENTS];
Stats stats;
double poolDifficulty = POOL_DIFFICULTY;
uint8_t merkleHashes [4][32]; 
uint32_t blockTime = BLOCK_TIME;
uint32_t blockNbits;
uint32_t sessionId = 1;
uint32_t jobId = 0;
volatile bool newJobRequired;
String jobJson;
char ssid[MAX_SSID_LENGTH];
char password[MAX_PASSWORD_LENGTH];
uint8_t currentLoggingLevel = LOG_LEVEL_DEBUG;

// Send output to the serial port
void logIt(uint8_t logLevel, const char *format, ...) {
  if (logLevel >= currentLoggingLevel) {
    char buffer[2048];       // Temporary buffer to hold the formatted string
    va_list args;           // Declare a variable to hold the arguments
    va_start(args, format); // Initialize the argument list with the last known argument
    
    vsnprintf(buffer, sizeof(buffer), format, args); // Format the string with the arguments
    va_end(args);           // Clean up the va_list
    
    Serial.print(buffer);   // Send the formatted string to Serial
  }
}
// Use the ESP32's built-in sha256, which is good enough for block verification
void sha256(const uint8_t *input, size_t inputLength, uint8_t* output) {
    // Initialize the context
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts_ret(&ctx, 0); // 0 means SHA-256, not SHA-224
    mbedtls_sha256_update_ret(&ctx, input, inputLength);
    mbedtls_sha256_finish_ret(&ctx, output);
    mbedtls_sha256_free(&ctx);
}

// Do a double SHA256
void doubleSha256(const uint8_t *input, size_t inputLength, uint8_t* output) {
  uint8_t sha1[32];
  sha256(input, inputLength, sha1);
  sha256(sha1, 32, output);
}


// Decodes a single hex character
unsigned char decodeHexChar(char c) {
    switch(c)
    {
        case 'a'...'f':
            return 0x0a + c - 'a';
        case 'A'...'F':
            return 0x0a + c - 'A';
        case '0'...'9':
            return c - '0';
    } 
    return 0;
}


// Decodes a hex string
uint32_t decodeHex(const char* hex) {
  uint32_t rv = 0;
  int16_t i = 0;
  uint8_t c;
  while(c = hex[i++]) {
    rv <<= 4;
    rv += decodeHexChar(c);
  }
  return rv;
}

// Binary to hex converter
void bin2hex(char *out, unsigned char* in, size_t len) {
    int i, j;
    char *tbl = "0123456789ABCDEF";
    for(i = 0, j = 0; i < len; i++) {
        out[j++] = tbl[(in[i] >> 4) & 0x0f];
        out[j++] = tbl[in[i] & 0x0f];        
    }
    out[j] = '\0';
}

// Encode a 32-bit value as a zero-padded hexadecimal string
void hexEncode32(char *dest, size_t len, uint32_t en) {
  static const char *tbl= "0123456789ABCDEF";  
  dest += len * 2;
  *dest-- = '\0';
  while( len-- ) {
      *dest-- = tbl[en & 0x0f];
      *dest-- = tbl[(en >> 4) & 0x0f];
      en >>= 8;
  }
}

// Previous hash needs byte swapping of each 32-bit chunk
void longSwap(uint32_t* val) {
  for(uint8_t i = 0; i < 8; i++) {
    val[i] = __builtin_bswap32(val[i]);
  }
}

// Converts hex string to binary
void hex2bin(unsigned char *out, const char *in, size_t len) {
    size_t b = 0;
    for(int i = 0; i < len; i+=2) {
        out[b++] = (unsigned char) (decodeHexChar(in[i]) << 4) + decodeHexChar(in[i+1]);
    }
}



// Create a new Job notification string to send to clients
void createJob() {
  
  char hn[65];
  hexEncode32(hn, 4, ++jobId);

  jobJson.clear();
  jobJson.concat("{\"id\": null, \"method\": \"mining.notify\", \"params\": [\"");
  jobJson.concat(hn);
  jobJson.concat("\", \"");
  jobJson.concat(PREV_HASH);
  jobJson.concat("\", \"");
  jobJson.concat(COINBASE_1);
  jobJson.concat("\", \"");
  jobJson.concat(COINBASE_2);
  jobJson.concat("\", [");

  // Randomly generate Merkle branch values
  for(uint8_t i = 0; i < MERKLE_BRANCHES; i++) {
    // Fill merkle hashes with random "hashes"
    esp_fill_random(merkleHashes[i], 32);
    bin2hex(hn, merkleHashes[i], 32);
    if( i ) {
      jobJson.concat(",");
    }
    jobJson.concat("\"");
    jobJson.concat(hn);
    jobJson.concat("\"");
  }

  hexEncode32(hn, 4, BLOCK_VERSION);
  jobJson.concat("], \"");
  jobJson.concat(hn);
  jobJson.concat("\", \"");

  hexEncode32(hn, 4, blockNbits);
  jobJson.concat(hn);
  jobJson.concat("\", \"");
  
  hexEncode32(hn, 4, blockTime);
  jobJson.concat(hn);
  jobJson.concat("\", true]}\n");

  newJobRequired = false;
  stats.blockTemplates++;

  logIt(LOG_LEVEL_DEBUG, "Job Created: %s\n", jobJson.c_str());

}


// Calculates the Merkle root by hashing the coinbase hash
// together with the Merkle branches
void calculateMerkleRoot(unsigned char* merkleRoot, unsigned char* cbHash) {

  uint8_t i;
  unsigned char merklePair[64];

  if( merkleRoot && cbHash ) {
    // Add coinbase hash to tree at position 0
    memcpy(merklePair, cbHash, 32);

    for(i = 0; i < MERKLE_BRANCHES; i++) {
      memcpy(&merklePair[32], merkleHashes[i], 32);
      doubleSha256(merklePair, 64, merklePair);
    }
    memcpy(merkleRoot, merklePair, 32);
  }
}

// Converts a double difficulty value to its corresponding nBits representation
//
// Function graciously provided by ChatGPT, which means it probably came
// from somewhere else. So, thank you.
uint32_t difficulty_to_nbits(double difficulty) {
    if (difficulty < 0) {
        return DEFAULT_NBITS;
    }

    // Check for infinity without using math.h
    double infinity = 1.0 / 0.0; // Represent infinity
    if (difficulty == infinity || difficulty == -infinity) {
        return DEFAULT_NBITS;
    }

    uint64_t word = 0;
    int shiftBytes = 0;

    // Calculate "word" without using pow or floating-point math
    for (shiftBytes = 1;; shiftBytes++) {
        // Scale factor is equivalent to 256^shiftBytes
        uint64_t scale_factor = 1ULL;
        for (int i = 0; i < shiftBytes; i++) {
            scale_factor *= 256;
        }

        word = (uint64_t)((0x00FFFFULL * scale_factor) / difficulty);

        if (word >= 0xFFFF) {
            break;
        }
    }

    word &= 0xFFFFFF; // Ensure it's within 24-bit bounds
    int size = 0x1D - shiftBytes;

    // Adjust for sign bit if necessary
    if (word & 0x800000) {
        word >>= 8;
        size++;
    }

    if ((word & ~0x007FFFFF) != 0) {
        return DEFAULT_NBITS;
    }
    if (size > 0xFF) {
        return DEFAULT_NBITS;
    }

    // Combine size and word into nBits
    uint32_t bits = (size << 24) | word;
    return bits;
}

// Calculates the difficulty of the hash
double difficultyFromHash(uint8_t* hash) {
  static const double maxTarget = 26959535291011309493156476344723991336010898738574164086137773096960.0;
  double hashValue = 0.0;

  int i,j;
  for(i = 0, j = 31; i < 32; i++, j--) {
    hashValue = hashValue * 256 + hash[j];
  }
  double difficulty = maxTarget / hashValue;
  return difficulty;
}


// Calculates the double hash of the coinbase
void calculateCoinbaseHash(unsigned char *output, char *extraNonce1, uint32_t extrNonce2) {
  unsigned char buf[256];
  uint16_t pos = 0;
  char en2[10];

  hex2bin(buf, COINBASE_1, strlen(COINBASE_1));
  pos += strlen(COINBASE_1) / 2;
  
  hex2bin(&buf[pos], extraNonce1, strlen(extraNonce1));
  pos += strlen(extraNonce1) / 2;

  hexEncode32(en2, EXTRA_NONCE2_SIZE, extrNonce2);
  hex2bin(&buf[pos], en2, EXTRA_NONCE2_SIZE * 2);  
  pos += EXTRA_NONCE2_SIZE;
  hex2bin(&buf[pos], COINBASE_2, strlen(COINBASE_2));
  pos += strlen(COINBASE_2) / 2;

  doubleSha256(buf, pos, output);
}

// Sends the client its expected difficulty
void sendDifficulty(StratumClient& sClient) {
  char resp[100];
  sprintf(resp, "{\"id\": null,\"method\":\"mining.set_difficulty\",\"params\":[%.5f]}\n", sClient.difficulty);
  sClient.client.print(resp);
}


// Sends the response to a client's submission with corresponding error code if any
void sendSubmitResponse(StratumClient& sClient, uint8_t errCode) {
  
  char* e21 = "Job not found.";
  char* e23 = "Low difficulty share.";
  char* enone = "";

  char *errMsgPtr = enone;

  const char* t = "true";
  const char* f = "false";
  bool result = (errCode == ERR_NONE) ? true : false;

  char ds[256];
  char dsErrMsg[60];

  if( sClient.client.connected() ) {
    sprintf(ds, "{\"id\": %lu, \"result\": %s, \"error\": ", sClient.lastId, (result ? t : f));
    if( result ) {
      strcat(ds, "null");
    } else {
      switch(errCode) {
        case ERR_JOB_NOT_FOUND:
          errMsgPtr = e21;            
          break;
        case ERR_LOW_DIFFICULTY:
          errMsgPtr = e23;
          break;
        default:
          break;
      }
      sprintf(dsErrMsg, "[%d, \"%s\", null]", errCode, errMsgPtr);
      strcat(ds, dsErrMsg);
    } 
    strcat(ds, "}\n");
    sClient.client.print(ds);

    logIt(LOG_LEVEL_DEBUG, "Response: %s\n", ds);

  }

}

// Handles pool submissions, calculates the hash, and determines client response
void handleSubmit(StratumClient& sClient, JsonDocument &doc) {
  
  char hBuffer[65];

  const char* userName = doc["params"][0];
  const char* jid = doc["params"][1];
  const char* extraNonce2 = doc["params"][2];
  const char* timestamp = doc["params"][3];
  const char* nonce = doc["params"][4];

  HashBlock hb;

  
  // See if this is the job we're currently working on
  // There is no backog, so you will see rejections.
  uint32_t job = decodeHex(jid);
  if( job != jobId ) {
    sendSubmitResponse(sClient, ERR_JOB_NOT_FOUND);
    logIt(LOG_LEVEL_DEBUG, "Invalid job ID (%lu) from miner!\n", job);
    stats.rejectedShares++;
    return;
  }

  // Populate the block with submitted parameters
  // and defaults
  hb.timestamp = decodeHex(timestamp);
  hb.difficulty = blockNbits;
  hb.nonce = decodeHex(nonce);
  hex2bin(hb.prev_hash, PREV_HASH, 64);
  hb.version = BLOCK_VERSION;
  longSwap((uint32_t*) &hb.prev_hash);

  // Calculate the coinbase hash and merkle root
  uint8_t cbh[32];
  uint32_t en2 = (uint32_t) strtoul(extraNonce2, NULL, 16);
  calculateCoinbaseHash(cbh, sClient.extraNonce1, en2);
  calculateMerkleRoot(hb.merkle_root, cbh);

  // Calculate the final block hash
  uint8_t hash[32];
  doubleSha256((uint8_t*) &hb, sizeof(HashBlock), hash);

  // Get the difficulty of the submitted block
  double blockDiff = difficultyFromHash(hash);


  logIt(LOG_LEVEL_DEBUG, "Work submitted:\n***************\nUser Name: %s\nJob ID:%s\nExtra Nonce 2: %s\nTimestamp: %s\nNonce: %s  (%lu)\nDifficulty: %0.5f\n", 
    userName, jid, extraNonce2, timestamp, nonce, BYTESWAP32(hb.nonce), blockDiff);


  // See if this beats our previous record
  if( blockDiff > stats.bestDifficulty ) {
    stats.bestDifficulty = blockDiff;
  }

  // Compare the difficulty to the block and pool.
  // This seems to be a good enough method
  // for what we're trying to do here.
  if( blockDiff >= sClient.difficulty ) {
    if( blockDiff >= BLOCK_DIFFICULTY ) {    
      stats.blockSolutions++;
      newJobRequired = true;
      logIt(LOG_LEVEL_DEBUG, "----> Block Solution found! <---->\n");
    } else {
      stats.poolSolutions++;
    }
    sendSubmitResponse(sClient, ERR_NONE);
  } else {
    char hashHex[65];
    bin2hex(hashHex, hash, 32);
    logIt(LOG_LEVEL_DEBUG, "Low difficulty (%.5f) hash.\n-->%s<--\n", blockDiff, hashHex);
    
    sendSubmitResponse(sClient, ERR_LOW_DIFFICULTY);
    stats.rejectedShares++;
  }


}

// Authorize a user
void handleAuthorize(StratumClient& sClient, JsonDocument &doc) {
  char resp[80];

  // Get the wallet, just for grins and debug messages
  if( doc.containsKey("params") ) {
    const char* wallet = doc["params"][0];
    if( wallet ) {
      strcpy(sClient.wallet, wallet);
    }    
  }

  sprintf(resp, "{\"id\": %lu, \"result\": true, \"error\": null}\n", sClient.lastId);
  sClient.client.print(resp);
  sClient.difficulty = POOL_DIFFICULTY;
  sClient.sendJob = true;
  sClient.sendDifficulty = true;
  sClient.authorized = true;

}


// Handle a new subscribe, assigning client a session ID and extra nonce 1 value
void handleSubscribe(StratumClient& sClient, JsonDocument &doc) {
  char resp[120];
  
  if( doc.containsKey("params") ) {
    const char* userAgent = doc["params"][0];
    if( userAgent ) {
      strcpy(sClient.userAgent, userAgent);
    }    
  }
  sClient.sessionId = sessionId++;
  sClient.extraNonce2Size = EXTRA_NONCE2_SIZE;

  uint32_t en1 = esp_random();   // Create an extra nonce 1
  hexEncode32(sClient.extraNonce1, 4, en1);
  
  sprintf(resp, "{\"error\": null, \"id\": %lu, \"result\": [[[\"mining.set_difficulty\", \"%x\"],[\"mining.notify\", \"%x\"]], \"%s\", %d]}\n", 
      sClient.lastId, sClient.sessionId, sClient.sessionId, sClient.extraNonce1, sClient.extraNonce2Size);

  logIt(LOG_LEVEL_DEBUG, "Server Message: %s\n", resp);
  
  sClient.client.print(resp);
  sClient.subscribed = true;
  
}

// Sets the difficulty for the client based on its own suggestion
void handleSuggestDifficulty(StratumClient& sClient, JsonDocument &doc) {
  
  if( doc.containsKey("params") && doc["params"].size() > 0 ) {
    sClient.difficulty = doc["params"][0];
    sClient.sendDifficulty = true;    
  }
}


// Receive a message from the client and process it
void receiveClientMsg(StratumClient& sClient, String& msg) {
  
  logIt(LOG_LEVEL_DEBUG, "Client Message: %s\n", msg.c_str());

  JsonDocument doc;
  DeserializationError err = deserializeJson(doc, msg);
  if( err == DeserializationError::Ok ) {
    
    if( doc.containsKey("method") ) {

      if( doc.containsKey("id") ) {
        uint32_t id = doc["id"];
        sClient.lastId = id;
      }

      const char* method = doc["method"];
      if( strcmp("mining.subscribe", method) == 0 ) {
        handleSubscribe(sClient, doc);                 
      } else if( sClient.subscribed && strcmp("mining.authorize", method) == 0 ) {
        handleAuthorize(sClient, doc);
      } else if( sClient.authorized && strcmp("mining.submit", method) == 0 ) {
        handleSubmit(sClient, doc);
      } else if( sClient.authorized && ALLOW_DIFFICULTY_SUGGESTION 
                  && strcmp("mining.suggest_difficulty", method) == 0 ) {
          handleSuggestDifficulty(sClient, doc);
      }

    }
  }
}


// Attemp to connec to WiFi
void wifiReconnect() {

  uint32_t waitTime = WIFI_CONNECT_WAIT_TIME_MS;

  if( WiFi.isConnected() ) {
    WiFi.disconnect();
    delay(200);
  }

  // If no SSID is set, see if there is a default
  if( ! strlen(ssid) && strlen(WIFI_SSID) && strlen(WIFI_PASSWORD) ) {
    strncpy(ssid, WIFI_SSID, MAX_SSID_LENGTH);
    ssid[MAX_SSID_LENGTH - 1] = '\0';
    strncpy(password, WIFI_PASSWORD, MAX_PASSWORD_LENGTH);
    ssid[MAX_PASSWORD_LENGTH - 1] = '\0';
  }
  
  if( strlen(ssid) && strlen(password) ) {
    Serial.printf("Attempting to connected to SSID %s\n", ssid);
    WiFi.begin(ssid, password);
    while( waitTime && ! WiFi.isConnected() ) {      
      delay(200);
      waitTime -= 200;
    }

    if( WiFi.isConnected() ) {
      Serial.print("Got IP Address: ");
      Serial.println(WiFi.localIP());
      saveWiFiInfo();
    }
        
  }

}

// Save WiFi ssid and password 
bool saveWiFiInfo() {
  bool rv = false;
  nvs_handle_t nvs_handle;
  if( nvs_open(NVS_STORAGE_NS, NVS_READWRITE, &nvs_handle) == ESP_OK ) {
    if( nvs_set_str(nvs_handle, NVS_SSID_KEY, ssid) == ESP_OK && 
      nvs_set_str(nvs_handle, NVS_SSID_PW_KEY, password) == ESP_OK )
    {
      rv = true;
    }
    nvs_close(nvs_handle);
  }
  return rv;
}


// Loads WiFi info from NVS
bool loadWiFiInfo() {
  bool rv = false;
  nvs_handle_t nvs_handle;
  if( nvs_open(NVS_STORAGE_NS, NVS_READWRITE, &nvs_handle) == ESP_OK ) {
    size_t s = MAX_SSID_LENGTH, s1 = MAX_PASSWORD_LENGTH;
    if( nvs_get_str(nvs_handle, NVS_SSID_KEY, ssid, &s) == ESP_OK && 
        nvs_get_str(nvs_handle, NVS_SSID_PW_KEY, password, &s) == ESP_OK ) {
      rv = true;
    }
    nvs_close(nvs_handle);
  }
  return rv;
}

// Handle commands from the serial port
void handleSerialCommand(const char* sc) {
  
  char *parm = strchr(sc, 0x20);

  // See if the command has a parameter
  if( parm && parm[1] != '\0' ) {    
    parm++;
  }

  // Figure out what to do for our little command set
  if( strcasecmp(sc, "help") == 0 ) {
    Serial.printf("\nHelp:\n--------\n");
    Serial.printf("ssid <your WiFi SSID>\n");
    Serial.printf("password <your WiFi password>\n");
    Serial.printf("newjob - Sends a new job to all clients.\n");
  } else if( strncasecmp(sc, "ssid ", 5) == 0 && parm) {
    Serial.printf("Setting ssid to %s\n", parm);
    strncpy(ssid, parm, MAX_SSID_LENGTH);
    ssid[MAX_SSID_LENGTH - 1] = '\0';
    wifiReconnect();
  } else if( strncasecmp(sc, "password ", 9) == 0 && parm) {
    Serial.printf("Setting password to %s\n", parm);
    strncpy(password, parm, MAX_PASSWORD_LENGTH);
    password[MAX_PASSWORD_LENGTH - 1] = '\0';
    wifiReconnect();
  } else if( strcasecmp(sc, "newjob") == 0 ) {
    newJobRequired = true;
    Serial.printf("Creating new job.\n");
  }
}

// Regular Arduino Setup
void setup() {

  Serial.begin(SERIAL_BAUD_RATE);
  Serial.setTimeout(0);
  delay(100);

  Serial.println("*****************************************************");
  Serial.println("* Type \"help\" on the serial console for more info *");
  Serial.println("*****************************************************");

  // Set the block difficulty in nBits format for use in hash blocks
  blockNbits = difficulty_to_nbits(BLOCK_DIFFICULTY);
  createJob();

  // If there is a saved SSID and password in NVS, then load it
  loadWiFiInfo();
}


// Arduino loop
void loop() {
  
  static uint32_t statsMillis, jobMillis = 0;
  static bool serverStarted = false;
  static bool showDisconnectMessage = true;

  uint8_t i;
  
  // Take commands on the serial port
  static uint8_t scl = 0;
  static char scommand[256];

  // Handle serial commands
  while( Serial.available() ) {
    char rc = Serial.read();
    if( rc == 10 || rc == 13 ) {
      if( scl > 0 ) {
        handleSerialCommand(scommand);
      }      
      scl = 0;
      break;
    }
    if( scl < 255 ) {
      scommand[scl++] = rc;
      scommand[scl] = '\0';
    }
  }

  // Check for WiFi connection
  if( ! WiFi.isConnected() ) {
    wifiReconnect();
    return;
  }

  // Server doesn't like starting without WiFi the first time around
  if( ! serverStarted ) {
    server.begin();
    serverStarted = true;
  }

  // Check for new client connections
  // and accept if we have an opening.
  if( server.hasClient() ) {
    logIt(LOG_LEVEL_DEBUG, "Client attempting connection...\n");
    for(i = 0; i < MAX_CLIENTS; i++) {
      if( ! stratumClients[i].client || ! stratumClients[i].client.connected() ) {
        stratumClients[i].client = server.available();
        stratumClients[i].connectTime = millis();
        stratumClients[i].subscribed = false;
        stratumClients[i].authorized = false;
        stratumClients[i].sendJob = false;
        break;
      }
    }
    // No empty client slots, then reject client.
    if( i >= MAX_CLIENTS ) {
      WiFiClient rejClient = server.available();
      rejClient.stop();
    }
  }
 
  bool sendNewJob = false;

  // Create a new job if we need it
  if( newJobRequired || millis() - jobMillis > (JOB_CHANGE_FREQUENCY * 1000) ) {
    createJob();
    sendNewJob = true;
    jobMillis = millis();
  }

  // Determine the number of clients below
  uint8_t clients = 0;

  // Process clients and incoming messages
  for(i = 0; i < MAX_CLIENTS; i++) {
    
    // Ignore empty slots
    if( ! stratumClients[i].client ) {
      continue;
    }

    // Close out any dead connections
    if( ! stratumClients[i].client.connected() ) {
      stratumClients[i].client.stop();
      stratumClients[i].client = NULL;
      continue;
    }

    clients++;

    // Check for incoming messages
    if( stratumClients[i].client.available() ) {

      String msg = stratumClients[i].client.readStringUntil('\n');
      if( msg.length() ) {
        receiveClientMsg(stratumClients[i], msg);
      }
    }

    // Send difficulty level to clients that need it
    if( stratumClients[i].sendDifficulty ) {      
      sendDifficulty(stratumClients[i]); 
      stratumClients[i].sendDifficulty = false;
    }

    // Send new jobs to clients that need it
    if( (sendNewJob && stratumClients[i].authorized) || stratumClients[i].sendJob ) {
      stratumClients[i].client.print(jobJson);
      stratumClients[i].sendJob = false;
    }
  }



  // Print out statistics periodically
  if( STATS_REFRESH_FREQUENCY_MS && millis() - statsMillis >= STATS_REFRESH_FREQUENCY_MS ) {
    Serial.printf("Jobs: %d  Pool Solutions: %d  Block Solutions: %d  Clients: %d  Best Diff: %.5f  Rej Shares: %d\n", 
      stats.blockTemplates, stats.poolSolutions, stats.blockSolutions, clients, stats.bestDifficulty, stats.rejectedShares);
    statsMillis = millis();
  }

  delay(100);
}
