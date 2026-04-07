#include <Arduino.h>
#include <WiFi.h>
#include <ArduinoJson.h>
#include <base64.h>

#include "mbedtls/base64.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/rsa.h"
#include "mbedtls/pk.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/gcm.h"
#include "mbedtls/md.h"

#include "keys.h"

#include <Adafruit_NeoPixel.h>

#define RGB_PIN 48
#define NUMPIXELS 1

Adafruit_NeoPixel hsm_led(NUMPIXELS, RGB_PIN, NEO_GRB + NEO_KHZ800);

void setLedColor(int r, int g, int b)
{
    hsm_led.setPixelColor(0, hsm_led.Color(r, g, b));
    hsm_led.show();
}

#define LED_PIN 2

mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;

void setup_rng()
{
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    const char *pers = "signet_hsm_trng";
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers));
}

String handleGenerateKey(String productName)
{
    unsigned char *priv_pem = (unsigned char *)malloc(1800);
    unsigned char *ciphertext = (unsigned char *)malloc(1800);
    unsigned char *base64_out = (unsigned char *)malloc(3000);

    if (!priv_pem || !ciphertext || !base64_out)
    {
        if (priv_pem)
            free(priv_pem);
        if (ciphertext)
            free(ciphertext);
        if (base64_out)
            free(base64_out);
        return "{\"status\":\"error\",\"message\":\"Out of Memory\"}";
    }

    memset(priv_pem, 0, 1800);
    memset(ciphertext, 0, 1800);
    memset(base64_out, 0, 3000);

    mbedtls_pk_context product_key;
    mbedtls_pk_init(&product_key);

    mbedtls_pk_setup(&product_key, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
    mbedtls_rsa_gen_key(mbedtls_pk_rsa(product_key), mbedtls_ctr_drbg_random, &ctr_drbg, 2048, 65537);

    mbedtls_pk_write_key_pem(&product_key, priv_pem, 1800);
    size_t pem_len = strlen((char *)priv_pem);

    unsigned char iv[12];
    unsigned char tag[16];
    mbedtls_ctr_drbg_random(&ctr_drbg, iv, sizeof(iv));

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, SIGNET_MASTER_KEK, 256);

    mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, pem_len, iv, sizeof(iv), NULL, 0, priv_pem, ciphertext, sizeof(tag), tag);
    mbedtls_gcm_free(&gcm);

    memset(priv_pem, 0, 1800);
    mbedtls_pk_free(&product_key);

    size_t wrapped_total_len = 12 + pem_len + 16;
    unsigned char *wrapped_buffer = (unsigned char *)malloc(wrapped_total_len);
    memcpy(wrapped_buffer, iv, 12);
    memcpy(wrapped_buffer + 12, ciphertext, pem_len);
    memcpy(wrapped_buffer + 12 + pem_len, tag, 16);

    size_t b64_len = 0;
    mbedtls_base64_encode(base64_out, 3000, &b64_len, wrapped_buffer, wrapped_total_len);
    String wrappedBase64 = String((char *)base64_out);

    free(wrapped_buffer);
    free(priv_pem);
    free(ciphertext);
    free(base64_out);

    JsonDocument responseDoc;
    responseDoc["status"] = "success";
    responseDoc["cmd"] = "GEN_KEY";
    responseDoc["data"]["wrapped_private_key"] = wrappedBase64;
    responseDoc["data"]["certificate"] = "-----BEGIN CERTIFICATE-----\nHSM_GENERATED_CERT\n-----END CERTIFICATE-----";

    String jsonOutput;
    serializeJson(responseDoc, jsonOutput);
    return jsonOutput;
}

String handleSignData(String wrappedKeyB64, String payload)
{
    unsigned char *wrapped_buffer = (unsigned char *)malloc(2500);
    unsigned char *ciphertext = (unsigned char *)malloc(2000);
    unsigned char *plaintext_pem = (unsigned char *)malloc(2000);

    if (!wrapped_buffer || !ciphertext || !plaintext_pem)
    {
        if (wrapped_buffer)
            free(wrapped_buffer);
        if (ciphertext)
            free(ciphertext);
        if (plaintext_pem)
            free(plaintext_pem);
        return "{\"status\":\"error\",\"message\":\"Out of memory\"}";
    }

    memset(wrapped_buffer, 0, 2500);
    memset(ciphertext, 0, 2000);
    memset(plaintext_pem, 0, 2000);

    size_t total_len = 0;
    mbedtls_base64_decode(wrapped_buffer, 2500, &total_len, (const unsigned char *)wrappedKeyB64.c_str(), wrappedKeyB64.length());

    if (total_len <= (12 + 16))
    {
        free(wrapped_buffer);
        free(ciphertext);
        free(plaintext_pem);
        return "{\"status\":\"error\",\"message\":\"Invalid wrapped key length\"}";
    }

    size_t ciphertext_len = total_len - 12 - 16;
    unsigned char iv[12];
    unsigned char tag[16];

    memcpy(iv, wrapped_buffer, 12);
    memcpy(ciphertext, wrapped_buffer + 12, ciphertext_len);
    memcpy(tag, wrapped_buffer + 12 + ciphertext_len, 16);

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, SIGNET_MASTER_KEK, 256);

    int ret = mbedtls_gcm_auth_decrypt(&gcm, ciphertext_len, iv, sizeof(iv), NULL, 0, tag, sizeof(tag), ciphertext, plaintext_pem);
    mbedtls_gcm_free(&gcm);

    if (ret != 0)
    {
        free(wrapped_buffer);
        free(ciphertext);
        free(plaintext_pem);
        return "{\"status\":\"error\",\"message\":\"GCM AUTH FAILED: Key tampered!\"}";
    }

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    mbedtls_pk_parse_key(&pk, plaintext_pem, ciphertext_len + 1, NULL, 0);

    unsigned char hash[32];
    mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), (const unsigned char *)payload.c_str(), payload.length(), hash);

    unsigned char sig[256];
    size_t sig_len;
    mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256, hash, 0, sig, &sig_len, mbedtls_ctr_drbg_random, &ctr_drbg);

    memset(plaintext_pem, 0, 2000);
    mbedtls_pk_free(&pk);

    unsigned char *sig_b64_out = (unsigned char *)malloc(512);
    size_t sig_b64_len = 0;
    memset(sig_b64_out, 0, 512);
    mbedtls_base64_encode(sig_b64_out, 512, &sig_b64_len, sig, sig_len);
    String sigBase64 = String((char *)sig_b64_out);

    free(wrapped_buffer);
    free(ciphertext);
    free(plaintext_pem);
    free(sig_b64_out);

    JsonDocument responseDoc;
    responseDoc["status"] = "success";
    responseDoc["cmd"] = "SIGN_DATA";
    responseDoc["data"]["signature"] = sigBase64;

    String jsonOutput;
    serializeJson(responseDoc, jsonOutput);
    return jsonOutput;
}

void setup()
{
#if defined(ARDUINO_USB_CDC_ON_BOOT) && ARDUINO_USB_CDC_ON_BOOT == 1
    Serial.setTxTimeoutMs(0);
#endif

    Serial.setRxBufferSize(4096);
    Serial.setTxBufferSize(4096);
    Serial.setTimeout(100);
    Serial.begin(2000000);

    hsm_led.begin();
    hsm_led.setBrightness(50);
    setLedColor(255, 165, 0);

    WiFi.mode(WIFI_OFF);
    btStop();

    setup_rng();

    setLedColor(0, 255, 0);
    Serial.println("{\"status\":\"ready\",\"message\":\"SIGNET HSM v1.0 ONLINE (AIR-GAPPED)\"}");
}

void loop()
{
    if (Serial.available())
    {
        setLedColor(0, 0, 255);

        String incomingPayload = Serial.readStringUntil('\n');

        if (incomingPayload.length() <= 2)
        {
            setLedColor(255, 165, 0);
            return;
        }

        JsonDocument doc;
        DeserializationError error = deserializeJson(doc, incomingPayload);

        if (error)
        {
            setLedColor(255, 0, 0);
            Serial.print("{\"status\":\"error\",\"message\":\"Invalid JSON: ");
            Serial.print(error.f_str());
            Serial.println("\"}");
            delay(1000);
            setLedColor(0, 255, 0);
            return;
        }

        String cmd = doc["cmd"] | "unknown";

        if (cmd == "GEN_KEY")
        {
            String productName = doc["data"]["product_name"] | "Signet App";
            Serial.println(handleGenerateKey(productName));
        }
        else if (cmd == "SIGN_DATA")
        {
            String wrappedKey = doc["data"]["wrapped_private_key"] | "";
            String payload = doc["data"]["payload"] | "";

            if (wrappedKey == "" || payload == "")
            {
                setLedColor(255, 0, 0);
                Serial.println("{\"status\":\"error\",\"message\":\"Missing wrapped_key or payload\"}");
            }
            else
            {
                String result = handleSignData(wrappedKey, payload);
                if (result.indexOf("GCM AUTH FAILED") != -1)
                {
                    setLedColor(255, 0, 0);
                    delay(2000);
                }
                Serial.println(result);
            }
        }
        else
        {
            Serial.println("{\"status\":\"error\",\"message\":\"Unknown command\"}");
        }

        delay(50);
        setLedColor(0, 255, 0);
    }
}