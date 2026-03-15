#include <Arduino.h>
#include <ArduinoJson.h>
#include <base64.h>
#include <WiFi.h>

#include "keys.h"

#include "mbedtls/pk.h"
#include "mbedtls/error.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/md.h"

#define LED_PIN 2

String signPayload(String dataToSign)
{
    mbedtls_pk_context pk;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_pk_init(&pk);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    String resultSignature = "";

    const char *pers = "signet_hsm_drbg";
    if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers)) != 0)
    {
        return "ERROR_RNG_INIT";
    }

    int ret = mbedtls_pk_parse_key(&pk, (const unsigned char *)SIGNET_PRIVATE_KEY, strlen(SIGNET_PRIVATE_KEY) + 1, NULL, 0);
    if (ret != 0)
    {
        return "ERROR_PARSE_KEY";
    }

    unsigned char hash[32];
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
    mbedtls_md_starts(&ctx);
    mbedtls_md_update(&ctx, (const unsigned char *)dataToSign.c_str(), dataToSign.length());
    mbedtls_md_finish(&ctx, hash);
    mbedtls_md_free(&ctx);

    unsigned char sig[MBEDTLS_MPI_MAX_SIZE];
    size_t sig_len = 0;
    ret = mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256, hash, sizeof(hash), sig, &sig_len, mbedtls_ctr_drbg_random, &ctr_drbg);

    if (ret == 0)
    {
        resultSignature = base64::encode(sig, sig_len);
    }
    else
    {
        resultSignature = "ERROR_SIGNING_PROCESS";
    }

    mbedtls_pk_free(&pk);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);

    return resultSignature;
}

void setup()
{
    Serial.begin(115200);
    pinMode(LED_PIN, OUTPUT);
    digitalWrite(LED_PIN, LOW);
    WiFi.mode(WIFI_OFF);
    btStop();
    delay(1000);
    Serial.println("{\"status\":\"ready\",\"message\":\"SIGNET_HSM_BOOT_COMPLETE\"}");
}

void loop()
{
    if (Serial.available())
    {
        String incomingPayload = Serial.readStringUntil('\n');

        JsonDocument doc;
        DeserializationError error = deserializeJson(doc, incomingPayload);

        if (error)
        {
            Serial.print("{\"status\":\"error\",\"message\":\"Invalid JSON Format: ");
            Serial.print(error.c_str());
            Serial.println("\"}");
            return;
        }

        String action = doc["action"] | "unknown";
        digitalWrite(LED_PIN, HIGH);

        if (action == "ping")
        {
            Serial.println("{\"status\":\"ok\",\"message\":\"HSM is alive and secure\"}");
        }
        else if (action == "sign_license")
        {
            String dataToSign = doc["data"] | "";

            String signatureBase64 = signPayload(dataToSign);

            if (signatureBase64.startsWith("ERROR"))
            {
                Serial.print("{\"status\":\"error\",\"message\":\"");
                Serial.print(signatureBase64);
                Serial.println("\"}");
            }
            else
            {
                Serial.print("{\"status\":\"success\",\"signature\":\"");
                Serial.print(signatureBase64);
                Serial.println("\"}");
            }
        }
        else
        {
            Serial.println("{\"status\":\"error\",\"message\":\"Unknown action requested\"}");
        }

        delay(100);
        digitalWrite(LED_PIN, LOW);
    }
}