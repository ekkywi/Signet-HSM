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
#include "mbedtls/x509_crt.h"
#include "mbedtls/x509_csr.h"

#define LED_PIN 2

int init_rng(mbedtls_ctr_drbg_context *ctr_drbg, mbedtls_entropy_context *entropy)
{
    mbedtls_ctr_drbg_init(ctr_drbg);
    mbedtls_entropy_init(entropy);
    const char *pers = "signet_hsm_root_ca";
    return mbedtls_ctr_drbg_seed(ctr_drbg, mbedtls_entropy_func, entropy, (const unsigned char *)pers, strlen(pers));
}

String generateIdentity(String productName)
{
    mbedtls_pk_context product_key;
    mbedtls_pk_context master_key;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    mbedtls_x509write_cert crt;
    mbedtls_mpi serial;

    unsigned char *priv_pem_buf = (unsigned char *)malloc(2000);
    unsigned char *cert_pem_buf = (unsigned char *)malloc(2500);

    if (!priv_pem_buf || !cert_pem_buf)
    {
        if (priv_pem_buf)
            free(priv_pem_buf);
        if (cert_pem_buf)
            free(cert_pem_buf);
        return "ERROR_OUT_OF_MEMORY";
    }

    memset(priv_pem_buf, 0, 2000);
    memset(cert_pem_buf, 0, 2500);

    mbedtls_pk_init(&product_key);
    mbedtls_pk_init(&master_key);
    mbedtls_x509write_crt_init(&crt);
    mbedtls_mpi_init(&serial);

    if (init_rng(&ctr_drbg, &entropy) != 0)
    {
        free(priv_pem_buf);
        free(cert_pem_buf);
        return "ERROR_RNG_INIT";
    }

    if (mbedtls_pk_parse_key(&master_key, (const unsigned char *)SIGNET_PRIVATE_KEY, strlen(SIGNET_PRIVATE_KEY) + 1, NULL, 0) != 0)
    {
        free(priv_pem_buf);
        free(cert_pem_buf);
        return "ERROR_PARSE_MASTER_KEY";
    }

    mbedtls_pk_setup(&product_key, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
    if (mbedtls_rsa_gen_key(mbedtls_pk_rsa(product_key), mbedtls_ctr_drbg_random, &ctr_drbg, 2048, 65537) != 0)
    {
        free(priv_pem_buf);
        free(cert_pem_buf);
        return "ERROR_KEY_GENERATION";
    }

    mbedtls_x509write_crt_set_version(&crt, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);

    mbedtls_x509write_crt_set_subject_key(&crt, &product_key);
    mbedtls_x509write_crt_set_issuer_key(&crt, &master_key);

    String subjectName = "CN=" + productName;
    mbedtls_x509write_crt_set_subject_name(&crt, subjectName.c_str());
    mbedtls_x509write_crt_set_issuer_name(&crt, "CN=Signet Hardware Root CA,O=Trezanix,C=ID");

    mbedtls_x509write_crt_set_validity(&crt, "20240101000000", "20340101000000");
    mbedtls_x509write_crt_set_basic_constraints(&crt, 0, -1);

    mbedtls_mpi_read_string(&serial, 10, "1");
    mbedtls_x509write_crt_set_serial(&crt, &serial);

    if (mbedtls_pk_write_key_pem(&product_key, priv_pem_buf, 2000) != 0)
    {
        free(priv_pem_buf);
        free(cert_pem_buf);
        return "ERROR_PRIV_KEY_WRITE";
    }

    if (mbedtls_x509write_crt_pem(&crt, cert_pem_buf, 2500, mbedtls_ctr_drbg_random, &ctr_drbg) != 0)
    {
        free(priv_pem_buf);
        free(cert_pem_buf);
        return "ERROR_CERT_CREATION";
    }

    JsonDocument responseDoc;
    responseDoc["status"] = "success";

    JsonObject data = responseDoc["data"].to<JsonObject>();
    data["raw_private_key"] = String((char *)priv_pem_buf);
    data["certificate"] = String((char *)cert_pem_buf);

    String jsonOutput;
    serializeJson(responseDoc, jsonOutput);

    mbedtls_pk_free(&product_key);
    mbedtls_pk_free(&master_key);
    mbedtls_x509write_crt_free(&crt);
    mbedtls_mpi_free(&serial);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    free(priv_pem_buf);
    free(cert_pem_buf);

    return jsonOutput;
}

void setup()
{
    Serial.setTxBufferSize(4096);
    Serial.begin(115200);
    pinMode(LED_PIN, OUTPUT);
    digitalWrite(LED_PIN, LOW);
    WiFi.mode(WIFI_OFF);
    btStop();
    delay(1000);
    Serial.println("{\"status\":\"ready\",\"message\":\"SIGNET_ROOT_CA_BOOT_COMPLETE\"}");
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
            Serial.print("{\"status\":\"error\",\"message\":\"Invalid JSON Format\"}");
            return;
        }

        String action = doc["action"] | "unknown";
        digitalWrite(LED_PIN, HIGH);

        if (action == "ping")
        {
            Serial.println("{\"status\":\"ok\",\"message\":\"Signet Root CA is secure and operational\"}");
        }
        else if (action == "generate_identity")
        {
            String productName = doc["data"]["product_name"] | "Unknown Product";

            String resultJson = generateIdentity(productName);

            if (resultJson.startsWith("ERROR"))
            {
                Serial.print("{\"status\":\"error\",\"message\":\"");
                Serial.print(resultJson);
                Serial.println("\"}");
            }
            else
            {
                Serial.println(resultJson);
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