#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <linux/reboot.h>
#include <linux/vm_sockets.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/reboot.h>
#include <sys/socket.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef EH_HAS_TPM2
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tcti_device.h>
#include <tss2/tss2_mu.h>
#endif

#define EH_VSOCK_PORT 5000
#define EH_MAX_FRAME 4096
#define EH_MAX_REQUESTS 32
#define EH_EFFECT_PORT 6000
#define EH_EFFECT_FRAME 65536
#ifndef EH_SCRATCH_DEVICE
#define EH_SCRATCH_DEVICE "/dev/vdb"
#endif

#define EH_TPM_DEVICE "/dev/tpmrm0"
#define EH_TPM_NONCE_SIZE 32
#define EH_TPM_PCR_SELECTION 0, 1, 2, 3, 4, 5, 6, 7

static int make_directory(const char *path, mode_t mode) {
    if (mkdir(path, mode) == 0 || errno == EEXIST) return 0;
    return -1;
}

static int mount_or_present(
    const char *source,
    const char *target,
    const char *filesystem,
    unsigned long flags,
    const void *data
) {
    if (mount(source, target, filesystem, flags, data) == 0 || errno == EBUSY) return 0;
    return -1;
}

static int prepare_pid_one(void) {
    const char *credential_names[] = {
        "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
        "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "GOOGLE_APPLICATION_CREDENTIALS",
        "GITHUB_TOKEN", "CI_JOB_TOKEN", "KUBECONFIG",
    };
    size_t index;
    if (getpid() != 1 || geteuid() != 0) return -1;
    if (make_directory("/proc", 0555) != 0 || make_directory("/sys", 0555) != 0
        || make_directory("/dev", 0755) != 0 || make_directory("/scratch", 0700) != 0) return -1;
    if (mount_or_present("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) != 0) return -1;
    if (mount_or_present("sysfs", "/sys", "sysfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) != 0) return -1;
    if (mount_or_present("devtmpfs", "/dev", "devtmpfs", MS_NOSUID, "mode=0755") != 0) return -1;
    if (mount(EH_SCRATCH_DEVICE, "/scratch", "ext4", MS_NOSUID | MS_NODEV | MS_NOATIME, NULL) != 0) return -1;
    for (index = 0; index < sizeof(credential_names) / sizeof(credential_names[0]); index += 1) {
        unsetenv(credential_names[index]);
    }
    setenv("PATH", "/", 1);
    return 0;
}

static int read_exact(int fd, void *buffer, size_t length) {
    size_t offset = 0;
    while (offset < length) {
        ssize_t count = read(fd, (char *)buffer + offset, length - offset);
        if (count == 0) return 0;
        if (count < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        offset += (size_t)count;
    }
    return 1;
}

static int write_exact(int fd, const void *buffer, size_t length) {
    size_t offset = 0;
    while (offset < length) {
        ssize_t count = write(fd, (const char *)buffer + offset, length - offset);
        if (count < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        offset += (size_t)count;
    }
    return 0;
}

static int write_frame(int fd, const char *payload) {
    size_t length = strlen(payload);
    if (length == 0 || length > EH_MAX_FRAME) return -1;
    uint32_t header = htonl((uint32_t)length);
    if (write_exact(fd, &header, sizeof(header)) != 0) return -1;
    return write_exact(fd, payload, length);
}

static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int base64_encode(const unsigned char *in, size_t in_len, char *out, size_t out_size) {
    size_t out_len = 0;
    for (size_t i = 0; i < in_len; i += 3) {
        uint32_t triple = 0;
        int padding = 0;
        triple |= (uint32_t)in[i] << 16;
        if (i + 1 < in_len) triple |= (uint32_t)in[i + 1] << 8;
        else padding = 2;
        if (i + 2 < in_len) triple |= (uint32_t)in[i + 2];
        else if (padding == 0) padding = 1;

        if (out_len + 4 > out_size) return -1;
        out[out_len++] = b64_table[(triple >> 18) & 0x3F];
        out[out_len++] = b64_table[(triple >> 12) & 0x3F];
        out[out_len++] = (padding >= 2) ? '=' : b64_table[(triple >> 6) & 0x3F];
        out[out_len++] = (padding >= 1) ? '=' : b64_table[triple & 0x3F];
    }
    if (out_len >= out_size) return -1;
    out[out_len] = '\0';
    return (int)out_len;
}

static int authority_file_count(void) {
    const char *paths[] = {
        "/root/.ssh/id_rsa",
        "/root/.aws/credentials",
        "/var/run/secrets/kubernetes.io/serviceaccount/token",
        "/run/secrets",
        "/sys/hypervisor/metadata",
    };
    int count = 0;
    size_t index;
    for (index = 0; index < sizeof(paths) / sizeof(paths[0]); index += 1) {
        if (access(paths[index], F_OK) == 0) count += 1;
    }
    return count;
}

static int authority_environment_count(void) {
    const char *names[] = {
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AZURE_CLIENT_SECRET",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "GITHUB_TOKEN",
        "KUBECONFIG",
    };
    int count = 0;
    size_t index;
    for (index = 0; index < sizeof(names) / sizeof(names[0]); index += 1) {
        const char *value = getenv(names[index]);
        if (value != NULL && value[0] != '\0') count += 1;
    }
    return count;
}

#ifdef EH_HAS_TPM2
static int tpm_generate_quote(const char *nonce_hex, char **quote_out, char **sig_out) {
    TSS2_TCTI_CONTEXT *tcti = NULL;
    ESYS_CONTEXT *ctx = NULL;
    TSS2_RC rc;
    TPMT_SIGNATURE *signature = NULL;
    TPML_DIGEST *pcr_digest = NULL;
    TPML_DIGEST_VALUES *digest_values = NULL;
    TPM2B_ATTEST *attest = NULL;
    TPM2B_DIGEST qualifying_data = {0};
    TPML_PCR_SELECTION pcr_select = {0};
    ESYS_TR sign_handle = ESYS_TR_RH_OWNER;
    TSS2L_SYS_AUTH_COMMAND sessions = {0};
    TSS2L_SYS_AUTH_RESPONSE *response_sessions = NULL;
    char *quote_b64 = NULL;
    char *sig_b64 = NULL;
    size_t quote_len = 0;
    size_t sig_len = 0;

    // Parse nonce from hex
    size_t nonce_len = strlen(nonce_hex) / 2;
    if (nonce_len != EH_TPM_NONCE_SIZE) {
        return -1;
    }
    for (size_t i = 0; i < nonce_len; i++) {
        sscanf(nonce_hex + 2*i, "%2hhx", &qualifying_data.buffer[i]);
    }
    qualifying_data.size = nonce_len;

    // Configure PCR selection (PCRs 0-7)
    pcr_select.count = 1;
    pcr_select.pcrSelections[0].hash = TPM2_ALG_SHA256;
    pcr_select.pcrSelections[0].sizeofSelect = 3;
    pcr_select.pcrSelections[0].pcrSelect[0] = 0xFF; // PCRs 0-7
    pcr_select.pcrSelections[0].pcrSelect[1] = 0x00;
    pcr_select.pcrSelections[0].pcrSelect[2] = 0x00;

    // Initialize TCTI
    rc = Tss2_TctiLdr_Initialize(EH_TPM_DEVICE, &tcti);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "TPM TCTI init failed: 0x%x\n", rc);
        return -1;
    }

    // Initialize ESYS context
    rc = Esys_Initialize(&ctx, tcti, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "TPM ESYS init failed: 0x%x\n", rc);
        Tss2_TctiLdr_Finalize(tcti);
        return -1;
    }

    // Set authorization for owner hierarchy (no password)
    sessions.count = 1;
    sessions.auths[0].sessionHandle = TPM2_RS_PW;
    sessions.auths[0].nonce.size = 0;
    sessions.auths[0].hmac.size = 0;
    sessions.auths[0].sessionAttributes = 0;

    // Generate quote
    rc = Esys_Quote(
        ctx,
        sign_handle,
        &sessions,
        &qualifying_data,
        &pcr_select,
        &attest,
        &signature,
        NULL,
        NULL
    );

    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "TPM Quote failed: 0x%x\n", rc);
        if (attest) Esys_Free(attest);
        if (signature) Esys_Free(signature);
        Esys_Finalize(&ctx);
        Tss2_TctiLdr_Finalize(tcti);
        return -1;
    }

    // Encode attest to CBOR/JSON
    // Base64 encode the raw attest structure
    quote_len = attest->size;
    quote_b64 = malloc(quote_len * 2);
    if (!quote_b64) {
        Esys_Free(attest);
        Esys_Free(signature);
        Esys_Finalize(&ctx);
        Tss2_TctiLdr_Finalize(tcti);
        return -1;
    }
    if (base64_encode((const unsigned char *)attest->attestationData, attest->size, quote_b64, quote_len * 2) < 0) {
        free(quote_b64);
        Esys_Free(attest);
        Esys_Free(signature);
        Esys_Finalize(&ctx);
        Tss2_TctiLdr_Finalize(tcti);
        return -1;
    }

    // Encode signature
    if (signature->sigAlg == TPM2_ALG_RSAPSS) {
        sig_len = signature->signature.rsapss.sig.size;
        sig_b64 = malloc(sig_len * 2);
        if (!sig_b64) {
            free(quote_b64);
            Esys_Free(attest);
            Esys_Free(signature);
            Esys_Finalize(&ctx);
            Tss2_TctiLdr_Finalize(tcti);
            return -1;
        }
        if (base64_encode((const unsigned char *)signature->signature.rsapss.sig.buffer, signature->signature.rsapss.sig.size, sig_b64, sig_len * 2) < 0) {
            free(quote_b64);
            free(sig_b64);
            Esys_Free(attest);
            Esys_Free(signature);
            Esys_Finalize(&ctx);
            Tss2_TctiLdr_Finalize(tcti);
            return -1;
        }
    } else if (signature->sigAlg == TPM2_ALG_ECDSA) {
        sig_len = signature->signature.ecdsa.signatureR.size + signature->signature.ecdsa.signatureS.size;
        sig_b64 = malloc(sig_len * 2);
        if (!sig_b64) {
            free(quote_b64);
            Esys_Free(attest);
            Esys_Free(signature);
            Esys_Finalize(&ctx);
            Tss2_TctiLdr_Finalize(tcti);
            return -1;
        }
        // Concatenate R and S
        unsigned char *sig_concat = malloc(sig_len);
        if (!sig_concat) {
            free(quote_b64);
            free(sig_b64);
            Esys_Free(attest);
            Esys_Free(signature);
            Esys_Finalize(&ctx);
            Tss2_TctiLdr_Finalize(tcti);
            return -1;
        }
        memcpy(sig_concat, signature->signature.ecdsa.signatureR.buffer, signature->signature.ecdsa.signatureR.size);
        memcpy(sig_concat + signature->signature.ecdsa.signatureR.size, signature->signature.ecdsa.signatureS.buffer, signature->signature.ecdsa.signatureS.size);
        if (base64_encode(sig_concat, sig_len, sig_b64, sig_len * 2) < 0) {
            free(quote_b64);
            free(sig_b64);
            free(sig_concat);
            Esys_Free(attest);
            Esys_Free(signature);
            Esys_Finalize(&ctx);
            Tss2_TctiLdr_Finalize(tcti);
            return -1;
        }
        free(sig_concat);
    } else {
        free(quote_b64);
        Esys_Free(attest);
        Esys_Free(signature);
        Esys_Finalize(&ctx);
        Tss2_TctiLdr_Finalize(tcti);
        return -1;
    }

    *quote_out = quote_b64;
    *sig_out = sig_b64;

    Esys_Free(attest);
    Esys_Free(signature);
    Esys_Finalize(&ctx);
    Tss2_TctiLdr_Finalize(tcti);

    return 0;
}
#else
static int tpm_generate_quote(const char *nonce_hex, char **quote_out, char **sig_out) {
    (void)nonce_hex;
    *quote_out = NULL;
    *sig_out = NULL;
    return -1;
}
#endif

/* Intentionally no guest-local authorization. Guest root can send arbitrary bytes;
 * the host effect service must validate and consume the capability independently. */
static int connect_effect(unsigned int port) {
    int fd = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct timeval timeout = {.tv_sec = 2, .tv_usec = 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    struct sockaddr_vm address;
    memset(&address, 0, sizeof(address));
    address.svm_family = AF_VSOCK;
    address.svm_cid = VMADDR_CID_HOST;
    address.svm_port = port;
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int relay_effect(int client) {
    uint32_t header;
    if (read_exact(client, &header, sizeof(header)) != 1) return -1;
    uint32_t length = ntohl(header);
    if (length == 0 || length > EH_EFFECT_FRAME) return -1;
    char request[EH_EFFECT_FRAME];
    if (read_exact(client, request, length) != 1) return -1;
    int effect = connect_effect(EH_EFFECT_PORT);
    if (effect < 0) return write_frame(client, "{\"error\":\"effect_unavailable\"}");
    int status = -1;
    if (write_exact(effect, &header, sizeof(header)) != 0
        || write_exact(effect, request, length) != 0
        || read_exact(effect, &header, sizeof(header)) != 1) goto done;
    length = ntohl(header);
    if (length == 0 || length > EH_MAX_FRAME - 128) goto done;
    char response[EH_MAX_FRAME];
    if (read_exact(effect, response, length) != 1) goto done;
    response[length] = '\0';
    uint32_t checksum = 2166136261u;
    for (uint32_t index = 0; index < length; index++) {
        checksum = (checksum ^ (unsigned char)response[index]) * 16777619u;
    }
    char summary[EH_MAX_FRAME];
    int count = snprintf(summary, sizeof(summary),
        "{\"bytes\":%u,\"checksum\":%u,\"response\":%s}", length, checksum, response);
    if (count > 0 && (size_t)count < sizeof(summary)) status = write_frame(client, summary);
done:
    close(effect);
    return status;
}

static void handle_client(int client) {
    unsigned int requests = 0;
    struct timeval timeout = {.tv_sec = 5, .tv_usec = 0};
    setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    while (requests < EH_MAX_REQUESTS) {
        uint32_t header;
        int status = read_exact(client, &header, sizeof(header));
        if (status <= 0) return;
        uint32_t length = ntohl(header);
        if (length == 0 || length > EH_MAX_FRAME) return;
        char payload[EH_MAX_FRAME + 1];
        status = read_exact(client, payload, length);
        if (status <= 0) return;
        payload[length] = '\0';
        requests += 1;
        if (strcmp(payload, "{\"type\":\"effect\"}") == 0) {
            if (relay_effect(client) != 0) return;
        } else if (strcmp(payload, "{\"type\":\"scratch_probe\"}") == 0) {
            if (write_frame(client, access("/scratch/prior-session", F_OK) == 0
                ? "{\"prior_state\":true}" : "{\"prior_state\":false}") != 0) return;
        } else if (strcmp(payload, "{\"type\":\"persist\"}") == 0) {
            int marker = open("/scratch/prior-session", O_WRONLY | O_CREAT | O_EXCL, 0600);
            if (marker < 0 || write_exact(marker, "synthetic-state", 15) != 0) return;
            fsync(marker);
            close(marker);
            sync();
            pid_t child = fork();
            if (child < 0) return;
            if (child == 0) {
                close(client);
                signal(SIGTERM, SIG_IGN);
                for (;;) pause();
            }
if (write_frame(client, "{\"attempted\":true}") != 0) return;
        } else if (strcmp(payload, "{\"type\":\"forbidden_port\"}") == 0) {
            int forbidden = connect_effect(EH_EFFECT_PORT + 1);
            if (forbidden >= 0) close(forbidden);
            if (write_frame(client, forbidden >= 0
                ? "{\"connected\":true}" : "{\"connected\":false}") != 0) return;
        } else if (strcmp(payload, "{\042type\042:\042root_probe\042}") == 0) {
            char response[256];
            snprintf(
                response,
                sizeof(response),
                "{\042authority_environment\042:%d,\042authority_files\042:%d,\042package_manager\042:false,\042uid\042:%u}",
                authority_environment_count(),
                authority_file_count(),
                (unsigned int)geteuid()
            );
            if (write_frame(client, response) != 0) return;
        } else if (strncmp(payload, "{\042type\042:\042tpm_attest\042", 20) == 0) {
            // Parse nonce from payload: {"type":"tpm_attest","nonce":"..."}
            char *nonce_start = strstr(payload, "{\042nonce\042:\042");
            if (!nonce_start) {
                if (write_frame(client, "{\042error\042:\042missing_nonce\042,\042ok\042:false}") != 0) return;
            }
            nonce_start += 12; // skip {"nonce":"
            char *nonce_end = strchr(nonce_start, '\042');
            if (!nonce_end) {
                if (write_frame(client, "{\042error\042:\042malformed_nonce\042,\042ok\042:false}") != 0) return;
            }
            size_t nonce_len = nonce_end - nonce_start;
            char nonce[nonce_len + 1];
            memcpy(nonce, nonce_start, nonce_len);
            nonce[nonce_len] = '\0';

#ifdef EH_HAS_TPM2
            char *quote = NULL;
            char *sig = NULL;
            if (tpm_generate_quote(nonce, &quote, &sig) != 0 || !quote || !sig) {
                if (write_frame(client, "{\042error\042:\042tpm_quote_failed\042,\042ok\042:false}") != 0) return;
            }
            char response[EH_MAX_FRAME];
            int count = snprintf(response, sizeof(response),
                "{\042quote\042:\042%s\042,\042signature\042:\042%s\042,\042nonce\042:\042%s\042,\042ok\042:true}",
                quote, sig, nonce);
            free(quote);
            free(sig);
            if (count > 0 && (size_t)count < sizeof(response)) {
                if (write_frame(client, response) != 0) return;
            }
#else
            if (write_frame(client, "{\042error\042:\042tpm_not_available\042,\042ok\042:false}") != 0) return;
#endif
        } else if (strcmp(payload, "{\042type\042:\042shutdown\042}") == 0) {
            if (write_frame(client, "{\042accepted\042:true}") != 0) return;
            shutdown(client, SHUT_WR);
            usleep(100000);
            reboot(LINUX_REBOOT_CMD_RESTART);
            return;
        } else {
            if (write_frame(client, "{\042error\042:\042unknown_message\042,\042ok\042:false}") != 0) return;
        }
    }
}
}

int main(void) {
    if (prepare_pid_one() != 0) return 69;
    int server = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (server < 0) return 70;
    struct sockaddr_vm address;
    memset(&address, 0, sizeof(address));
    address.svm_family = AF_VSOCK;
    address.svm_cid = VMADDR_CID_ANY;
    address.svm_port = EH_VSOCK_PORT;
    if (bind(server, (struct sockaddr *)&address, sizeof(address)) != 0) return 71;
    if (listen(server, 1) != 0) return 72;
    while (1) {
        int client = accept(server, NULL, NULL);
        if (client < 0) {
            if (errno == EINTR) continue;
            return 73;
        }
        handle_client(client);
        close(client);
    }
}
