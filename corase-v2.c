/*
 * Gerador de senhas com criptografia AES-256-GCM
 *
 * Compilar (Linux/macOS):
 *   gcc gerador_senhas.c -o gerador_senhas -lcrypto
 *
 * Compilar (Windows com MSYS2/MinGW):
 *   gcc gerador_senhas.c -o gerador_senhas.exe -lcrypto
 *
 * Dependencia: OpenSSL (Ubuntu/Debian: sudo apt install libssl-dev
 *                       macOS: brew install openssl)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#ifdef _WIN32
  #include <conio.h>
#else
  #include <termios.h>
  #include <unistd.h>
  #include <sys/stat.h>
#endif

#define ARQUIVO        "senhas.dat"
#define MAX_SENHA      100
#define MIN_SENHA      4        /* precisa caber 1 de cada categoria */
#define MIN_QTD        3
#define MAX_QTD        10
#define TAM_NOME       100
#define TAM_SALT       16
#define TAM_IV         12
#define TAM_TAG        16
#define TAM_CHAVE      32       /* AES-256 */
#define ITERACOES_KDF  200000
#define TAM_HEX_MAX    ((TAM_SALT + TAM_IV + TAM_TAG + MAX_SENHA) * 2 + 1)

static const char MINUSCULAS[] = "abcdefghijklmnopqrstuvwxyz";
static const char MAIUSCULAS[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
static const char NUMEROS[]    = "0123456789";
static const char SIMBOLOS[]   = "!@#$%^&*()_+-=[]{}|;:,.<>?";

/* ------------------------------------------------------------------ */
/* Utilitarios de entrada                                              */
/* ------------------------------------------------------------------ */

static void limparNovaLinha(char *s) {
    s[strcspn(s, "\r\n")] = '\0';
}

static int lerInteiro(const char *msg, int *valor) {
    char buf[32];
    char *fim;
    printf("%s", msg);
    if (fgets(buf, sizeof buf, stdin) == NULL) return 0;
    long v = strtol(buf, &fim, 10);
    if (fim == buf) return 0;
    *valor = (int)v;
    return 1;
}

static int lerTexto(const char *msg, char *dest, size_t tam) {
    printf("%s", msg);
    if (fgets(dest, (int)tam, stdin) == NULL) return 0;
    limparNovaLinha(dest);
    return dest[0] != '\0';
}

/* Le a senha mestra sem mostrar o que e digitado */
static int lerSenhaOculta(const char *msg, char *dest, size_t tam) {
    printf("%s", msg);
    fflush(stdout);
#ifdef _WIN32
    size_t i = 0;
    int c;
    while ((c = _getch()) != '\r' && c != '\n' && c != EOF) {
        if (c == '\b') { if (i > 0) i--; }
        else if (i < tam - 1) dest[i++] = (char)c;
    }
    dest[i] = '\0';
    printf("\n");
#else
    struct termios antigo, novo;
    int tem_tty = isatty(STDIN_FILENO);
    if (tem_tty) {
        tcgetattr(STDIN_FILENO, &antigo);
        novo = antigo;
        novo.c_lflag &= ~(tcflag_t)ECHO;
        tcsetattr(STDIN_FILENO, TCSANOW, &novo);
    }
    char *r = fgets(dest, (int)tam, stdin);
    if (tem_tty) {
        tcsetattr(STDIN_FILENO, TCSANOW, &antigo);
        printf("\n");
    }
    if (r == NULL) return 0;
    limparNovaLinha(dest);
#endif
    return dest[0] != '\0';
}

/* Apaga dados sensiveis da memoria sem que o compilador otimize a chamada */
static void apagarMemoria(void *p, size_t n) {
    OPENSSL_cleanse(p, n);
}

/* ------------------------------------------------------------------ */
/* Aleatoriedade segura                                                */
/* ------------------------------------------------------------------ */

/* Retorna um numero uniforme em [0, n) sem vies de modulo */
static uint32_t aleatorioAte(uint32_t n) {
    uint32_t r;
    uint32_t limite = UINT32_MAX - (UINT32_MAX % n);
    do {
        if (RAND_bytes((unsigned char *)&r, sizeof r) != 1) {
            fprintf(stderr, "Falha no gerador aleatorio seguro.\n");
            exit(1);
        }
    } while (r >= limite);
    return r % n;
}

static char sortearDe(const char *conjunto) {
    return conjunto[aleatorioAte((uint32_t)strlen(conjunto))];
}

/*
 * Gera uma senha com pelo menos 1 minuscula, 1 maiuscula, 1 numero e 1 simbolo.
 * Depois embaralha com Fisher-Yates para a posicao ser imprevisivel.
 */
static void gerarSenha(char *senha, int tamanho) {
    char todos[sizeof MINUSCULAS + sizeof MAIUSCULAS + sizeof NUMEROS + sizeof SIMBOLOS];
    snprintf(todos, sizeof todos, "%s%s%s%s", MINUSCULAS, MAIUSCULAS, NUMEROS, SIMBOLOS);

    senha[0] = sortearDe(MINUSCULAS);
    senha[1] = sortearDe(MAIUSCULAS);
    senha[2] = sortearDe(NUMEROS);
    senha[3] = sortearDe(SIMBOLOS);
    for (int i = 4; i < tamanho; i++) senha[i] = sortearDe(todos);

    for (int i = tamanho - 1; i > 0; i--) {
        int j = (int)aleatorioAte((uint32_t)(i + 1));
        char t = senha[i]; senha[i] = senha[j]; senha[j] = t;
    }
    senha[tamanho] = '\0';
}

/* ------------------------------------------------------------------ */
/* Hex                                                                 */
/* ------------------------------------------------------------------ */

static void paraHex(const unsigned char *in, size_t n, char *out) {
    static const char H[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[i * 2]     = H[in[i] >> 4];
        out[i * 2 + 1] = H[in[i] & 0x0F];
    }
    out[n * 2] = '\0';
}

static int valorHex(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Retorna o numero de bytes escritos, ou -1 se invalido */
static int deHex(const char *hex, unsigned char *out, size_t max) {
    size_t len = strlen(hex);
    if (len % 2 != 0 || len / 2 > max) return -1;
    for (size_t i = 0; i < len / 2; i++) {
        int a = valorHex(hex[i * 2]), b = valorHex(hex[i * 2 + 1]);
        if (a < 0 || b < 0) return -1;
        out[i] = (unsigned char)((a << 4) | b);
    }
    return (int)(len / 2);
}

/* ------------------------------------------------------------------ */
/* AES-256-GCM                                                         */
/* ------------------------------------------------------------------ */

static int derivarChave(const char *mestra, const unsigned char *salt, unsigned char *chave) {
    return PKCS5_PBKDF2_HMAC(mestra, (int)strlen(mestra), salt, TAM_SALT,
                             ITERACOES_KDF, EVP_sha256(), TAM_CHAVE, chave) == 1;
}

/*
 * Criptografa a senha. Saida em hex no formato: salt | iv | tag | texto cifrado.
 * Cada senha usa salt e IV novos (nunca reutilize IV com a mesma chave no GCM).
 */
static int criptografar(const char *senha, const char *mestra, char *saida_hex) {
    unsigned char salt[TAM_SALT], iv[TAM_IV], tag[TAM_TAG], chave[TAM_CHAVE];
    unsigned char cifra[MAX_SENHA + 16];
    unsigned char pacote[TAM_SALT + TAM_IV + TAM_TAG + MAX_SENHA + 16];
    int len = 0, total = 0, ok = 0;

    if (RAND_bytes(salt, sizeof salt) != 1 || RAND_bytes(iv, sizeof iv) != 1) return 0;
    if (!derivarChave(mestra, salt, chave)) return 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) goto fim;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto fim;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, TAM_IV, NULL) != 1) goto fim;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, chave, iv) != 1) goto fim;
    if (EVP_EncryptUpdate(ctx, cifra, &len, (const unsigned char *)senha, (int)strlen(senha)) != 1) goto fim;
    total = len;
    if (EVP_EncryptFinal_ex(ctx, cifra + total, &len) != 1) goto fim;
    total += len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAM_TAG, tag) != 1) goto fim;

    memcpy(pacote, salt, TAM_SALT);
    memcpy(pacote + TAM_SALT, iv, TAM_IV);
    memcpy(pacote + TAM_SALT + TAM_IV, tag, TAM_TAG);
    memcpy(pacote + TAM_SALT + TAM_IV + TAM_TAG, cifra, (size_t)total);
    paraHex(pacote, (size_t)(TAM_SALT + TAM_IV + TAM_TAG + total), saida_hex);
    ok = 1;

fim:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    apagarMemoria(chave, sizeof chave);
    return ok;
}

/* Retorna 1 se descriptografou; 0 se senha mestra errada ou dado corrompido */
static int descriptografar(const char *hex, const char *mestra, char *senha_out) {
    unsigned char pacote[TAM_SALT + TAM_IV + TAM_TAG + MAX_SENHA + 16];
    unsigned char chave[TAM_CHAVE], plano[MAX_SENHA + 16];
    int len = 0, total = 0, ok = 0;

    int n = deHex(hex, pacote, sizeof pacote);
    if (n < TAM_SALT + TAM_IV + TAM_TAG) return 0;

    const unsigned char *salt = pacote;
    const unsigned char *iv   = pacote + TAM_SALT;
    unsigned char tag[TAM_TAG];
    memcpy(tag, pacote + TAM_SALT + TAM_IV, TAM_TAG);
    const unsigned char *cifra = pacote + TAM_SALT + TAM_IV + TAM_TAG;
    int tam_cifra = n - TAM_SALT - TAM_IV - TAM_TAG;
    if (tam_cifra > MAX_SENHA) return 0;

    if (!derivarChave(mestra, salt, chave)) return 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) goto fim;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto fim;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, TAM_IV, NULL) != 1) goto fim;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, chave, iv) != 1) goto fim;
    if (EVP_DecryptUpdate(ctx, plano, &len, cifra, tam_cifra) != 1) goto fim;
    total = len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAM_TAG, tag) != 1) goto fim;
    /* Final falha se a tag nao bater (senha mestra errada ou arquivo adulterado) */
    if (EVP_DecryptFinal_ex(ctx, plano + total, &len) != 1) goto fim;
    total += len;

    memcpy(senha_out, plano, (size_t)total);
    senha_out[total] = '\0';
    ok = 1;

fim:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    apagarMemoria(chave, sizeof chave);
    apagarMemoria(plano, sizeof plano);
    return ok;
}

/* ------------------------------------------------------------------ */
/* Arquivo                                                             */
/* ------------------------------------------------------------------ */

static void salvarRegistro(FILE *f, const char *servico, const char *hex) {
    /* '|' separa os campos, entao nao pode aparecer no nome */
    char nome[TAM_NOME];
    snprintf(nome, sizeof nome, "%s", servico);
    for (char *p = nome; *p; p++) if (*p == '|') *p = '-';
    fprintf(f, "%s|%s\n", nome, hex);
}

static FILE *abrirArquivoAppend(void) {
#ifndef _WIN32
    mode_t antigo = umask(077);          /* arquivo criado so com permissao do dono */
    FILE *f = fopen(ARQUIVO, "a");
    umask(antigo);
    return f;
#else
    return fopen(ARQUIVO, "a");
#endif
}

/* ------------------------------------------------------------------ */
/* Funcionalidades do menu                                             */
/* ------------------------------------------------------------------ */

/* Gera de 3 a 10 senhas diferentes, criptografa e salva */
static void gerarVariasSenhas(void) {
    char servico[TAM_NOME], mestra[128], confirma[128];
    int qtd, tamanho;

    if (!lerTexto("Nome do site ou servico: ", servico, sizeof servico)) {
        printf("Nome invalido.\n");
        return;
    }
    if (!lerInteiro("Quantas senhas gerar (3 a 10): ", &qtd) || qtd < MIN_QTD || qtd > MAX_QTD) {
        printf("Quantidade invalida. Escolha de %d a %d.\n", MIN_QTD, MAX_QTD);
        return;
    }
    if (!lerInteiro("Tamanho de cada senha (4 a 100): ", &tamanho) ||
        tamanho < MIN_SENHA || tamanho > MAX_SENHA) {
        printf("Tamanho invalido. Escolha de %d a %d.\n", MIN_SENHA, MAX_SENHA);
        return;
    }

    if (!lerSenhaOculta("Senha mestra (protege o arquivo): ", mestra, sizeof mestra) ||
        !lerSenhaOculta("Confirme a senha mestra: ", confirma, sizeof confirma) ||
        strcmp(mestra, confirma) != 0) {
        printf("Senha mestra vazia ou diferente da confirmacao.\n");
        apagarMemoria(mestra, sizeof mestra);
        apagarMemoria(confirma, sizeof confirma);
        return;
    }
    apagarMemoria(confirma, sizeof confirma);

    char senhas[MAX_QTD][MAX_SENHA + 1];
    for (int i = 0; i < qtd; i++) {
        int repetida;
        do {                               /* garante que todas sejam diferentes */
            gerarSenha(senhas[i], tamanho);
            repetida = 0;
            for (int j = 0; j < i; j++)
                if (strcmp(senhas[i], senhas[j]) == 0) { repetida = 1; break; }
        } while (repetida);
    }

    FILE *f = abrirArquivoAppend();
    if (!f) {
        printf("Erro ao abrir o arquivo '%s'.\n", ARQUIVO);
        goto limpar;
    }

    printf("\n--- %d senhas geradas para '%s' ---\n", qtd, servico);
    int salvas = 0;
    for (int i = 0; i < qtd; i++) {
        char hex[TAM_HEX_MAX];
        printf("%2d) %s\n", i + 1, senhas[i]);
        if (criptografar(senhas[i], mestra, hex)) {
            salvarRegistro(f, servico, hex);
            salvas++;
        } else {
            printf("    (falha ao criptografar esta senha)\n");
        }
    }
    fclose(f);
    printf("\n%d senha(s) salva(s) criptografadas em '%s'.\n", salvas, ARQUIVO);
    printf("Anote a que for usar: o arquivo so pode ser lido com a senha mestra.\n");

limpar:
    apagarMemoria(senhas, sizeof senhas);
    apagarMemoria(mestra, sizeof mestra);
}

/* Le o arquivo e descriptografa cada registro com a senha mestra */
static void listarSenhas(void) {
    FILE *f = fopen(ARQUIVO, "r");
    if (!f) {
        printf("Nenhuma senha salva ainda.\n");
        return;
    }

    char mestra[128];
    if (!lerSenhaOculta("Senha mestra: ", mestra, sizeof mestra)) {
        fclose(f);
        return;
    }

    char linha[TAM_NOME + TAM_HEX_MAX + 4];
    int n = 0, falhas = 0;
    printf("\n");
    while (fgets(linha, sizeof linha, f)) {
        limparNovaLinha(linha);
        char *sep = strrchr(linha, '|');
        if (!sep) continue;
        *sep = '\0';

        char senha[MAX_SENHA + 1];
        if (descriptografar(sep + 1, mestra, senha)) {
            printf("%-30s %s\n", linha, senha);
            apagarMemoria(senha, sizeof senha);
            n++;
        } else {
            falhas++;
        }
    }
    fclose(f);
    apagarMemoria(mestra, sizeof mestra);

    if (n == 0 && falhas > 0)
        printf("Nao foi possivel descriptografar: senha mestra incorreta?\n");
    else if (falhas > 0)
        printf("\n%d registro(s) nao puderam ser lidos (outra senha mestra ou dado corrompido).\n", falhas);
    if (n == 0 && falhas == 0)
        printf("Arquivo vazio.\n");
}

int main(void) {
    int opcao;
    for (;;) {
        printf("\n===== Gerador de Senhas (AES-256-GCM) =====\n");
        printf("1) Gerar de 3 a 10 senhas diferentes\n");
        printf("2) Ver senhas salvas (descriptografar)\n");
        printf("0) Sair\n");
        if (!lerInteiro("Opcao: ", &opcao)) {
            printf("Opcao invalida.\n");
            continue;
        }
        switch (opcao) {
            case 1: gerarVariasSenhas(); break;
            case 2: listarSenhas();      break;
            case 0: return 0;
            default: printf("Opcao invalida.\n");
        }
    }
}
