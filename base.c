#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

// Função para criptografar usando cifra de César
void cifraDeCesar(char *senha, char *criptografada, int deslocamento) {
    int i = 0;
    while (senha[i] != '\0') {
        criptografada[i] = senha[i] + deslocamento;
        i++;
    }
    criptografada[i] = '\0'; // Final da string
}

int main() {
    // 1. Lista de caracteres possíveis
    char caracteres[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?";
    int tamanho;
    char nome[100];  // Nome do serviço

    // 2. Entrada do usuário
    printf("Digite o nome do site ou servico (ex: Instagram): ");
    scanf(" %[^\n]", nome);

    printf("Digite o tamanho da senha que deseja gerar: ");
    scanf("%d", &tamanho);

    // 3. Verificação de tamanho
    if (tamanho <= 0 || tamanho > 100) {
        printf("Tamanho invalido. Escolha um numero entre 1 e 100.\n");
        return 1;
    }

    // 4. Gerar senha
    char senha[101];
    int totalCaracteres = strlen(caracteres);
    srand(time(NULL));

    for (int i = 0; i < tamanho; i++) {
        int indice = rand() % totalCaracteres;
        senha[i] = caracteres[indice];
    }
    senha[tamanho] = '\0';

    // 5. Criptografar a senha
    char senhaCriptografada[101];
    int deslocamento = 3; // Exemplo: cifra de César com +3
    cifraDeCesar(senha, senhaCriptografada, deslocamento);

    // 6. Mostrar na tela
    printf("\nSenha gerada: %s\n", senha);
    printf("Senha criptografada: %s\n", senhaCriptografada);

    // 7. Salvar no arquivo
    FILE *arquivo = fopen("senhas.txt", "a");
    if (arquivo == NULL) {
        printf("Erro ao abrir o arquivo!\n");
        return 1;
    }

    fprintf(arquivo, "Site/Serviço: %s\n", nome);
    fprintf(arquivo, "Senha original     : %s\n", senha);
    fprintf(arquivo, "Senha criptografada: %s\n", senhaCriptografada);
    fprintf(arquivo, "------------------------------\n");

    fclose(arquivo);

    printf("\nSenha salva com sucesso no arquivo 'senhas.txt'!\n");

    return 0;
}

// credits: https://github.com/BrunoZanquetta/gerador-de-senhas-c
