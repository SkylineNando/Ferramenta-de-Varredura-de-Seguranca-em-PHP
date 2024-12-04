### Ferramenta de Varredura de Segurança em PHP

Este repositório contém um script PHP que realiza uma varredura básica de segurança em um site ou servidor. Ele é útil para identificar vulnerabilidades comuns, como listagem de diretórios, exposição de arquivos sensíveis, configurações inseguras do PHP, e vulnerabilidades de XSS e SQL Injection. Também inclui uma verificação básica para detectar padrões de malware.

---

## **Como Funciona**

O script executa as seguintes verificações:

1. **Listagem de Diretórios**  
   Verifica se a listagem de diretórios está habilitada no servidor, o que pode expor informações sensíveis.

2. **Arquivos Sensíveis**  
   Procura por arquivos comumente expostos que podem conter informações críticas, como `.env`, `config.php`, e backups de banco de dados.

3. **Configurações Inseguras do PHP**  
   Verifica configurações críticas do PHP que podem comprometer a segurança, como `allow_url_include` e `display_errors`.

4. **Teste de XSS (Cross-Site Scripting)**  
   Simula um ataque de XSS básico para identificar páginas que podem estar vulneráveis.

5. **Teste de SQL Injection**  
   Executa consultas simuladas com payloads comuns para identificar falhas de SQL Injection.

6. **Scanner de Malware Básico**  
   Analisa arquivos locais em busca de padrões de código potencialmente maliciosos, como `base64_decode` e `eval`.

---

## **Como Usar**

### Requisitos:
- PHP 7.4 ou superior.
- Acesso ao servidor onde o site está hospedado.

### Passos:
1. Clone o repositório:
   ```bash
   git clone https://github.com/skylinenando/security-scanner.git
   cd security-scanner
   ```

2. Edite o arquivo para incluir a URL do site:
   ```php
   $target_url = "https://seusite.com"; // Substitua pelo URL do site a ser analisado
   ```

3. Execute o script:
   ```bash
   php security_scanner.php
   ```

---

## **Descrição das Funções**

### **1. checkDirectoryListing($url)**
- Verifica se a listagem de diretórios está habilitada.
- Procura por palavras-chave como "Index of" e "Parent Directory" na resposta da URL.

### **2. checkSensitiveFiles($url, $files)**
- Verifica a existência de arquivos sensíveis no servidor.
- Faz solicitações para arquivos como `.env`, `config.php`, `wp-config.php`, entre outros.

### **3. checkPHPConfig()**
- Valida configurações críticas do PHP:
  - `display_errors`: Deve estar desativado.
  - `allow_url_include`: Deve estar desativado.
  - `expose_php`: Deve estar desativado.

### **4. testXSS($url, $pages)**
- Simula ataques XSS usando URLs com payloads maliciosos.
- Exemplo de payload: `<script>alert(1)</script>`.

### **5. testSQLInjection($url, $pages)**
- Simula ataques de SQL Injection usando payloads básicos como:
  - `' OR 1=1 --`
  - `' OR 'a'='a`

### **6. checkMalware($directory)**
- Varre o diretório local para detectar padrões de código potencialmente maliciosos, como:
  - `base64_decode`
  - `eval`
  - `shell_exec`
  - `system`
- Analisa arquivos com extensões `.php`, `.html`, e `.js`.

---

## **Saída do Script**

O script exibe os resultados diretamente no console, com mensagens como:
- `[ALERTA]`: Indica uma possível vulnerabilidade ou configuração insegura.
- `[OK]`: Indica que a verificação foi concluída sem problemas.
- `[INFO]`: Mensagens informativas durante a execução.

---

## **Exemplo de Saída**

```plaintext
Iniciando varredura de segurança em https://seusite.com...

[ALERTA] Listagem de diretórios habilitada: https://seusite.com/uploads
[OK] Arquivo não exposto: https://seusite.com/.env
[ALERTA] Configuração insegura de PHP ativa: allow_url_include
[OK] Nenhuma vulnerabilidade XSS em https://seusite.com?page=home
[ALERTA] Vulnerabilidade de SQL Injection detectada: https://seusite.com?id=1' OR 1=1 --
[ALERTA] Código potencialmente malicioso encontrado em: /var/www/html/malware.php

Varredura concluída.
```

---

## **Limitações**
1. Este script é básico e pode não detectar vulnerabilidades mais avançadas.
2. Não substitui ferramentas profissionais como OWASP ZAP, Nikto, ou Burp Suite.
3. Deve ser usado apenas em sites que você possui ou tem permissão para testar.

---

## **Licença**
Este projeto é distribuído sob a [MIT License](LICENSE). Use-o por sua conta e risco.

---

Se tiver dúvidas ou sugestões, sinta-se à vontade para abrir uma issue no repositório! 😊
