<?php

// Configurações
$target_url = "http://www.tgvtec.com.br"; // Substitua pelo URL do seu site
$sensitive_files = [
    '.env', 'config.php', 'db_backup.sql', 'wp-config.php',
    'composer.json', 'composer.lock', '.git', '.htaccess'
];
$test_pages = [
    '?id=1', '?search=test', '?page=home', '?query=<script>alert(1)</script>'
];

// Função para verificar listagem de diretórios
function checkDirectoryListing($url) {
    $response = @file_get_contents($url);
    if ($response && (strpos($response, 'Index of') !== false || strpos($response, 'Parent Directory') !== false)) {
        echo "[ALERTA] Listagem de diretórios habilitada: $url\n";
    } else {
        echo "[OK] Sem listagem de diretórios em $url\n";
    }
}

// Função para verificar arquivos sensíveis
function checkSensitiveFiles($url, $files) {
    foreach ($files as $file) {
        $file_url = $url . '/' . $file;
        $response = @file_get_contents($file_url);
        if ($response) {
            echo "[ALERTA] Arquivo sensível encontrado: $file_url\n";
        } else {
            echo "[OK] Arquivo não exposto: $file_url\n";
        }
    }
}

// Função para verificar configurações inseguras de PHP
function checkPHPConfig() {
    $settings = [
        'display_errors' => ini_get('display_errors'),
        'allow_url_include' => ini_get('allow_url_include'),
        'expose_php' => ini_get('expose_php'),
    ];
    foreach ($settings as $key => $value) {
        if ($value == 1 || $value === 'On') {
            echo "[ALERTA] Configuração insegura de PHP ativa: $key\n";
        } else {
            echo "[OK] Configuração segura: $key\n";
        }
    }
}

// Função para testar XSS básico
function testXSS($url, $pages) {
    foreach ($pages as $page) {
        $full_url = $url . $page;
        $response = @file_get_contents($full_url);
        if ($response && strpos($response, '<script>alert(1)</script>') !== false) {
            echo "[ALERTA] Vulnerabilidade de XSS detectada: $full_url\n";
        } else {
            echo "[OK] Nenhuma vulnerabilidade XSS em $full_url\n";
        }
    }
}

// Função para testar SQL Injection básico
function testSQLInjection($url, $pages) {
    $payloads = ["' OR 1=1 --", "' OR 'a'='a", "' UNION SELECT null --"];
    foreach ($pages as $page) {
        foreach ($payloads as $payload) {
            $test_url = $url . $page . $payload;
            $response = @file_get_contents($test_url);
            if ($response && (strpos($response, 'error in your SQL syntax') !== false || strpos($response, 'mysql_fetch') !== false)) {
                echo "[ALERTA] Vulnerabilidade de SQL Injection detectada: $test_url\n";
            } else {
                echo "[OK] Nenhuma vulnerabilidade de SQL Injection em $test_url\n";
            }
        }
    }
}

// Função para verificar malware básico
function checkMalware($directory) {
    $malicious_strings = ['base64_decode', 'eval(', 'gzinflate(', 'shell_exec', 'system('];
    $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($directory));
    foreach ($iterator as $file) {
        if ($file->isFile() && in_array($file->getExtension(), ['php', 'html', 'js'])) {
            $content = file_get_contents($file->getPathname());
            foreach ($malicious_strings as $malware) {
                if (strpos($content, $malware) !== false) {
                    echo "[ALERTA] Código potencialmente malicioso encontrado em: " . $file->getPathname() . "\n";
                }
            }
        }
    }
}

// Função para verificar cabeçalhos HTTP
function checkHTTPHeaders($url) {
    $headers = get_headers($url, 1);
    $required_headers = [
        'Strict-Transport-Security',
        'Content-Security-Policy',
        'X-Frame-Options',
    ];

    foreach ($required_headers as $header) {
        if (isset($headers[$header])) {
            echo "[OK] Cabeçalho de segurança encontrado: $header\n";
        } else {
            echo "[ALERTA] Cabeçalho de segurança ausente: $header\n";
        }
    }
}

// Função para verificar HTTPS
function checkHTTPS($url) {
    if (strpos($url, 'https://') === 0) {
        echo "[OK] HTTPS está habilitado no site.\n";
    } else {
        echo "[ALERTA] O site não força HTTPS.\n";
    }
}

// Início do Scan
echo "Iniciando varredura de segurança em $target_url...\n\n";

// Verificações
checkDirectoryListing($target_url);
checkSensitiveFiles($target_url, $sensitive_files);
checkPHPConfig();
testXSS($target_url, $test_pages);
testSQLInjection($target_url, $test_pages);
checkHTTPS($target_url);
checkHTTPHeaders($target_url);

// Verificação de malware (local)
echo "\n[INFO] Verificando malware no diretório local...\n";
checkMalware(__DIR__);

echo "\nVarredura concluída.\n";

?>
