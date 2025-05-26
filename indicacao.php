<?php
header('Content-Type: application/json');
error_reporting(0);
ini_set('display_errors', 0);

// Configurações do banco de dados
define('DB_HOST', '127.0.0.1');
define('DB_NAME', 'sistema_indicacoes');
define('DB_USER', 'root');
define('DB_PASS', '');

// Headers de segurança
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("X-XSS-Protection: 1; mode=block");

try {
    // Conexão com o banco de dados
    $pdo = new PDO(
        'mysql:host=' . DB_HOST . ';dbname=' . DB_NAME . ';charset=utf8mb4',
        DB_USER,
        DB_PASS,
        [
            PDO::ATTR_EMULATE_PREPARES => false,
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
        ]
    );

    // Verifica método HTTP
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        throw new Exception('Método não permitido', 405);
    }

    // Obtém os dados da requisição
    $input = file_get_contents('php://input');
    $data = json_decode($input, true) ?: $_POST;

    // Validação dos campos obrigatórios
    $requiredFields = [
        'primeiro-nome', 'sobrenome', 'email', 'whatsapp', 'conheceu',
        'nome-indicado', 'sobrenome-indicado', 'email-indicado', 
        'whatsapp-indicado', 'tipo-projeto', 'descricao-projeto'
    ];

    foreach ($requiredFields as $field) {
        if (empty($data[$field])) {
            throw new Exception("O campo {$field} é obrigatório", 400);
        }
    }

    // Sanitização e validação dos dados
    $indicador = [
        'nome' => trim($data['primeiro-nome'] . ' ' . $data['sobrenome']),
        'email' => filter_var($data['email'], FILTER_SANITIZE_EMAIL),
        'whatsapp' => preg_replace('/[^0-9]/', '', $data['whatsapp']),
        'como_conheceu' => htmlspecialchars($data['conheceu'])
    ];

    $cliente = [
        'nome' => trim($data['nome-indicado'] . ' ' . $data['sobrenome-indicado']),
        'email' => filter_var($data['email-indicado'], FILTER_SANITIZE_EMAIL),
        'whatsapp' => preg_replace('/[^0-9]/', '', $data['whatsapp-indicado']),
        'tipo_servico' => htmlspecialchars($data['tipo-projeto']),
        'descricao' => htmlspecialchars($data['descricao-projeto'])
    ];

    // Validações específicas
    if (!filter_var($indicador['email'], FILTER_VALIDATE_EMAIL)) {
        throw new Exception('E-mail do indicador inválido', 400);
    }

    if (!filter_var($cliente['email'], FILTER_VALIDATE_EMAIL)) {
        throw new Exception('E-mail do cliente indicado inválido', 400);
    }

    if (strlen($indicador['whatsapp']) < 11) {
        throw new Exception('WhatsApp do indicador deve conter DDD + número completo', 400);
    }

    if (strlen($cliente['whatsapp']) < 11) {
        throw new Exception('WhatsApp do cliente indicado deve conter DDD + número completo', 400);
    }

    // Inicia transação para garantir integridade dos dados
    $pdo->beginTransaction();

    try {
        // Processa o indicador (insere ou busca existente)
        $stmt = $pdo->prepare("SELECT id FROM indicador WHERE email = ? OR whatsapp = ? LIMIT 1");
        $stmt->execute([$indicador['email'], $indicador['whatsapp']]);
        $indicadorExistente = $stmt->fetch();

        if ($indicadorExistente) {
            $idIndicador = $indicadorExistente['id'];
        } else {
            $stmt = $pdo->prepare("INSERT INTO indicador (nome, whatsapp, email, como_nos_conheceu) VALUES (?, ?, ?, ?)");
            $stmt->execute([
                $indicador['nome'],
                $indicador['whatsapp'],
                $indicador['email'],
                $indicador['como_conheceu']
            ]);
            $idIndicador = $pdo->lastInsertId();
        }

        // Verifica se o cliente já existe
        $stmt = $pdo->prepare("SELECT id FROM cliente WHERE email = ? OR whatsapp = ? LIMIT 1");
        $stmt->execute([$cliente['email'], $cliente['whatsapp']]);
        if ($stmt->fetch()) {
            throw new Exception('Este cliente já foi cadastrado anteriormente', 400);
        }

        // Insere o novo cliente
        $stmt = $pdo->prepare("INSERT INTO cliente (nome, whatsapp, email, tipo_servico, descricao, id_indicador) VALUES (?, ?, ?, ?, ?, ?)");
        $stmt->execute([
            $cliente['nome'],
            $cliente['whatsapp'],
            $cliente['email'],
            $cliente['tipo_servico'],
            $cliente['descricao'],
            $idIndicador
        ]);

        $pdo->commit();

        // Resposta de sucesso
        echo json_encode([
            'success' => true,
            'id_indicador' => $idIndicador,
            'message' => 'Indicação cadastrada com sucesso!'
        ]);

    } catch (Exception $e) {
        $pdo->rollBack();
        throw $e;
    }

} catch (Exception $e) {
    http_response_code($e->getCode() ?: 500);
    echo json_encode([
        'success' => false,
        'message' => $e->getMessage(),
        'error_code' => $e->getCode()
    ]);
    exit;
}