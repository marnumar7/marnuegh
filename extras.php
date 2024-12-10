<?php
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Slim\Factory\AppFactory;
use Slim\Exception\HttpNotFoundException;

require __DIR__ . '/vendor/autoload.php';

$app = AppFactory::create();
$app->setBasePath('/marnu_rest');

// Clave secreta para JWT
$secretKey = 'marnumar7mar';

// Configuración de la base de datos
$dsn = 'mysql:host=localhost;dbname=eghouse;charset=utf8';
$dbUser = 'root';
$dbPassword = '';
$pdo = new PDO($dsn, $dbUser, $dbPassword, [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
]);

// Middleware de manejo de errores
$app->addErrorMiddleware(true, true, true)->setErrorHandler(
    HttpNotFoundException::class,
    function ($request, $exception, $displayErrorDetails) use ($app) {
        $response = $app->getResponseFactory()->createResponse();
        $response->getBody()->write(json_encode(['error' => 'Ruta no encontrada']));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(404);
    }
);

// Ruta para registro de usuario
// Ruta para registro de usuario
$app->post('/register', function ($request, $response) use ($pdo, $secretKey) {
    // Obtener los datos del formulario
    $data = $request->getParsedBody();

    // Obtener los datos del formulario
    $username = $data['usuario'] ?? null;
    $password = $data['contrasena'] ?? null;
    $contact = $data['contacto'] ?? null;
    $whatsapp = $data['whatsapp'] ?? null;

    // Verificar si los datos obligatorios están presentes
    if (!$username || !$password || !$contact || !isset($_FILES['imagen_perfil'])) {
        $response->getBody()->write(json_encode(['error' => 'Datos incompletos']));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(400);
    }

    // Verificar la imagen
    $imagen = $_FILES['imagen_perfil'];
    if ($imagen['size'] > 2 * 1024 * 1024) { // Si la imagen pesa más de 2MB
        $response->getBody()->write(json_encode(['error' => 'La imagen de perfil no puede pesar más de 2MB']));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(400);
    }

    // Subir la imagen a la carpeta 'img/all'
    $uploadDir = __DIR__ . '/img/all/';
    $fileName = time() . '_' . basename($imagen['name']);
    $filePath = $uploadDir . $fileName;

    if (!move_uploaded_file($imagen['tmp_name'], $filePath)) {
        $response->getBody()->write(json_encode(['error' => 'Error al subir la imagen de perfil']));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(500);
    }

    // Registrar usuario
    $hashedPassword = password_hash($password, PASSWORD_BCRYPT);
    $stmt = $pdo->prepare('INSERT INTO usuario (usuario, contrasena, contacto, whatsapp, imagen_perfil) VALUES (?, ?, ?, ?, ?)');
    $stmt->execute([$username, $hashedPassword, $contact, $whatsapp, $filePath]);

    // Generar token JWT
    $userId = $pdo->lastInsertId();
    $payload = [
        'sub' => $userId,
        'username' => $username,
        'exp' => time() + 3600
    ];
    $jwt = JWT::encode($payload, $secretKey, 'HS256');

    $response->getBody()->write(json_encode(['message' => 'Usuario registrado', 'token' => $jwt]));
    return $response->withHeader('Content-Type', 'application/json')->withStatus(201);
});



// Ruta para inicio de sesión
$app->post('/login', function ($request, $response) use ($pdo, $secretKey) {
    $data = json_decode($request->getBody()->getContents(), true);

    $username = $data['usuario'] ?? null;
    $password = $data['contrasena'] ?? null;

    if (!$username || !$password) {
        $response->getBody()->write(json_encode(['error' => 'Datos incompletos']));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(400);
    }

    // Buscar usuario en la base de datos
    $stmt = $pdo->prepare('SELECT id_usuario, contrasena FROM usuario WHERE usuario = ?');
    $stmt->execute([$username]);
    $user = $stmt->fetch();

    if (!$user || !password_verify($password, $user['contrasena'])) {
        $response->getBody()->write(json_encode(['error' => 'Credenciales inválidas']));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(401);
    }

    // Generar token JWT
    $payload = [
        'sub' => $user['id_usuario'],
        'username' => $username,
        'exp' => time() + 3600
    ];
    $jwt = JWT::encode($payload, $secretKey, 'HS256');

    $response->getBody()->write(json_encode(['message' => 'Inicio de sesión exitoso', 'token' => $jwt]));
    return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
});

// Ruta para crear anuncios
$app->post('/post-ad', function ($request, $response) use ($pdo, $secretKey) {
    $authHeader = $request->getHeader('Authorization')[0] ?? '';
    $jwt = str_replace('Bearer ', '', $authHeader);

    try {
        $decoded = JWT::decode($jwt, new Key($secretKey, 'HS256'));
    } catch (Exception $e) {
        $response->getBody()->write(json_encode(['error' => 'Token inválido o expirado']));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(401);
    }

    $data = json_decode($request->getBody()->getContents(), true);

    $type = $data['tipo'] ?? null;
    $city = $data['ciudad'] ?? null;

    if (!$type || !$city) {
        $response->getBody()->write(json_encode(['error' => 'Datos incompletos']));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(400);
    }

    $stmt = $pdo->prepare('INSERT INTO anuncio (idUsuario, tipo, ciudad) VALUES (?, ?, ?)');
    $stmt->execute([$decoded->sub, $type, $city]);

    $response->getBody()->write(json_encode(['message' => 'Anuncio creado']));
    return $response->withHeader('Content-Type', 'application/json')->withStatus(201);
});

$app->run();