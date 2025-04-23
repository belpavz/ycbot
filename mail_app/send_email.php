<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// Подключение автозагрузчика Composer
require 'vendor/autoload.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\SMTP;
use PHPMailer\PHPMailer\Exception;


// Получение параметров из командной строки или POST-запроса
$to = $_REQUEST['to'] ?? $argv[1] ?? '';
$subject = $_REQUEST['subject'] ?? $argv[2] ?? '';
$body = $_REQUEST['body'] ?? $argv[3] ?? '';

// Проверка наличия обязательных параметров
if (empty($to) || empty($subject) || empty($body)) {
    echo "Ошибка: Не указаны обязательные параметры (получатель, тема, текст)";
    exit(1);
}

// Создание экземпляра PHPMailer
$mail = new PHPMailer(true);
$mail->CharSet = 'UTF-8'; 

try {
    // Настройка вывода отладочной информации
    $mail->SMTPDebug = SMTP::DEBUG_SERVER;


    // Настройки сервера
    $mail->isSMTP();
    $mail->Host = 'smtp.timeweb.ru';
    $mail->SMTPAuth = true;
    $mail->Username = 'mail@ycbot.ru'; 
    $mail->Password = 'bT9eb$VVf=d%6?7';  
    $mail->SMTPSecure = PHPMailer::ENCRYPTION_SMTPS; // Использование SSL
    $mail->Port = 465;
    
    // Настройка DKIM
    $mail->DKIM_domain = 'ycbot.ru';
    $mail->DKIM_private = '/home/belpav/ycbot/ycbot.ru.private'; // Путь к приватному ключу
    $mail->DKIM_selector = 'mail'; // Селектор, указанный в DNS
    $mail->DKIM_identity = 'mail@ycbot.ru';
    
    // Отправитель и получатель
    $mail->setFrom('mail@ycbot.ru', 'YCBot');
    $mail->addAddress($to);
    
    // Содержимое письма
    $mail->isHTML(true);
    $mail->Subject = $subject;
    $mail->Body = $body;
    $mail->AltBody = strip_tags($body); // Текстовая версия для клиентов без поддержки HTML
    
    // Отправка письма
    $mail->send();
    echo "Письмо успешно отправлено на $to\n";
    exit(0);
} catch (Exception $e) {
    // Оставляем вывод ошибок для catch блока
    echo "Ошибка отправки письма: {$mail->ErrorInfo}\n"; 
    exit(1);
}
?>