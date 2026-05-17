<?php

function shieldurl_mail_is_configured()
{
    $config = require __DIR__ . '/../config/mail.php';
    return !empty($config['host']) && !empty($config['username']) && !empty($config['password']);
}

function shieldurl_send_mail($to, $subject, $body)
{
    $config = require __DIR__ . '/../config/mail.php';
    if (empty($config['host']) || empty($config['username']) || empty($config['password'])) {
        error_log("ShieldURL mail not configured. Message for {$to}:\nSubject: {$subject}\n{$body}");
        return false;
    }

    $host = $config['host'];
    $port = (int)$config['port'];
    $timeout = 20;
    $remote = ($config['encryption'] === 'ssl' ? 'ssl://' : '') . $host . ':' . $port;
    $socket = @stream_socket_client($remote, $errno, $errstr, $timeout, STREAM_CLIENT_CONNECT);
    if (!$socket) {
        error_log("ShieldURL SMTP connection failed: {$errstr} ({$errno})");
        return false;
    }

    stream_set_timeout($socket, $timeout);

    $read = function () use ($socket) {
        $response = '';
        while (($line = fgets($socket, 515)) !== false) {
            $response .= $line;
            if (isset($line[3]) && $line[3] === ' ') {
                break;
            }
        }
        return $response;
    };

    $command = function ($line, $expected) use ($socket, $read) {
        fwrite($socket, $line . "\r\n");
        $response = $read();
        $code = (int)substr($response, 0, 3);
        $expected = (array)$expected;
        if (!in_array($code, $expected, true)) {
            throw new RuntimeException("SMTP command failed: {$line}; response: {$response}");
        }
        return $response;
    };

    try {
        $greeting = $read();
        if ((int)substr($greeting, 0, 3) !== 220) {
            throw new RuntimeException("SMTP greeting failed: {$greeting}");
        }

        $serverName = $_SERVER['SERVER_NAME'] ?? 'localhost';
        $command("EHLO {$serverName}", 250);

        if ($config['encryption'] === 'tls') {
            $command('STARTTLS', 220);
            if (!stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_TLS_CLIENT)) {
                throw new RuntimeException('SMTP STARTTLS negotiation failed.');
            }
            $command("EHLO {$serverName}", 250);
        }

        $command('AUTH LOGIN', 334);
        $command(base64_encode($config['username']), 334);
        $command(base64_encode($config['password']), 235);

        $fromEmail = $config['from_email'];
        $fromName = trim($config['from_name']);
        $encodedFrom = $fromName !== '' ? sprintf('"%s" <%s>', addcslashes($fromName, '"\\'), $fromEmail) : $fromEmail;

        $command("MAIL FROM:<{$fromEmail}>", 250);
        $command("RCPT TO:<{$to}>", [250, 251]);
        $command('DATA', 354);

        $headers = [
            'From: ' . $encodedFrom,
            'To: <' . $to . '>',
            'Subject: ' . $subject,
            'MIME-Version: 1.0',
            'Content-Type: text/plain; charset=UTF-8',
        ];
        $message = implode("\r\n", $headers) . "\r\n\r\n" . $body;
        $message = str_replace(["\r\n.", "\n."], ["\r\n..", "\n.."], $message);
        fwrite($socket, $message . "\r\n.\r\n");
        $response = $read();
        if ((int)substr($response, 0, 3) !== 250) {
            throw new RuntimeException("SMTP DATA failed: {$response}");
        }

        $command('QUIT', 221);
        fclose($socket);
        return true;
    } catch (Throwable $e) {
        fclose($socket);
        error_log('ShieldURL SMTP error: ' . $e->getMessage());
        return false;
    }
}
