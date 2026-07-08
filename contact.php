<?php
// ============================================================================
// Skill Route contact form handler (self-contained SMTP sender).
// Because this host has disabled PHP mail(), we send through your mailbox
// via authenticated SMTP. No external libraries required.
//
//  >>> EDIT THE 4 SETTINGS BELOW <<<
//  The only value you normally must change is $smtp_pass — the password of
//  the info@skillroute.pk mailbox (set/reset it in cPanel > Email Accounts).
// ============================================================================

$smtp_host = 'mail.skillroute.pk';    // usually mail.<yourdomain>
$smtp_port = 465;                     // 465 = SSL (try 587 if 465 fails)
$smtp_user = 'info@skillroute.pk';    // mailbox to send FROM / log in with
$smtp_pass = 'PUT-MAILBOX-PASSWORD-HERE';  // <-- password for that mailbox

$send_to   = 'info@skillroute.pk';    // where enquiries are delivered

// ----------------------------------------------------------------------------
// Nothing below normally needs editing.
// ----------------------------------------------------------------------------

// Buffer output so a stray notice can never break our redirect header.
ob_start();

// Only accept POST.
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: index.html');
    exit;
}

// Honeypot: real users leave this empty; bots tend to fill it.
if (!empty($_POST['_honey'])) {
    header('Location: index.html?sent=1#contact');
    exit;
}

// Collect + trim input.
$name    = trim($_POST['name']    ?? '');
$email   = trim($_POST['email']   ?? '');
$subject = trim($_POST['subject'] ?? '');
$message = trim($_POST['message'] ?? '');

// Strip line breaks from header-bound values (prevents header injection).
$email   = str_replace(array("\r", "\n"), '', $email);
$subject = str_replace(array("\r", "\n"), '', $subject);
$name    = str_replace(array("\r", "\n"), '', $name);

// Basic validation.
if ($name === '' || $message === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
    header('Location: index.html?sent=0#contact');
    exit;
}

$mailSubject = $subject !== '' ? $subject : 'New enquiry from Skill Route website';

$body  = "You have a new message from the Skill Route website:\n\n";
$body .= "Name:    $name\n";
$body .= "Email:   $email\n";
$body .= "Subject: $subject\n\n";
$body .= "Message:\n$message\n";

$err = '';
$ok  = smtp_send(
    $smtp_host, $smtp_port, $smtp_user, $smtp_pass,
    $smtp_user, 'Skill Route Website',   // From
    $send_to,                            // To
    $email, $name,                       // Reply-To
    $mailSubject, $body, $err
);

ob_end_clean();
header('Location: index.html?sent=' . ($ok ? '1' : '0') . '#contact');
exit;


// ----------------------------------------------------------------------------
// Minimal authenticated SMTP client (SSL on 465, or STARTTLS on 587).
// ----------------------------------------------------------------------------
function smtp_send($host, $port, $user, $pass, $from, $fromName, $to, $replyTo, $replyName, $subject, $body, &$err) {

    $ctx = stream_context_create(array('ssl' => array(
        'verify_peer'       => false,
        'verify_peer_name'  => false,
        'allow_self_signed' => true,
    )));

    $transport = ($port == 465) ? "ssl://$host:$port" : "tcp://$host:$port";
    $fp = @stream_socket_client($transport, $errno, $errstr, 20, STREAM_CLIENT_CONNECT, $ctx);
    if (!$fp) { $err = "Connect failed: $errstr ($errno)"; return false; }
    stream_set_timeout($fp, 20);

    $read = function () use ($fp) {
        $data = '';
        while (($line = fgets($fp, 515)) !== false) {
            $data .= $line;
            if (isset($line[3]) && $line[3] === ' ') break;
        }
        return $data;
    };
    $cmd = function ($c) use ($fp) { fwrite($fp, $c . "\r\n"); };
    $expect = function ($resp, $code) use (&$err) {
        if (strncmp($resp, $code, 3) !== 0) { $err = "SMTP said: " . trim($resp); return false; }
        return true;
    };

    if (!$expect($read(), '220')) return false;
    $cmd("EHLO skillroute.pk"); if (!$expect($read(), '250')) return false;

    if ($port == 587) {
        $cmd("STARTTLS"); if (!$expect($read(), '220')) return false;
        if (!stream_socket_enable_crypto($fp, true, STREAM_CRYPTO_METHOD_TLS_CLIENT)) { $err = 'STARTTLS failed'; return false; }
        $cmd("EHLO skillroute.pk"); if (!$expect($read(), '250')) return false;
    }

    $cmd("AUTH LOGIN");            if (!$expect($read(), '334')) return false;
    $cmd(base64_encode($user));   if (!$expect($read(), '334')) return false;
    $cmd(base64_encode($pass));   if (!$expect($read(), '235')) { $err = 'Login failed — check the mailbox password.'; return false; }

    $cmd("MAIL FROM:<$from>");     if (!$expect($read(), '250')) return false;
    $cmd("RCPT TO:<$to>");         if (!$expect($read(), '250')) return false;
    $cmd("DATA");                  if (!$expect($read(), '354')) return false;

    $encSubject = '=?UTF-8?B?' . base64_encode($subject) . '?=';
    $headers  = "From: $fromName <$from>\r\n";
    $headers .= "Reply-To: $replyName <$replyTo>\r\n";
    $headers .= "To: <$to>\r\n";
    $headers .= "Subject: $encSubject\r\n";
    $headers .= "MIME-Version: 1.0\r\n";
    $headers .= "Content-Type: text/plain; charset=UTF-8\r\n";
    $headers .= "Date: " . date('r') . "\r\n";

    // Normalise line endings + dot-stuff lines beginning with a period.
    $body = str_replace("\r\n", "\n", $body);
    $body = preg_replace('/^\./m', '..', $body);
    $body = str_replace("\n", "\r\n", $body);

    $cmd($headers . "\r\n" . $body . "\r\n.");
    if (!$expect($read(), '250')) return false;

    $cmd("QUIT");
    fclose($fp);
    return true;
}
