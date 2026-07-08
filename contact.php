<?php
// Simple same-domain contact handler for Skill Route.
// Receives the contact form POST and emails it to info@skillroute.pk.

// Only accept POST requests.
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: index.html');
    exit;
}

// Honeypot: real users leave this empty; bots tend to fill it.
if (!empty($_POST['_honey'])) {
    // Pretend success so bots don't retry.
    header('Location: index.html?sent=1#contact');
    exit;
}

// Collect and trim input.
$name    = trim($_POST['name']    ?? '');
$email   = trim($_POST['email']   ?? '');
$subject = trim($_POST['subject'] ?? '');
$message = trim($_POST['message'] ?? '');

// Strip line breaks from values that go into mail headers (prevents header injection).
$email   = str_replace(array("\r", "\n"), '', $email);
$subject = str_replace(array("\r", "\n"), '', $subject);

// Basic validation.
if ($name === '' || $message === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
    header('Location: index.html?sent=0#contact');
    exit;
}

// Where the enquiry is sent.
$to          = 'info@skillroute.pk';
$mailSubject = $subject !== '' ? $subject : 'New enquiry from Skill Route website';

$body  = "You have a new message from the Skill Route website:\n\n";
$body .= "Name:    $name\n";
$body .= "Email:   $email\n";
$body .= "Subject: $subject\n\n";
$body .= "Message:\n$message\n";

// From must be an address on your own domain for reliable delivery.
// Reply-To is the visitor, so you can just hit "Reply" to answer them.
$headers  = "From: Skill Route Website <info@skillroute.pk>\r\n";
$headers .= "Reply-To: $name <$email>\r\n";
$headers .= "Content-Type: text/plain; charset=UTF-8\r\n";

$sent = mail($to, $mailSubject, $body, $headers);

// Redirect back to the site with a status flag the page can read.
if ($sent) {
    header('Location: index.html?sent=1#contact');
} else {
    header('Location: index.html?sent=0#contact');
}
exit;
