<?php
include 'config.php';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $username = $_POST['username'];
    $password = $_POST['password'];

    $sql = "SELECT * FROM users WHERE username = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
        $user = $result->fetch_assoc();
        if (password_verify($password, $user['password'])) {
            // Login successful
            echo "Login successful!";
            // Start session and redirect to dashboard or product page
            session_start();
            $_SESSION['user_id'] = $user['id'];
            header("Location: products.html");
            exit();
        } else {
            echo "Invalid username or password!";
        }
    } else {
        echo "No such user found!";
    }

    $stmt->close();
    $conn->close();
}
?>
